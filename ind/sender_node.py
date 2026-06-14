import os
import random
import socket
import time
import threading
import ipaddress
import requests
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from . import runtime as runtime_json
from . import settings as ind_settings
from . import token as ind_token
from . import transport as ind_transport

logger = logging.getLogger(__name__)
already_tried = []
PORT = 8888
MAX_PEERS_PER_IPV4_C_BLOCK = 3
MAX_PEERS_PER_ADDRESS_BLOCK = MAX_PEERS_PER_IPV4_C_BLOCK
DEFAULT_DIVERSE_PEER_SAMPLE = 12
DNS_SEED_REFRESH_SECONDS = 3600
MAX_DNS_SEED_RESULTS = 128
DEFAULT_CONNECT_ATTEMPT_BUDGET_SECONDS = 45
REQUEST_RATE_LIMIT_MIN_BACKOFF_SECONDS = 8
REQUEST_RATE_LIMIT_MAX_BACKOFF_SECONDS = 30
BROADCAST_RECONCILE_ATTEMPTS = 2
BROADCAST_RECONCILE_RETRY_DELAY_SECONDS = 1.5
BROADCAST_RECONCILE_BUDGET_SECONDS = 20
BROADCAST_RECONCILED_STATUSES = {
    "unreceipted",
    "pending",
    "settled",
    "settled_fresh",
    "strong_local",
}

REQUEST_TIMEOUT = "timeout"
REQUEST_RATE_LIMITED = "rate_limited"
REQUEST_CONNECTION_CLOSED = "connection_closed"
REQUEST_HANDSHAKE_FAILED = "handshake_failed"
REQUEST_PEER_KEY_MISMATCH = "peer_key_mismatch"
REQUEST_INVALID = "invalid"
REQUEST_OK = "ok"
REQUEST_RETRYABLE_STATUSES = {
    REQUEST_TIMEOUT,
    REQUEST_RATE_LIMITED,
    REQUEST_CONNECTION_CLOSED,
    REQUEST_HANDSHAKE_FAILED,
}
REQUEST_FAILURE_STATUSES = REQUEST_RETRYABLE_STATUSES | {REQUEST_PEER_KEY_MISMATCH, REQUEST_INVALID}

RUNTIME_DIRS = runtime_json.RUNTIME_DIRS
_last_dns_seed_refresh = 0
_peer_backoff_until = {}
_peer_backoff_lock = threading.Lock()
_queued_gossip_retries = set()
_queued_gossip_retry_lock = threading.Lock()


@dataclass(frozen=True)
class PeerRequestResult:
    """Structured result for one logical node request across all tried routes."""

    status: str
    response: str = ""
    peer: str = ""
    route: str = ""
    attempts: tuple = ()
    retry_after_seconds: float = 0.0
    error: str = ""

    @property
    def ok(self):
        return self.status == REQUEST_OK


def node_port():
    return ind_settings.node_port()


def _runtime_path(path):
    path = Path(path)
    parts = path.parts
    if parts and parts[0] == "ip_folder":
        return runtime_json.peer_root() / Path(*parts[1:])
    return path


def _read_text(path):
    try:
        with open(_runtime_path(path), 'r') as handle:
            return handle.read()
    except FileNotFoundError:
        return ''


def _list_dir(path):
    path = _runtime_path(path)
    try:
        return os.listdir(path)
    except FileNotFoundError:
        os.makedirs(path, exist_ok=True)
        return []


def _strip_peer_brackets(value):
    value = str(value).strip()
    if value.startswith("[") and "]" in value:
        return value[1:value.index("]")]
    return value


def _normalize_peer_address(value):
    """Return a canonical IP literal, or an empty string."""

    value = _strip_peer_brackets(value)
    if value.startswith("::ffff:"):
        value = value[len("::ffff:"):]
    try:
        ip = ipaddress.ip_address(value)
        if getattr(ip, "ipv4_mapped", None) is not None:
            ip = ip.ipv4_mapped
        return ip.compressed
    except ValueError:
        return ""


def _valid_peer_address(value):
    """Return whether a peer address is a globally-routable IPv4 or IPv6 literal."""

    normalized = _normalize_peer_address(value)
    if not normalized:
        return False
    try:
        ip = ipaddress.ip_address(normalized)
        return (
            ip.is_global
            and not ip.is_loopback
            and not ip.is_private
            and not ip.is_multicast
            and not ip.is_reserved
            and not ip.is_unspecified
            and not ip.is_link_local
        )
    except ValueError:
        return False


def _valid_ipv4(value):
    try:
        ip = ipaddress.ip_address(_strip_peer_brackets(value))
        return ip.version == 4 and _valid_peer_address(ip.compressed)
    except ValueError:
        return False


def _peer_files(path):
    peers = []
    folder = _runtime_path(path)
    for item in _list_dir(path):
        if not item.endswith(('.json', '.txt')):
            continue
        ip = _peer_from_cache_file(folder / item, item)
        if _valid_peer_address(ip):
            peers.append(_normalize_peer_address(ip))
    return peers


def _ipv4_c_block(value):
    normalized = _normalize_peer_address(value)
    if not _valid_ipv4(normalized):
        return None
    parts = normalized.split('.')
    return '.'.join(parts[:3])


def _peer_diversity_block(value):
    normalized = _normalize_peer_address(value)
    if not normalized:
        return None
    try:
        ip = ipaddress.ip_address(normalized)
    except ValueError:
        return None
    if ip.version == 4:
        return "ipv4:" + ".".join(normalized.split(".")[:3])
    return "ipv6:" + str(ipaddress.ip_network(f"{normalized}/48", strict=False))


def _valid_configured_peer_host(value):
    host = str(value).strip().lower()
    if not host or len(host) > 253:
        return False
    if _valid_peer_address(host):
        return True
    if any(char.isspace() for char in host) or any(char in host for char in "/\\[]"):
        return False
    labels = host.rstrip(".").split(".")
    if len(labels) < 2:
        return False
    for label in labels:
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if not all(char.isalnum() or char == "-" for char in label):
            return False
    return True


def _peer_is_ip_literal(value):
    try:
        ipaddress.ip_address(_strip_peer_brackets(value))
        return True
    except ValueError:
        return False


def _dedupe_preserving_order(items):
    seen = set()
    result = []
    for item in items:
        value = str(item).strip()
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _ordered_peer_candidates(peers):
    result = []
    seen = set()
    for peer in peers or []:
        host, _block = _peer_group(peer)
        if host and host not in seen:
            seen.add(host)
            result.append(host)
    return result


def _resolved_peer_routes(peer):
    """Return routes for one peer as hostname, then resolved IPv6, then resolved IPv4."""

    host = _peer_ip(peer)
    normalized = _normalize_peer_address(host)
    if normalized:
        return [normalized] if _valid_peer_address(normalized) else []
    host = str(host).strip().lower()
    if not _valid_configured_peer_host(host):
        return []
    ipv6_routes = []
    ipv4_routes = []
    try:
        records = socket.getaddrinfo(host, node_port(), family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    except OSError as exc:
        logger.debug("peer host %s could not be resolved for route fallback: %s", host, exc)
        records = []
    for family, _socktype, _proto, _canonname, sockaddr in records:
        if not sockaddr:
            continue
        address = _normalize_peer_address(str(sockaddr[0]).strip())
        if not _valid_peer_address(address):
            continue
        try:
            version = ipaddress.ip_address(address).version
        except ValueError:
            continue
        if family == socket.AF_INET6 or version == 6:
            ipv6_routes.append(address)
        elif family == socket.AF_INET or version == 4:
            ipv4_routes.append(address)
    return _dedupe_preserving_order([host] + ipv6_routes + ipv4_routes)


def expanded_peer_routes(peers):
    """Expand peers into attempted routes while preserving DNS seed order."""

    routes = []
    for peer in _ordered_peer_candidates(peers):
        for route in _resolved_peer_routes(peer):
            routes.append({"peer": peer, "route": route})
    return routes


def _peer_group(value):
    host = _peer_ip(value)
    normalized = _normalize_peer_address(host)
    if normalized:
        if not _valid_peer_address(normalized):
            return None, None
        return normalized, _peer_diversity_block(normalized)
    if _valid_configured_peer_host(host):
        return host.lower(), "host:" + host.lower()
    return None, None


def _peer_from_cache_file(path, item):
    try:
        if str(item).endswith(".json"):
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            ip = _normalize_peer_address(data.get("ip", ""))
            if ip:
                return ip
    except Exception as exc:
        logger.debug("could not read cached peer %s: %s", item, exc)
    return _peer_ip(item)


def _peer_ip(item):
    item = str(item).strip()
    if item.endswith('.json'):
        item = item[:-5]
    elif item.endswith('.txt'):
        item = item[:-4]
    if item.startswith("ipv6_"):
        maybe = item[len("ipv6_"):].replace("-", ":")
        normalized = _normalize_peer_address(maybe)
        if normalized:
            return normalized
    return _normalize_peer_address(item) or item


def _configured_peer_servers():
    try:
        return ind_settings.peer_ping_servers()
    except Exception as exc:
        logger.debug("could not read configured peer servers: %s", exc)
        return []


def _configured_dns_seed_hosts():
    try:
        return ind_settings.dns_seed_hosts()
    except Exception as exc:
        logger.debug("could not read configured DNS seed hosts: %s", exc)
        return []


def resolve_dns_seed_hosts(seed_hosts=None, limit=MAX_DNS_SEED_RESULTS):
    """Resolve DNS seed hostnames into globally-routable IPv4/IPv6 node hints."""

    seed_hosts = _configured_dns_seed_hosts() if seed_hosts is None else list(seed_hosts)
    peers = []
    seen = set()
    for seed_host in seed_hosts:
        seed_host = str(seed_host).strip()
        if not seed_host:
            continue
        try:
            records = socket.getaddrinfo(seed_host, node_port(), family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
        except OSError as exc:
            logger.debug("DNS seed %s could not be resolved: %s", seed_host, exc)
            continue
        for _family, _socktype, _proto, _canonname, sockaddr in records:
            ip = _normalize_peer_address(str(sockaddr[0]).strip())
            if _valid_peer_address(ip) and ip not in seen:
                seen.add(ip)
                peers.append(ip)
                if len(peers) >= int(limit):
                    return peers
    return peers


def refresh_dns_seed_peers(seed_hosts=None, version='2'):
    """Resolve configured DNS seeds and store their IPs as ordinary peer hints."""

    ensure_runtime_files()
    added = []
    for ip in resolve_dns_seed_hosts(seed_hosts=seed_hosts):
        if add_peer(ip, version=version):
            added.append(ip)
    return added


def maybe_refresh_dns_seed_peers(now=None, force=False):
    """Refresh DNS seeds at most hourly unless explicitly forced."""

    global _last_dns_seed_refresh
    now = int(time.time() if now is None else now)
    if not force and now - _last_dns_seed_refresh < DNS_SEED_REFRESH_SECONDS:
        return []
    _last_dns_seed_refresh = now
    return refresh_dns_seed_peers()


def _with_configured_peers(peers):
    try:
        maybe_refresh_dns_seed_peers()
    except Exception as exc:
        logger.debug("DNS seed refresh failed: %s", exc)
    seen = set()
    result = []
    configured = _configured_peer_servers() + _configured_dns_seed_hosts()
    for peer in list(peers) + _peer_files('ip_folder/2') + configured:
        host, _block = _peer_group(peer)
        if host and host not in seen:
            seen.add(host)
            result.append(host)
    return result


def _existing_peer_block_count(block):
    if not block:
        return 0
    count = 0
    for folder in ('ip_folder/1', 'ip_folder/2'):
        for item in _peer_files(folder):
            if _peer_diversity_block(item) == block:
                count += 1
    return count


def add_peer(ip, version='2'):
    """Add a routable IPv4/IPv6 peer while limiting concentration per network block."""

    ip = _normalize_peer_address(ip)
    if version not in ('1', '2') or not _valid_peer_address(ip):
        return False
    block = _peer_diversity_block(ip)
    target = runtime_json.peer_path(ip, version)
    if not os.path.exists(target) and _existing_peer_block_count(block) >= MAX_PEERS_PER_ADDRESS_BLOCK:
        return False
    runtime_json.write_peer(ip, version)
    return True


def diverse_peer_sample(peers, limit=DEFAULT_DIVERSE_PEER_SAMPLE):
    """Sample peers across IPv4 /24, IPv6 /48, and configured-host buckets."""

    by_block = {}
    for item in peers:
        peer, block = _peer_group(item)
        if not peer or not block:
            continue
        by_block.setdefault(block, []).append(peer)
    for items in by_block.values():
        random.shuffle(items)
    blocks = list(by_block)
    random.shuffle(blocks)
    selected = []
    while blocks and len(selected) < int(limit):
        next_blocks = []
        for block in blocks:
            items = by_block[block]
            if items and len(selected) < int(limit):
                selected.append(items.pop())
            if items:
                next_blocks.append(block)
        blocks = next_blocks
    return selected


def _rate_limit_backoff_seconds():
    return random.uniform(REQUEST_RATE_LIMIT_MIN_BACKOFF_SECONDS, REQUEST_RATE_LIMIT_MAX_BACKOFF_SECONDS)


def _set_peer_backoff(peer, seconds, now=None):
    peer = str(peer or "").strip()
    if not peer:
        return 0.0
    now = time.monotonic() if now is None else float(now)
    until = now + max(0.0, float(seconds))
    with _peer_backoff_lock:
        _peer_backoff_until[peer] = max(until, _peer_backoff_until.get(peer, 0.0))
        return max(0.0, _peer_backoff_until[peer] - now)


def _peer_backoff_remaining(peer, now=None):
    peer = str(peer or "").strip()
    if not peer:
        return 0.0
    now = time.monotonic() if now is None else float(now)
    with _peer_backoff_lock:
        until = _peer_backoff_until.get(peer, 0.0)
        remaining = until - now
        if remaining <= 0:
            _peer_backoff_until.pop(peer, None)
            return 0.0
        return remaining


def _note_rate_limited(peer, route):
    delay = _rate_limit_backoff_seconds()
    return max(_set_peer_backoff(peer, delay), _set_peer_backoff(route, delay))


def _response_status(response):
    response = str(response or "")
    if response == REQUEST_RATE_LIMITED:
        return REQUEST_RATE_LIMITED
    if response in {"", "n", REQUEST_INVALID, "too_many_refs"}:
        return REQUEST_INVALID
    return REQUEST_OK


def response_indicates_success(response):
    return _response_status(response) == REQUEST_OK


def _classify_request_exception(exc):
    if isinstance(exc, ind_transport.PeerKeyMismatch):
        return REQUEST_PEER_KEY_MISMATCH
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return REQUEST_TIMEOUT
    if isinstance(exc, (ConnectionAbortedError, ConnectionResetError, BrokenPipeError, ConnectionRefusedError)):
        return REQUEST_CONNECTION_CLOSED
    if isinstance(exc, ind_transport.TransportError):
        text = str(exc).lower()
        if "too large" in text:
            return REQUEST_INVALID
        if "handshake" in text or "hello" in text or "public key" in text:
            return REQUEST_HANDSHAKE_FAILED
        if "ended early" in text or "closed" in text:
            return REQUEST_CONNECTION_CLOSED
        return REQUEST_CONNECTION_CLOSED
    if isinstance(exc, OSError):
        return REQUEST_CONNECTION_CLOSED
    return REQUEST_INVALID


def _attempt_dict(peer, route, status, response="", error="", elapsed_seconds=0.0, retry_after_seconds=0.0):
    return {
        "peer": str(peer or ""),
        "route": str(route or ""),
        "status": str(status or ""),
        "response": str(response or ""),
        "error": str(error or ""),
        "elapsed_seconds": round(float(elapsed_seconds), 3),
        "retry_after_seconds": round(float(retry_after_seconds), 3),
    }


def _final_failure_result(attempts):
    if not attempts:
        return PeerRequestResult(status=REQUEST_CONNECTION_CLOSED, error="no peer routes available")
    for status in (
        REQUEST_RATE_LIMITED,
        REQUEST_TIMEOUT,
        REQUEST_CONNECTION_CLOSED,
        REQUEST_HANDSHAKE_FAILED,
        REQUEST_PEER_KEY_MISMATCH,
        REQUEST_INVALID,
    ):
        matching = [attempt for attempt in attempts if attempt.get("status") == status]
        if matching:
            retry_after = max(float(attempt.get("retry_after_seconds") or 0) for attempt in matching)
            return PeerRequestResult(
                status=status,
                response=matching[-1].get("response", ""),
                peer=matching[-1].get("peer", ""),
                route=matching[-1].get("route", ""),
                attempts=tuple(attempts),
                retry_after_seconds=retry_after,
                error=matching[-1].get("error", ""),
            )
    last = attempts[-1]
    return PeerRequestResult(
        status=last.get("status", REQUEST_INVALID),
        response=last.get("response", ""),
        peer=last.get("peer", ""),
        route=last.get("route", ""),
        attempts=tuple(attempts),
        error=last.get("error", ""),
    )


def _compat_response_from_result(result):
    if result.status == REQUEST_OK:
        return result.response
    if result.response in {REQUEST_INVALID, REQUEST_RATE_LIMITED, "too_many_refs"}:
        return result.response
    return result.status


def ensure_runtime_files():
    """Create runtime folders, state files, and local transport keypairs."""

    runtime_json.ensure_runtime_files()
    ind_transport.ensure_transport_keypair()


def connect_result(
    indicator,
    data,
    ipnl,
    *,
    timeout=None,
    max_duration_seconds=DEFAULT_CONNECT_ATTEMPT_BUDGET_SECONDS,
):
    """Send one logical encrypted request and return a structured route result."""

    ensure_runtime_files()
    data = str(data)
    if len(data.encode('utf-8')) > ind_token.MAX_WIRE_DECOMPRESSED_BYTES:
        return PeerRequestResult(status=REQUEST_INVALID, error="request payload is too large")
    candidates = _ordered_peer_candidates(ipnl)
    if len(candidates) > DEFAULT_DIVERSE_PEER_SAMPLE:
        candidates = diverse_peer_sample(candidates, limit=DEFAULT_DIVERSE_PEER_SAMPLE)
    routes = expanded_peer_routes(candidates)
    if not routes:
        return PeerRequestResult(status=REQUEST_CONNECTION_CLOSED, error="no peer routes available")

    timeout = ind_settings.peer_request_timeout_seconds() if timeout is None else float(timeout)
    timeout = max(1.0, float(timeout))
    deadline = time.monotonic() + max(1.0, float(max_duration_seconds))
    attempts = []
    invalid_peers = set()
    for route_info in routes:
        peer = route_info["peer"]
        route = route_info["route"]
        if peer in invalid_peers:
            continue
        remaining_budget = deadline - time.monotonic()
        if remaining_budget <= 0:
            attempts.append(_attempt_dict(peer, route, REQUEST_TIMEOUT, error="request route budget exhausted"))
            break
        backoff_remaining = max(_peer_backoff_remaining(peer), _peer_backoff_remaining(route))
        if backoff_remaining > 0:
            attempts.append(
                _attempt_dict(
                    peer,
                    route,
                    REQUEST_RATE_LIMITED,
                    error="peer is in rate-limit backoff",
                    retry_after_seconds=backoff_remaining,
                )
            )
            continue
        if route in already_tried:
            attempts.append(_attempt_dict(peer, route, REQUEST_PEER_KEY_MISMATCH, error="peer key previously changed"))
            continue

        started = time.monotonic()
        try:
            response = ind_transport.request(
                (route, node_port()),
                indicator,
                data,
                peer_ip=route,
                timeout=min(timeout, max(1.0, remaining_budget)),
            )
            status = _response_status(response)
            retry_after = 0.0
            if status == REQUEST_RATE_LIMITED:
                retry_after = _note_rate_limited(peer, route)
            attempts.append(
                _attempt_dict(
                    peer,
                    route,
                    status,
                    response=response,
                    elapsed_seconds=time.monotonic() - started,
                    retry_after_seconds=retry_after,
                )
            )
            if status == REQUEST_INVALID:
                invalid_peers.add(peer)
                logger.debug("peer %s returned invalid; skipping alternate routes for same peer", peer)
                continue
            if status == REQUEST_OK:
                retry_after = max(float(attempt.get("retry_after_seconds") or 0) for attempt in attempts)
                return PeerRequestResult(
                    status=REQUEST_OK,
                    response=response,
                    peer=peer,
                    route=route,
                    attempts=tuple(attempts),
                    retry_after_seconds=retry_after,
                )
            logger.debug("peer request to %s returned %s", route, status)
        except Exception as exc:
            status = _classify_request_exception(exc)
            if status == REQUEST_PEER_KEY_MISMATCH and route not in already_tried:
                already_tried.append(route)
            attempts.append(
                _attempt_dict(
                    peer,
                    route,
                    status,
                    error=str(exc),
                    elapsed_seconds=time.monotonic() - started,
                )
            )
            logger.debug("peer request to %s failed as %s: %s", route, status, exc)
    return _final_failure_result(attempts)


def connect(indicator, data, ipnl, *, timeout=None, max_duration_seconds=DEFAULT_CONNECT_ATTEMPT_BUDGET_SECONDS):
    """Send one encrypted request to a peer and return its plaintext reply or failure status."""

    return _compat_response_from_result(
        connect_result(
            indicator,
            data,
            ipnl,
            timeout=timeout,
            max_duration_seconds=max_duration_seconds,
        )
    )


def _failed_peers_before_success(result):
    failed = []
    succeeded = set()
    for attempt in result.attempts:
        peer = attempt.get("peer", "")
        if not peer:
            continue
        if attempt.get("status") == REQUEST_OK:
            succeeded.add(peer)
            continue
        if peer not in succeeded and peer not in failed:
            failed.append(peer)
    return [peer for peer in failed if peer not in succeeded]


def _retry_delay_for_result(result):
    if result.retry_after_seconds > 0:
        return result.retry_after_seconds
    if result.status == REQUEST_RATE_LIMITED:
        return _rate_limit_backoff_seconds()
    if result.status in REQUEST_RETRYABLE_STATUSES:
        return random.uniform(20, 90)
    return 0.0


def _parse_status_response(raw):
    lines = [line.strip() for line in str(raw or "").splitlines() if line.strip()]
    records = []
    index = 0
    while index < len(lines):
        ref = lines[index]
        if index + 2 < len(lines) and lines[index + 1] == "x" and lines[index + 2] == REQUEST_INVALID:
            records.append(
                {
                    "ref": ref,
                    "display_id": ref,
                    "owner_address": "",
                    "sequence": None,
                    "status": REQUEST_INVALID,
                }
            )
            index += 3
            continue
        if index + 3 >= len(lines):
            records.append(
                {
                    "ref": ref,
                    "display_id": ref,
                    "owner_address": "",
                    "sequence": None,
                    "status": "malformed_response",
                }
            )
            break
        try:
            sequence = int(lines[index + 2])
        except ValueError:
            sequence = None
        owner_address = lines[index + 1]
        status = lines[index + 3]
        if status == "conflict":
            owner_address = ""
        records.append(
            {
                "ref": ref,
                "display_id": lines[index],
                "owner_address": owner_address,
                "sequence": sequence,
                "status": status,
            }
        )
        index += 4
    return records


def _gossip_bill(message):
    if not isinstance(message, dict):
        return None
    message_type = message.get("type")
    if message_type in {ind_token.TRANSFER_ANNOUNCEMENT_V2_TYPE, ind_token.RECEIPT_ANNOUNCEMENT_V2_TYPE}:
        return message.get("bill")
    if message_type in {ind_token.TRANSFER_ANNOUNCEMENT_TYPE, ind_token.RECEIPT_ANNOUNCEMENT_TYPE}:
        return message.get("token")
    if message_type == ind_token.TOKEN_TYPE:
        return message
    return None


def _broadcast_status_expectation(message):
    bill = _gossip_bill(message)
    if not bill:
        return None
    try:
        state = ind_token.verify_token(
            bill,
            require_checkpoint_transparency=False,
            require_recent_transparency=False,
        )
    except Exception as exc:
        logger.debug("could not derive broadcast status expectation: %s", exc)
        return None
    return {
        "display_id": state.display_id,
        "owner_address": state.owner_address,
        "sequence": int(state.sequence),
    }


def _status_record_confirms_broadcast(record, expected):
    if not record or not expected:
        return False
    return (
        record.get("display_id") == expected["display_id"]
        and record.get("owner_address") == expected["owner_address"]
        and record.get("sequence") == expected["sequence"]
        and record.get("status") in BROADCAST_RECONCILED_STATUSES
    )


def _remote_status_confirms_gossip(message, peers, *, attempts=BROADCAST_RECONCILE_ATTEMPTS):
    expected = _broadcast_status_expectation(message)
    peers = _ordered_peer_candidates(peers)
    if not expected or not peers:
        return False
    for attempt in range(max(1, int(attempts))):
        result = connect_result(
            "c",
            expected["display_id"],
            peers,
            max_duration_seconds=BROADCAST_RECONCILE_BUDGET_SECONDS,
        )
        if result.status == REQUEST_OK:
            for record in _parse_status_response(result.response):
                if _status_record_confirms_broadcast(record, expected):
                    logger.info(
                        "reconciled timed-out gossip for %s via status from %s",
                        expected["display_id"],
                        result.route or result.peer,
                    )
                    return True
                if record.get("display_id") == expected["display_id"] and record.get("status") in {
                    REQUEST_INVALID,
                    "conflict",
                    "rejected",
                    "wrong_owner",
                }:
                    logger.warning(
                        "status reconciliation for %s returned %s",
                        expected["display_id"],
                        record.get("status"),
                    )
                    return False
        else:
            logger.debug(
                "status reconciliation for %s failed as %s",
                expected["display_id"],
                result.status,
            )
        if attempt + 1 < max(1, int(attempts)):
            time.sleep(BROADCAST_RECONCILE_RETRY_DELAY_SECONDS)
    return False


def _schedule_raw_gossip_retry(raw, peers, *, delay_seconds=None):
    peers = _ordered_peer_candidates(peers)
    if not raw or not peers:
        return False

    def retry():
        delay = float(_rate_limit_backoff_seconds() if delay_seconds is None else delay_seconds)
        if delay > 0:
            time.sleep(delay)
        result = connect_result("b", raw, peers)
        if result.status != REQUEST_OK:
            logger.info("background gossip retry kept failing with %s for peers %s", result.status, peers)

    threading.Thread(target=retry, daemon=True).start()
    return True


def _schedule_queued_gossip_retry(transaction_path, raw, peers, *, delay_seconds=None):
    transaction_path = Path(transaction_path)
    key = str(transaction_path)
    peers = _ordered_peer_candidates(peers)
    if not raw or not peers:
        return False
    with _queued_gossip_retry_lock:
        if key in _queued_gossip_retries:
            return False
        _queued_gossip_retries.add(key)

    def retry():
        try:
            delay = float(_rate_limit_backoff_seconds() if delay_seconds is None else delay_seconds)
            if delay > 0:
                time.sleep(delay)
            result = connect_result("b", raw, peers)
            if result.status == REQUEST_OK:
                try:
                    os.remove(transaction_path)
                    logger.info("queued gossip %s accepted after background retry", transaction_path)
                except FileNotFoundError:
                    pass
            else:
                try:
                    queued_message = runtime_json.read_transaction_message(transaction_path)
                except FileNotFoundError:
                    return
                except Exception as exc:
                    queued_message = None
                    logger.debug("could not read queued gossip %s for reconciliation: %s", transaction_path, exc)
                if queued_message and _remote_status_confirms_gossip(queued_message, peers):
                    try:
                        os.remove(transaction_path)
                        logger.info("queued gossip %s confirmed by status after background retry", transaction_path)
                    except FileNotFoundError:
                        pass
                    return
                logger.info(
                    "queued gossip %s remains pending after %s retry",
                    transaction_path,
                    result.status,
                )
        finally:
            with _queued_gossip_retry_lock:
                _queued_gossip_retries.discard(key)

    threading.Thread(target=retry, daemon=True).start()
    return True


def public_ip():
    """Discover the public IPv4 or IPv6 address without making peer gossip the first dependency."""

    for discover in (
        lambda: requests.get('https://api64.ipify.org', timeout=4).text.strip(),
        lambda: requests.get('https://www.wikipedia.org', timeout=4).headers['X-Client-IP'],
        lambda: requests.get('https://checkip.amazonaws.com', timeout=4).text.strip(),
    ):
        try:
            my_ip = discover()
            if _valid_peer_address(my_ip):
                return _normalize_peer_address(my_ip)
        except Exception as exc:
            logger.debug("public IP discovery failed: %s", exc)
    try:
        ipnl = _with_configured_peers(_peer_files('ip_folder/1') + _peer_files('ip_folder/2'))
        my_ip = connect('x', '', ipnl)
        if my_ip != 'n' and _valid_peer_address(my_ip):
            return _normalize_peer_address(my_ip)
    except Exception as exc:
        logger.debug("peer-assisted public IP discovery failed: %s", exc)
    return None
    

def send_bills():
    """Validate queued wallet gossip locally, then broadcast it to sampled peers."""

    ensure_runtime_files()
    ipnl1 = diverse_peer_sample(_peer_files('ip_folder/1'), limit=6)
    ipnl2 = _with_configured_peers(diverse_peer_sample(_peer_files('ip_folder/2'), limit=12))
    store = ind_token.INDLocalStore()
    for transaction_path in runtime_json.transaction_files():
        tm = runtime_json.read_transaction_message(transaction_path)
        try:
            result = store.ingest_message(tm)
            proof = result.get("conflict_proof")
            if proof:
                broadcast_message(proof)
        except Exception as exc:
            logger.debug("dropping invalid queued transaction %s: %s", transaction_path, exc)
            os.remove(transaction_path)
            continue
        wire_message = ind_token.pack_wire_message(tm)
        peers = _dedupe_preserving_order(ipnl1 + ipnl2)
        result = connect_result('b', wire_message, peers)
        if result.status == REQUEST_OK:
            failed_peers = _failed_peers_before_success(result)
            if failed_peers:
                _schedule_queued_gossip_retry(
                    transaction_path,
                    wire_message,
                    failed_peers,
                    delay_seconds=_retry_delay_for_result(result),
                )
                logger.info(
                    "queued gossip %s accepted by %s; retrying failed peers %s in background",
                    transaction_path,
                    result.route or result.peer,
                    failed_peers,
                )
            else:
                os.remove(transaction_path)
            continue
        if result.status == REQUEST_INVALID:
            logger.warning("dropping remotely invalid queued transaction %s", transaction_path)
            os.remove(transaction_path)
            continue
        if result.status in REQUEST_RETRYABLE_STATUSES and _remote_status_confirms_gossip(tm, peers):
            os.remove(transaction_path)
            logger.info("removed queued transaction %s after status reconciliation", transaction_path)
            continue
        _schedule_queued_gossip_retry(
            transaction_path,
            wire_message,
            peers,
            delay_seconds=_retry_delay_for_result(result),
        )
        logger.info("kept queued transaction %s after %s network result", transaction_path, result.status)


def broadcast_message(message):
    """Broadcast a protocol message after converting it to the current wire format."""

    ensure_runtime_files()
    raw = ind_token.pack_wire_message(message)
    ipnl1 = diverse_peer_sample(_peer_files('ip_folder/1'), limit=6)
    ipnl2 = _with_configured_peers(diverse_peer_sample(_peer_files('ip_folder/2'), limit=12))
    peers = _dedupe_preserving_order(ipnl1 + ipnl2)
    result = connect_result('b', raw, peers)
    if result.status == REQUEST_OK:
        failed_peers = _failed_peers_before_success(result)
        if failed_peers:
            _schedule_raw_gossip_retry(
                raw,
                failed_peers,
                delay_seconds=_retry_delay_for_result(result),
            )
    elif result.status in REQUEST_RETRYABLE_STATUSES:
        _schedule_raw_gossip_retry(raw, peers, delay_seconds=_retry_delay_for_result(result))
    return result


def _parse_peer_messages(raw):
    if not raw or raw == 'n':
        return []
    try:
        decoded = json.loads(raw)
        if isinstance(decoded, list):
            return decoded
        if isinstance(decoded, dict):
            return [decoded]
    except Exception:
        return []
    return []


def check_validity(serial_num_list):
    """Return locally settled bill records for wallet display ids or protocol bill ids."""

    store = ind_token.INDLocalStore()
    store.finalize_pending(buffer_seconds=ind_settings.finality_buffer_seconds())
    verified = []
    for item in serial_num_list:
        bill = store.get_compact_bill(item) or store.get_token(item) or store.get_compact_bill_by_display_id(item) or store.get_token_by_display_id(item)
        if not bill:
            continue
        try:
            state = ind_token.verify_token(bill)
            confidence = store.token_confidence(state.token_id, expected_owner=state.owner_address, min_settled_seconds=0)
            if confidence["accepted"]:
                verified.append((state.display_id, state.owner_address, str(state.sequence)))
        except Exception as exc:
            logger.debug("bill validity check failed for %s: %s", item, exc)
            continue
    return verified


def update_ip_list():
    """Refresh the local peer cache from bootstrap and ordinary nodes."""

    maybe_refresh_dns_seed_peers(force=True)

    def new_main_ip():
        comparison_ip = []
        main_ips = _peer_files('ip_folder/1')
        def thrd():
            new_main = connect('u', 'main ip', main_ips)
            comparison_ip.append(new_main)
        for _ in range(len(main_ips)):
            threading.Thread(target=thrd).start()
        time.sleep(10)
        try:
            new_ip = random.choice([ip for ip in comparison_ip if ip != 'n'])
            add_peer(str(new_ip), '1')
        except Exception as exc:
            logger.debug("could not add sampled peer: %s", exc)

    if random.randint(0, 27) == 3:
        threading.Thread(target=new_main_ip).start()

    ipnl = _with_configured_peers(_peer_files('ip_folder/2'))
    list_ips = connect('u', '', ipnl)

    for ip in list_ips.splitlines():
        add_peer(str(ip), '2')


def receive_bills():
    """Pull wallet-addressed gossip, sign receipts, and import settled bills."""

    ensure_runtime_files()
    ipnl = _with_configured_peers(_peer_files('ip_folder/1') + _peer_files('ip_folder/2'))
    store = ind_token.INDLocalStore()
    for wallet_path in runtime_json.iter_decrypted_wallet_files():
        if wallet_path.name.startswith('wallet_decrypted'):
            wallet = runtime_json.read_decrypted_wallet_lines(wallet_path)
            address = wallet[0].strip()
            private_key = wallet[1].strip()
            public_key = wallet[2].strip()
            full_messages = store.messages_for_recipient(address)

            def thrd_recv():
                msg = connect('r', address, ipnl)
                full_messages.extend(_parse_peer_messages(msg))
            for iteration in range(5):
                threading.Thread(target=thrd_recv).start()
            time.sleep(5)

            for message in full_messages:
                try:
                    result = store.ingest_message(message)
                    proof = result.get("conflict_proof")
                    if proof:
                        broadcast_message(proof)
                    if message.get("type") in {ind_token.TRANSFER_ANNOUNCEMENT_TYPE, ind_token.TRANSFER_ANNOUNCEMENT_V2_TYPE}:
                        bill = message["bill"] if message.get("type") == ind_token.TRANSFER_ANNOUNCEMENT_V2_TYPE else message["token"]
                        state = ind_token.verify_token(bill)
                        if state.owner_address == address:
                            receipt = ind_token.create_receipt_announcement(bill, private_key, public_key)
                            store.ingest_message(receipt)
                            broadcast_message(receipt)
                except Exception as exc:
                    logger.debug("could not create or broadcast receipt for %s: %s", address, exc)

            store.finalize_pending(buffer_seconds=ind_settings.finality_buffer_seconds())
            wallet_ids = {line.split()[0].lstrip('-') for line in runtime_json.wallet_bill_lines(wallet) if line.split()}
            settled = store.token_records_for_owner(address, settled_only=True)
            updated_wallet = list(wallet)
            for record in settled:
                if record["display_id"] not in wallet_ids:
                    updated_wallet.append(record["display_id"] + ' ' + str(record["sequence"]) + ' ' + str(int(time.time())) + '\n')
                    wallet_ids.add(record["display_id"])
            runtime_json.write_decrypted_wallet_lines(wallet_path, updated_wallet)
