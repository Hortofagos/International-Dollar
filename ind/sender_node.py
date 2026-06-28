import ipaddress
import json
import logging
import math
import os
import random
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError, as_completed
from dataclasses import dataclass
from pathlib import Path

import requests

from . import env as ind_env
from . import runtime as runtime_json
from . import settings as ind_settings
from . import token as ind_token
from . import transport as ind_transport
from . import wallet_services

logger = logging.getLogger(__name__)
already_tried = []
PORT = 8888

_env_int = ind_env.int_value
_env_float = ind_env.float_value


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
WALLET_SYNC_MAX_PEERS = 12
WALLET_SYNC_WORKERS = 4
WALLET_SYNC_REQUEST_TIMEOUT_SECONDS = 6
WALLET_SYNC_REQUEST_BUDGET_SECONDS = 8
WALLET_SYNC_RECONCILE_REQUEST_TIMEOUT_SECONDS = _env_int(
    "IND_WALLET_SYNC_RECONCILE_REQUEST_TIMEOUT_SECONDS",
    15,
    minimum=1,
    maximum=120,
)
WALLET_SYNC_RECONCILE_REQUEST_BUDGET_SECONDS = _env_int(
    "IND_WALLET_SYNC_RECONCILE_REQUEST_BUDGET_SECONDS",
    20,
    minimum=1,
    maximum=180,
)
WALLET_SYNC_FETCH_BUDGET_SECONDS = 30
WALLET_SYNC_TOKEN_CURSOR_LIMIT = 0
WALLET_SYNC_DISPLAY_RANGE_LIMIT = _env_int(
    "IND_WALLET_SYNC_DISPLAY_RANGE_LIMIT",
    2048,
    minimum=0,
    maximum=100000,
)
WALLET_SYNC_DISPLAY_RANGE_BYTES = _env_int(
    "IND_WALLET_SYNC_DISPLAY_RANGE_BYTES",
    128 * 1024,
    minimum=0,
    maximum=1024 * 1024,
)
WALLET_SYNC_RESPONSE_LIMIT = 100
WALLET_SEND_WINDOW_SECONDS = _env_int("IND_WALLET_SEND_WINDOW_SECONDS", 5, minimum=1)
WALLET_MAX_BILLS_PER_SECOND = _env_float(
    "IND_WALLET_MAX_BILLS_PER_SECOND", 2.0, minimum=0.1
)
WALLET_MAX_GOSSIP_PER_PEER_WINDOW = _env_int(
    "IND_WALLET_MAX_GOSSIP_PER_PEER_WINDOW", 100, minimum=1
)
WALLET_BROADCAST_MIN_PEER_ACKS = _env_int("IND_WALLET_BROADCAST_MIN_PEER_ACKS", 2, minimum=1)
WALLET_BROADCAST_PEER_FANOUT = _env_int("IND_WALLET_BROADCAST_PEER_FANOUT", 2, minimum=1)
WALLET_BROADCAST_PEER_TIMEOUT_SECONDS = _env_int(
    "IND_WALLET_BROADCAST_PEER_TIMEOUT_SECONDS", 4, minimum=1, maximum=30
)
WALLET_BROADCAST_ROUTE_BUDGET_SECONDS = _env_int(
    "IND_WALLET_BROADCAST_ROUTE_BUDGET_SECONDS", 6, minimum=1, maximum=45
)
WALLET_BROADCAST_BILL_BUDGET_SECONDS = _env_int(
    "IND_WALLET_BROADCAST_BILL_BUDGET_SECONDS", 12, minimum=1, maximum=120
)
WALLET_FIRE_AND_FORGET_PEER_FANOUT = _env_int(
    "IND_WALLET_FIRE_AND_FORGET_PEER_FANOUT", 1, minimum=1
)
WALLET_FIRE_AND_FORGET_PEER_TIMEOUT_SECONDS = _env_float(
    "IND_WALLET_FIRE_AND_FORGET_PEER_TIMEOUT_SECONDS", 2.0, minimum=0.2, maximum=10.0
)
WALLET_QUEUED_RETRY_MAX_ATTEMPTS = _env_int(
    "IND_WALLET_QUEUED_RETRY_MAX_ATTEMPTS", 12, minimum=1
)
WALLET_QUEUED_RETRY_MAX_DELAY_SECONDS = _env_int(
    "IND_WALLET_QUEUED_RETRY_MAX_DELAY_SECONDS", 30, minimum=1
)
WALLET_SEND_MIN_OBSERVED_ETA_SENT = 3
BROADCAST_RECONCILED_STATUSES = {
    "pending",
    "verified",
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
REQUEST_PARTIAL_ACK = "partial_ack"
REQUEST_RETRYABLE_STATUSES = {
    REQUEST_TIMEOUT,
    REQUEST_RATE_LIMITED,
    REQUEST_CONNECTION_CLOSED,
    REQUEST_HANDSHAKE_FAILED,
    REQUEST_PARTIAL_ACK,
}
REQUEST_FAILURE_STATUSES = REQUEST_RETRYABLE_STATUSES | {REQUEST_PEER_KEY_MISMATCH, REQUEST_INVALID}
MISSING_TRANSPARENCY_VERIFIER = "transparency log verification is required but not configured"

RUNTIME_DIRS = runtime_json.RUNTIME_DIRS
_last_dns_seed_refresh = 0
_peer_backoff_until = {}
_peer_backoff_lock = threading.Lock()
_paced_send_lock = threading.Lock()
_queued_send_cancel_event = threading.Event()
_queued_gossip_retries = set()
_queued_gossip_retry_lock = threading.Lock()


# Structured result for one logical node request across all tried routes.
@dataclass(frozen=True)
class PeerRequestResult:
    status: str
    response: str = ""
    peer: str = ""
    route: str = ""
    attempts: tuple = ()
    retry_after_seconds: float = 0.0
    error: str = ""
    acked_peers: tuple = ()

    @property
    def ok(self):
        return self.status == REQUEST_OK


def node_port():
    return ind_settings.node_port()


_env_enabled = ind_env.enabled


def _allow_development_transparency_fallback():
    if _env_enabled("IND_REQUIRE_TRANSPARENCY_LOG"):
        return False
    try:
        settings = ind_settings.load_security_settings(validate_production=False)
    except Exception:
        return False
    return not ind_settings.production_mode(settings)


def wallet_sync_store(db_path=None):
    kwargs = {"db_path": db_path} if db_path is not None else {}
    if _allow_development_transparency_fallback():
        logger.info(
            "strict transparency verifier is not configured; "
            "wallet sync is using development local-proof mode"
        )
        return ind_token.INDLocalStore(require_transparency=False, **kwargs)
    try:
        return ind_token.INDLocalStore(**kwargs)
    except ind_token.ValidationError as exc:
        if MISSING_TRANSPARENCY_VERIFIER in str(exc) and _allow_development_transparency_fallback():
            logger.info(
                "strict transparency verifier is not configured; "
                "wallet sync is using development local-proof mode"
            )
            return ind_token.INDLocalStore(require_transparency=False, **kwargs)
        raise


def _runtime_path(path):
    path = Path(path)
    parts = path.parts
    if parts and parts[0] == "ip_folder":
        return runtime_json.peer_root() / Path(*parts[1:])
    return path


def _read_text(path):
    try:
        with open(_runtime_path(path)) as handle:
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
        return value[1 : value.index("]")]
    return value


# Return a canonical IP literal, or an empty string.
def _normalize_peer_address(value):
    value = _strip_peer_brackets(value)
    if value.startswith("::ffff:"):
        value = value[len("::ffff:") :]
    try:
        ip = ipaddress.ip_address(value)
        if getattr(ip, "ipv4_mapped", None) is not None:
            ip = ip.ipv4_mapped
        return ip.compressed
    except ValueError:
        return ""


# Return whether a peer address is a globally-routable IPv4 or IPv6 literal.
def _valid_peer_address(value):
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


# Return routes for one peer as hostname, then resolved IPv6, then resolved IPv4.
def _resolved_peer_routes(peer):
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
        records = socket.getaddrinfo(
            host, node_port(), family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
        )
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


# Expand peers into attempted routes while preserving DNS seed order.
def expanded_peer_routes(peers):
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
            with open(path, encoding="utf-8") as handle:
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
        maybe = item[len("ipv6_") :].replace("-", ":")
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


# Resolve DNS seed hostnames into globally-routable IPv4/IPv6 node hints.
def resolve_dns_seed_hosts(seed_hosts=None, limit=MAX_DNS_SEED_RESULTS):
    seed_hosts = _configured_dns_seed_hosts() if seed_hosts is None else list(seed_hosts)
    peers = []
    seen = set()
    for seed_host in seed_hosts:
        seed_host = str(seed_host).strip()
        if not seed_host:
            continue
        try:
            records = socket.getaddrinfo(
                seed_host, node_port(), family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
            )
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


# Resolve configured DNS seeds and store their IPs as ordinary peer hints.
def refresh_dns_seed_peers(seed_hosts=None, version='2'):
    ensure_runtime_files()
    added = []
    for ip in resolve_dns_seed_hosts(seed_hosts=seed_hosts):
        if add_peer(ip, version=version):
            added.append(ip)
    return added


# Refresh DNS seeds at most hourly unless explicitly forced.
def maybe_refresh_dns_seed_peers(now=None, force=False):
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


# Add a routable IPv4/IPv6 peer while limiting concentration per network block.
def add_peer(ip, version='2'):
    ip = _normalize_peer_address(ip)
    if version not in ('1', '2') or not _valid_peer_address(ip):
        return False
    block = _peer_diversity_block(ip)
    target = runtime_json.peer_path(ip, version)
    if (
        not os.path.exists(target)
        and _existing_peer_block_count(block) >= MAX_PEERS_PER_ADDRESS_BLOCK
    ):
        return False
    runtime_json.write_peer(ip, version)
    return True


# Sample peers across IPv4 /24, IPv6 /48, and configured-host buckets.
def diverse_peer_sample(peers, limit=DEFAULT_DIVERSE_PEER_SAMPLE):
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
    return random.uniform(
        REQUEST_RATE_LIMIT_MIN_BACKOFF_SECONDS, REQUEST_RATE_LIMIT_MAX_BACKOFF_SECONDS
    )


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


def _retry_after_from_response(response):
    response = str(response or "").strip()
    if response.startswith(REQUEST_RATE_LIMITED + ":"):
        try:
            return max(0.0, float(response.split(":", 1)[1]))
        except (TypeError, ValueError):
            return 0.0
    try:
        decoded = json.loads(response)
    except Exception:
        return 0.0
    if isinstance(decoded, dict) and decoded.get("status") == REQUEST_RATE_LIMITED:
        try:
            return max(0.0, float(decoded.get("retry_after_seconds") or 0))
        except (TypeError, ValueError):
            return 0.0
    return 0.0


def _note_rate_limited(peer, route, delay=None):
    delay = _rate_limit_backoff_seconds() if delay is None else float(delay)
    return max(_set_peer_backoff(peer, delay), _set_peer_backoff(route, delay))


def _response_status(response):
    response = str(response or "").strip()
    if response == REQUEST_RATE_LIMITED or response.startswith(REQUEST_RATE_LIMITED + ":"):
        return REQUEST_RATE_LIMITED
    try:
        decoded = json.loads(response)
    except Exception:
        decoded = None
    if isinstance(decoded, dict):
        status = str(decoded.get("status") or "")
        if status == REQUEST_RATE_LIMITED:
            return REQUEST_RATE_LIMITED
        if status in {"invalid", "rejected"}:
            return REQUEST_INVALID
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
    if isinstance(
        exc, (ConnectionAbortedError, ConnectionResetError, BrokenPipeError, ConnectionRefusedError)
    ):
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


def _attempt_dict(
    peer, route, status, response="", error="", elapsed_seconds=0.0, retry_after_seconds=0.0
):
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
            retry_after = max(
                float(attempt.get("retry_after_seconds") or 0) for attempt in matching
            )
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


# Create runtime folders, state files, and local transport keypairs.
def ensure_runtime_files():
    runtime_json.ensure_runtime_files()
    ind_transport.ensure_transport_keypair()


# Send one logical encrypted request and return a structured route result.
def connect_result(
    indicator,
    data,
    ipnl,
    *,
    timeout=None,
    max_duration_seconds=DEFAULT_CONNECT_ATTEMPT_BUDGET_SECONDS,
):
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
            attempts.append(
                _attempt_dict(peer, route, REQUEST_TIMEOUT, error="request route budget exhausted")
            )
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
            attempts.append(
                _attempt_dict(
                    peer, route, REQUEST_PEER_KEY_MISMATCH, error="peer key previously changed"
                )
            )
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
                retry_after = _note_rate_limited(
                    peer,
                    route,
                    delay=_retry_after_from_response(response) or None,
                )
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
                logger.debug(
                    "peer %s returned invalid; skipping alternate routes for same peer", peer
                )
                continue
            if status == REQUEST_OK:
                retry_after = max(
                    float(attempt.get("retry_after_seconds") or 0) for attempt in attempts
                )
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


# Send one encrypted request to a peer and return its plaintext reply or failure status.
def connect(
    indicator,
    data,
    ipnl,
    *,
    timeout=None,
    max_duration_seconds=DEFAULT_CONNECT_ATTEMPT_BUDGET_SECONDS,
):
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


def request_cancel_queued_bills():
    _queued_send_cancel_event.set()


def clear_cancel_queued_bills():
    _queued_send_cancel_event.clear()


def queued_bill_cancel_requested():
    return _queued_send_cancel_event.is_set()


class OutboundGossipPacer:
    def __init__(
        self,
        limit=WALLET_MAX_GOSSIP_PER_PEER_WINDOW,
        window_seconds=WALLET_SEND_WINDOW_SECONDS,
        now_func=None,
    ):
        self.limit = max(1, int(limit))
        self.window_seconds = max(1.0, float(window_seconds))
        self.now_func = now_func or time.monotonic
        self.events = {}

    def _now(self, now=None):
        return float(self.now_func() if now is None else now)

    def _trim(self, peer, now=None):
        peer = str(peer or "").strip()
        if not peer:
            return []
        now = self._now(now)
        cutoff = now - self.window_seconds
        timestamps = [item for item in self.events.get(peer, []) if item > cutoff]
        self.events[peer] = timestamps
        return timestamps

    def available(self, peer, now=None):
        return len(self._trim(peer, now=now)) < self.limit

    def available_peers(self, peers, now=None):
        now = self._now(now)
        return [peer for peer in peers if self.available(peer, now=now)]

    def wait_seconds(self, peers, now=None):
        now = self._now(now)
        waits = []
        for peer in peers:
            timestamps = self._trim(peer, now=now)
            if len(timestamps) < self.limit:
                return 0.0
            waits.append(timestamps[0] + self.window_seconds - now)
        if not waits:
            return 0.0
        return max(0.0, min(waits))

    def record(self, peer, now=None):
        peer = str(peer or "").strip()
        if not peer:
            return
        now = self._now(now)
        timestamps = self._trim(peer, now=now)
        timestamps.append(now)
        self.events[peer] = timestamps

    def record_result(self, result, now=None):
        now = self._now(now)
        for attempt in result.attempts:
            status = attempt.get("status", "")
            if status not in {
                REQUEST_OK,
                REQUEST_RATE_LIMITED,
                REQUEST_TIMEOUT,
                REQUEST_INVALID,
            }:
                continue
            peer = attempt.get("peer", "")
            if peer:
                self.record(peer, now=now)


class OutboundBillPacer:
    def __init__(
        self,
        max_bills_per_second=WALLET_MAX_BILLS_PER_SECOND,
        now_func=None,
        sleep_func=None,
    ):
        self.max_bills_per_second = max(0.1, float(max_bills_per_second))
        self.interval_seconds = 1.0 / self.max_bills_per_second
        self.now_func = now_func or time.monotonic
        self.sleep_func = sleep_func or time.sleep
        self.next_send_at = 0.0

    def _now(self):
        return float(self.now_func())

    def wait(self, deadline=None):
        now = self._now()
        if self.next_send_at > now:
            delay = self.next_send_at - now
            if not _can_wait_for(deadline, delay):
                return False
            self.sleep_func(delay)
            now = self._now()
        self.next_send_at = max(self.next_send_at, now) + self.interval_seconds
        return True


def _is_v3_transfer_announcement(message):
    return (
        isinstance(message, dict)
        and message.get("type")
        == getattr(ind_token, "TRANSFER_ANNOUNCEMENT_V3_TYPE", "ind.transfer_announcement.v3")
    )


def _validate_v3_transfer_announcement_for_broadcast(store, message):
    from . import protocol_v3

    _bill, embedded_bundle, _archive_segments = protocol_v3.decode_transfer_announcement(message)
    trusted_operator_public_key = None
    trusted_key_getter = getattr(store, "_trusted_operator_key_from_proof_bundle_v3", None)
    if callable(trusted_key_getter) and embedded_bundle is not None:
        trusted_operator_public_key = trusted_key_getter(embedded_bundle)
    protocol_v3.verify_transfer_announcement(
        message,
        proof_bundle_resolver=getattr(store, "proof_bundle_resolver_v3", None),
        transparency_verifier=getattr(store, "transparency_verifier", None),
        trusted_operator_public_key=trusted_operator_public_key,
        archive_segment_resolver=getattr(store, "archive_segment_resolver_v3", None),
    )


def _prepare_queued_gossip_for_broadcast(transaction_path, store):
    message = runtime_json.read_transaction_message(transaction_path)
    if _is_v3_transfer_announcement(message):
        _validate_v3_transfer_announcement_for_broadcast(store, message)
        result = {"accepted": True}
    else:
        result = store.ingest_message(message)
    return message, ind_token.pack_wire_message(message), result


def _result_attempts(result):
    return tuple(getattr(result, "attempts", ()) or ())


def _broadcast_gossip_to_peer_quorum(
    raw,
    peers,
    *,
    pacer=None,
    min_peer_acks=None,
    fanout=None,
    timeout=None,
    route_budget_seconds=None,
    bill_budget_seconds=None,
    deadline=None,
):
    peers = _dedupe_preserving_order(str(peer).strip() for peer in peers or [] if str(peer).strip())
    if not raw or not peers:
        return PeerRequestResult(
            status=REQUEST_CONNECTION_CLOSED,
            error="no peer routes available",
        )

    min_peer_acks = max(1, int(min_peer_acks or WALLET_BROADCAST_MIN_PEER_ACKS))
    min_peer_acks = min(min_peer_acks, len(peers))
    fanout = max(min_peer_acks, int(fanout or WALLET_BROADCAST_PEER_FANOUT))
    fanout = min(fanout, len(peers))
    timeout = float(timeout or WALLET_BROADCAST_PEER_TIMEOUT_SECONDS)
    route_budget_seconds = float(route_budget_seconds or WALLET_BROADCAST_ROUTE_BUDGET_SECONDS)
    bill_budget_seconds = float(bill_budget_seconds or WALLET_BROADCAST_BILL_BUDGET_SECONDS)
    local_deadline = time.monotonic() + max(1.0, bill_budget_seconds)
    if deadline is not None:
        local_deadline = min(local_deadline, float(deadline))

    attempts = []
    acked_peers = []
    tried_peers = set()
    retry_after = 0.0
    last_response = ""
    last_peer = ""
    last_route = ""
    statuses = []

    while len(acked_peers) < min_peer_acks:
        remaining = local_deadline - time.monotonic()
        if remaining <= 0:
            break
        remaining_peers = [peer for peer in peers if peer not in tried_peers]
        if not remaining_peers:
            break
        ready_peers = remaining_peers if pacer is None else pacer.available_peers(remaining_peers)
        if not ready_peers:
            delay = max(0.1, pacer.wait_seconds(remaining_peers) if pacer is not None else 0.1)
            if delay >= remaining or not _can_wait_for(deadline, delay):
                break
            time.sleep(delay)
            continue

        batch = ready_peers[:fanout]
        for peer in batch:
            tried_peers.add(peer)
        request_budget = max(1.0, min(route_budget_seconds, local_deadline - time.monotonic()))

        def send_one(peer, request_budget=request_budget):
            return peer, connect_result(
                "b",
                raw,
                [peer],
                timeout=timeout,
                max_duration_seconds=request_budget,
            )

        if len(batch) == 1:
            results = [send_one(batch[0])]
        else:
            results = []
            with ThreadPoolExecutor(max_workers=len(batch)) as executor:
                futures = [executor.submit(send_one, peer) for peer in batch]
                for future in as_completed(futures):
                    results.append(future.result())

        for requested_peer, result in results:
            if pacer is not None:
                pacer.record_result(result)
            retry_after = max(retry_after, float(getattr(result, "retry_after_seconds", 0) or 0))
            statuses.append(result.status)
            attempts.extend(_result_attempts(result))
            last_response = result.response
            last_peer = result.peer or requested_peer
            last_route = result.route or requested_peer
            if result.status == REQUEST_OK:
                peer_key = result.peer or requested_peer
                if peer_key not in acked_peers:
                    acked_peers.append(peer_key)
            if len(acked_peers) >= min_peer_acks:
                break

    if len(acked_peers) >= min_peer_acks:
        status = REQUEST_OK
        error = ""
    elif acked_peers:
        status = REQUEST_PARTIAL_ACK
        error = f"only {len(acked_peers)} of {min_peer_acks} peer acknowledgements"
    elif REQUEST_INVALID in statuses:
        status = REQUEST_INVALID
        error = "all reachable peers rejected gossip" if statuses else ""
    elif REQUEST_RATE_LIMITED in statuses:
        status = REQUEST_RATE_LIMITED
        error = "peer quorum rate limited"
    elif statuses:
        status = statuses[-1]
        error = "peer quorum not reached"
    else:
        status = REQUEST_TIMEOUT
        error = "peer quorum budget exhausted"

    return PeerRequestResult(
        status=status,
        response=last_response,
        peer=last_peer,
        route=last_route,
        attempts=tuple(attempts),
        retry_after_seconds=retry_after,
        error=error,
        acked_peers=tuple(acked_peers),
    )


def _send_gossip_no_response(raw, route_info, timeout):
    peer = route_info["peer"]
    route = route_info["route"]
    started = time.monotonic()
    try:
        ind_transport.send_no_response(
            (route, node_port()),
            "b",
            raw,
            peer_ip=route,
            timeout=timeout,
        )
        return _attempt_dict(
            peer,
            route,
            REQUEST_OK,
            response="",
            elapsed_seconds=time.monotonic() - started,
        )
    except Exception as exc:
        status = _classify_request_exception(exc)
        if status == REQUEST_PEER_KEY_MISMATCH and route not in already_tried:
            already_tried.append(route)
        logger.debug("fire-and-forget gossip to %s failed as %s: %s", route, status, exc)
        return _attempt_dict(
            peer,
            route,
            status,
            error=str(exc),
            elapsed_seconds=time.monotonic() - started,
        )


def _broadcast_gossip_fire_and_forget(
    raw,
    peers,
    *,
    pacer=None,
    fanout=None,
    timeout=None,
    deadline=None,
):
    peers = _dedupe_preserving_order(str(peer).strip() for peer in peers or [] if str(peer).strip())
    if not raw or not peers:
        return PeerRequestResult(
            status=REQUEST_CONNECTION_CLOSED,
            error="no peer routes available",
        )

    fanout = max(1, int(fanout or WALLET_FIRE_AND_FORGET_PEER_FANOUT))
    timeout = float(timeout or WALLET_FIRE_AND_FORGET_PEER_TIMEOUT_SECONDS)
    attempts = []
    dispatched_peers = []
    dispatched_routes = []
    tried_routes = set()

    while len(dispatched_peers) < fanout:
        if deadline is not None and _remaining_deadline_seconds(deadline) <= 0:
            break
        remaining_peers = [
            peer for peer in _ordered_peer_candidates(peers) if peer not in dispatched_peers
        ]
        if not remaining_peers:
            break
        ready_peers = remaining_peers if pacer is None else pacer.available_peers(remaining_peers)
        if not ready_peers:
            delay = max(0.1, pacer.wait_seconds(remaining_peers) if pacer is not None else 0.1)
            if not _can_wait_for(deadline, delay):
                break
            time.sleep(delay)
            continue

        routes = [
            route_info
            for route_info in expanded_peer_routes(ready_peers)
            if route_info["route"] not in tried_routes
        ]
        if not routes:
            break
        route_info = routes[0]
        tried_routes.add(route_info["route"])
        if pacer is not None:
            pacer.record(route_info["peer"])
        attempt = _send_gossip_no_response(raw, route_info, timeout)
        attempts.append(attempt)
        if attempt.get("status") == REQUEST_OK:
            dispatched_peers.append(route_info["peer"])
            dispatched_routes.append(route_info["route"])

    if dispatched_peers:
        return PeerRequestResult(
            status=REQUEST_OK,
            response="",
            peer=dispatched_peers[0],
            route=dispatched_routes[0],
            attempts=tuple(attempts),
            acked_peers=tuple(dispatched_peers),
        )
    if attempts:
        status = attempts[-1].get("status") or REQUEST_TIMEOUT
        return PeerRequestResult(
            status=status,
            response="",
            peer=attempts[-1].get("peer", ""),
            route=attempts[-1].get("route", ""),
            attempts=tuple(attempts),
            error="gossip frame was not handed to a peer",
        )
    return PeerRequestResult(
        status=REQUEST_TIMEOUT,
        response="",
        attempts=tuple(attempts),
        error="fire-and-forget route budget exhausted",
    )


def _send_progress_payload(
    event,
    *,
    total,
    sent,
    queued_remaining,
    rate_limited_peers=None,
    eta_seconds=0,
    message="",
    **extra,
):
    payload = {
        "event": str(event),
        "total": int(total or 0),
        "sent": int(sent or 0),
        "queued_remaining": int(queued_remaining or 0),
        "rate_limited_peers": int(rate_limited_peers or 0),
        "eta_seconds": max(0, int(math.ceil(float(eta_seconds or 0)))),
        "message": str(message or ""),
    }
    payload.update(extra)
    return payload


def _emit_send_progress(progress_callback, event, **details):
    if not callable(progress_callback):
        return
    try:
        progress_callback(_send_progress_payload(event, **details))
    except Exception:
        logger.debug("wallet send progress callback failed", exc_info=True)


def _transaction_file_count():
    try:
        return len(runtime_json.transaction_files())
    except Exception:
        return 0


def _queued_send_peers():
    ipnl1 = diverse_peer_sample(_peer_files('ip_folder/1'), limit=6)
    ipnl2 = _with_configured_peers(diverse_peer_sample(_peer_files('ip_folder/2'), limit=12))
    return _dedupe_preserving_order(ipnl1 + ipnl2)


def _rate_limited_attempt_peers(result):
    peers = set()
    for attempt in result.attempts:
        if attempt.get("status") == REQUEST_RATE_LIMITED:
            peer = attempt.get("peer") or attempt.get("route")
            if peer:
                peers.add(peer)
    return peers


def _estimate_send_eta(sent, queued_remaining, started_at, peer_count, now=None):
    queued_remaining = int(queued_remaining or 0)
    if queued_remaining <= 0:
        return 0
    now = time.monotonic() if now is None else float(now)
    elapsed = max(0.0, now - float(started_at))
    observed_rate = 0.0
    if sent >= WALLET_SEND_MIN_OBSERVED_ETA_SENT and elapsed > 0:
        observed_rate = float(sent) / elapsed
    configured_rate = (
        max(1, int(peer_count or 0))
        * float(WALLET_MAX_GOSSIP_PER_PEER_WINDOW)
        / float(WALLET_SEND_WINDOW_SECONDS)
    )
    configured_rate = min(configured_rate, float(WALLET_MAX_BILLS_PER_SECOND))
    rate = observed_rate or configured_rate
    if rate <= 0:
        return 0
    return int(math.ceil(queued_remaining / rate))


def _remaining_deadline_seconds(deadline):
    if deadline is None:
        return None
    return max(0.0, float(deadline) - time.monotonic())


def _can_wait_for(deadline, delay_seconds):
    remaining = _remaining_deadline_seconds(deadline)
    return remaining is None or remaining >= float(delay_seconds)


def _remove_transaction_file(transaction_path):
    try:
        os.remove(transaction_path)
        return True
    except FileNotFoundError:
        return False


def _parse_status_response(raw):
    lines = [line.strip() for line in str(raw or "").splitlines() if line.strip()]
    records = []
    index = 0
    while index < len(lines):
        ref = lines[index]
        if (
            index + 2 < len(lines)
            and lines[index + 1] == "x"
            and lines[index + 2] == REQUEST_INVALID
        ):
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
    from . import protocol_v3

    if not isinstance(message, dict):
        return None
    message_type = message.get("type")
    if message_type == protocol_v3.TRANSFER_ANNOUNCEMENT_TYPE:
        try:
            bill, _proof_bundle, _segments = protocol_v3.decode_transfer_announcement(message)
            return bill
        except Exception:
            return None
    return None


def _broadcast_status_expectation(message):
    from . import protocol_v3

    bill = _gossip_bill(message)
    if not bill:
        return None
    try:
        if isinstance(bill, dict) and bill.get("type") == protocol_v3.BILL_TYPE:
            store = wallet_sync_store()
            state = protocol_v3.verify_bill(
                bill,
                proof_bundle_resolver=store.proof_bundle_resolver_v3,
                transparency_verifier=getattr(store, "transparency_verifier", None),
                archive_segment_resolver=store.archive_segment_resolver_v3,
            )
        else:
            return None
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


def _queued_retry_delay_seconds(result=None, fallback=None):
    if fallback is not None:
        return max(
            0.0,
            min(float(WALLET_QUEUED_RETRY_MAX_DELAY_SECONDS), float(fallback)),
        )
    elif result is not None:
        delay = _retry_delay_for_result(result)
    else:
        delay = _rate_limit_backoff_seconds()
    if delay <= 0:
        delay = _rate_limit_backoff_seconds()
    return max(0.1, min(float(WALLET_QUEUED_RETRY_MAX_DELAY_SECONDS), float(delay)))


def _run_queued_gossip_retry(transaction_path, raw, peers, *, initial_delay_seconds=None):
    transaction_path = Path(transaction_path)
    delay = _queued_retry_delay_seconds(fallback=initial_delay_seconds)
    max_attempts = max(1, int(WALLET_QUEUED_RETRY_MAX_ATTEMPTS))

    for attempt in range(1, max_attempts + 1):
        if delay > 0:
            time.sleep(delay)
        if not transaction_path.exists():
            return True

        result = _broadcast_gossip_fire_and_forget(
            raw,
            peers,
            pacer=OutboundGossipPacer(),
        )
        if result.status == REQUEST_OK:
            if _remove_transaction_file(transaction_path):
                logger.info("queued gossip %s dispatched after background retry", transaction_path)
            return True

        if attempt >= max_attempts:
            break

        delay = _queued_retry_delay_seconds(result)
        logger.info(
            "queued gossip %s retry %s/%s failed as %s; retrying in %.1fs",
            transaction_path,
            attempt,
            max_attempts,
            result.status,
            delay,
        )

    logger.info(
        "queued gossip %s remains pending after %s retry attempts",
        transaction_path,
        max_attempts,
    )
    return False


def _schedule_raw_gossip_retry(raw, peers, *, delay_seconds=None):
    peers = _ordered_peer_candidates(peers)
    if not raw or not peers:
        return False

    def retry():
        delay = float(_rate_limit_backoff_seconds() if delay_seconds is None else delay_seconds)
        if delay > 0:
            time.sleep(delay)
        result = _broadcast_gossip_to_peer_quorum(
            raw,
            peers,
            pacer=OutboundGossipPacer(),
            min_peer_acks=1,
        )
        if result.status != REQUEST_OK:
            logger.info(
                "background gossip retry kept failing with %s for peers %s", result.status, peers
            )

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
            _run_queued_gossip_retry(
                transaction_path,
                raw,
                peers,
                initial_delay_seconds=delay_seconds,
            )
        finally:
            with _queued_gossip_retry_lock:
                _queued_gossip_retries.discard(key)

    threading.Thread(target=retry, daemon=True).start()
    return True


# Discover the public IPv4 or IPv6 address without making peer gossip the first dependency.
def public_ip():
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


# Validate queued wallet gossip locally, then dispatch it to sampled peers at a polite pace.
def send_queued_bills_paced(progress_callback=None, max_duration_seconds=None):
    if not _paced_send_lock.acquire(blocking=False):
        queued = _transaction_file_count()
        _emit_send_progress(
            progress_callback,
            "waiting",
            total=queued,
            sent=0,
            queued_remaining=queued,
            eta_seconds=0,
            message="Outgoing sends are already running; new bills will stay in the queue.",
        )
        return {
            "status": "running",
            "total": queued,
            "sent": 0,
            "dropped": 0,
            "queued_remaining": queued,
            "rate_limited_peers": 0,
        }

    try:
        clear_cancel_queued_bills()
        ensure_runtime_files()
        started_at = time.monotonic()
        deadline = (
            None
            if max_duration_seconds is None
            else started_at + max(0.0, float(max_duration_seconds))
        )
        initial_total = _transaction_file_count()
        sent = 0
        dropped = 0
        deferred_paths = set()
        rate_limited_peers = set()
        pacer = OutboundGossipPacer()
        bill_pacer = OutboundBillPacer()
        peer_count = 0

        def emit(event, message="", **extra):
            queued_remaining = _transaction_file_count()
            total = max(initial_total, sent + dropped + queued_remaining)
            eta_seconds = _estimate_send_eta(
                sent,
                queued_remaining,
                started_at,
                peer_count,
            )
            _emit_send_progress(
                progress_callback,
                event,
                total=total,
                sent=sent,
                queued_remaining=queued_remaining,
                rate_limited_peers=len(rate_limited_peers),
                eta_seconds=eta_seconds,
                message=message,
                dropped=dropped,
                **extra,
            )

        emit("preparing", "Preparing queued bills.")
        if initial_total <= 0:
            emit("complete", "No queued bills to send.")
            return {
                "status": "complete",
                "total": 0,
                "sent": 0,
                "dropped": 0,
                "queued_remaining": 0,
                "rate_limited_peers": 0,
            }

        peers = _queued_send_peers()
        peer_count = len(peers)
        if not peers:
            emit("partial", "No peers are available. Bills will stay queued.")
            return {
                "status": "partial",
                "total": initial_total,
                "sent": sent,
                "dropped": dropped,
                "queued_remaining": _transaction_file_count(),
                "rate_limited_peers": 0,
            }

        store = wallet_sync_store()
        stop_reason = ""

        while True:
            if queued_bill_cancel_requested():
                stop_reason = "cancelled"
                break
            if deadline is not None and _remaining_deadline_seconds(deadline) <= 0:
                stop_reason = "send time budget exhausted"
                break

            all_paths = runtime_json.transaction_files()
            process_paths = [path for path in all_paths if str(path) not in deferred_paths]
            if not all_paths:
                stop_reason = "complete"
                break
            if not process_paths:
                stop_reason = "deferred"
                break

            for transaction_path in process_paths:
                if queued_bill_cancel_requested():
                    stop_reason = "cancelled"
                    break
                if deadline is not None and _remaining_deadline_seconds(deadline) <= 0:
                    stop_reason = "send time budget exhausted"
                    break

                transaction_key = str(transaction_path)
                try:
                    tm, wire_message, local_result = _prepare_queued_gossip_for_broadcast(
                        transaction_path,
                        store,
                    )
                    proof = local_result.get("conflict_proof")
                    if proof:
                        broadcast_message(proof)
                except Exception as exc:
                    logger.debug("dropping invalid queued transaction %s: %s", transaction_path, exc)
                    _remove_transaction_file(transaction_path)
                    dropped += 1
                    emit("error", "Dropped one invalid queued bill.")
                    continue

                if not bill_pacer.wait(deadline=deadline):
                    stop_reason = "send time budget exhausted"
                    break
                if queued_bill_cancel_requested():
                    stop_reason = "cancelled"
                    break

                result = _broadcast_gossip_fire_and_forget(
                    wire_message,
                    peers,
                    pacer=pacer,
                    deadline=deadline,
                )

                if result.status == REQUEST_OK:
                    _remove_transaction_file(transaction_path)
                    sent += 1
                    emit(
                        "sending",
                        f"Dispatched {sent} queued bill(s).",
                        dispatched_peers=len(result.acked_peers),
                    )
                else:
                    _schedule_queued_gossip_retry(
                        transaction_path,
                        wire_message,
                        peers,
                        delay_seconds=_retry_delay_for_result(result),
                    )
                    deferred_paths.add(transaction_key)
                    logger.info(
                        "kept queued transaction %s after %s handoff result",
                        transaction_path,
                        result.status,
                    )
                    emit("waiting", "One bill is queued for automatic handoff retry.")

                if stop_reason:
                    break

            if stop_reason and stop_reason != "complete":
                break

        queued_remaining = _transaction_file_count()
        if stop_reason == "cancelled":
            status = "cancelled"
        else:
            status = "complete" if queued_remaining == 0 else "partial"
        if status == "complete":
            emit("complete", f"Dispatched {sent} queued bill(s).")
        elif status == "cancelled":
            emit("cancelled", f"Send cancelled. {queued_remaining} queued bill(s) were not dispatched.")
        else:
            message = f"{queued_remaining} bill(s) still queued. Retrying automatically."
            if stop_reason == "send time budget exhausted":
                message = "Send time budget ended; " + message
            elif stop_reason == "rate limited":
                message = "Network is busy; " + message
            emit("partial", message)
        return {
            "status": status,
            "total": max(initial_total, sent + dropped + queued_remaining),
            "sent": sent,
            "dropped": dropped,
            "queued_remaining": queued_remaining,
            "rate_limited_peers": len(rate_limited_peers),
        }
    finally:
        _paced_send_lock.release()


# Compatibility entry point for callers that do not need progress events.
def send_bills():
    return send_queued_bills_paced()


# Broadcast a protocol message after converting it to the current wire format.
def broadcast_message(message, *, timeout=None, max_duration_seconds=DEFAULT_CONNECT_ATTEMPT_BUDGET_SECONDS):
    ensure_runtime_files()
    raw = ind_token.pack_wire_message(message)
    ipnl1 = diverse_peer_sample(_peer_files('ip_folder/1'), limit=6)
    ipnl2 = _with_configured_peers(diverse_peer_sample(_peer_files('ip_folder/2'), limit=12))
    peers = _dedupe_preserving_order(ipnl1 + ipnl2)
    result = connect_result(
        'b',
        raw,
        peers,
        timeout=timeout,
        max_duration_seconds=max_duration_seconds,
    )
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


def _parse_wallet_sync_response(raw):
    empty = {"records": [], "messages": [], "has_more": False, "next_cursor": None, "direction": ""}
    if not raw or raw == 'n':
        return empty
    try:
        decoded = json.loads(raw)
    except Exception:
        return empty
    if isinstance(decoded, dict):
        records = decoded.get("records")
        messages = decoded.get("messages")
        result = {
            "records": [],
            "messages": [],
            "has_more": bool(decoded.get("has_more")),
            "next_cursor": decoded.get("next_cursor") if isinstance(decoded.get("next_cursor"), dict) else None,
            "direction": str(decoded.get("direction") or ""),
        }
        if isinstance(records, list):
            result["records"] = records
        if isinstance(messages, list):
            result["messages"] = messages
        elif decoded.get("type") != "ind.wallet_bill_sync_response.v3":
            result["messages"] = [decoded]
        return result
    if isinstance(decoded, list):
        result = dict(empty)
        result["messages"] = decoded
        return result
    return empty


def _wallet_sync_record_identity(record):
    if not isinstance(record, dict):
        return ""
    token_id = str(record.get("token_id") or "").strip()
    display_id = str(record.get("display_id") or "").strip()
    sequence = str(record.get("sequence") or "").strip()
    if token_id or display_id:
        return "|".join((token_id, display_id, sequence))
    try:
        return json.dumps(record, sort_keys=True, separators=(",", ":"))
    except Exception:
        return ""


def _compact_wallet_sync_display_ranges(display_ranges):
    normalized = []
    for item in display_ranges or []:
        try:
            if isinstance(item, dict):
                value = int(item.get("value", item.get("v")))
                start = int(item.get("start", item.get("s")))
                end = int(item.get("end", item.get("e", start)))
                sequence = int(item.get("sequence", item.get("q")))
            else:
                value, start, end, sequence = item[:4]
                value = int(value)
                start = int(start)
                end = int(end)
                sequence = int(sequence)
        except Exception:
            continue
        if start > end or sequence <= 0:
            continue
        normalized.append((value, start, end, sequence))
    if not normalized:
        return []

    normalized.sort(key=lambda item: (item[0], item[3], item[1], item[2]))
    merged = []
    for value, start, end, sequence in normalized:
        if (
            merged
            and merged[-1][0] == value
            and merged[-1][3] == sequence
            and start <= merged[-1][2] + 1
        ):
            previous = merged[-1]
            merged[-1] = (previous[0], previous[1], max(previous[2], end), previous[3])
            continue
        merged.append((value, start, end, sequence))

    selected = []
    used_bytes = 2
    for item in merged:
        encoded = json.dumps(list(item), separators=(",", ":"))
        extra = len(encoded.encode("utf-8")) + (1 if selected else 0)
        if (
            len(selected) >= WALLET_SYNC_DISPLAY_RANGE_LIMIT
            or used_bytes + extra > WALLET_SYNC_DISPLAY_RANGE_BYTES
        ):
            break
        selected.append(list(item))
        used_bytes += extra
    return selected


def _wallet_display_ids_from_lines(wallet_lines):
    display_ids = []
    for line in runtime_json.wallet_bill_lines(wallet_lines):
        parts = str(line).split()
        if not parts:
            continue
        display_id = parts[0].lstrip("-")
        if display_id:
            display_ids.append(display_id)
    return display_ids


def _spendable_wallet_display_ids_for_ranges(store, address, wallet_lines):
    display_ids = _wallet_display_ids_from_lines(wallet_lines)
    if not display_ids:
        return set()
    try:
        return wallet_services.spendable_wallet_display_ids(
            address,
            display_ids,
            store=store,
        )
    except Exception:
        logger.debug("could not read spendable wallet display ids for sync hint", exc_info=True)
        return set()


def _wallet_known_display_ranges_from_lines(wallet_lines, known_display_ids=None):
    try:
        from . import protocol_v3
    except Exception:
        return []
    known_display_ids = set(known_display_ids or [])
    if not known_display_ids:
        return []
    known_points = {}
    for line in runtime_json.wallet_bill_lines(wallet_lines):
        parts = str(line).split()
        if len(parts) < 2:
            continue
        display_id = parts[0].lstrip("-")
        if display_id not in known_display_ids:
            continue
        try:
            parsed = protocol_v3.parse_display_id(display_id, "wallet bill display id")
            sequence = int(parts[1])
        except Exception:
            continue
        if sequence <= 0:
            continue
        point = (int(parsed["value"]), int(parsed["serial"]))
        known_points[point] = max(int(known_points.get(point, 0)), sequence)
    ranges = [
        [value, serial, serial, sequence]
        for (value, serial), sequence in known_points.items()
    ]
    return _compact_wallet_sync_display_ranges(ranges)


def _wallet_sync_request_with_wallet_ranges(sync_request, store, address, wallet_lines):
    if not isinstance(sync_request, dict):
        return sync_request
    spendable_display_ids = _spendable_wallet_display_ids_for_ranges(
        store,
        address,
        wallet_lines,
    )
    wallet_ranges = _wallet_known_display_ranges_from_lines(
        wallet_lines,
        known_display_ids=spendable_display_ids,
    )
    if not wallet_ranges:
        return sync_request
    existing_ranges = sync_request.get("known_display_ranges")
    combined_ranges = list(existing_ranges) if isinstance(existing_ranges, list) else []
    combined_ranges.extend(wallet_ranges)
    merged_ranges = _compact_wallet_sync_display_ranges(combined_ranges)
    if not merged_ranges:
        return sync_request
    updated_request = dict(sync_request)
    updated_request["known_display_ranges"] = merged_ranges
    return updated_request


def _wallet_sync_request_for_address(
    store,
    address,
    response_limit=WALLET_SYNC_RESPONSE_LIMIT,
    direction="backfill",
    page_cursor=None,
    wallet_lines=None,
):
    request_builder = getattr(store, "wallet_delta_sync_request", None)
    if not callable(request_builder):
        return None
    try:
        request = request_builder(
            address,
            token_limit=WALLET_SYNC_TOKEN_CURSOR_LIMIT,
            response_limit=response_limit,
            direction=direction,
            page_cursor=page_cursor,
        )
        return _wallet_sync_request_with_wallet_ranges(request, store, address, wallet_lines)
    except TypeError:
        try:
            request = request_builder(
                address,
                token_limit=WALLET_SYNC_TOKEN_CURSOR_LIMIT,
                response_limit=response_limit,
            )
            return _wallet_sync_request_with_wallet_ranges(request, store, address, wallet_lines)
        except Exception as exc:
            logger.debug("could not build wallet delta sync request for %s: %s", address, exc)
            return None
    except Exception as exc:
        logger.debug("could not build wallet delta sync request for %s: %s", address, exc)
        return None


def _wallet_sync_peer_candidates():
    peers = _with_configured_peers(_peer_files('ip_folder/1') + _peer_files('ip_folder/2'))
    peers = _ordered_peer_candidates(peers)
    if len(peers) <= WALLET_SYNC_MAX_PEERS:
        return peers
    configured = _ordered_peer_candidates(_configured_peer_servers())
    selected = []
    for peer in configured + diverse_peer_sample(peers, limit=WALLET_SYNC_MAX_PEERS):
        if peer not in selected:
            selected.append(peer)
        if len(selected) >= WALLET_SYNC_MAX_PEERS:
            break
    return selected


def _wallet_sync_request_timing(sync_request):
    direction = ""
    if isinstance(sync_request, dict):
        direction = str(sync_request.get("direction") or "").lower()
    if direction == "reconcile":
        return (
            WALLET_SYNC_RECONCILE_REQUEST_TIMEOUT_SECONDS,
            WALLET_SYNC_RECONCILE_REQUEST_BUDGET_SECONDS,
        )
    return WALLET_SYNC_REQUEST_TIMEOUT_SECONDS, WALLET_SYNC_REQUEST_BUDGET_SECONDS


def _fetch_wallet_messages_from_peer(peer, address, sync_request=None):
    if sync_request:
        request_timeout, request_budget = _wallet_sync_request_timing(sync_request)
        request_direction = (
            str(sync_request.get("direction") or "")
            if isinstance(sync_request, dict)
            else ""
        )
        result = connect_result(
            'R',
            json.dumps(sync_request, sort_keys=True, separators=(",", ":")),
            [peer],
            timeout=request_timeout,
            max_duration_seconds=request_budget,
        )
        if result.status == REQUEST_OK:
            parsed = _parse_wallet_sync_response(result.response)
            return {
                "peer": result.route or result.peer or peer,
                "status": result.status,
                "messages": parsed["messages"],
                "records": parsed["records"],
                "has_more": parsed["has_more"],
                "next_cursor": parsed["next_cursor"],
                "direction": parsed["direction"] or request_direction,
                "delta": True,
            }
        if result.status != REQUEST_INVALID:
            logger.debug(
                "wallet delta sync request for %s via %s failed as %s",
                address,
                result.route or result.peer or peer,
                result.status,
            )
            return {
                "peer": result.route or result.peer or peer,
                "status": result.status,
                "messages": [],
                "records": [],
                "has_more": False,
                "next_cursor": None,
                "direction": request_direction,
                "delta": True,
            }

    result = connect_result(
        'r',
        address,
        [peer],
        timeout=WALLET_SYNC_REQUEST_TIMEOUT_SECONDS,
        max_duration_seconds=WALLET_SYNC_REQUEST_BUDGET_SECONDS,
    )
    if result.status != REQUEST_OK:
        logger.debug(
            "wallet sync request for %s via %s failed as %s",
            address,
            result.route or result.peer or peer,
            result.status,
        )
        return {
            "peer": result.route or result.peer or peer,
            "status": result.status,
            "messages": [],
            "records": [],
        }
    parsed = _parse_wallet_sync_response(result.response)
    return {
        "peer": result.route or result.peer or peer,
        "status": result.status,
        "messages": parsed["messages"],
        "records": parsed["records"],
        "delta": False,
    }


def iter_wallet_message_reports(address, peers=None, sync_request=None):
    peers = _ordered_peer_candidates(peers or _wallet_sync_peer_candidates())
    if not peers:
        return
    workers = max(1, min(WALLET_SYNC_WORKERS, len(peers)))
    executor = ThreadPoolExecutor(max_workers=workers)
    futures = [
        executor.submit(_fetch_wallet_messages_from_peer, peer, address, sync_request)
        for peer in peers
    ]
    try:
        for future in as_completed(futures, timeout=WALLET_SYNC_FETCH_BUDGET_SECONDS):
            try:
                yield future.result()
            except Exception as exc:
                logger.debug("wallet sync peer worker failed for %s: %s", address, exc)
                yield {"peer": "", "status": REQUEST_INVALID, "messages": []}
    except FuturesTimeoutError:
        for future in futures:
            if not future.done():
                future.cancel()
                yield {"peer": "", "status": REQUEST_TIMEOUT, "messages": []}
        logger.debug("wallet sync fetch timed out for %s", address)
    finally:
        executor.shutdown(wait=False, cancel_futures=True)


def fetch_wallet_messages(address, peers=None, return_report=False):
    messages = []
    reports = []
    for report in iter_wallet_message_reports(address, peers=peers):
        reports.append(report)
        messages.extend(report["messages"])
    return (messages, reports) if return_report else messages


# Return locally settled bill records for wallet display ids or protocol bill ids.
def check_validity(serial_num_list):
    from . import protocol_v3

    store = wallet_sync_store()
    store.finalize_pending(buffer_seconds=ind_settings.finality_buffer_seconds())
    verified = []
    for item in serial_num_list:
        bill_v3 = store.get_bill_v3_by_token_id(item) or store.get_bill_v3_by_display_id(item)
        if bill_v3:
            try:
                state = protocol_v3.verify_bill(
                    bill_v3,
                    proof_bundle_resolver=store.proof_bundle_resolver_v3,
                    transparency_verifier=getattr(store, "transparency_verifier", None),
                    archive_segment_resolver=store.archive_segment_resolver_v3,
                )
                confidence = store.bill_v3_confidence(
                    state.token_id, expected_owner=state.owner_address, min_settled_seconds=0
                )
                if confidence["accepted"]:
                    verified.append((state.display_id, state.owner_address, str(state.sequence)))
            except Exception as exc:
                logger.debug("V3 bill validity check failed for %s: %s", item, exc)
            continue
        continue
    return verified


# Refresh the local peer cache from bootstrap and ordinary nodes.
def update_ip_list():
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


def _wallet_sync_summary_snapshot(summary):
    snapshot = dict(summary)
    snapshot["errors"] = list(summary.get("errors") or [])
    return snapshot


def _emit_wallet_sync_progress(progress_callback, event, summary, **details):
    if not callable(progress_callback):
        return
    payload = {
        "event": event,
        "summary": _wallet_sync_summary_snapshot(summary),
    }
    payload.update(details)
    try:
        progress_callback(payload)
    except Exception:
        logger.debug("wallet sync progress callback failed", exc_info=True)


# Pull owner-addressed bill records and import spendable bills.
def receive_bills(
    progress_callback=None,
    stop_requested=None,
    response_limit=WALLET_SYNC_RESPONSE_LIMIT,
):
    from . import keys_v3

    ensure_runtime_files()
    store = wallet_sync_store()
    try:
        response_limit = max(1, min(WALLET_SYNC_RESPONSE_LIMIT, int(response_limit)))
    except (TypeError, ValueError):
        response_limit = WALLET_SYNC_RESPONSE_LIMIT
    summary = {
        "status": "running",
        "wallets": 0,
        "sync_rounds": 0,
        "local_messages": 0,
        "fetched_messages": 0,
        "fetched_records": 0,
        "fetched_unique_records": 0,
        "fetched_duplicate_records": 0,
        "processed_messages": 0,
        "checked_records": 0,
        "processed_records": 0,
        "accepted_messages": 0,
        "accepted_records": 0,
        "skipped_known_records": 0,
        "finalized": 0,
        "settled": 0,
        "pending": 0,
        "peer_failures": 0,
        "peer_timeouts": 0,
        "wallet_bills_added": 0,
        "skipped_known_messages": 0,
        "errors": [],
    }
    cancelled = False

    def sync_stop_requested():
        if not callable(stop_requested):
            return False
        try:
            return bool(stop_requested())
        except Exception:
            logger.debug("wallet sync stop callback failed", exc_info=True)
            return False

    def maybe_cancel(address="", source=""):
        nonlocal cancelled
        if cancelled:
            return True
        if not sync_stop_requested():
            return False
        cancelled = True
        summary["status"] = "cancelled"
        _emit_wallet_sync_progress(
            progress_callback,
            "cancelled",
            summary,
            address=address,
            source=source,
        )
        return True
    for wallet_path in runtime_json.iter_decrypted_wallet_files():
        if maybe_cancel(source="startup"):
            break
        if wallet_path.name.startswith('wallet_decrypted'):
            wallet = runtime_json.read_decrypted_wallet_lines(wallet_path)
            address = wallet[0].strip()
            if maybe_cancel(address=address, source="wallet"):
                break
            summary["wallets"] += 1
            _emit_wallet_sync_progress(
                progress_callback,
                "wallet_started",
                summary,
                address=address,
            )
            wallet_ids = {
                line.split()[0].lstrip('-')
                for line in runtime_json.wallet_bill_lines(wallet)
                if line.split()
            }
            wallet_context = {
                "address": address,
                "wallet": wallet,
                "wallet_ids": wallet_ids,
                "wallet_path": wallet_path,
            }

            def wallet_settled_records_for_address(current_address):
                if keys_v3.is_address(current_address):
                    metadata_reader = getattr(store, "bill_v3_metadata_records_for_owner", None)
                    if callable(metadata_reader):
                        return metadata_reader(
                            current_address,
                            statuses=("settled", "verified"),
                            limit=None,
                        )
                    return store.bill_v3_records_for_owner(
                        current_address,
                        statuses=("settled", "verified"),
                        limit=None,
                    )
                return store.token_records_for_owner(current_address, settled_only=True)

            def wallet_pending_records_for_address(current_address):
                if keys_v3.is_address(current_address):
                    metadata_reader = getattr(store, "bill_v3_metadata_records_for_owner", None)
                    if callable(metadata_reader):
                        return metadata_reader(
                            current_address,
                            statuses=("pending",),
                            limit=None,
                        )
                    return store.bill_v3_records_for_owner(
                        current_address,
                        statuses=("pending",),
                        limit=None,
                    )
                return []

            def wallet_record_history_timestamp(record, current_address=address):
                fallback = record.get("updated_at") or time.time()
                bill = None
                if "bill_blob" not in record and keys_v3.is_address(current_address):
                    lookup = getattr(store, "get_bill_v3_by_display_id_sequence", None)
                    if callable(lookup):
                        try:
                            bill = lookup(record.get("display_id"), record.get("sequence"))
                        except Exception:
                            logger.debug("could not load wallet sync bill timestamp", exc_info=True)
                return wallet_services.latest_bill_transfer_timestamp(
                    record=record,
                    bill=bill,
                    fallback=fallback,
                )

            def add_new_settled_bills(reason, context=wallet_context):
                current_address = context["address"]
                settled_records = wallet_settled_records_for_address(current_address)
                updated_wallet = list(context["wallet"])
                added_records = []
                for record in settled_records:
                    if record["display_id"] not in context["wallet_ids"]:
                        history_timestamp = wallet_record_history_timestamp(record)
                        updated_wallet.append(
                            record["display_id"]
                            + ' '
                            + str(record["sequence"])
                            + ' '
                            + str(history_timestamp)
                            + '\n'
                        )
                        context["wallet_ids"].add(record["display_id"])
                        added_records.append(record)
                if added_records:
                    runtime_json.write_decrypted_wallet_lines(context["wallet_path"], updated_wallet)
                    context["wallet"] = updated_wallet
                    summary["wallet_bills_added"] += len(added_records)
                    _emit_wallet_sync_progress(
                        progress_callback,
                        "bills_added",
                        summary,
                        address=current_address,
                        count=len(added_records),
                        display_id=added_records[-1]["display_id"],
                        sequence=int(added_records[-1]["sequence"]),
                        reason=reason,
                    )
                return settled_records

            def finalize_ready_bills(reason, context=wallet_context):
                finalized = store.finalize_pending(
                    buffer_seconds=ind_settings.finality_buffer_seconds()
                )
                if finalized:
                    summary["finalized"] += len(finalized)
                    _emit_wallet_sync_progress(
                        progress_callback,
                        "finalized",
                        summary,
                        address=context["address"],
                        count=len(finalized),
                        reason=reason,
                    )
                    add_new_settled_bills(reason)
                return finalized

            add_new_settled_bills("startup")
            local_known_sequences = {}
            if keys_v3.is_address(address):
                known_reader = getattr(store, "wallet_known_token_sequences", None)
                if callable(known_reader):
                    try:
                        local_known_sequences = known_reader(address, limit=None)
                    except Exception:
                        logger.debug("could not read wallet known token sequences", exc_info=True)
            known_message_hashes = set()
            known_record_identities = set()
            local_messages = []
            summary["local_messages"] += len(local_messages)
            _emit_wallet_sync_progress(
                progress_callback,
                "local_messages",
                summary,
                address=address,
                message_count=len(local_messages),
            )

            def process_messages(
                messages,
                source,
                peer="",
                context=wallet_context,
                known_message_hashes=known_message_hashes,
            ):
                current_address = context["address"]
                for message in messages:
                    if maybe_cancel(address=current_address, source=source):
                        return False
                    try:
                        current_message_hash = ind_token.message_hash(message)
                    except Exception:
                        current_message_hash = ""
                    if current_message_hash and current_message_hash in known_message_hashes:
                        summary["skipped_known_messages"] += 1
                        continue
                    try:
                        result = store.ingest_message(message)
                        summary["processed_messages"] += 1
                        if result.get("accepted"):
                            summary["accepted_messages"] += 1
                            _emit_wallet_sync_progress(
                                progress_callback,
                                "message_accepted",
                                summary,
                                address=current_address,
                                source=source,
                                peer=peer,
                                status=result.get("status", ""),
                            )
                        proof = result.get("conflict_proof")
                        if proof:
                            broadcast_message(proof)
                        if current_message_hash:
                            known_message_hashes.add(current_message_hash)
                        finalize_ready_bills("message")
                    except Exception as exc:
                        logger.debug(
                            "could not process wallet sync message for %s: %s",
                            current_address,
                            exc,
                        )
                        if len(summary["errors"]) < 5:
                            summary["errors"].append(str(exc))
                        _emit_wallet_sync_progress(
                            progress_callback,
                            "message_error",
                            summary,
                            address=current_address,
                            source=source,
                            peer=peer,
                            error=str(exc),
                        )
                return True

            def process_records(
                records,
                source,
                peer="",
                context=wallet_context,
                known_sequences=local_known_sequences,
            ):
                current_address = context["address"]
                progress_started = time.monotonic()
                progress_last_emit = progress_started
                progress_since_emit = 0

                def emit_record_check_progress(force=False, display_id="", sequence=None):
                    nonlocal progress_last_emit, progress_since_emit
                    if progress_since_emit <= 0:
                        return
                    now = time.monotonic()
                    if not force and progress_since_emit < 25 and now - progress_last_emit < 0.75:
                        return
                    _emit_wallet_sync_progress(
                        progress_callback,
                        "records_checked",
                        summary,
                        address=current_address,
                        source=source,
                        peer=peer,
                        display_id=display_id,
                        sequence=sequence if sequence is not None else "",
                        count=progress_since_emit,
                    )
                    progress_last_emit = now
                    progress_since_emit = 0

                for record in records:
                    if maybe_cancel(address=current_address, source=source):
                        return False
                    token_id = str(record.get("token_id") or "").strip()
                    display_id = str(record.get("display_id") or "").strip()
                    try:
                        sequence = int(record.get("sequence"))
                    except (TypeError, ValueError):
                        sequence = None
                    summary["checked_records"] += 1
                    progress_since_emit += 1
                    if token_id and sequence is not None:
                        known_sequence = known_sequences.get(token_id)
                        if known_sequence is not None and int(known_sequence) >= sequence:
                            summary["skipped_known_records"] += 1
                            emit_record_check_progress(display_id=display_id, sequence=sequence)
                            continue
                    try:
                        result = store.ingest_wallet_bill_sync_record(record)
                        summary["processed_records"] += 1
                        if result.get("accepted"):
                            summary["accepted_records"] += 1
                            if token_id and sequence is not None:
                                known_sequences[token_id] = max(
                                    int(known_sequences.get(token_id, 0) or 0),
                                    sequence,
                                )
                            state = result.get("state")
                            accepted_display_id = str(
                                getattr(state, "display_id", "") or record.get("display_id") or ""
                            ).strip()
                            try:
                                accepted_sequence = int(
                                    getattr(state, "sequence", None) or record.get("sequence") or 0
                                )
                            except (TypeError, ValueError):
                                accepted_sequence = 0
                            _emit_wallet_sync_progress(
                                progress_callback,
                                "record_accepted",
                                summary,
                                address=current_address,
                                source=source,
                                peer=peer,
                                status=result.get("status", ""),
                                display_id=accepted_display_id,
                                sequence=accepted_sequence,
                            )
                            progress_since_emit = 0
                            progress_last_emit = time.monotonic()
                        else:
                            emit_record_check_progress(display_id=display_id, sequence=sequence)
                    except Exception as exc:
                        logger.debug(
                            "could not process wallet sync record for %s: %s",
                            current_address,
                            exc,
                        )
                        if len(summary["errors"]) < 5:
                            summary["errors"].append(str(exc))
                        _emit_wallet_sync_progress(
                            progress_callback,
                            "message_error",
                            summary,
                            address=current_address,
                            source=source,
                            peer=peer,
                            error=str(exc),
                        )
                        progress_since_emit = 0
                        progress_last_emit = time.monotonic()
                emit_record_check_progress(force=True)
                return True

            if not process_messages(local_messages, "local"):
                break

            sync_phases = []
            if local_known_sequences:
                sync_phases.append("newer")
            sync_phases.append("reconcile")
            for sync_direction in sync_phases:
                page_cursor = None
                while True:
                    if maybe_cancel(address=address, source="peer"):
                        break
                    sync_request = _wallet_sync_request_for_address(
                        store,
                        address,
                        response_limit=response_limit,
                        direction=sync_direction,
                        page_cursor=page_cursor,
                        wallet_lines=wallet_context["wallet"],
                    )
                    legacy_request_without_builder = (
                        sync_request is None
                        and sync_direction in {"backfill", "reconcile"}
                        and page_cursor is None
                    )
                    if sync_request is None and not legacy_request_without_builder:
                        break
                    round_processed_start = int(summary.get("processed_records") or 0)
                    round_has_more = False
                    round_next_cursor = None
                    round_saw_delta_response = False
                    summary["sync_rounds"] += 1
                    _emit_wallet_sync_progress(
                        progress_callback,
                        "peer_request_started",
                        summary,
                        address=address,
                        direction=sync_direction,
                        has_more=bool(page_cursor),
                    )

                    for report in iter_wallet_message_reports(address, sync_request=sync_request):
                        if maybe_cancel(address=address, source="peer"):
                            break
                        messages = report.get("messages") or []
                        records = report.get("records") or []
                        if report.get("delta"):
                            round_saw_delta_response = True
                        if report.get("has_more") or len(records) >= response_limit:
                            round_has_more = True
                            if report.get("next_cursor"):
                                round_next_cursor = report.get("next_cursor")
                        summary["fetched_messages"] += len(messages)
                        summary["fetched_records"] += len(records)
                        duplicate_records = 0
                        for record in records:
                            identity = _wallet_sync_record_identity(record)
                            if identity and identity in known_record_identities:
                                duplicate_records += 1
                                continue
                            if identity:
                                known_record_identities.add(identity)
                        summary["fetched_unique_records"] = len(known_record_identities)
                        summary["fetched_duplicate_records"] += duplicate_records
                        if report.get("status") != REQUEST_OK:
                            summary["peer_failures"] += 1
                            if report.get("status") == REQUEST_TIMEOUT:
                                summary["peer_timeouts"] += 1
                        _emit_wallet_sync_progress(
                            progress_callback,
                            "peer_report",
                            summary,
                            address=address,
                            peer=report.get("peer", ""),
                            status=report.get("status", ""),
                            direction=report.get("direction", ""),
                            has_more=bool(report.get("has_more")),
                            next_cursor=bool(report.get("next_cursor")),
                            message_count=len(messages) + len(records),
                        )
                        if not process_records(records, "peer", peer=report.get("peer", "")):
                            break
                        if not process_messages(messages, "peer", peer=report.get("peer", "")):
                            break

                    if cancelled:
                        break
                    if legacy_request_without_builder:
                        break
                    round_processed_records = (
                        int(summary.get("processed_records") or 0) - round_processed_start
                    )
                    legacy_known_token_request = (
                        round_next_cursor is None
                        and isinstance(sync_request, dict)
                        and "known_tokens" in sync_request
                    )
                    if not (
                        round_saw_delta_response
                        and round_has_more
                        and (round_next_cursor or legacy_known_token_request)
                        and round_processed_records > 0
                    ):
                        break
                    page_cursor = round_next_cursor

            if cancelled:
                break

            finalize_ready_bills("wallet_complete")
            settled = add_new_settled_bills("wallet_complete")
            if keys_v3.is_address(address):
                waiting = wallet_pending_records_for_address(address)
                for record in waiting:
                    if record["status"] == "pending":
                        summary["pending"] += 1
                summary["settled"] += len(settled)
            _emit_wallet_sync_progress(
                progress_callback,
                "wallet_complete",
                summary,
                address=address,
            )
    if cancelled:
        return summary
    if summary["wallets"] == 0:
        summary["errors"].append("No unlocked wallet.")
    summary["status"] = "complete"
    _emit_wallet_sync_progress(progress_callback, "complete", summary)
    return summary
