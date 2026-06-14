"""TCP gossip node service for IND peer discovery, message relay, and settlement."""

import json
import ipaddress
import logging
import os
import random
import socket
import threading
import time
from collections import deque
from multiprocessing import Manager, Process

from . import runtime as runtime_json
from . import sender_node
from . import settings as ind_settings
from . import token as ind_token
from . import transport as ind_transport


PORT = 8888


def _env_int(name, default, minimum=None, maximum=None):
    try:
        result = int(os.environ.get(name, default))
    except (TypeError, ValueError):
        result = int(default)
    if minimum is not None:
        result = max(int(minimum), result)
    if maximum is not None:
        result = min(int(maximum), result)
    return result


PEER_RATE_WINDOW_SECONDS = _env_int("IND_NODE_RATE_WINDOW_SECONDS", 60, minimum=1, maximum=3600)
MAX_CONNECTIONS_PER_PEER_WINDOW = _env_int("IND_NODE_MAX_CONNECTIONS_PER_IP_WINDOW", 240, minimum=1)
MAX_GOSSIP_DECODE_ATTEMPTS_PER_PEER_WINDOW = _env_int(
    "IND_NODE_MAX_GOSSIP_DECODE_ATTEMPTS_PER_IP_WINDOW",
    600,
    minimum=1,
)
MAX_GOSSIP_PER_PEER_WINDOW = _env_int("IND_NODE_MAX_GOSSIP_PER_IP_WINDOW", 180, minimum=1)
MAX_ROOT_GOSSIP_PER_PEER_WINDOW = _env_int("IND_NODE_MAX_ROOT_GOSSIP_PER_IP_WINDOW", 180, minimum=1)
MAX_EQUIVOCATION_GOSSIP_PER_PEER_WINDOW = _env_int(
    "IND_NODE_MAX_EQUIVOCATION_GOSSIP_PER_IP_WINDOW",
    60,
    minimum=1,
)
MAX_RECIPIENT_LOOKUPS_PER_PEER_WINDOW = _env_int(
    "IND_NODE_MAX_RECIPIENT_LOOKUPS_PER_IP_WINDOW",
    120,
    minimum=1,
)
MAX_STATUS_REQUESTS_PER_PEER_WINDOW = _env_int("IND_NODE_MAX_STATUS_REQUESTS_PER_IP_WINDOW", 120, minimum=1)
MAX_PEER_DISCOVERY_REQUESTS_PER_PEER_WINDOW = _env_int(
    "IND_NODE_MAX_PEER_DISCOVERY_REQUESTS_PER_IP_WINDOW",
    60,
    minimum=1,
)
MAX_PEER_ANNOUNCEMENTS_PER_PEER_WINDOW = _env_int(
    "IND_NODE_MAX_PEER_ANNOUNCEMENTS_PER_IP_WINDOW",
    60,
    minimum=1,
)
MAX_MISC_REQUESTS_PER_PEER_WINDOW = _env_int("IND_NODE_MAX_MISC_REQUESTS_PER_IP_WINDOW", 60, minimum=1)
MAX_ACTIVE_CONNECTIONS = _env_int("IND_NODE_MAX_ACTIVE_CONNECTIONS", 128, minimum=1)
MAX_ACTIVE_CONNECTIONS_PER_PEER = _env_int("IND_NODE_MAX_ACTIVE_CONNECTIONS_PER_IP", 12, minimum=1)
NODE_REQUEST_TIMEOUT_SECONDS = _env_int("IND_NODE_REQUEST_TIMEOUT_SECONDS", 10, minimum=1, maximum=120)
NODE_SOCKET_BACKLOG = _env_int("IND_NODE_SOCKET_BACKLOG", 128, minimum=1)
MAX_STATUS_REFS_PER_REQUEST = _env_int("IND_NODE_MAX_STATUS_REFS_PER_REQUEST", 200, minimum=1)
INVALID_SCORE_BAN_THRESHOLD = 5
INVALID_SCORE_DECAY_SECONDS = 600
MAX_PEER_TRACKING_ENTRIES = 5000
MAX_SEEN_GOSSIP_MESSAGES = 10000
MAX_GOSSIP_POOL_MESSAGES = 500
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class ServerCloseCounters:
    """Thread-safe counters for why the node closed peer connections."""

    def __init__(self):
        self.counts = {}
        self.lock = threading.Lock()

    def increment(self, reason):
        reason = str(reason or "unknown")
        with self.lock:
            self.counts[reason] = self.counts.get(reason, 0) + 1
            return self.counts[reason]

    def snapshot(self):
        with self.lock:
            return dict(self.counts)


SERVER_CLOSE_COUNTERS = ServerCloseCounters()


def record_server_close(reason, peer_ip="", detail="", level=logging.INFO):
    count = SERVER_CLOSE_COUNTERS.increment(reason)
    message = "closed peer connection reason=%s peer=%s count=%s"
    if detail:
        message += " detail=%s"
        logger.log(level, message, reason, peer_ip, count, detail)
    else:
        logger.log(level, message, reason, peer_ip, count)
    return count


def node_port():
    return ind_settings.node_port()


def _normalized_ip(value):
    normalized = sender_node._normalize_peer_address(str(value).replace("::ffff:", ""))
    return normalized or str(value).replace("::ffff:", "")


def _valid_ipv4(value):
    return sender_node._valid_ipv4(value)


def _valid_peer_address(value):
    return sender_node._valid_peer_address(value)


def _is_loopback_peer(value):
    try:
        return ipaddress.ip_address(_normalized_ip(value)).is_loopback
    except ValueError:
        return False


class PeerRateLimiter:
    """Small in-memory rate limiter for per-peer connection and gossip buckets."""

    def __init__(self, window_seconds=PEER_RATE_WINDOW_SECONDS, max_entries=MAX_PEER_TRACKING_ENTRIES):
        self.window_seconds = int(window_seconds)
        self.max_entries = int(max_entries)
        self.events = {}
        self.lock = threading.Lock()

    def _trim(self):
        overflow = len(self.events) - self.max_entries
        if overflow <= 0:
            return
        oldest = sorted(self.events.items(), key=lambda item: item[1][-1] if item[1] else 0)[:overflow]
        for key, _timestamps in oldest:
            self.events.pop(key, None)

    def allow(self, peer, bucket, limit, now=None):
        now = int(time.time() if now is None else now)
        limit = max(1, int(limit))
        with self.lock:
            key = (peer, bucket)
            cutoff = now - self.window_seconds
            timestamps = [item for item in self.events.get(key, []) if item > cutoff]
            if len(timestamps) >= limit:
                self.events[key] = timestamps
                return False
            timestamps.append(now)
            self.events[key] = timestamps
            self._trim()
            return True


class PeerPenaltyBook:
    """Tracks peers that repeatedly send malformed gossip and cools scores over time."""

    def __init__(
        self,
        threshold=INVALID_SCORE_BAN_THRESHOLD,
        decay_seconds=INVALID_SCORE_DECAY_SECONDS,
        max_entries=MAX_PEER_TRACKING_ENTRIES,
    ):
        self.threshold = int(threshold)
        self.decay_seconds = int(decay_seconds)
        self.max_entries = int(max_entries)
        self.scores = {}
        self.lock = threading.Lock()

    def _trim(self):
        overflow = len(self.scores) - self.max_entries
        if overflow <= 0:
            return
        oldest = sorted(self.scores.items(), key=lambda item: item[1][1])[:overflow]
        for peer, _score in oldest:
            self.scores.pop(peer, None)

    def _current(self, peer, now=None):
        now = int(time.time() if now is None else now)
        score, updated_at = self.scores.get(peer, (0, now))
        if now - updated_at >= self.decay_seconds:
            return 0, now
        return score, updated_at

    def penalize(self, peer, amount=1, now=None):
        now = int(time.time() if now is None else now)
        with self.lock:
            score, _updated_at = self._current(peer, now)
            score += int(amount)
            self.scores[peer] = (score, now)
            self._trim()
            return score

    def allow(self, peer, now=None):
        now = int(time.time() if now is None else now)
        with self.lock:
            score, updated_at = self._current(peer, now)
            self.scores[peer] = (score, updated_at)
            self._trim()
            return score < self.threshold


class ActivePeerConnections:
    """Caps concurrent handler threads globally and per peer IP."""

    def __init__(self, max_total=MAX_ACTIVE_CONNECTIONS, max_per_peer=MAX_ACTIVE_CONNECTIONS_PER_PEER):
        self.max_total = int(max_total)
        self.max_per_peer = int(max_per_peer)
        self.total = 0
        self.by_peer = {}
        self.lock = threading.Lock()

    def try_acquire(self, peer):
        with self.lock:
            peer_count = self.by_peer.get(peer, 0)
            if self.total >= self.max_total or peer_count >= self.max_per_peer:
                return False
            self.total += 1
            self.by_peer[peer] = peer_count + 1
            return True

    def release(self, peer):
        with self.lock:
            peer_count = self.by_peer.get(peer, 0)
            if peer_count <= 0:
                return
            if peer_count == 1:
                self.by_peer.pop(peer, None)
            else:
                self.by_peer[peer] = peer_count - 1
            self.total = max(0, self.total - 1)


class BoundedSeenSet:
    """Bounded dedupe set for recently processed gossip messages."""

    def __init__(self, limit=MAX_SEEN_GOSSIP_MESSAGES):
        self.limit = int(limit)
        self.items = set()
        self.order = deque()
        self.lock = threading.Lock()

    def add(self, value):
        with self.lock:
            if value in self.items:
                return False
            self.items.add(value)
            self.order.append(value)
            while len(self.order) > self.limit:
                self.items.discard(self.order.popleft())
            return True

    def __len__(self):
        with self.lock:
            return len(self.items)

    def __contains__(self, value):
        with self.lock:
            return value in self.items


def append_unique_gossip(gossip_pool, raw, limit=MAX_GOSSIP_POOL_MESSAGES):
    """Add a gossip payload to the shared queue while keeping memory bounded."""

    return append_gossip(gossip_pool, raw, limit=limit, high_priority=False)


def append_gossip(gossip_pool, raw, limit=MAX_GOSSIP_POOL_MESSAGES, high_priority=False):
    """Add a gossip payload, optionally putting urgent evidence at the front."""

    try:
        if raw in gossip_pool:
            return False
        if high_priority:
            gossip_pool.insert(0, raw)
        else:
            gossip_pool.append(raw)
        overflow = len(gossip_pool) - int(limit)
        if overflow > 0:
            if high_priority:
                del gossip_pool[-overflow:]
            else:
                del gossip_pool[:overflow]
        return True
    except Exception as exc:
        logger.debug("could not append gossip payload: %s", exc)
        return False


def queue_store_result_gossip(gossip_pool, result):
    """Queue follow-up gossip emitted by local store ingestion."""

    if not isinstance(result, dict):
        return
    for gossip_message in result.get("gossip_messages", []):
        high_priority = gossip_message.get("type") in {
            ind_token.TRANSPARENCY_EQUIVOCATION_PROOF_TYPE,
            ind_token.TRANSPARENCY_OPERATOR_POLICY_VIOLATION_TYPE,
        }
        append_gossip(
            gossip_pool,
            ind_token.pack_wire_message(gossip_message),
            high_priority=high_priority,
        )
    proof = result.get("conflict_proof")
    if proof:
        append_gossip(gossip_pool, ind_token.pack_wire_message(proof), high_priority=True)


def gossip_rate_bucket(message_type):
    if message_type == ind_token.TRANSPARENCY_ROOT_ANNOUNCEMENT_TYPE:
        return "root_gossip", MAX_ROOT_GOSSIP_PER_PEER_WINDOW
    if message_type == ind_token.TRANSPARENCY_EQUIVOCATION_PROOF_TYPE:
        return "equivocation_gossip", MAX_EQUIVOCATION_GOSSIP_PER_PEER_WINDOW
    if message_type == ind_token.TRANSPARENCY_OPERATOR_POLICY_VIOLATION_TYPE:
        return "equivocation_gossip", MAX_EQUIVOCATION_GOSSIP_PER_PEER_WINDOW
    return "gossip", MAX_GOSSIP_PER_PEER_WINDOW


def request_rate_bucket(indicator):
    if indicator == "r":
        return "recipient_lookup", MAX_RECIPIENT_LOOKUPS_PER_PEER_WINDOW
    if indicator == "c":
        return "status_lookup", MAX_STATUS_REQUESTS_PER_PEER_WINDOW
    if indicator == "u":
        return "peer_discovery", MAX_PEER_DISCOVERY_REQUESTS_PER_PEER_WINDOW
    if indicator == "i":
        return "peer_announcement", MAX_PEER_ANNOUNCEMENTS_PER_PEER_WINDOW
    return "misc_request", MAX_MISC_REQUESTS_PER_PEER_WINDOW


def _transport_error_is_oversize(exc):
    return "too large" in str(exc).lower()


def _should_penalize_gossip_decode_error(exc):
    return not isinstance(exc, ind_token.WireSizeError)


def prepare_incoming_gossip(peer_ip, raw, seen, rate_limiter):
    """Cheaply cap decode attempts, then dedupe and type-limit incoming gossip.

    The caller marks ``message_hash`` as seen only after full store validation
    succeeds, so invalid payloads cannot poison the duplicate cache.
    """

    if not rate_limiter.allow(peer_ip, "gossip_decode", MAX_GOSSIP_DECODE_ATTEMPTS_PER_PEER_WINDOW):
        return {"accepted": False, "rate_limited": True}
    message = ind_token.unpack_wire_message(raw)
    mh = ind_token.message_hash(message)
    if mh in seen:
        return {"accepted": False, "duplicate": True, "message_hash": mh, "message": message}
    bucket, limit = gossip_rate_bucket(message.get("type"))
    if not rate_limiter.allow(peer_ip, bucket, limit):
        return {"accepted": False, "rate_limited": True, "message_hash": mh, "message": message}
    return {"accepted": True, "message_hash": mh, "message": message}


def handle_incoming_gossip(peer_ip, msg, seen_gossip, rate_limiter, store, gossip_pool, penalties):
    """Validate one incoming gossip payload and return its wire response text."""

    try:
        prepared = prepare_incoming_gossip(peer_ip, msg, seen_gossip, rate_limiter)
    except ind_token.ValidationError as exc:
        if _should_penalize_gossip_decode_error(exc):
            penalties.penalize(peer_ip)
        logger.warning("rejected malformed IND gossip from %s: %s", peer_ip, exc)
        return "invalid"
    if prepared.get("duplicate"):
        return "ok"
    if prepared.get("rate_limited"):
        return "rate_limited"
    try:
        result = store.ingest_message(prepared["message"], peer_id=peer_ip)
    except Exception as exc:
        penalties.penalize(peer_ip)
        logger.warning("rejected invalid IND gossip from %s: %s", peer_ip, exc)
        return "invalid"
    if result.get("accepted"):
        seen_gossip.add(prepared["message_hash"])
        if result.get("relay", True):
            high_priority = prepared["message"].get("type") in {
                ind_token.CONFLICT_PROOF_TYPE,
                ind_token.TRANSPARENCY_EQUIVOCATION_PROOF_TYPE,
                ind_token.TRANSPARENCY_OPERATOR_POLICY_VIOLATION_TYPE,
            }
            append_gossip(
                gossip_pool,
                ind_token.pack_wire_message(prepared["message"]),
                high_priority=high_priority,
            )
    queue_store_result_gossip(gossip_pool, result)
    if result.get("conflict_proof"):
        logger.warning("queued double-spend proof from %s", peer_ip)
    if result.get("accepted"):
        logger.info("accepted %s gossip from %s", prepared["message"].get("type", "message"), peer_ip)
    return "ok"


def _peer_files():
    sender_node.ensure_runtime_files()
    try:
        sender_node.maybe_refresh_dns_seed_peers()
    except Exception as exc:
        logger.debug("DNS seed refresh failed while listing peers: %s", exc)
    peers = []
    for folder in ("ip_folder/1", "ip_folder/2"):
        try:
            peers.extend(sender_node._peer_files(folder))
        except Exception as exc:
            logger.debug("could not read peer folder %s: %s", folder, exc)
    try:
        peers.extend(ind_settings.peer_ping_servers())
    except Exception as exc:
        logger.debug("could not read configured peer servers: %s", exc)
    return peers


def _status_lines_for_refs(refs):
    """Resolve wallet display ids or protocol bill ids into compact local confidence lines."""

    store = ind_token.INDLocalStore()
    store.finalize_pending(buffer_seconds=ind_settings.finality_buffer_seconds())
    lines = []
    for ref in refs:
        record = store.status_record_for_ref(ref)
        if not record:
            lines.extend([ref, "x", "invalid"])
            continue
        owner = record.get("owner_address") or "x"
        sequence = "" if record.get("sequence") is None else str(record["sequence"])
        lines.extend([record["display_id"], owner, sequence, record["status"]])
    return "\n".join(lines)


def _status_response_for_request(msg):
    refs = [line.strip() for line in msg.splitlines() if line.strip()]
    if len(refs) > MAX_STATUS_REFS_PER_REQUEST:
        return "too_many_refs"
    return _status_lines_for_refs(refs)


def new_ip(v):
    """Register this desktop node with peers as a reachability hint."""

    sender_node.ensure_runtime_files()
    public_ip = sender_node.public_ip()
    if not public_ip:
        return
    public_ip = _normalized_ip(public_ip)
    if not _valid_peer_address(public_ip):
        return

    ipnl = _peer_files()

    def announce():
        runtime_json.set_public_ip(public_ip)
        for _ in range(len(ipnl)):
            threading.Thread(target=sender_node.connect, args=("i", public_ip + "\n" + v, ipnl)).start()

    if runtime_json.get_public_ip() != public_ip:
        announce()


def node_protocol(rfb, rfb_response, gossip_pool, _unused_bill_pool):
    """Run the TCP gossip service that validates and relays IND protocol messages."""

    sender_node.ensure_runtime_files()
    new_ip("2")
    logger.info("node protocol initialized")
    store = ind_token.INDLocalStore()
    rate_limiter = PeerRateLimiter()
    penalties = PeerPenaltyBook()
    seen_gossip = BoundedSeenSet()
    active_connections = ActivePeerConnections()

    def handle_client(conn, addr):
        peer_ip = _normalized_ip(addr[0])
        try:
            # Penalties are checked before the Noise handshake to shed abusive peers cheaply.
            if not penalties.allow(peer_ip):
                record_server_close("invalid_peer_penalty", peer_ip, level=logging.WARNING)
                return
            conn.settimeout(NODE_REQUEST_TIMEOUT_SECONDS)
            try:
                first_packet = conn.recv(1024)
            except socket.timeout:
                record_server_close("timeout", peer_ip, "waiting for first packet", logging.WARNING)
                return
            if not first_packet:
                record_server_close("connection_closed", peer_ip, "empty first packet")
                return
            if not ind_transport.is_noise_hello(first_packet):
                record_server_close("bad_handshake", peer_ip, "missing INDN1 hello", logging.WARNING)
                return
            try:
                session = ind_transport.server_handshake(conn, first_packet)
            except socket.timeout:
                record_server_close("timeout", peer_ip, "during handshake", logging.WARNING)
                return
            except ind_transport.TransportError as exc:
                record_server_close("bad_handshake", peer_ip, str(exc), logging.WARNING)
                return

            def send_response(data):
                session.send_text(conn, data, ind_token.MAX_WIRE_DECOMPRESSED_BYTES)

            try:
                request = session.recv_text(conn, ind_token.MAX_WIRE_DECOMPRESSED_BYTES + 1)
            except socket.timeout:
                record_server_close("timeout", peer_ip, "waiting for encrypted request", logging.WARNING)
                return
            except ind_transport.TransportError as exc:
                if _transport_error_is_oversize(exc):
                    logger.warning("rejected oversized IND request from %s: %s", peer_ip, exc)
                    record_server_close("invalid", peer_ip, str(exc), logging.WARNING)
                    send_response("invalid")
                else:
                    record_server_close("connection_closed", peer_ip, str(exc))
                return
            indicator = request[:1]
            msg = request[1:]

            if indicator == "b":
                # Gossip payloads are deduped and rate-limited before touching local state.
                response = handle_incoming_gossip(
                    peer_ip,
                    msg,
                    seen_gossip,
                    rate_limiter,
                    store,
                    gossip_pool,
                    penalties,
                )
                if response == "rate_limited":
                    record_server_close("gossip_rate_limited", peer_ip, level=logging.WARNING)
                send_response(response)
                return

            else:
                # Non-gossip requests still share the per-peer limiter.
                bucket, limit = request_rate_bucket(indicator)
                if not rate_limiter.allow(peer_ip, bucket, limit):
                    record_server_close(
                        "request_rate_limited",
                        peer_ip,
                        bucket,
                        logging.WARNING,
                    )
                    send_response("rate_limited")
                    return

            if indicator == "r":
                store.finalize_pending(buffer_seconds=ind_settings.finality_buffer_seconds())
                messages = store.messages_for_recipient(msg, limit=100)
                send_response(json.dumps(messages))

            elif indicator == "c":
                send_response(_status_response_for_request(msg))

            elif indicator == "u":
                ip_txt = ""
                if msg == "main ip":
                    peers = sender_node._peer_files("ip_folder/1")
                    if peers:
                        ip_txt = sender_node._peer_ip(random.choice(peers))
                else:
                    peers = sender_node._peer_files("ip_folder/2")
                    for _ in range(8):
                        if peers:
                            ip_txt += sender_node._peer_ip(random.choice(peers)) + "\n"
                send_response(ip_txt)

            elif indicator == "i":
                lines = msg.splitlines()
                if (
                    len(lines) >= 2
                    and peer_ip == _normalized_ip(lines[0])
                    and _valid_peer_address(lines[0])
                    and lines[1] in ("1", "2")
                ):
                    version = lines[1]
                    sender_node.add_peer(_normalized_ip(lines[0]), version)
                send_response("ok")

            elif indicator == "x":
                send_response(peer_ip)

            elif indicator == "d":
                send_response("END")

            else:
                record_server_close("invalid", peer_ip, "unknown indicator", logging.WARNING)
                send_response("n")
        except socket.timeout:
            record_server_close("timeout", peer_ip, "handler timeout", logging.WARNING)
        except Exception as exc:
            logger.debug("peer handler failed for %s: %s", peer_ip, exc, exc_info=True)
        finally:
            try:
                conn.close()
            finally:
                active_connections.release(peer_ip)

    time.sleep(3)
    addr = ("", node_port())
    if socket.has_dualstack_ipv6():
        server = socket.create_server(addr, family=socket.AF_INET6, dualstack_ipv6=True)
    else:
        server = socket.create_server(addr)
    server.settimeout(None)
    server.listen(NODE_SOCKET_BACKLOG)
    logger.info("listening on TCP :%s", node_port())
    while True:
        try:
            conn1, addr1 = server.accept()
            peer_ip = _normalized_ip(addr1[0])
            if runtime_json.get_kill_node():
                record_server_close("shutdown", peer_ip)
                conn1.close()
                break
            if _is_loopback_peer(peer_ip):
                record_server_close("loopback_rejected", peer_ip)
                conn1.close()
            elif rate_limiter.allow(peer_ip, "connect", MAX_CONNECTIONS_PER_PEER_WINDOW):
                if active_connections.try_acquire(peer_ip):
                    threading.Thread(target=handle_client, args=(conn1, addr1), daemon=True).start()
                else:
                    record_server_close("active_connection_limit", peer_ip, level=logging.WARNING)
                    conn1.close()
            else:
                record_server_close("connection_limit", peer_ip, level=logging.WARNING)
                conn1.close()
        except OSError as exc:
            logger.warning("node accept loop error: %s", exc)
            time.sleep(0.2)


def database(_rfb, _rfb_response, gossip_pool):
    """Maintain local settlement and ingest gossip collected by the TCP service."""

    logger.info("local settlement worker started")
    store = ind_token.INDLocalStore()
    seen = BoundedSeenSet()
    for message in store.transparency_equivocation_messages(limit=100):
        append_gossip(gossip_pool, ind_token.pack_wire_message(message), high_priority=True)
    for message in store.transparency_operator_policy_violation_messages(limit=100):
        append_gossip(gossip_pool, ind_token.pack_wire_message(message), high_priority=True)
    for message in store.conflict_messages(limit=100):
        append_gossip(gossip_pool, ind_token.pack_wire_message(message), high_priority=True)
    while True:
        time.sleep(1)
        if runtime_json.get_kill_node():
            break
        try:
            store.finalize_pending(buffer_seconds=ind_settings.finality_buffer_seconds())
        except Exception as exc:
            logger.warning("local settlement finalization failed: %s", exc)
        for raw in list(gossip_pool):
            if not seen.add(raw):
                continue
            try:
                result = store.ingest_wire_message(raw)
                queue_store_result_gossip(gossip_pool, result)
            except Exception as exc:
                logger.debug("queued gossip was rejected locally: %s", exc)
        if len(gossip_pool) > MAX_GOSSIP_POOL_MESSAGES:
            del gossip_pool[:len(gossip_pool) - MAX_GOSSIP_POOL_MESSAGES]


def download_bills(_pos, _transaction_pool):
    """Compatibility stub for the old global bill database flow."""

    return


def maintain_connections(gossip_pool):
    """Rebroadcast queued gossip to sampled peers so messages continue spreading."""

    sender_node.ensure_runtime_files()
    logger.info("gossip rebroadcaster started")
    last_evidence_broadcast = {}
    evidence_types = {
        ind_token.CONFLICT_PROOF_TYPE,
        ind_token.TRANSPARENCY_EQUIVOCATION_PROOF_TYPE,
        ind_token.TRANSPARENCY_OPERATOR_POLICY_VIOLATION_TYPE,
    }

    def unpack_type(raw):
        try:
            message = ind_token.unpack_wire_message(raw)
            return message.get("type"), ind_token.message_hash(message)
        except ind_token.ValidationError:
            return "", ""

    while True:
        time.sleep(5)
        try:
            if runtime_json.get_kill_node():
                break
            if not gossip_pool:
                continue
            peers = _peer_files()
            if not peers:
                continue
            my_ip = runtime_json.get_public_ip()
            queued = list(gossip_pool)
            raw = queued[0]
            message_type, mh = unpack_type(raw)
            if message_type in evidence_types:
                now = int(time.time())
                if now - int(last_evidence_broadcast.get(mh, 0)) >= 300:
                    last_evidence_broadcast[mh] = now
                    for peer in peers:
                        ip_addr = sender_node._peer_ip(peer)
                        if ip_addr != my_ip:
                            sender_node.connect("b", raw, [peer])
                candidates = [item for item in queued[1:] if unpack_type(item)[0] not in evidence_types]
                if not candidates:
                    continue
                raw = random.choice(candidates)
            else:
                raw = random.choice(queued)
            peer = random.choice(peers)
            ip_addr = sender_node._peer_ip(peer)
            if ip_addr != my_ip:
                sender_node.connect("b", raw, [peer])
        except Exception as exc:
            logger.debug("gossip rebroadcast loop iteration failed: %s", exc, exc_info=True)


def main():
    """Run the IND gossip node service."""

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    port = node_port()
    print(f"IND {ind_settings.network_name()} gossip node is starting...", flush=True)
    print(f"Open/forward TCP port {port} on your router and firewall so peers can reach this node.", flush=True)
    with Manager() as manager:
        rf1 = manager.list()
        rf2 = manager.dict()
        gossip = manager.list()
        Process(target=database, args=(rf1, rf2, gossip)).start()
        Process(target=maintain_connections, args=(gossip,)).start()
        node_protocol(rf1, rf2, gossip, gossip)


if __name__ == "__main__":
    main()
