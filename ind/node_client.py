import json
import ipaddress
import logging
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
PEER_RATE_WINDOW_SECONDS = 60
MAX_CONNECTIONS_PER_PEER_WINDOW = 60
MAX_GOSSIP_PER_PEER_WINDOW = 30
MAX_ROOT_GOSSIP_PER_PEER_WINDOW = 30
MAX_EQUIVOCATION_GOSSIP_PER_PEER_WINDOW = 10
INVALID_SCORE_BAN_THRESHOLD = 5
INVALID_SCORE_DECAY_SECONDS = 600
MAX_PEER_TRACKING_ENTRIES = 5000
MAX_SEEN_GOSSIP_MESSAGES = 10000
MAX_GOSSIP_POOL_MESSAGES = 500
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


def _normalized_ip(value):
    return value.replace("::ffff:", "")


def _valid_ipv4(value):
    try:
        ip = ipaddress.ip_address(value)
        return (
            ip.version == 4
            and ip.is_global
            and not ip.is_loopback
            and not ip.is_private
            and not ip.is_multicast
            and not ip.is_reserved
            and not ip.is_unspecified
            and not ip.is_link_local
        )
    except Exception:
        return False


class PeerRateLimiter:
    """Small in-memory rate limiter for per-peer connection and gossip buckets."""

    def __init__(self, window_seconds=PEER_RATE_WINDOW_SECONDS, max_entries=MAX_PEER_TRACKING_ENTRIES):
        self.window_seconds = int(window_seconds)
        self.max_entries = int(max_entries)
        self.events = {}

    def _trim(self):
        overflow = len(self.events) - self.max_entries
        if overflow <= 0:
            return
        oldest = sorted(self.events.items(), key=lambda item: item[1][-1] if item[1] else 0)[:overflow]
        for key, _timestamps in oldest:
            self.events.pop(key, None)

    def allow(self, peer, bucket, limit, now=None):
        now = int(now or time.time())
        key = (peer, bucket)
        cutoff = now - self.window_seconds
        timestamps = [item for item in self.events.get(key, []) if item > cutoff]
        if len(timestamps) >= int(limit):
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

    def _trim(self):
        overflow = len(self.scores) - self.max_entries
        if overflow <= 0:
            return
        oldest = sorted(self.scores.items(), key=lambda item: item[1][1])[:overflow]
        for peer, _score in oldest:
            self.scores.pop(peer, None)

    def _current(self, peer, now=None):
        now = int(now or time.time())
        score, updated_at = self.scores.get(peer, (0, now))
        if now - updated_at >= self.decay_seconds:
            return 0, now
        return score, updated_at

    def penalize(self, peer, amount=1, now=None):
        now = int(now or time.time())
        score, _updated_at = self._current(peer, now)
        score += int(amount)
        self.scores[peer] = (score, now)
        self._trim()
        return score

    def allow(self, peer, now=None):
        score, updated_at = self._current(peer, now)
        self.scores[peer] = (score, updated_at)
        self._trim()
        return score < self.threshold


class BoundedSeenSet:
    """Bounded dedupe set for recently processed gossip messages."""

    def __init__(self, limit=MAX_SEEN_GOSSIP_MESSAGES):
        self.limit = int(limit)
        self.items = set()
        self.order = deque()

    def add(self, value):
        if value in self.items:
            return False
        self.items.add(value)
        self.order.append(value)
        while len(self.order) > self.limit:
            self.items.discard(self.order.popleft())
        return True

    def __len__(self):
        return len(self.items)

    def __contains__(self, value):
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
    except Exception:
        return False


def gossip_rate_bucket(message_type):
    if message_type == ind_token.TRANSPARENCY_ROOT_ANNOUNCEMENT_TYPE:
        return "root_gossip", MAX_ROOT_GOSSIP_PER_PEER_WINDOW
    if message_type == ind_token.TRANSPARENCY_EQUIVOCATION_PROOF_TYPE:
        return "equivocation_gossip", MAX_EQUIVOCATION_GOSSIP_PER_PEER_WINDOW
    return "gossip", MAX_GOSSIP_PER_PEER_WINDOW


def prepare_incoming_gossip(peer_ip, raw, seen, rate_limiter):
    """Decode, dedupe, then rate-limit incoming gossip in that order."""

    message = ind_token.unpack_wire_message(raw)
    mh = ind_token.message_hash(message)
    if mh in seen:
        return {"accepted": False, "duplicate": True, "message_hash": mh, "message": message}
    bucket, limit = gossip_rate_bucket(message.get("type"))
    if not rate_limiter.allow(peer_ip, bucket, limit):
        return {"accepted": False, "rate_limited": True, "message_hash": mh, "message": message}
    seen.add(mh)
    return {"accepted": True, "message_hash": mh, "message": message}


def _peer_files():
    sender_node.ensure_runtime_files()
    peers = []
    for folder in ("ip_folder/1", "ip_folder/2"):
        try:
            peers.extend(sender_node._peer_files(folder))
        except Exception:
            pass
    try:
        peers.extend(ind_settings.peer_ping_servers())
    except Exception:
        pass
    return peers


def _status_lines_for_refs(refs):
    """Resolve wallet display ids or token ids into compact local confidence lines."""

    store = ind_token.INDLocalStore()
    store.finalize_pending(buffer_seconds=ind_settings.finality_buffer_seconds())
    lines = []
    for ref in refs:
        token = store.get_token(ref) or store.get_token_by_display_id(ref)
        if not token:
            lines.extend([ref, "x", "invalid"])
            continue
        try:
            state = ind_token.verify_token(token)
            confidence = store.token_confidence(state.token_id, expected_owner=state.owner_address, min_settled_seconds=0)
            status = confidence["level"]
            lines.extend([state.display_id, state.owner_address, str(state.sequence), status])
        except Exception:
            lines.extend([ref, "x", "invalid"])
    return "\n".join(lines)


def new_ip(v):
    """Register this desktop node with peers as a reachability hint."""

    sender_node.ensure_runtime_files()
    public_ip = sender_node.public_ip()
    if not public_ip:
        return
    if not _valid_ipv4(public_ip):
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
    store = ind_token.INDLocalStore()
    rate_limiter = PeerRateLimiter()
    penalties = PeerPenaltyBook()
    seen_gossip = BoundedSeenSet()

    def handle_client(conn, addr):
        peer_ip = _normalized_ip(addr[0])
        try:
            if not penalties.allow(peer_ip):
                conn.close()
                return
            conn.settimeout(30)
            first_packet = conn.recv(1024)
            if not ind_transport.is_noise_hello(first_packet):
                conn.close()
                return
            session = ind_transport.server_handshake(conn, first_packet)
            request = session.recv_text(conn, ind_token.MAX_WIRE_DECOMPRESSED_BYTES + 1)
            indicator = request[:1]
            msg = request[1:]

            def send_response(data):
                session.send_text(conn, data, ind_token.MAX_WIRE_DECOMPRESSED_BYTES)

            if indicator == "b":
                try:
                    prepared = prepare_incoming_gossip(peer_ip, msg, seen_gossip, rate_limiter)
                except Exception:
                    penalties.penalize(peer_ip)
                    logger.warning("rejected malformed IND gossip from %s", peer_ip)
                    send_response("invalid")
                    conn.close()
                    return
                if prepared.get("duplicate"):
                    send_response("ok")
                    conn.close()
                    return
                if prepared.get("rate_limited"):
                    send_response("rate_limited")
                    conn.close()
                    return
                try:
                    result = store.ingest_message(prepared["message"], peer_id=peer_ip)
                except Exception:
                    penalties.penalize(peer_ip)
                    logger.warning("rejected invalid IND gossip from %s", peer_ip)
                    send_response("invalid")
                    conn.close()
                    return
                if result.get("accepted"):
                    high_priority = prepared["message"].get("type") == ind_token.TRANSPARENCY_EQUIVOCATION_PROOF_TYPE
                    append_gossip(
                        gossip_pool,
                        ind_token.pack_wire_message(prepared["message"]),
                        high_priority=high_priority,
                    )
                for gossip_message in result.get("gossip_messages", []):
                    high_priority = gossip_message.get("type") == ind_token.TRANSPARENCY_EQUIVOCATION_PROOF_TYPE
                    append_gossip(gossip_pool, ind_token.pack_wire_message(gossip_message), high_priority=high_priority)
                proof = result.get("conflict_proof")
                if proof:
                    proof_raw = ind_token.pack_wire_message(proof)
                    append_unique_gossip(gossip_pool, proof_raw)
                send_response("ok")

            elif indicator == "r":
                store.finalize_pending(buffer_seconds=ind_settings.finality_buffer_seconds())
                messages = store.messages_for_recipient(msg, limit=100)
                send_response(json.dumps(messages))

            elif indicator == "c":
                refs = [line.strip() for line in msg.splitlines() if line.strip()]
                send_response(_status_lines_for_refs(refs))

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
                    and peer_ip == lines[0]
                    and _valid_ipv4(lines[0])
                    and lines[1] in ("1", "2")
                ):
                    version = lines[1]
                    sender_node.add_peer(lines[0], version)
                send_response("ok")

            elif indicator == "x":
                send_response(peer_ip)

            elif indicator == "d":
                send_response("END")

            else:
                send_response("n")
            conn.close()
        except Exception:
            conn.close()

    time.sleep(3)
    addr = ("", PORT)
    if socket.has_dualstack_ipv6():
        server = socket.create_server(addr, family=socket.AF_INET6, dualstack_ipv6=True)
    else:
        server = socket.create_server(addr)
    server.settimeout(None)
    server.listen()
    connections = []
    while True:
        try:
            conn1, addr1 = server.accept()
            peer_ip = _normalized_ip(addr1[0])
            if runtime_json.get_kill_node():
                conn1.close()
                break
            if peer_ip in ("127.0.0.1", "::1"):
                conn1.close()
            elif rate_limiter.allow(peer_ip, "connect", MAX_CONNECTIONS_PER_PEER_WINDOW):
                threading.Thread(target=handle_client, args=(conn1, addr1)).start()
            else:
                conn1.close()
        except Exception:
            pass


def database(_rfb, _rfb_response, gossip_pool):
    """Maintain local settlement and ingest gossip collected by the TCP service."""

    store = ind_token.INDLocalStore()
    seen = BoundedSeenSet()
    for message in store.transparency_equivocation_messages(limit=100):
        append_gossip(gossip_pool, ind_token.pack_wire_message(message), high_priority=True)
    while True:
        time.sleep(1)
        if runtime_json.get_kill_node():
            break
        try:
            store.finalize_pending(buffer_seconds=ind_settings.finality_buffer_seconds())
        except Exception:
            pass
        for raw in list(gossip_pool):
            if not seen.add(raw):
                continue
            try:
                store.ingest_wire_message(raw)
            except Exception:
                pass
        if len(gossip_pool) > MAX_GOSSIP_POOL_MESSAGES:
            del gossip_pool[:len(gossip_pool) - MAX_GOSSIP_POOL_MESSAGES]


def download_bills(_pos, _transaction_pool):
    """Compatibility stub for the old global bill database flow."""

    return


def maintain_connections(gossip_pool):
    """Rebroadcast queued gossip to sampled peers so messages continue spreading."""

    sender_node.ensure_runtime_files()
    last_evidence_broadcast = {}
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
            try:
                message = ind_token.unpack_wire_message(raw)
            except Exception:
                message = {}
            if message.get("type") == ind_token.TRANSPARENCY_EQUIVOCATION_PROOF_TYPE:
                mh = ind_token.message_hash(message)
                now = int(time.time())
                if now - int(last_evidence_broadcast.get(mh, 0)) >= 300:
                    last_evidence_broadcast[mh] = now
                    for peer in peers:
                        ip_addr = sender_node._peer_ip(peer)
                        if ip_addr != my_ip:
                            sender_node.connect("b", raw, [peer])
                continue
            peer = random.choice(peers)
            ip_addr = sender_node._peer_ip(peer)
            if ip_addr != my_ip:
                sender_node.connect("b", raw, [peer])
        except Exception:
            pass


def main():
    """Run the IND gossip node service."""

    print("IND gossip node is starting...")
    print("Open/forward TCP port 8888 on your router and firewall so peers can reach this node.")
    with Manager() as manager:
        rf1 = manager.list()
        rf2 = manager.dict()
        gossip = manager.list()
        Process(target=database, args=(rf1, rf2, gossip)).start()
        Process(target=maintain_connections, args=(gossip,)).start()
        node_protocol(rf1, rf2, gossip, gossip)


if __name__ == "__main__":
    main()
