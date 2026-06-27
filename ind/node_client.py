# TCP gossip node service for IND peer discovery, message relay, and settlement.

import ipaddress
import json
import logging
import os
import queue
import random
import socket
import threading
import time
from collections import deque
from dataclasses import dataclass
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


def _env_float(name, default, minimum=None, maximum=None):
    try:
        result = float(os.environ.get(name, default))
    except (TypeError, ValueError):
        result = float(default)
    if minimum is not None:
        result = max(float(minimum), result)
    if maximum is not None:
        result = min(float(maximum), result)
    return result


def _env_enabled(name):
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _runtime_kill_requested():
    if _env_enabled("IND_IGNORE_RUNTIME_KILL_FLAG"):
        return False
    return runtime_json.get_kill_node()


NODE_CAPACITY_PROFILES = {"desktop", "operator"}


def _runtime_operator_enabled():
    try:
        return runtime_json.read_node_operator_enabled() == "YES"
    except Exception:
        return False


def _settings_operator_role():
    try:
        return ind_settings.security_role() == "operator"
    except Exception:
        return False


def resolve_node_capacity_profile(profile=None):
    requested = str(profile or os.environ.get("IND_NODE_CAPACITY_PROFILE", "auto")).strip().lower()
    if requested in NODE_CAPACITY_PROFILES:
        return requested
    if _settings_operator_role() or _runtime_operator_enabled():
        return "operator"
    return "desktop"


def _profile_default(profile, desktop, operator):
    return operator if resolve_node_capacity_profile(profile) == "operator" else desktop


NODE_CAPACITY_PROFILE = resolve_node_capacity_profile()
NODE_RATE_WINDOW_SECONDS = _env_int("IND_NODE_RATE_WINDOW_SECONDS", 60, minimum=1, maximum=3600)
NODE_GOSSIP_RATE_PER_IP = _env_float(
    "IND_NODE_GOSSIP_RATE_PER_IP",
    _profile_default(NODE_CAPACITY_PROFILE, 50, 500),
    minimum=1,
)
NODE_GOSSIP_BURST_PER_IP = _env_int(
    "IND_NODE_GOSSIP_BURST_PER_IP",
    _profile_default(NODE_CAPACITY_PROFILE, 1000, 25000),
    minimum=1,
)
NODE_GOSSIP_RATE_PER_SUBNET = _env_float(
    "IND_NODE_GOSSIP_RATE_PER_SUBNET",
    _profile_default(NODE_CAPACITY_PROFILE, 200, 2000),
    minimum=1,
)
NODE_GOSSIP_BURST_PER_SUBNET = _env_int(
    "IND_NODE_GOSSIP_BURST_PER_SUBNET",
    _profile_default(NODE_CAPACITY_PROFILE, 4000, 50000),
    minimum=1,
)
NODE_GOSSIP_RATE_GLOBAL = _env_float(
    "IND_NODE_GOSSIP_RATE_GLOBAL",
    _profile_default(NODE_CAPACITY_PROFILE, 500, 5000),
    minimum=1,
)
NODE_GOSSIP_BURST_GLOBAL = _env_int(
    "IND_NODE_GOSSIP_BURST_GLOBAL",
    _profile_default(NODE_CAPACITY_PROFILE, 5000, 50000),
    minimum=1,
)
NODE_CRITICAL_RATE_PER_IP = _env_float(
    "IND_NODE_CRITICAL_RATE_PER_IP",
    _profile_default(NODE_CAPACITY_PROFILE, 10, 100),
    minimum=1,
)
NODE_CRITICAL_BURST_PER_IP = _env_int(
    "IND_NODE_CRITICAL_BURST_PER_IP",
    _profile_default(NODE_CAPACITY_PROFILE, 200, 5000),
    minimum=1,
)
NODE_CRITICAL_RATE_GLOBAL = _env_float(
    "IND_NODE_CRITICAL_RATE_GLOBAL",
    _profile_default(NODE_CAPACITY_PROFILE, 100, 1000),
    minimum=1,
)
NODE_CRITICAL_BURST_GLOBAL = _env_int(
    "IND_NODE_CRITICAL_BURST_GLOBAL",
    _profile_default(NODE_CAPACITY_PROFILE, 1000, 10000),
    minimum=1,
)
NODE_CONTROL_RATE_PER_IP = _env_float(
    "IND_NODE_CONTROL_RATE_PER_IP",
    _profile_default(NODE_CAPACITY_PROFILE, 50, 250),
    minimum=1,
)
NODE_CONTROL_BURST_PER_IP = _env_int(
    "IND_NODE_CONTROL_BURST_PER_IP",
    _profile_default(NODE_CAPACITY_PROFILE, 500, 5000),
    minimum=1,
)
NODE_CONTROL_RATE_GLOBAL = _env_float(
    "IND_NODE_CONTROL_RATE_GLOBAL",
    _profile_default(NODE_CAPACITY_PROFILE, 500, 2500),
    minimum=1,
)
NODE_CONTROL_BURST_GLOBAL = _env_int(
    "IND_NODE_CONTROL_BURST_GLOBAL",
    _profile_default(NODE_CAPACITY_PROFILE, 5000, 25000),
    minimum=1,
)
NODE_INVALID_RATE_PER_IP = _env_float("IND_NODE_INVALID_RATE_PER_IP", 10, minimum=1)
NODE_INVALID_BURST_PER_IP = _env_int("IND_NODE_INVALID_BURST_PER_IP", 100, minimum=1)
NODE_INVALID_RATE_GLOBAL = _env_float("IND_NODE_INVALID_RATE_GLOBAL", 100, minimum=1)
NODE_INVALID_BURST_GLOBAL = _env_int("IND_NODE_INVALID_BURST_GLOBAL", 1000, minimum=1)
NODE_GOSSIP_QUEUE_MAX = _env_int(
    "IND_NODE_GOSSIP_QUEUE_MAX",
    _profile_default(NODE_CAPACITY_PROFILE, 10000, 250000),
    minimum=1,
)
NODE_CRITICAL_QUEUE_MAX = _env_int(
    "IND_NODE_CRITICAL_QUEUE_MAX",
    _profile_default(NODE_CAPACITY_PROFILE, 1000, 25000),
    minimum=1,
)
NODE_GOSSIP_WORKERS = _env_int(
    "IND_NODE_GOSSIP_WORKERS",
    _profile_default(NODE_CAPACITY_PROFILE, 16, 64),
    minimum=1,
)
NODE_GOSSIP_BATCH_MAX_MESSAGES = _env_int(
    "IND_NODE_GOSSIP_BATCH_MAX_MESSAGES",
    _profile_default(NODE_CAPACITY_PROFILE, 64, 512),
    minimum=1,
)
NODE_GOSSIP_BATCH_MAX_BYTES = _env_int(
    "IND_NODE_GOSSIP_BATCH_MAX_BYTES",
    _profile_default(NODE_CAPACITY_PROFILE, 1024 * 1024, 4 * 1024 * 1024),
    minimum=1024,
)
NODE_REBROADCAST_INTERVAL_SECONDS = _env_float(
    "IND_NODE_REBROADCAST_INTERVAL_SECONDS",
    _profile_default(NODE_CAPACITY_PROFILE, 2.0, 0.5),
    minimum=0.1,
)
NODE_REBROADCAST_BATCH_MAX_MESSAGES = _env_int(
    "IND_NODE_REBROADCAST_BATCH_MAX_MESSAGES",
    _profile_default(NODE_CAPACITY_PROFILE, 32, 256),
    minimum=1,
)
NODE_REBROADCAST_FANOUT = _env_int(
    "IND_NODE_REBROADCAST_FANOUT",
    _profile_default(NODE_CAPACITY_PROFILE, 3, 8),
    minimum=1,
)
NODE_CRITICAL_REBROADCAST_FANOUT = _env_int(
    "IND_NODE_CRITICAL_REBROADCAST_FANOUT",
    _profile_default(NODE_CAPACITY_PROFILE, 8, 24),
    minimum=1,
)
MAX_CONNECTIONS_PER_PEER_WINDOW = _env_int("IND_NODE_MAX_CONNECTIONS_PER_IP_WINDOW", 480, minimum=1)
MAX_ACTIVE_CONNECTIONS = _env_int(
    "IND_NODE_MAX_ACTIVE_CONNECTIONS",
    _profile_default(NODE_CAPACITY_PROFILE, 128, 512),
    minimum=1,
)
MAX_ACTIVE_CONNECTIONS_PER_PEER = _env_int(
    "IND_NODE_MAX_ACTIVE_CONNECTIONS_PER_IP",
    _profile_default(NODE_CAPACITY_PROFILE, 24, 128),
    minimum=1,
)
NODE_REQUEST_TIMEOUT_SECONDS = _env_int(
    "IND_NODE_REQUEST_TIMEOUT_SECONDS", 10, minimum=1, maximum=120
)
NODE_SETTLEMENT_QUERY_TIMEOUT_SECONDS = _env_int(
    "IND_NODE_SETTLEMENT_QUERY_TIMEOUT_SECONDS", 8, minimum=1, maximum=60
)
NODE_SETTLEMENT_QUERY_BUDGET_SECONDS = _env_int(
    "IND_NODE_SETTLEMENT_QUERY_BUDGET_SECONDS", 12, minimum=1, maximum=120
)
NODE_SOCKET_BACKLOG = _env_int("IND_NODE_SOCKET_BACKLOG", 128, minimum=1)
MAX_STATUS_REFS_PER_REQUEST = _env_int("IND_NODE_MAX_STATUS_REFS_PER_REQUEST", 200, minimum=1)
MAX_SETTLEMENT_MESSAGES_PER_RESPONSE = _env_int(
    "IND_NODE_MAX_SETTLEMENT_MESSAGES_PER_RESPONSE", 100, minimum=1, maximum=500
)
INVALID_SCORE_BAN_THRESHOLD = 5
INVALID_SCORE_DECAY_SECONDS = 600
MAX_PEER_TRACKING_ENTRIES = 5000
MAX_SEEN_GOSSIP_MESSAGES = 10000
MAX_GOSSIP_POOL_MESSAGES = _env_int(
    "IND_NODE_MAX_GOSSIP_POOL_MESSAGES",
    _profile_default(NODE_CAPACITY_PROFILE, 5000, 50000),
    minimum=100,
)
TRANSIENT_GOSSIP_RETRY_ATTEMPTS = _env_int(
    "IND_NODE_TRANSIENT_GOSSIP_RETRY_ATTEMPTS", 12, minimum=1, maximum=100
)
TRANSIENT_GOSSIP_RETRY_SECONDS = _env_float(
    "IND_NODE_TRANSIENT_GOSSIP_RETRY_SECONDS", 5, minimum=0.1, maximum=60
)
PEER_RATE_WINDOW_SECONDS = NODE_RATE_WINDOW_SECONDS
MAX_GOSSIP_DECODE_ATTEMPTS_PER_PEER_WINDOW = NODE_INVALID_BURST_PER_IP
MAX_GOSSIP_PER_PEER_WINDOW = NODE_GOSSIP_BURST_PER_IP
MAX_ROOT_GOSSIP_PER_PEER_WINDOW = NODE_GOSSIP_BURST_PER_IP
MAX_EQUIVOCATION_GOSSIP_PER_PEER_WINDOW = NODE_CRITICAL_BURST_PER_IP
MAX_RECIPIENT_LOOKUPS_PER_PEER_WINDOW = NODE_CONTROL_BURST_PER_IP
MAX_STATUS_REQUESTS_PER_PEER_WINDOW = NODE_CONTROL_BURST_PER_IP
MAX_SETTLEMENT_REQUESTS_PER_PEER_WINDOW = NODE_CONTROL_BURST_PER_IP
MAX_PEER_DISCOVERY_REQUESTS_PER_PEER_WINDOW = NODE_CONTROL_BURST_PER_IP
MAX_PEER_ANNOUNCEMENTS_PER_PEER_WINDOW = NODE_CONTROL_BURST_PER_IP
MAX_MISC_REQUESTS_PER_PEER_WINDOW = NODE_CONTROL_BURST_PER_IP
ASYNC_GOSSIP_INGEST_WORKERS = NODE_GOSSIP_WORKERS
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# Thread-safe counters for why the node closed peer connections.
class ServerCloseCounters:
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


def _subnet_key(value):
    try:
        addr = ipaddress.ip_address(_normalized_ip(value))
    except ValueError:
        return str(value or "")
    prefix = 24 if addr.version == 4 else 48
    return str(ipaddress.ip_network(f"{addr}/{prefix}", strict=False))


def _lane_limit_config(profile=None):
    profile = resolve_node_capacity_profile(profile)
    evidence_subnet_rate = _env_float(
        "IND_NODE_EVIDENCE_RATE_PER_SUBNET",
        _profile_default(profile, 20, 200),
        minimum=1,
    )
    evidence_subnet_burst = _env_int(
        "IND_NODE_EVIDENCE_BURST_PER_SUBNET",
        _profile_default(profile, 200, 2000),
        minimum=1,
    )
    critical_subnet_rate = _env_float(
        "IND_NODE_CRITICAL_RATE_PER_SUBNET",
        _profile_default(profile, 40, 400),
        minimum=1,
    )
    critical_subnet_burst = _env_int(
        "IND_NODE_CRITICAL_BURST_PER_SUBNET",
        _profile_default(profile, 800, 10000),
        minimum=1,
    )
    control_subnet_rate = _env_float(
        "IND_NODE_CONTROL_RATE_PER_SUBNET",
        _profile_default(profile, 200, 1000),
        minimum=1,
    )
    control_subnet_burst = _env_int(
        "IND_NODE_CONTROL_BURST_PER_SUBNET",
        _profile_default(profile, 2000, 10000),
        minimum=1,
    )
    invalid_subnet_rate = _env_float("IND_NODE_INVALID_RATE_PER_SUBNET", 40, minimum=1)
    invalid_subnet_burst = _env_int("IND_NODE_INVALID_BURST_PER_SUBNET", 400, minimum=1)
    return {
        "gossip": {
            "global": (
                _env_float(
                    "IND_NODE_GOSSIP_RATE_GLOBAL",
                    _profile_default(profile, 500, 5000),
                    minimum=1,
                ),
                _env_int(
                    "IND_NODE_GOSSIP_BURST_GLOBAL",
                    _profile_default(profile, 5000, 50000),
                    minimum=1,
                ),
            ),
            "subnet": (
                _env_float(
                    "IND_NODE_GOSSIP_RATE_PER_SUBNET",
                    _profile_default(profile, 200, 2000),
                    minimum=1,
                ),
                _env_int(
                    "IND_NODE_GOSSIP_BURST_PER_SUBNET",
                    _profile_default(profile, 4000, 50000),
                    minimum=1,
                ),
            ),
            "ip": (
                _env_float(
                    "IND_NODE_GOSSIP_RATE_PER_IP",
                    _profile_default(profile, 50, 500),
                    minimum=1,
                ),
                _env_int(
                    "IND_NODE_GOSSIP_BURST_PER_IP",
                    _profile_default(profile, 1000, 25000),
                    minimum=1,
                ),
            ),
        },
        "evidence": {
            "global": (
                _env_float(
                    "IND_NODE_EVIDENCE_RATE_GLOBAL",
                    _profile_default(profile, 50, 500),
                    minimum=1,
                ),
                _env_int(
                    "IND_NODE_EVIDENCE_BURST_GLOBAL",
                    _profile_default(profile, 500, 5000),
                    minimum=1,
                ),
            ),
            "subnet": (evidence_subnet_rate, evidence_subnet_burst),
            "ip": (
                _env_float(
                    "IND_NODE_EVIDENCE_RATE_PER_IP",
                    _profile_default(profile, 5, 50),
                    minimum=1,
                ),
                _env_int(
                    "IND_NODE_EVIDENCE_BURST_PER_IP",
                    _profile_default(profile, 50, 500),
                    minimum=1,
                ),
            ),
        },
        "critical": {
            "global": (
                _env_float(
                    "IND_NODE_CRITICAL_RATE_GLOBAL",
                    _profile_default(profile, 100, 1000),
                    minimum=1,
                ),
                _env_int(
                    "IND_NODE_CRITICAL_BURST_GLOBAL",
                    _profile_default(profile, 1000, 10000),
                    minimum=1,
                ),
            ),
            "subnet": (critical_subnet_rate, critical_subnet_burst),
            "ip": (
                _env_float(
                    "IND_NODE_CRITICAL_RATE_PER_IP",
                    _profile_default(profile, 10, 100),
                    minimum=1,
                ),
                _env_int(
                    "IND_NODE_CRITICAL_BURST_PER_IP",
                    _profile_default(profile, 200, 5000),
                    minimum=1,
                ),
            ),
        },
        "control": {
            "global": (
                _env_float(
                    "IND_NODE_CONTROL_RATE_GLOBAL",
                    _profile_default(profile, 500, 2500),
                    minimum=1,
                ),
                _env_int(
                    "IND_NODE_CONTROL_BURST_GLOBAL",
                    _profile_default(profile, 5000, 25000),
                    minimum=1,
                ),
            ),
            "subnet": (control_subnet_rate, control_subnet_burst),
            "ip": (
                _env_float(
                    "IND_NODE_CONTROL_RATE_PER_IP",
                    _profile_default(profile, 50, 250),
                    minimum=1,
                ),
                _env_int(
                    "IND_NODE_CONTROL_BURST_PER_IP",
                    _profile_default(profile, 500, 5000),
                    minimum=1,
                ),
            ),
        },
        "invalid": {
            "global": (
                _env_float("IND_NODE_INVALID_RATE_GLOBAL", 100, minimum=1),
                _env_int("IND_NODE_INVALID_BURST_GLOBAL", 1000, minimum=1),
            ),
            "subnet": (invalid_subnet_rate, invalid_subnet_burst),
            "ip": (
                _env_float("IND_NODE_INVALID_RATE_PER_IP", 10, minimum=1),
                _env_int("IND_NODE_INVALID_BURST_PER_IP", 100, minimum=1),
            ),
        },
    }


@dataclass
class RateLimitDecision:
    allowed: bool
    retry_after_seconds: float = 0.0


class TokenBucket:
    def __init__(self, rate, burst, now):
        self.rate = max(0.001, float(rate))
        self.burst = max(1.0, float(burst))
        self.tokens = self.burst
        self.updated_at = float(now)

    def refill(self, now):
        now = float(now)
        elapsed = max(0.0, now - self.updated_at)
        if elapsed:
            self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
            self.updated_at = now

    def retry_after(self, cost):
        missing = max(0.0, float(cost) - self.tokens)
        if missing <= 0:
            return 0.0
        return missing / self.rate

    def consume(self, cost):
        self.tokens = max(0.0, self.tokens - float(cost))


# In-memory token bucket limiter for global, subnet, and peer-IP fairness.
class PeerRateLimiter:
    def __init__(
        self,
        window_seconds=PEER_RATE_WINDOW_SECONDS,
        max_entries=MAX_PEER_TRACKING_ENTRIES,
        *,
        profile=None,
        now_func=None,
        limits=None,
    ):
        self.window_seconds = int(window_seconds)
        self.max_entries = int(max_entries)
        self.profile = resolve_node_capacity_profile(profile)
        self.now_func = now_func or time.monotonic
        self.limits = limits or _lane_limit_config(self.profile)
        self.buckets = {}
        self.lock = threading.Lock()

    def _now(self, now=None):
        return float(self.now_func() if now is None else now)

    def _trim(self):
        overflow = len(self.buckets) - self.max_entries
        if overflow <= 0:
            return
        oldest = sorted(self.buckets.items(), key=lambda item: item[1].updated_at)[:overflow]
        for key, _bucket in oldest:
            self.buckets.pop(key, None)

    def _bucket_for(self, key, rate, burst, now):
        bucket = self.buckets.get(key)
        if bucket is None:
            bucket = TokenBucket(rate, burst, now)
            self.buckets[key] = bucket
        bucket.refill(now)
        return bucket

    def _keys_for(self, peer, lane):
        peer = _normalized_ip(peer)
        return (
            ("global", lane, "*"),
            ("subnet", lane, _subnet_key(peer)),
            ("ip", lane, peer),
        )

    def _lane_for_bucket(self, bucket):
        if bucket in {"gossip", "root_gossip"}:
            return "gossip"
        if bucket in {"evidence", "evidence_verification"}:
            return "evidence"
        if bucket in {"equivocation_gossip", "critical"}:
            return "critical"
        if bucket in {"gossip_decode_error", "invalid"}:
            return "invalid"
        return "control"

    def check(self, peer, lane, cost=1, now=None):
        lane = self._lane_for_bucket(lane)
        cost = max(1.0, float(cost))
        now = self._now(now)
        with self.lock:
            buckets = []
            retry_after = 0.0
            for scope, lane_name, key in self._keys_for(peer, lane):
                rate, burst = self.limits[lane_name][scope]
                bucket = self._bucket_for((scope, lane_name, key), rate, burst, now)
                buckets.append(bucket)
                retry_after = max(retry_after, bucket.retry_after(cost))
            if retry_after > 0:
                self._trim()
                return RateLimitDecision(False, max(0.1, retry_after))
            for bucket in buckets:
                bucket.consume(cost)
            self._trim()
            return RateLimitDecision(True, 0.0)

    def allow_lane(self, peer, lane, cost=1, now=None):
        return self.check(peer, lane, cost=cost, now=now)

    def allow(self, peer, bucket, limit=None, now=None):
        return self.check(peer, self._lane_for_bucket(bucket), now=now).allowed


# Tracks peers that repeatedly send malformed gossip and cools scores over time.
class PeerPenaltyBook:
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


# Caps concurrent handler threads globally and per peer IP.
class ActivePeerConnections:
    def __init__(
        self, max_total=MAX_ACTIVE_CONNECTIONS, max_per_peer=MAX_ACTIVE_CONNECTIONS_PER_PEER
    ):
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


# Bounded dedupe set for recently processed gossip messages.
class BoundedSeenSet:
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

    def discard(self, value):
        with self.lock:
            self.items.discard(value)


_ASYNC_GOSSIP_INGEST_SLOTS = threading.BoundedSemaphore(ASYNC_GOSSIP_INGEST_WORKERS)


# Add a gossip payload to the shared queue while keeping memory bounded.
def append_unique_gossip(gossip_pool, raw, limit=MAX_GOSSIP_POOL_MESSAGES):
    return append_gossip(gossip_pool, raw, limit=limit, high_priority=False)


# Add a gossip payload, optionally putting urgent evidence at the front.
def append_gossip(gossip_pool, raw, limit=MAX_GOSSIP_POOL_MESSAGES, high_priority=False):
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


# Queue follow-up gossip emitted by local store ingestion.
def queue_store_result_gossip(gossip_pool, result):
    from . import protocol_v3

    if not isinstance(result, dict):
        return
    for gossip_message in result.get("gossip_messages", []):
        high_priority = gossip_message.get("type") in {
            protocol_v3.CONFLICT_PROOF_TYPE,
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


GOSSIP_BATCH_TYPE = "ind.gossip_batch.v1"
GOSSIP_BATCH_RESPONSE_TYPE = "ind.gossip_batch_response.v1"


def _rate_limited_response(retry_after_seconds=1.0):
    return "rate_limited:" + str(max(1, int(round(float(retry_after_seconds or 1)))))


def _gossip_lane(message_type):
    return "critical" if _high_priority_gossip_type(message_type) else "gossip"


def gossip_rate_bucket(message_type):
    lane = _gossip_lane(message_type)
    if lane == "critical":
        return "critical", MAX_EQUIVOCATION_GOSSIP_PER_PEER_WINDOW
    return "gossip", MAX_GOSSIP_PER_PEER_WINDOW


def gossip_allowed_during_invalid_penalty(message_type):
    return message_type in {
        ind_token.CONFLICT_PROOF_TYPE,
        ind_token.TRANSPARENCY_EQUIVOCATION_PROOF_TYPE,
        ind_token.TRANSPARENCY_OPERATOR_POLICY_VIOLATION_TYPE,
    }


def request_rate_bucket(indicator):
    if indicator in {"r", "R"}:
        return "recipient_lookup", MAX_RECIPIENT_LOOKUPS_PER_PEER_WINDOW
    if indicator == "c":
        return "status_lookup", MAX_STATUS_REQUESTS_PER_PEER_WINDOW
    if indicator == "s":
        return "settlement_lookup", MAX_SETTLEMENT_REQUESTS_PER_PEER_WINDOW
    if indicator == "u":
        return "peer_discovery", MAX_PEER_DISCOVERY_REQUESTS_PER_PEER_WINDOW
    if indicator == "i":
        return "peer_announcement", MAX_PEER_ANNOUNCEMENTS_PER_PEER_WINDOW
    return "misc_request", MAX_MISC_REQUESTS_PER_PEER_WINDOW


def _transport_error_is_oversize(exc):
    return "too large" in str(exc).lower()


def _should_penalize_gossip_decode_error(exc):
    return not isinstance(exc, ind_token.WireSizeError)


def _transient_ingest_error(exc):
    text = str(exc).lower()
    transient_markers = (
        "not enough usable transparency root mirrors",
        "not enough usable current transparency root mirrors",
        "no mirrored transparency root close enough",
        "mirror is lagging",
        "mirror has no historical root",
        "static http mirror has no historical root",
        "current transparency root does not contain v3 transfer",
        "current transparency root does not contain v3 checkpoint",
        "mirror has no signed roots",
        "consistency check cannot reach",
    )
    return any(marker in text for marker in transient_markers)


def _should_penalize_ingest_error(exc):
    text = str(exc).lower()
    if _transient_ingest_error(exc):
        return False
    return "unsupported gossip message type" not in text


def _retry_after_for_transient_ingest():
    return max(1.0, float(TRANSIENT_GOSSIP_RETRY_SECONDS))


def _prevalidate_v3_gossip_envelope(message):
    from . import protocol_v3

    message_type = message.get("type") if isinstance(message, dict) else None
    if message_type == protocol_v3.CONFLICT_PROOF_TYPE:
        return {"evidence_key": _cheap_prevalidate_v3_conflict_proof(message)}
    if message_type in {
        ind_token.TRANSPARENCY_ROOT_ANNOUNCEMENT_TYPE,
        ind_token.TRANSPARENCY_EQUIVOCATION_PROOF_TYPE,
        ind_token.TRANSPARENCY_OPERATOR_POLICY_VIOLATION_TYPE,
    }:
        return {}
    protocol_v3.validate_gossip_envelope_shape(message)
    return {}


def _cheap_require_int(value, label, minimum=None):
    if type(value) is not int:
        raise ind_token.ValidationError(f"{label} must be an integer")
    if minimum is not None and value < int(minimum):
        raise ind_token.ValidationError(f"{label} is below the allowed range")
    return value


def _cheap_require_hex32(value, label):
    if not isinstance(value, str) or len(value) != 64:
        raise ind_token.ValidationError(f"invalid {label}")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise ind_token.ValidationError(f"invalid {label}") from exc
    return value.lower()


def _cheap_prevalidate_v3_conflict_proof(message):
    from . import protocol_v3

    if not isinstance(message, dict) or set(message) != set(protocol_v3.CONFLICT_PROOF_FIELDS):
        raise ind_token.ValidationError("malformed ConflictProofV3")
    if message["type"] != protocol_v3.CONFLICT_PROOF_TYPE:
        raise ind_token.ValidationError("not a ConflictProofV3")
    if _cheap_require_int(message["version"], "ConflictProofV3 version") != protocol_v3.VERSION:
        raise ind_token.ValidationError("unsupported ConflictProofV3 version")
    network_id = _cheap_require_int(
        message["network_id"], "ConflictProofV3 network id", minimum=0
    )
    _cheap_require_hex32(message["token_id"], "ConflictProofV3 token id")
    _cheap_require_hex32(message["previous_hash"], "ConflictProofV3 previous hash")
    _cheap_require_int(message["sequence"], "ConflictProofV3 sequence", minimum=1)
    _cheap_require_hex32(message["spend_key"], "ConflictProofV3 spend key")
    _cheap_require_hex32(message["transfer_hash_a"], "ConflictProofV3 transfer hash a")
    _cheap_require_hex32(message["transfer_hash_b"], "ConflictProofV3 transfer hash b")
    _cheap_require_int(message["detected_at"], "ConflictProofV3 detected_at", minimum=0)
    _cheap_require_hex32(message["proof_hash"], "ConflictProofV3 proof hash")

    transfer_a = message["transfer_a"]
    transfer_b = message["transfer_b"]
    try:
        protocol_v3._validate_transfer_shape(transfer_a, network_id)
        protocol_v3._validate_transfer_shape(transfer_b, network_id)
    except Exception as exc:
        raise ind_token.ValidationError(str(exc)) from exc

    for transfer in (transfer_a, transfer_b):
        if transfer["token_id"] != message["token_id"]:
            raise ind_token.ValidationError(
                "ConflictProofV3 transfers reference different bills"
            )
        if transfer["previous_hash"] != message["previous_hash"]:
            raise ind_token.ValidationError(
                "ConflictProofV3 transfers do not share a previous hash"
            )
        if int(transfer["sequence"]) != int(message["sequence"]):
            raise ind_token.ValidationError("ConflictProofV3 transfers do not share a sequence")
        if transfer["sender_address"] != message["sender_address"]:
            raise ind_token.ValidationError("ConflictProofV3 transfers do not share a sender")

    spend_key = protocol_v3.spend_key_for_transfer(transfer_a)
    if spend_key != protocol_v3.spend_key_for_transfer(transfer_b):
        raise ind_token.ValidationError("ConflictProofV3 transfers do not share a spend key")
    if spend_key != message["spend_key"]:
        raise ind_token.ValidationError("ConflictProofV3 spend key mismatch")

    hash_a = protocol_v3.transfer_hash(transfer_a)
    hash_b = protocol_v3.transfer_hash(transfer_b)
    if hash_a == hash_b:
        raise ind_token.ValidationError("ConflictProofV3 requires two different transfers")
    expected_hash_a, expected_hash_b = sorted((hash_a, hash_b))
    if (
        message["transfer_hash_a"] != expected_hash_a
        or message["transfer_hash_b"] != expected_hash_b
    ):
        raise ind_token.ValidationError("ConflictProofV3 transfer hash mismatch")

    try:
        key = protocol_v3.conflict_proof_key(message)
    except Exception as exc:
        raise ind_token.ValidationError(str(exc)) from exc
    return "conflict_v3:" + key


def prepare_incoming_gossip(peer_ip, raw, seen, rate_limiter):
    """Decode, dedupe, and type-limit incoming gossip.

    The caller marks ``message_hash`` as seen only after full store validation
    succeeds, so invalid payloads cannot poison the duplicate cache.
    """

    message = ind_token.unpack_wire_message(raw)
    if not isinstance(message, dict):
        raise ind_token.ValidationError("malformed gossip message")
    prevalidation = _prevalidate_v3_gossip_envelope(message)
    evidence_key = prevalidation.get("evidence_key") if isinstance(prevalidation, dict) else None
    mh = ind_token.message_hash(message)
    if mh in seen or (evidence_key and evidence_key in seen):
        return {"accepted": False, "duplicate": True, "message_hash": mh, "message": message}
    if evidence_key:
        decision = rate_limiter.allow_lane(peer_ip, "evidence")
        if not decision.allowed:
            return {
                "accepted": False,
                "rate_limited": True,
                "retry_after_seconds": decision.retry_after_seconds,
                "message_hash": mh,
                "message": message,
                "lane": "critical",
                "evidence_key": evidence_key,
            }
        from . import protocol_v3

        protocol_v3.verify_conflict_proof(
            message,
            expected_network_id=message["network_id"],
        )
        return {
            "accepted": True,
            "message_hash": mh,
            "message": message,
            "lane": "critical",
            "evidence_key": evidence_key,
        }
    lane, _limit = gossip_rate_bucket(message.get("type"))
    decision = rate_limiter.allow_lane(peer_ip, lane)
    if not decision.allowed:
        return {
            "accepted": False,
            "rate_limited": True,
            "retry_after_seconds": decision.retry_after_seconds,
            "message_hash": mh,
            "message": message,
            "lane": lane,
        }
    return {"accepted": True, "message_hash": mh, "message": message, "lane": lane}


def _high_priority_gossip_type(message_type):
    from . import protocol_v3

    return message_type in {
        protocol_v3.CONFLICT_PROOF_TYPE,
        ind_token.CONFLICT_PROOF_TYPE,
        ind_token.TRANSPARENCY_EQUIVOCATION_PROOF_TYPE,
        ind_token.TRANSPARENCY_OPERATOR_POLICY_VIOLATION_TYPE,
    }


def _gossip_type_can_ack_before_ingest(message_type):
    return message_type == getattr(
        ind_token,
        "TRANSFER_ANNOUNCEMENT_V3_TYPE",
        "ind.transfer_announcement.v3",
    )


def _gossip_type_requires_sync_ingest(message_type):
    from . import protocol_v3

    return message_type == protocol_v3.CONFLICT_PROOF_TYPE


def _prepared_seen_keys(prepared):
    keys = [prepared.get("message_hash")]
    evidence_key = prepared.get("evidence_key")
    if evidence_key:
        keys.append(evidence_key)
    return [key for key in keys if key]


def _ingest_prepared_gossip(
    peer_ip,
    prepared,
    seen_gossip,
    store,
    gossip_pool,
    penalties,
    *,
    keep_seen_on_retry=False,
):
    message = prepared["message"]
    message_hash = prepared["message_hash"]
    seen_keys = _prepared_seen_keys(prepared)
    try:
        result = store.ingest_message(message, peer_id=peer_ip)
    except Exception as exc:
        if _transient_ingest_error(exc):
            if keep_seen_on_retry:
                for key in seen_keys:
                    seen_gossip.add(key)
            else:
                for key in seen_keys:
                    seen_gossip.discard(key)
            logger.warning("deferred IND gossip from %s: %s", peer_ip, exc)
            return {
                "status": "retryable",
                "message_hash": message_hash,
                "retry_after_seconds": _retry_after_for_transient_ingest(),
                "error": str(exc),
            }
        if _should_penalize_ingest_error(exc):
            penalties.penalize(peer_ip)
        for key in seen_keys:
            seen_gossip.discard(key)
        logger.warning("rejected invalid IND gossip from %s: %s", peer_ip, exc)
        return {"status": "rejected", "message_hash": message_hash, "error": str(exc)}
    if result.get("accepted"):
        for key in seen_keys:
            seen_gossip.add(key)
        if result.get("relay", True):
            append_gossip(
                gossip_pool,
                ind_token.pack_wire_message(message),
                high_priority=_high_priority_gossip_type(message.get("type")),
            )
    else:
        for key in seen_keys:
            seen_gossip.discard(key)
    queue_store_result_gossip(gossip_pool, result)
    if result.get("conflict_proof"):
        logger.warning("queued double-spend proof from %s", peer_ip)
    if result.get("accepted"):
        logger.info("accepted %s gossip from %s", message.get("type", "message"), peer_ip)
        return {"status": "accepted", "message_hash": message_hash}
    return {"status": "rejected", "message_hash": message_hash}


def _ingest_prepared_gossip_with_transient_retry(
    peer_ip,
    prepared,
    seen_gossip,
    store,
    gossip_pool,
    penalties,
):
    attempts = max(1, int(TRANSIENT_GOSSIP_RETRY_ATTEMPTS))
    retry_delay = max(0.1, float(TRANSIENT_GOSSIP_RETRY_SECONDS))
    result = {"status": "rejected", "message_hash": prepared.get("message_hash", "")}
    for attempt in range(1, attempts + 1):
        result = _ingest_prepared_gossip(
            peer_ip,
            prepared,
            seen_gossip,
            store,
            gossip_pool,
            penalties,
            keep_seen_on_retry=attempt < attempts,
        )
        if result.get("status") != "retryable":
            return result
        if attempt < attempts:
            time.sleep(retry_delay)
    for key in _prepared_seen_keys(prepared):
        seen_gossip.discard(key)
    logger.warning(
        "dropped deferred IND gossip from %s after %s transient verification attempts",
        peer_ip,
        attempts,
    )
    return result


def _queue_async_gossip_ingest(peer_ip, prepared, seen_gossip, store, gossip_pool, penalties):
    if not _ASYNC_GOSSIP_INGEST_SLOTS.acquire(blocking=False):
        return False
    for key in _prepared_seen_keys(prepared):
        seen_gossip.add(key)

    def ingest():
        try:
            _ingest_prepared_gossip_with_transient_retry(
                peer_ip,
                prepared,
                seen_gossip,
                store,
                gossip_pool,
                penalties,
            )
        finally:
            _ASYNC_GOSSIP_INGEST_SLOTS.release()

    threading.Thread(target=ingest, daemon=True).start()
    return True


class GossipIngestQueue:
    def __init__(
        self,
        store,
        gossip_pool,
        seen_gossip,
        penalties,
        *,
        workers=NODE_GOSSIP_WORKERS,
        gossip_max=NODE_GOSSIP_QUEUE_MAX,
        critical_max=NODE_CRITICAL_QUEUE_MAX,
    ):
        self.store = store
        self.gossip_pool = gossip_pool
        self.seen_gossip = seen_gossip
        self.penalties = penalties
        self.queues = {
            "critical": queue.Queue(maxsize=max(1, int(critical_max))),
            "gossip": queue.Queue(maxsize=max(1, int(gossip_max))),
        }
        self.workers = []
        for index in range(max(0, int(workers))):
            worker = threading.Thread(
                target=self._worker,
                name=f"ind-gossip-ingest-{index}",
                daemon=True,
            )
            worker.start()
            self.workers.append(worker)

    def _queue_for_lane(self, lane):
        return self.queues["critical" if lane == "critical" else "gossip"]

    def enqueue(self, peer_ip, prepared):
        lane = prepared.get("lane") or _gossip_lane(prepared["message"].get("type"))
        target_queue = self._queue_for_lane(lane)
        try:
            for key in _prepared_seen_keys(prepared):
                self.seen_gossip.add(key)
            target_queue.put_nowait((peer_ip, prepared))
            return RateLimitDecision(True, 0.0)
        except queue.Full:
            for key in _prepared_seen_keys(prepared):
                self.seen_gossip.discard(key)
            maxsize = max(1, int(target_queue.maxsize))
            retry_after = max(1.0, min(30.0, 1.0 + (target_queue.qsize() / maxsize) * 10.0))
            return RateLimitDecision(False, retry_after)

    def _next_item(self):
        try:
            return self.queues["critical"].get_nowait(), "critical"
        except queue.Empty:
            item = self.queues["gossip"].get(timeout=0.5)
            return item, "gossip"

    def _worker(self):
        while True:
            try:
                (peer_ip, prepared), lane = self._next_item()
            except queue.Empty:
                continue
            try:
                _ingest_prepared_gossip_with_transient_retry(
                    peer_ip,
                    prepared,
                    self.seen_gossip,
                    self.store,
                    self.gossip_pool,
                    self.penalties,
                )
            finally:
                self.queues[lane].task_done()


def _incoming_gossip_result(
    peer_ip,
    msg,
    seen_gossip,
    rate_limiter,
    store,
    gossip_pool,
    penalties,
    *,
    async_transfer_ingest=True,
    ingest_queue=None,
):
    try:
        prepared = prepare_incoming_gossip(peer_ip, msg, seen_gossip, rate_limiter)
    except ind_token.ValidationError as exc:
        if _should_penalize_gossip_decode_error(exc):
            penalties.penalize(peer_ip)
        decision = rate_limiter.allow_lane(peer_ip, "invalid")
        if not decision.allowed:
            return {"status": "rate_limited", "retry_after_seconds": decision.retry_after_seconds}
        logger.warning("rejected malformed IND gossip from %s: %s", peer_ip, exc)
        return {"status": "rejected", "error": str(exc)}
    if prepared.get("duplicate"):
        return {"status": "duplicate", "message_hash": prepared.get("message_hash", "")}
    if prepared.get("rate_limited"):
        return {
            "status": "rate_limited",
            "message_hash": prepared.get("message_hash", ""),
            "retry_after_seconds": prepared.get("retry_after_seconds", 1),
        }
    if not penalties.allow(peer_ip) and not gossip_allowed_during_invalid_penalty(
        prepared["message"].get("type")
    ):
        return {"status": "rate_limited", "retry_after_seconds": 1}
    if _gossip_type_requires_sync_ingest(prepared["message"].get("type")):
        ingest_result = _ingest_prepared_gossip(
            peer_ip,
            prepared,
            seen_gossip,
            store,
            gossip_pool,
            penalties,
        )
        if ingest_result.get("status") == "retryable":
            return {
                "status": "rate_limited",
                "message_hash": prepared.get("message_hash", ""),
                "retry_after_seconds": ingest_result.get("retry_after_seconds", 1),
                "error": ingest_result.get("error", ""),
            }
        if ingest_result.get("status") != "accepted":
            return {"status": "rejected", "message_hash": prepared.get("message_hash", "")}
        return {"status": "accepted", "message_hash": prepared.get("message_hash", "")}
    if ingest_queue is not None:
        decision = ingest_queue.enqueue(peer_ip, prepared)
        if not decision.allowed:
            return {
                "status": "rate_limited",
                "message_hash": prepared.get("message_hash", ""),
                "retry_after_seconds": decision.retry_after_seconds,
            }
        return {"status": "queued", "message_hash": prepared.get("message_hash", "")}
    if async_transfer_ingest and _gossip_type_can_ack_before_ingest(
        prepared["message"].get("type")
    ):
        if not _queue_async_gossip_ingest(
            peer_ip,
            prepared,
            seen_gossip,
            store,
            gossip_pool,
            penalties,
        ):
            return {"status": "rate_limited", "retry_after_seconds": 1}
        return {"status": "queued", "message_hash": prepared.get("message_hash", "")}
    ingest_result = _ingest_prepared_gossip(
        peer_ip,
        prepared,
        seen_gossip,
        store,
        gossip_pool,
        penalties,
    )
    if ingest_result.get("status") == "retryable":
        return {
            "status": "rate_limited",
            "message_hash": prepared.get("message_hash", ""),
            "retry_after_seconds": ingest_result.get("retry_after_seconds", 1),
            "error": ingest_result.get("error", ""),
        }
    if ingest_result.get("status") != "accepted":
        return {"status": "rejected", "message_hash": prepared.get("message_hash", "")}
    return {"status": "accepted", "message_hash": prepared.get("message_hash", "")}


def _wire_response_from_gossip_result(result):
    status = result.get("status")
    if status in {"accepted", "queued", "duplicate"}:
        return "ok"
    if status == "rate_limited":
        return _rate_limited_response(result.get("retry_after_seconds", 1))
    return "invalid"


# Validate or queue one incoming gossip payload and return its wire response text.
def handle_incoming_gossip(
    peer_ip,
    msg,
    seen_gossip,
    rate_limiter,
    store,
    gossip_pool,
    penalties,
    *,
    async_transfer_ingest=True,
    ingest_queue=None,
):
    return _wire_response_from_gossip_result(
        _incoming_gossip_result(
            peer_ip,
            msg,
            seen_gossip,
            rate_limiter,
            store,
            gossip_pool,
            penalties,
            async_transfer_ingest=async_transfer_ingest,
            ingest_queue=ingest_queue,
        )
    )


def _load_gossip_batch(msg):
    try:
        payload = json.loads(msg)
    except json.JSONDecodeError as exc:
        raise ind_token.ValidationError("malformed gossip batch") from exc
    if not isinstance(payload, dict) or payload.get("type") != GOSSIP_BATCH_TYPE:
        raise ind_token.ValidationError("malformed gossip batch")
    messages = payload.get("messages")
    if not isinstance(messages, list):
        raise ind_token.ValidationError("malformed gossip batch messages")
    if len(messages) > NODE_GOSSIP_BATCH_MAX_MESSAGES:
        raise ind_token.ValidationError("gossip batch has too many messages")
    total_bytes = 0
    normalized = []
    for item in messages:
        if not isinstance(item, str):
            raise ind_token.ValidationError("malformed gossip batch item")
        total_bytes += len(item.encode("utf-8"))
        if total_bytes > NODE_GOSSIP_BATCH_MAX_BYTES:
            raise ind_token.ValidationError("gossip batch is too large")
        normalized.append(item)
    return normalized


def handle_incoming_gossip_batch(
    peer_ip,
    msg,
    seen_gossip,
    rate_limiter,
    store,
    gossip_pool,
    penalties,
    *,
    ingest_queue=None,
):
    try:
        messages = _load_gossip_batch(msg)
    except ind_token.ValidationError as exc:
        penalties.penalize(peer_ip)
        return json.dumps(
            {
                "type": GOSSIP_BATCH_RESPONSE_TYPE,
                "status": "invalid",
                "accepted": 0,
                "duplicate": 0,
                "rejected": 1,
                "rate_limited": 0,
                "retry_after_seconds": 0,
                "results": [{"index": 0, "status": "rejected", "error": str(exc)}],
            },
            sort_keys=True,
        )

    results = []
    counts = {"accepted": 0, "duplicate": 0, "rejected": 0, "rate_limited": 0}
    retry_after = 0.0
    for index, raw in enumerate(messages):
        result = _incoming_gossip_result(
            peer_ip,
            raw,
            seen_gossip,
            rate_limiter,
            store,
            gossip_pool,
            penalties,
            ingest_queue=ingest_queue,
        )
        status = result.get("status", "rejected")
        if status in {"accepted", "queued"}:
            counts["accepted"] += 1
        elif status == "duplicate":
            counts["duplicate"] += 1
        elif status == "rate_limited":
            counts["rate_limited"] += 1
            retry_after = max(retry_after, float(result.get("retry_after_seconds") or 0))
        else:
            counts["rejected"] += 1
        item = {"index": index, "status": status}
        if result.get("message_hash"):
            item["message_hash"] = result["message_hash"]
        if status == "rate_limited":
            item["retry_after_seconds"] = max(1, int(round(result.get("retry_after_seconds") or 1)))
        if result.get("error"):
            item["error"] = result["error"]
        results.append(item)

    if counts["rate_limited"] and not (counts["accepted"] or counts["duplicate"]):
        status = "rate_limited"
    elif counts["rejected"] or counts["rate_limited"]:
        status = "partial"
    else:
        status = "ok"
    return json.dumps(
        {
            "type": GOSSIP_BATCH_RESPONSE_TYPE,
            "status": status,
            "accepted": counts["accepted"],
            "duplicate": counts["duplicate"],
            "rejected": counts["rejected"],
            "rate_limited": counts["rate_limited"],
            "retry_after_seconds": max(0, int(round(retry_after))),
            "results": results,
        },
        sort_keys=True,
    )


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


# Return configured durable peers that participate in V3 settlement finality.
def _settlement_peers():
    try:
        return [peer for peer in ind_settings.settlement_peers() if peer]
    except Exception as exc:
        logger.warning("could not read settlement peer configuration: %s", exc)
        return []


def _settlement_enabled():
    try:
        return ind_settings.settlement_quorum_enabled()
    except Exception:
        return False


def _settlement_message_high_priority(raw):
    try:
        message = ind_token.unpack_wire_message(raw)
    except Exception:
        return False
    message_type = message.get("type") if isinstance(message, dict) else ""
    try:
        from . import protocol_v3

        conflict_type = protocol_v3.CONFLICT_PROOF_TYPE
    except Exception:
        conflict_type = ""
    return message_type in {
        conflict_type,
        ind_token.CONFLICT_PROOF_TYPE,
        ind_token.TRANSPARENCY_EQUIVOCATION_PROOF_TYPE,
        ind_token.TRANSPARENCY_OPERATOR_POLICY_VIOLATION_TYPE,
    }


def _settlement_response_for_request(store, msg):
    try:
        query = json.loads(msg or "{}")
        response = store.peer_settlement_response_v3(
            query,
            limit=MAX_SETTLEMENT_MESSAGES_PER_RESPONSE,
        )
    except Exception as exc:
        logger.warning("rejected malformed V3 settlement query: %s", exc)
        response = {
            "type": "ind.peer_settlement_response.v3",
            "version": 1,
            "status": "invalid",
            "error": str(exc),
            "messages": [],
        }
    return json.dumps(response, sort_keys=True, separators=(",", ":"))


def _query_settlement_peer(peer, query):
    payload = json.dumps(query, sort_keys=True, separators=(",", ":"))
    result = sender_node.connect_result(
        "s",
        payload,
        [peer],
        timeout=NODE_SETTLEMENT_QUERY_TIMEOUT_SECONDS,
        max_duration_seconds=NODE_SETTLEMENT_QUERY_BUDGET_SECONDS,
    )
    if not result.ok:
        return {
            "ok": False,
            "peer": peer,
            "status": result.status,
            "error": result.error or result.response,
        }
    try:
        response = json.loads(result.response)
    except json.JSONDecodeError as exc:
        return {
            "ok": False,
            "peer": peer,
            "status": "invalid_json",
            "error": str(exc),
        }
    if response.get("type") != "ind.peer_settlement_response.v3":
        return {
            "ok": False,
            "peer": peer,
            "status": "invalid_response",
            "error": "unexpected settlement response type",
        }
    return {"ok": True, "peer": peer, "status": "ok", "response": response}


def _ingest_settlement_response_messages(store, gossip_pool, response, peer):
    ingested = 0
    for raw in list(response.get("messages") or [])[:MAX_SETTLEMENT_MESSAGES_PER_RESPONSE]:
        try:
            result = store.ingest_wire_message(raw, peer_id=peer)
            if gossip_pool is not None:
                queue_store_result_gossip(gossip_pool, result)
            if result.get("accepted") and gossip_pool is not None:
                append_gossip(
                    gossip_pool,
                    raw,
                    high_priority=_settlement_message_high_priority(raw),
                )
            if result.get("accepted"):
                ingested += 1
        except Exception as exc:
            logger.debug("peer settlement evidence from %s was rejected: %s", peer, exc)
    return ingested


def _local_conflict_status(store, token_id):
    record = store.status_record_for_ref(token_id)
    return bool(record and record.get("status") == "conflict")


def _reconcile_v3_settlement_candidate(store, candidate, gossip_pool=None):
    if not _settlement_enabled():
        return {"decision": "settle", "reason": "settlement quorum disabled"}
    peers = _settlement_peers()
    min_confirmations = max(0, int(ind_settings.settlement_min_remote_confirmations()))
    require_all = bool(ind_settings.settlement_require_all_configured_peers())
    query = candidate.get("query") or {}
    token_id = str(query.get("token_id") or candidate.get("token_id") or "")
    if min_confirmations > 0 and not peers:
        return {"decision": "await", "reason": "no settlement peers configured"}

    confirmations = 0
    failures = []
    divergent = []
    for peer in peers:
        peer_result = _query_settlement_peer(peer, query)
        if not peer_result.get("ok"):
            failures.append(peer_result)
            continue
        response = peer_result["response"]
        if str(response.get("token_id") or "") != token_id:
            failures.append(
                {
                    "peer": peer,
                    "status": "wrong_token",
                    "error": "settlement response token mismatch",
                }
            )
            continue
        _ingest_settlement_response_messages(store, gossip_pool, response, peer)
        if response.get("conflict") or _local_conflict_status(store, token_id):
            return {"decision": "conflict", "reason": "peer reported or proved conflict"}
        if response.get("matches_query"):
            confirmations += 1
            continue
        if response.get("local_transfer_hash"):
            divergent.append(
                {
                    "peer": peer,
                    "local_transfer_hash": response.get("local_transfer_hash"),
                    "status": response.get("status"),
                }
            )
        else:
            failures.append(
                {
                    "peer": peer,
                    "status": response.get("status", "unknown"),
                    "error": "peer does not have matching settlement state",
                }
            )

    if _local_conflict_status(store, token_id):
        return {"decision": "conflict", "reason": "local conflict proof stored"}
    if divergent:
        return {"decision": "await", "reason": "peer has divergent spend", "peers": divergent}
    if require_all and confirmations < len(peers):
        return {
            "decision": "await",
            "reason": "awaiting all configured settlement peers",
            "confirmations": confirmations,
            "failures": failures,
        }
    if confirmations >= min_confirmations:
        return {
            "decision": "settle",
            "reason": "peer settlement quorum reached",
            "confirmations": confirmations,
        }
    return {
        "decision": "await",
        "reason": "awaiting settlement peer quorum",
        "confirmations": confirmations,
        "failures": failures,
    }


def _finalize_pending_for_node(store, gossip_pool=None):
    require_log_proof = bool(getattr(store, "require_transparency", False))
    if not _settlement_enabled():
        return store.finalize_pending(
            buffer_seconds=ind_settings.finality_buffer_seconds(),
            require_v3_log_proof=require_log_proof,
        )
    return store.finalize_pending(
        buffer_seconds=ind_settings.finality_buffer_seconds(),
        settlement_reconciler=lambda candidate: _reconcile_v3_settlement_candidate(
            store,
            candidate,
            gossip_pool=gossip_pool,
        ),
        require_v3_log_proof=require_log_proof,
    )


# Resolve wallet display ids or protocol bill ids into compact local confidence lines.
def _status_lines_for_refs(refs, store=None, gossip_pool=None):
    store = store or ind_token.INDLocalStore()
    # Public status must stay read-only; background workers advance settlement/finality.
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


def _status_response_for_request(msg, store=None, gossip_pool=None):
    refs = [line.strip() for line in msg.splitlines() if line.strip()]
    if len(refs) > MAX_STATUS_REFS_PER_REQUEST:
        return "too_many_refs"
    return _status_lines_for_refs(refs, store=store, gossip_pool=gossip_pool)


# Register this desktop node with peers as a reachability hint.
def new_ip(v):
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
            threading.Thread(
                target=sender_node.connect, args=("i", public_ip + "\n" + v, ipnl)
            ).start()

    if runtime_json.get_public_ip() != public_ip:
        announce()


# Run the TCP gossip service that validates and relays IND protocol messages.
def node_protocol(rfb, rfb_response, gossip_pool, _unused_bill_pool):
    sender_node.ensure_runtime_files()
    new_ip("2")
    logger.info("node protocol initialized")
    store = ind_token.INDLocalStore()
    rate_limiter = PeerRateLimiter()
    penalties = PeerPenaltyBook()
    seen_gossip = BoundedSeenSet()
    ingest_queue = GossipIngestQueue(store, gossip_pool, seen_gossip, penalties)
    active_connections = ActivePeerConnections()
    logger.info(
        "node capacity profile=%s gossip_workers=%s gossip_queue=%s critical_queue=%s",
        rate_limiter.profile,
        NODE_GOSSIP_WORKERS,
        NODE_GOSSIP_QUEUE_MAX,
        NODE_CRITICAL_QUEUE_MAX,
    )

    def handle_client(conn, addr):
        peer_ip = _normalized_ip(addr[0])
        try:
            conn.settimeout(NODE_REQUEST_TIMEOUT_SECONDS)
            try:
                first_packet = conn.recv(1024)
            except TimeoutError:
                record_server_close("timeout", peer_ip, "waiting for first packet", logging.WARNING)
                return
            if not first_packet:
                record_server_close("connection_closed", peer_ip, "empty first packet")
                return
            if not ind_transport.is_noise_hello(first_packet):
                if not penalties.allow(peer_ip):
                    record_server_close("invalid_peer_penalty", peer_ip, level=logging.WARNING)
                    return
                record_server_close(
                    "bad_handshake", peer_ip, "missing INDN1 hello", logging.WARNING
                )
                return
            try:
                session = ind_transport.server_handshake(conn, first_packet)
            except TimeoutError:
                record_server_close("timeout", peer_ip, "during handshake", logging.WARNING)
                return
            except ind_transport.TransportError as exc:
                record_server_close("bad_handshake", peer_ip, str(exc), logging.WARNING)
                return

            def send_response(data):
                session.send_text(conn, data, ind_token.MAX_WIRE_DECOMPRESSED_BYTES)

            try:
                request = session.recv_text(conn, ind_token.MAX_WIRE_DECOMPRESSED_BYTES + 1)
            except TimeoutError:
                record_server_close(
                    "timeout", peer_ip, "waiting for encrypted request", logging.WARNING
                )
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
                    ingest_queue=ingest_queue,
                )
                if response.startswith("rate_limited"):
                    record_server_close("gossip_rate_limited", peer_ip, level=logging.WARNING)
                send_response(response)
                return

            elif indicator == "B":
                response = handle_incoming_gossip_batch(
                    peer_ip,
                    msg,
                    seen_gossip,
                    rate_limiter,
                    store,
                    gossip_pool,
                    penalties,
                    ingest_queue=ingest_queue,
                )
                try:
                    response_status = json.loads(response).get("status")
                except Exception:
                    response_status = ""
                if response_status == "rate_limited":
                    record_server_close("gossip_rate_limited", peer_ip, level=logging.WARNING)
                send_response(response)
                return

            else:
                # Non-gossip requests still share the per-peer limiter.
                bucket, _limit = request_rate_bucket(indicator)
                decision = rate_limiter.allow_lane(peer_ip, "control")
                if not decision.allowed:
                    record_server_close(
                        "request_rate_limited",
                        peer_ip,
                        bucket,
                        logging.WARNING,
                    )
                    send_response(_rate_limited_response(decision.retry_after_seconds))
                    return

            if indicator == "r":
                _finalize_pending_for_node(store, gossip_pool=gossip_pool)
                response = store.wallet_bill_sync_response({"address": msg, "limit": 100})
                send_response(json.dumps(response))

            elif indicator == "R":
                _finalize_pending_for_node(store, gossip_pool=gossip_pool)
                try:
                    request_payload = json.loads(msg)
                    if not isinstance(request_payload, dict):
                        raise ValueError("delta request must be a JSON object")
                    address = str(request_payload.get("address") or "").strip()
                    if not address:
                        raise ValueError("delta request is missing address")
                    response = store.wallet_bill_sync_response(
                        request_payload,
                        limit=min(100, max(1, int(request_payload.get("limit") or 100))),
                    )
                except Exception as exc:
                    logger.debug("invalid wallet delta request from %s: %s", peer_ip, exc)
                    send_response("n")
                    return
                send_response(json.dumps(response))

            elif indicator == "c":
                send_response(_status_response_for_request(msg, store=store, gossip_pool=gossip_pool))

            elif indicator == "s":
                send_response(_settlement_response_for_request(store, msg))

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
        except TimeoutError:
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
            if _runtime_kill_requested():
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


# Maintain local settlement and ingest gossip collected by the TCP service.
def database(_rfb, _rfb_response, gossip_pool):
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
        if _runtime_kill_requested():
            break
        try:
            _finalize_pending_for_node(store, gossip_pool=gossip_pool)
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
            del gossip_pool[: len(gossip_pool) - MAX_GOSSIP_POOL_MESSAGES]


# Compatibility stub for the old global bill database flow.
def download_bills(_pos, _transaction_pool):
    return


# Rebroadcast queued gossip to sampled peers so messages continue spreading.
def maintain_connections(gossip_pool):
    from . import protocol_v3

    sender_node.ensure_runtime_files()
    logger.info("gossip rebroadcaster started")
    last_evidence_broadcast = {}
    evidence_types = {
        protocol_v3.CONFLICT_PROOF_TYPE,
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

    def live_peer_sample(peers, fanout, my_ip):
        candidates = []
        for peer in peers:
            ip_addr = sender_node._peer_ip(peer)
            if ip_addr and ip_addr != my_ip:
                candidates.append(peer)
        random.shuffle(candidates)
        return candidates[: max(1, int(fanout))]

    def send_batch(raw_items, peers, fanout):
        raw_items = [item for item in raw_items if item]
        if not raw_items:
            return
        payload = json.dumps(
            {
                "type": GOSSIP_BATCH_TYPE,
                "messages": raw_items[:NODE_REBROADCAST_BATCH_MAX_MESSAGES],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        for peer in live_peer_sample(peers, fanout, runtime_json.get_public_ip()):
            sender_node.connect("B", payload, [peer], max_duration_seconds=10)

    while True:
        time.sleep(NODE_REBROADCAST_INTERVAL_SECONDS)
        try:
            if _runtime_kill_requested():
                break
            if not gossip_pool:
                continue
            peers = _peer_files()
            if not peers:
                continue
            queued = list(gossip_pool)
            now = int(time.time())
            due_evidence = []
            normal_candidates = []
            for raw in queued:
                message_type, mh = unpack_type(raw)
                if message_type in evidence_types:
                    if mh and now - int(last_evidence_broadcast.get(mh, 0)) >= 300:
                        last_evidence_broadcast[mh] = now
                        due_evidence.append(raw)
                    continue
                normal_candidates.append(raw)
            if due_evidence:
                send_batch(
                    due_evidence,
                    peers,
                    NODE_CRITICAL_REBROADCAST_FANOUT,
                )
            if normal_candidates:
                random.shuffle(normal_candidates)
                send_batch(
                    normal_candidates[:NODE_REBROADCAST_BATCH_MAX_MESSAGES],
                    peers,
                    NODE_REBROADCAST_FANOUT,
                )
        except Exception as exc:
            logger.debug("gossip rebroadcast loop iteration failed: %s", exc, exc_info=True)


# Run the IND gossip node service.
def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    port = node_port()
    print(f"IND {ind_settings.network_name()} gossip node is starting...", flush=True)
    print(
        f"Open/forward TCP port {port} on your router and firewall so peers can reach this node.",
        flush=True,
    )
    with Manager() as manager:
        rf1 = manager.list()
        rf2 = manager.dict()
        gossip = manager.list()
        processes = [
            Process(target=database, args=(rf1, rf2, gossip)),
            Process(target=maintain_connections, args=(gossip,)),
        ]
        for process in processes:
            process.start()
        try:
            node_protocol(rf1, rf2, gossip, gossip)
        finally:
            for process in processes:
                if process.is_alive():
                    process.terminate()
            for process in processes:
                process.join(timeout=5)


if __name__ == "__main__":
    main()
