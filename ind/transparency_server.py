import argparse
import collections
import copy
import json
import logging
import os
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from pymerkle.core import InvalidChallenge

from . import env as ind_env
from . import keys_v3
from . import memory_pressure
from . import operator_storage
from . import protocol_policy
from . import token as ind_token
from . import transparency_client as log_client
from .io_utils import atomic_write_text

DEFAULT_LOG_DB = "files/ind_transparency_log.db"
logger = logging.getLogger(__name__)
DEFAULT_LOG_PRIVATE_KEY = "files/log_operator_private_key.json"
DEFAULT_LOG_PUBLIC_KEY = "files/log_operator_public_key.json"
DEFAULT_ROOT_INTERVAL_SECONDS = 60
DEFAULT_MAX_APPEND_BODY_BYTES = 8 * 1024 * 1024
DEFAULT_APPEND_BODY_READ_TIMEOUT_SECONDS = 10
DEFAULT_APPEND_VALIDATION_WORKERS = 4
DEFAULT_APPEND_VALIDATION_QUEUE_MAX = 128
DEFAULT_APPEND_VALIDATION_PER_IP_QUEUE_MAX = 16
DEFAULT_APPEND_VALIDATION_ADMISSION_TIMEOUT_SECONDS = 1
DEFAULT_APPEND_VALIDATION_RESULT_TIMEOUT_SECONDS = 60
DEFAULT_APPEND_VALIDATION_RETRY_AFTER_SECONDS = 2
DEFAULT_OPERATOR_RECOVERY_MIN_FEEDS = 2
DEFAULT_OPERATOR_RECOVERY_STABLE_SECONDS = 120

OPERATOR_STATE_STARTING = "starting"
OPERATOR_STATE_RECOVERING = "recovering"
OPERATOR_STATE_CATCHING_UP = "catching_up"
OPERATOR_STATE_ACTIVE = "active"
OPERATOR_STATE_FAILED_SAFE = "failed_safe"
OPERATOR_RECOVERY_MANIFEST_TYPE = "ind.operator_recovery_manifest.v3"
OPERATOR_RECOVERY_MANIFEST_SIGNATURE_DOMAIN = "IND_OPERATOR_RECOVERY_MANIFEST_V3"


_env_int = ind_env.int_value
_env_bool = ind_env.bool_value


def _env_list(name):
    return ind_env.list_value(name)


def _env_operator_public_keys():
    keys = []
    legacy_key = os.environ.get("IND_LOG_OPERATOR_PUBLIC_KEY", "").strip()
    if legacy_key:
        keys.append(legacy_key)
    operators_raw = os.environ.get("IND_LOG_OPERATORS", "").strip()
    if operators_raw:
        try:
            operators = json.loads(operators_raw)
        except json.JSONDecodeError:
            operators = []
        if isinstance(operators, list):
            for operator in operators:
                if not isinstance(operator, dict):
                    continue
                public_key = str(operator.get("public_key") or "").strip()
                if public_key:
                    keys.append(public_key)
    return list(dict.fromkeys(keys))


MAX_APPEND_BODY_BYTES = max(
    1024, _env_int("IND_LOG_MAX_APPEND_BODY_BYTES", DEFAULT_MAX_APPEND_BODY_BYTES)
)
APPEND_BODY_READ_TIMEOUT_SECONDS = max(
    1,
    _env_int("IND_LOG_APPEND_BODY_READ_TIMEOUT_SECONDS", DEFAULT_APPEND_BODY_READ_TIMEOUT_SECONDS),
)
APPEND_VALIDATION_WORKERS = max(
    1,
    _env_int("IND_LOG_APPEND_VALIDATION_WORKERS", DEFAULT_APPEND_VALIDATION_WORKERS),
)
APPEND_VALIDATION_QUEUE_MAX = max(
    1,
    _env_int("IND_LOG_APPEND_VALIDATION_QUEUE_MAX", DEFAULT_APPEND_VALIDATION_QUEUE_MAX),
)
APPEND_VALIDATION_PER_IP_QUEUE_MAX = max(
    1,
    _env_int(
        "IND_LOG_APPEND_VALIDATION_PER_IP_QUEUE_MAX",
        DEFAULT_APPEND_VALIDATION_PER_IP_QUEUE_MAX,
    ),
)
APPEND_VALIDATION_ADMISSION_TIMEOUT_SECONDS = max(
    0,
    _env_int(
        "IND_LOG_APPEND_VALIDATION_ADMISSION_TIMEOUT_SECONDS",
        DEFAULT_APPEND_VALIDATION_ADMISSION_TIMEOUT_SECONDS,
    ),
)
APPEND_VALIDATION_RESULT_TIMEOUT_SECONDS = max(
    1,
    _env_int(
        "IND_LOG_APPEND_VALIDATION_RESULT_TIMEOUT_SECONDS",
        DEFAULT_APPEND_VALIDATION_RESULT_TIMEOUT_SECONDS,
    ),
)
APPEND_VALIDATION_RETRY_AFTER_SECONDS = max(
    1,
    _env_int(
        "IND_LOG_APPEND_VALIDATION_RETRY_AFTER_SECONDS",
        DEFAULT_APPEND_VALIDATION_RETRY_AFTER_SECONDS,
    ),
)
WRITE_MIRROR_PROOF_ARCHIVES = _env_bool("IND_LOG_WRITE_MIRROR_PROOF_ARCHIVES", False)


# Raised when the transparency log operator cannot serve a request.
class LogServerError(Exception):
    pass


class AppendValidationBackpressure(LogServerError):
    def __init__(self, message="append validation busy", retry_after_seconds=None):
        super().__init__(message)
        self.retry_after_seconds = int(
            retry_after_seconds
            if retry_after_seconds is not None
            else APPEND_VALIDATION_RETRY_AFTER_SECONDS
        )


# Represents one append validation request waiting for a worker result.
class AppendValidationJob:
    def __init__(self, peer_ip, payload=None, operation=None):
        if operation is None:
            operation = payload
        self.peer_ip = str(peer_ip or "")
        self.operation = operation
        self.event = threading.Event()
        self.result = None
        self.error = None


# Bounded per-peer validation queue that protects append endpoints from bursts.
class AppendValidationQueue:
    # Start worker threads and configure global plus per-IP queue limits.
    def __init__(self, workers=None, queue_max=None, per_ip_queue_max=None):
        self.worker_count = max(
            1,
            int(workers if workers is not None else APPEND_VALIDATION_WORKERS),
        )
        self.queue_max = max(
            0,
            int(queue_max if queue_max is not None else APPEND_VALIDATION_QUEUE_MAX),
        )
        self.per_ip_queue_max = max(
            0,
            int(
                per_ip_queue_max
                if per_ip_queue_max is not None
                else APPEND_VALIDATION_PER_IP_QUEUE_MAX
            ),
        )
        self._condition = threading.Condition()
        self._queues = {}
        self._ready_peers = collections.deque()
        self._queued_count = 0
        self._closed = False
        self._workers = [
            threading.Thread(
                target=self._worker,
                name=f"append-validation-{index}",
                daemon=True,
            )
            for index in range(self.worker_count)
        ]
        for worker in self._workers:
            worker.start()

    # Enqueue one validation operation and wait for its result or backpressure error.
    def submit(
        self,
        peer_ip,
        payload,
        operation,
        *,
        admission_timeout=None,
        result_timeout=None,
    ):
        job = AppendValidationJob(peer_ip, operation)
        admission_timeout = (
            APPEND_VALIDATION_ADMISSION_TIMEOUT_SECONDS
            if admission_timeout is None
            else max(0, float(admission_timeout))
        )
        result_timeout = (
            APPEND_VALIDATION_RESULT_TIMEOUT_SECONDS
            if result_timeout is None
            else max(1, float(result_timeout))
        )
        self._admit(job, admission_timeout)
        if not job.event.wait(result_timeout):
            raise AppendValidationBackpressure("append validation timed out")
        if job.error is not None:
            raise job.error
        return job.result

    # Admit a job only when both global and per-peer queue capacity are available.
    def _admit(self, job, admission_timeout):
        deadline = time.monotonic() + float(admission_timeout)
        with self._condition:
            while True:
                if self._closed:
                    raise AppendValidationBackpressure("append validation shutting down")
                peer_queue = self._queues.get(job.peer_ip)
                peer_depth = len(peer_queue) if peer_queue is not None else 0
                has_global_room = self._queued_count < self.queue_max
                has_peer_room = peer_depth < self.per_ip_queue_max
                if has_global_room and has_peer_room:
                    if peer_queue is None:
                        peer_queue = collections.deque()
                        self._queues[job.peer_ip] = peer_queue
                    was_empty = not peer_queue
                    peer_queue.append(job)
                    self._queued_count += 1
                    if was_empty:
                        self._ready_peers.append(job.peer_ip)
                    self._condition.notify()
                    return
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise AppendValidationBackpressure()
                self._condition.wait(min(remaining, 0.05))

    # Pull jobs in peer-rotating order so one sender cannot monopolize validation.
    def _next_job(self):
        with self._condition:
            while True:
                while not self._ready_peers and not self._closed:
                    self._condition.wait()
                if not self._ready_peers and self._closed:
                    return None
                peer_ip = self._ready_peers.popleft()
                peer_queue = self._queues.get(peer_ip)
                if not peer_queue:
                    self._queues.pop(peer_ip, None)
                    continue
                job = peer_queue.popleft()
                self._queued_count -= 1
                if peer_queue:
                    self._ready_peers.append(peer_ip)
                else:
                    self._queues.pop(peer_ip, None)
                self._condition.notify_all()
                return job

    # Execute admitted validation jobs and attach either result or exception.
    def _worker(self):
        while True:
            job = self._next_job()
            if job is None:
                return
            try:
                job.result = job.operation()
            except Exception as exc:
                exc.__traceback__ = None
                job.error = exc
            finally:
                job.operation = None
                job.event.set()
                memory_pressure.maybe_collect_after_pressure("append_validation")

    # Stop workers after all waiting threads have been notified.
    def close(self):
        with self._condition:
            self._closed = True
            self._condition.notify_all()


def _legacy_text_path(path):
    path = Path(path)
    if path.suffix == ".json":
        return path.with_suffix(".txt")
    return path


def _write_key_json(path, field, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix != ".json":
        path.write_text(value + "\n", encoding="utf-8")
        return
    atomic_write_text(
        path,
        json.dumps({field: value}, sort_keys=True, indent=2, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def _read_key_json_or_legacy(path, field):
    path = Path(path)
    if path.exists():
        if path.suffix == ".json":
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                return str(data.get(field, "")).strip()
            except (json.JSONDecodeError, OSError):
                return ""
        return path.read_text(encoding="utf-8").strip()
    legacy_path = _legacy_text_path(path)
    if legacy_path != path and legacy_path.exists():
        return legacy_path.read_text(encoding="utf-8").strip()
    return ""


# Load or create the Ed25519 key pair used to sign log roots.
def load_or_create_operator_keys(
    private_key_path=DEFAULT_LOG_PRIVATE_KEY, public_key_path=DEFAULT_LOG_PUBLIC_KEY
):
    private_key_path = Path(private_key_path)
    public_key_path = Path(public_key_path)
    private_key = _read_key_json_or_legacy(private_key_path, "private_key")
    public_key = _read_key_json_or_legacy(public_key_path, "public_key")
    if private_key.startswith(keys_v3.PRIVATE_KEY_PREFIX) and public_key.startswith(
        keys_v3.PUBLIC_KEY_PREFIX
    ):
        if not private_key_path.exists():
            _write_key_json(private_key_path, "private_key", private_key)
        if not public_key_path.exists():
            _write_key_json(public_key_path, "public_key", public_key)
        return private_key, public_key

    private_key_path.parent.mkdir(parents=True, exist_ok=True)
    public_key_path.parent.mkdir(parents=True, exist_ok=True)
    _address, private_key, public_key = keys_v3.generate_keypair()
    _write_key_json(private_key_path, "private_key", private_key)
    _write_key_json(public_key_path, "public_key", public_key)
    return private_key, public_key


# Persistent CT-style SHA3-256 append-only log of IND transfer hashes.
class TransparencyLog:
    # Build an append-only transparency log with configured storage and recovery policy.
    def __init__(
        self,
        db_path,
        private_key_base85,
        public_key_base85,
        mirror_dirs=None,
        recovery_required=False,
        recovery_feeds=None,
        recovery_min_feeds=DEFAULT_OPERATOR_RECOVERY_MIN_FEEDS,
        recovery_stable_seconds=DEFAULT_OPERATOR_RECOVERY_STABLE_SECONDS,
        recovery_mirrors=None,
        recovery_proof_archives=None,
        max_root_lag_seconds=log_client.DEFAULT_MAX_ROOT_LAG_SECONDS,
        enforce_late_witnesses=False,
        storage_backend=None,
    ):
        self.private_key = private_key_base85
        self.public_key = public_key_base85
        self.log_id = log_client.log_id_from_public_key(public_key_base85)
        self.storage = operator_storage.create_operator_storage(db_path, backend=storage_backend)
        self.storage_backend = self.storage.backend_name
        self.db_path = self.storage.display_path
        self.mirror_dirs = [Path(path) for path in (mirror_dirs or [])]
        self.recovery_required = bool(recovery_required)
        self.recovery_feeds = list(recovery_feeds or [])
        self.recovery_min_feeds = int(recovery_min_feeds)
        self.recovery_stable_seconds = int(recovery_stable_seconds)
        self.recovery_mirrors = list(recovery_mirrors or [])
        self.recovery_proof_archives = list(recovery_proof_archives or [])
        self.max_root_lag_seconds = int(max_root_lag_seconds)
        self.enforce_late_witnesses = bool(enforce_late_witnesses)
        self._append_lock = threading.RLock()
        self._init_db()
        self._initialize_operator_state()

    # Return a backend connection for log, root, and recovery state operations.
    def _connect(self):
        return self.storage.connect()

    # Initialize the selected storage backend schema.
    def _init_db(self):
        self.storage.init_schema()

    # Put a recovery-required operator into recovering state on startup.
    def _initialize_operator_state(self):
        with self._connect() as conn:
            row = conn.execute(
                "SELECT value FROM operator_recovery_state WHERE key = 'state'"
            ).fetchone()
            if row is None:
                initial_state = (
                    OPERATOR_STATE_RECOVERING
                    if self.recovery_required
                    else OPERATOR_STATE_ACTIVE
                )
                self._set_operator_state(
                    initial_state,
                    conn=conn,
                    report=self._empty_recovery_report(phase=initial_state),
                )
                return
            current = str(row["value"])
            if self.recovery_required and current != OPERATOR_STATE_FAILED_SAFE:
                self._set_operator_state(
                    OPERATOR_STATE_RECOVERING,
                    conn=conn,
                    report=self._empty_recovery_report(phase=OPERATOR_STATE_RECOVERING),
                )

    # Read one recovery/operator-state value from storage.
    def _state_value(self, conn, key, default=""):
        row = conn.execute(
            "SELECT value FROM operator_recovery_state WHERE key = ?",
            (str(key),),
        ).fetchone()
        return row["value"] if row else default

    # Persist one recovery/operator-state value.
    def _set_state_value(self, conn, key, value):
        conn.execute(
            """
            INSERT OR REPLACE INTO operator_recovery_state(key, value)
            VALUES (?, ?)
            """,
            (str(key), str(value)),
        )

    # Build the default recovery report shape used by status and fail-safe paths.
    def _empty_recovery_report(self, phase=None):
        return {
            "phase": phase or self.operator_state(),
            "feeds_required": int(self.recovery_min_feeds),
            "feeds_seen": 0,
            "stable_high_watermarks": {},
            "appended": [],
            "duplicates": [],
            "rejected": [],
            "quarantined": [],
            "missing_feed_quorum": [],
        }

    # Persist operator active/recovering/fail-safe state and optional recovery report.
    def _set_operator_state(self, state, reason="", report=None, conn=None):
        owns_conn = conn is None
        conn = conn or self._connect()
        try:
            self._set_state_value(conn, "state", state)
            self._set_state_value(conn, "failure_reason", str(reason or ""))
            self._set_state_value(conn, "updated_at", int(time.time()))
            if report is not None:
                self._set_state_value(conn, "recovery_report", log_client.canonical_json(report))
            if owns_conn:
                conn.commit()
        finally:
            if owns_conn:
                conn.close()

    # Return the current operator safety state.
    def operator_state(self):
        with self._connect() as conn:
            return self._state_value(conn, "state", OPERATOR_STATE_ACTIVE)

    # Return whether the operator should accept new append requests.
    def is_active(self):
        return self.operator_state() == OPERATOR_STATE_ACTIVE

    # Enter fail-safe mode after recovery or consistency checks fail.
    def fail_safe(self, reason, report=None):
        current_report = report or self._empty_recovery_report(phase=OPERATOR_STATE_FAILED_SAFE)
        current_report["phase"] = OPERATOR_STATE_FAILED_SAFE
        self._set_operator_state(OPERATOR_STATE_FAILED_SAFE, reason=reason, report=current_report)
        return current_report

    # Mark the operator active after recovery checks establish a safe high-watermark.
    def activate(self, report=None):
        current_report = report or self._empty_recovery_report(phase=OPERATOR_STATE_ACTIVE)
        current_report["phase"] = OPERATOR_STATE_ACTIVE
        self._set_operator_state(OPERATOR_STATE_ACTIVE, report=current_report)
        return current_report

    def _trusted_checkpoint_operator_keys(self):
        keys = _env_operator_public_keys()
        if self.public_key:
            keys.append(self.public_key)
        return list(dict.fromkeys(key for key in keys if key))

    def _verify_transfer_announcement_for_append(self, announcement):
        from . import protocol_v3

        errors = []
        for public_key in self._trusted_checkpoint_operator_keys():
            try:
                return protocol_v3.verify_transfer_announcement(
                    announcement,
                    trusted_operator_public_key=public_key,
                )
            except Exception as exc:
                errors.append(str(exc))
        detail = "; ".join(dict.fromkeys(errors))
        raise LogServerError(f"v3 transfer announcement is invalid: {detail}")

    # Return operator health, latest root, storage status, and recovery state.
    def status(self):
        storage_health = self.storage.health()
        with self._connect() as conn:
            report_raw = self._state_value(conn, "recovery_report", "")
            try:
                report = json.loads(report_raw) if report_raw else self._empty_recovery_report()
            except json.JSONDecodeError:
                report = self._empty_recovery_report()
            return {
                "type": "ind.transparency_operator_status.v3",
                "version": 1,
                "log_id": self.log_id,
                "operator_public_key": self.public_key,
                "storage_backend": self.storage_backend,
                "storage_healthy": bool(storage_health.get("ok")),
                "storage": storage_health,
                "state": self._state_value(conn, "state", OPERATOR_STATE_ACTIVE),
                "tree_size": self.tree_size(),
                "latest_signed_root": self.latest_root(),
                "recovery": report,
                "failure_reason": self._state_value(conn, "failure_reason", ""),
                "updated_at": int(self._state_value(conn, "updated_at", "0") or 0),
            }

    def _ensure_log_entry_columns(self, conn):
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(log_entries)").fetchall()}
        if "entry_kind" not in columns:
            conn.execute(
                "ALTER TABLE log_entries ADD COLUMN entry_kind TEXT NOT NULL DEFAULT 'transfer'"
            )
        if "entry_json" not in columns:
            conn.execute("ALTER TABLE log_entries ADD COLUMN entry_json TEXT")
        if "transfer_json" not in columns:
            conn.execute("ALTER TABLE log_entries ADD COLUMN transfer_json TEXT")

    def _ensure_spend_claim_columns(self, conn):
        table_info = conn.execute("PRAGMA table_info(spend_claims)").fetchall()
        columns = {row["name"] for row in table_info}
        primary_key_columns = [
            row["name"]
            for row in sorted(table_info, key=lambda item: int(item["pk"]))
            if int(row["pk"]) > 0
        ]
        if primary_key_columns == ["spend_key"] and "transfer_leaf_index" not in columns:
            conn.execute("ALTER TABLE spend_claims ADD COLUMN transfer_leaf_index INTEGER")
            table_info = conn.execute("PRAGMA table_info(spend_claims)").fetchall()
            columns = {row["name"] for row in table_info}
        if primary_key_columns == ["spend_key"]:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS spend_claims_next (
                    spend_key TEXT NOT NULL,
                    token_id TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    sender_address TEXT NOT NULL,
                    sender_public_key TEXT NOT NULL,
                    transfer_hash TEXT NOT NULL,
                    transfer_leaf_index INTEGER,
                    first_seen INTEGER NOT NULL,
                    PRIMARY KEY(spend_key, transfer_hash)
                );
                INSERT OR IGNORE INTO spend_claims_next(
                    spend_key, token_id, previous_hash, sequence, sender_address,
                    sender_public_key, transfer_hash, transfer_leaf_index, first_seen
                )
                SELECT spend_key, token_id, previous_hash, sequence, sender_address,
                    sender_public_key, transfer_hash, transfer_leaf_index, first_seen
                FROM spend_claims;
                DROP TABLE spend_claims;
                ALTER TABLE spend_claims_next RENAME TO spend_claims;
                """)
            columns = {
                row["name"] for row in conn.execute("PRAGMA table_info(spend_claims)").fetchall()
            }
        if "transfer_leaf_index" not in columns:
            conn.execute("ALTER TABLE spend_claims ADD COLUMN transfer_leaf_index INTEGER")

    def _tree(self):
        return self.storage.tree()

    def tree_size(self):
        with self._tree() as tree:
            return int(tree.get_size())

    def current_root_hash(self, tree_size=None):
        with self._tree() as tree:
            size = tree.get_size() if tree_size is None else int(tree_size)
            if size == 0:
                return log_client.LOG_EMPTY_ROOT_HASH
            return tree.get_state(size).hex()

    # Append a 32-byte protocol commitment to the log, idempotently.
    def append_entry_hash(
        self, entry_hash, submitted_at=None, transfer=None, entry_kind="transfer", entry=None
    ):
        entry_hash = str(entry_hash).lower()
        try:
            entry_bytes = bytes.fromhex(entry_hash)
        except ValueError as exc:
            raise LogServerError("invalid transparency entry hash") from exc
        if len(entry_bytes) != 32:
            raise LogServerError("invalid transparency entry hash length")

        submitted_at = int(submitted_at if submitted_at is not None else time.time())
        transfer_json = log_client.canonical_json(transfer) if transfer is not None else None
        entry_json = log_client.canonical_json(entry) if entry is not None else None
        entry_kind = str(entry_kind or "transfer")
        with self._tree() as tree:
            leaf_hash = tree.hash_buff(entry_bytes)
        with self._append_lock:
            stored = self.storage.append_log_entry(
                entry_hash,
                entry_bytes,
                leaf_hash,
                submitted_at,
                entry_kind,
                entry_json,
                transfer_json,
            )
            leaf_index = int(stored["leaf_index"])
        return {
            "accepted": True,
            "duplicate": bool(stored["duplicate"]),
            "entry_hash": entry_hash,
            "leaf_index": int(leaf_index) - 1,
            "tree_size": int(stored["tree_size"]),
        }

    def _spend_claim_from_transfer(self, transfer):
        if isinstance(transfer, dict) and transfer.get("type") == "ind.transfer.v3":
            from . import protocol_v3

            claim = {
                "token_id": transfer["token_id"],
                "previous_hash": transfer["previous_hash"],
                "sequence": int(transfer["sequence"]),
                "sender_address": transfer["sender_address"],
                "sender_public_key": transfer["sender_public_key"],
            }
            claim["spend_key"] = protocol_v3.spend_key_for_transfer(transfer)
            return claim
        claim = {
            "token_id": transfer["token_id"],
            "previous_hash": transfer["previous_hash"],
            "sequence": int(transfer["sequence"]),
            "sender_address": transfer["sender_address"],
            "sender_public_key": transfer["sender_public_key"],
        }
        claim["spend_key"] = log_client.spend_key_for_transfer(transfer)
        return claim

    def _reject_conflicting_spend_claim(self, conn, claim, transfer_hash):
        existing = conn.execute(
            """
            SELECT transfer_hash FROM spend_claims
            WHERE spend_key = ? AND transfer_hash != ?
            ORDER BY first_seen ASC
            LIMIT 1
            """,
            (claim["spend_key"], transfer_hash),
        ).fetchone()
        if existing:
            raise LogServerError("conflicting spend is rejected")
        return None

    def _record_spend_claim(
        self,
        conn,
        claim,
        transfer_hash,
        transfer_leaf_index,
        first_seen,
    ):
        existing = conn.execute(
            """
            SELECT transfer_leaf_index FROM spend_claims
            WHERE spend_key = ? AND transfer_hash = ?
            """,
            (claim["spend_key"], transfer_hash),
        ).fetchone()
        conn.execute(
            """
            INSERT OR IGNORE INTO spend_claims(
                spend_key, token_id, previous_hash, sequence, sender_address,
                sender_public_key, transfer_hash, transfer_leaf_index, first_seen
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                claim["spend_key"],
                claim["token_id"],
                claim["previous_hash"],
                int(claim["sequence"]),
                claim["sender_address"],
                claim["sender_public_key"],
                transfer_hash,
                int(transfer_leaf_index),
                int(first_seen),
            ),
        )
        conn.execute(
            """
            UPDATE spend_claims
            SET transfer_leaf_index = COALESCE(transfer_leaf_index, ?)
            WHERE spend_key = ? AND transfer_hash = ?
            """,
            (
                int(transfer_leaf_index),
                claim["spend_key"],
                transfer_hash,
            ),
        )
        persisted = conn.execute(
            """
            SELECT spend_key, token_id, previous_hash, sequence, sender_address,
                   sender_public_key, transfer_hash, transfer_leaf_index, first_seen
            FROM spend_claims
            WHERE spend_key = ? AND transfer_hash = ?
            """,
            (claim["spend_key"], transfer_hash),
        ).fetchone()
        if persisted is None:
            raise LogServerError("spend claim was not recorded")
        persisted_claim = {
            "spend_key": persisted["spend_key"],
            "token_id": persisted["token_id"],
            "previous_hash": persisted["previous_hash"],
            "sequence": int(persisted["sequence"]),
            "sender_address": persisted["sender_address"],
            "sender_public_key": persisted["sender_public_key"],
        }
        existing_was_unindexed = existing is not None and existing["transfer_leaf_index"] is None
        self._record_current_spend_map_claim(
            conn,
            persisted_claim,
            persisted["transfer_hash"],
            persisted["transfer_leaf_index"],
            persisted["first_seen"],
            increment_size=existing is None or existing_was_unindexed,
        )

    def _spend_map_meta(self, conn, key, default=None):
        row = conn.execute(
            "SELECT value FROM spend_map_meta_v3 WHERE key = ?",
            (str(key),),
        ).fetchone()
        return row["value"] if row else default

    def _set_spend_map_meta(self, conn, key, value):
        conn.execute(
            """
            INSERT OR REPLACE INTO spend_map_meta_v3(key, value)
            VALUES (?, ?)
            """,
            (str(key), str(value)),
        )

    def _spend_map_node(self, conn, depth, position):
        row = conn.execute(
            """
            SELECT node_hash FROM spend_map_nodes_v3
            WHERE depth = ? AND position = ?
            """,
            (int(depth), str(int(position))),
        ).fetchone()
        return row["node_hash"] if row else None

    def _spend_map_hash_at(self, conn, depth, position):
        stored = self._spend_map_node(conn, depth, position)
        if stored is not None:
            return stored
        return log_client._spend_map_empty_hashes()[int(depth)]

    def _set_spend_map_node(self, conn, depth, position, node_hash):
        depth = int(depth)
        position = str(int(position))
        node_hash = str(node_hash)
        if node_hash == log_client._spend_map_empty_hashes()[depth]:
            conn.execute(
                """
                DELETE FROM spend_map_nodes_v3
                WHERE depth = ? AND position = ?
                """,
                (depth, position),
            )
            return
        conn.execute(
            """
            INSERT OR REPLACE INTO spend_map_nodes_v3(depth, position, node_hash)
            VALUES (?, ?, ?)
            """,
            (depth, position, node_hash),
        )

    def _current_claim_for_map(self, conn, claim, transfer_hash, transfer_leaf_index, first_seen):
        row = conn.execute(
            """
            SELECT entry_hash, leaf_index, submitted_at, transfer_json
            FROM log_entries
            WHERE entry_hash = ?
            """,
            (transfer_hash,),
        ).fetchone()
        result = {
            "type": "ind.transparency_spend_claim.v3",
            "version": log_client.LOG_VERSION,
            "log_id": self.log_id,
            "spend_key": claim["spend_key"],
            "token_id": claim["token_id"],
            "previous_hash": claim["previous_hash"],
            "sequence": int(claim["sequence"]),
            "sender_address": claim["sender_address"],
            "sender_public_key": claim["sender_public_key"],
            "transfer_hash": transfer_hash,
            "transfer_leaf_index": int(transfer_leaf_index),
            "accepted_at": int(first_seen),
        }
        return self._normalize_claim_with_stored_transfer(conn, result, row)

    def _normalize_claim_with_stored_transfer(self, conn, claim, row):
        normalized_without_body = log_client._normalize_spend_claim(claim)
        if not row or not row["transfer_json"]:
            return normalized_without_body
        transfer = None
        try:
            transfer = json.loads(row["transfer_json"])
            with_body = copy.deepcopy(claim)
            with_body["transfer"] = transfer
            return log_client._normalize_spend_claim(with_body)
        except Exception as exc:
            self._quarantine_unreconciled_transfer_entry(
                conn,
                row,
                f"stored transfer body omitted from spend claim: {exc}",
                transfer,
            )
            return normalized_without_body

    def _claims_for_current_spend_key(self, conn, spend_key):
        spend_key = log_client._hex32(spend_key, "spend key")
        rows = conn.execute(
            """
            SELECT claim_json FROM spend_map_claims_v3
            WHERE spend_key = ?
            """,
            (spend_key,),
        ).fetchall()
        if rows:
            return sorted(
                (
                    log_client._normalize_spend_claim(json.loads(row["claim_json"]))
                    for row in rows
                ),
                key=log_client._spend_claim_sort_key,
            )
        return [
            claim
            for claim in self._spend_claim_records(conn)
            if claim["spend_key"] == spend_key
        ]

    def _spend_map_claim_count(self, conn):
        row = conn.execute(
            "SELECT COUNT(*) AS count_value FROM spend_map_claims_v3"
        ).fetchone()
        return int(row["count_value"])

    def _current_spend_map_needs_rebuild(self, conn):
        if self._spend_map_meta(conn, "algorithm") != log_client.LOG_SPEND_MAP_ALGORITHM:
            return True
        root = self._spend_map_meta(conn, "root_hash")
        if root is None:
            return True
        try:
            root = log_client._hex32(root, "spend-map root")
            map_size = int(self._spend_map_meta(conn, "map_size", "0"))
        except (TypeError, ValueError, log_client.TransparencyLogError):
            return True
        stored_root = self._spend_map_node(conn, 0, 0)
        empty_root = log_client._spend_map_empty_root()
        if root == empty_root:
            if stored_root not in (None, empty_root):
                return True
        elif stored_root != root:
            return True
        return map_size != self._spend_map_claim_count(conn)

    def _store_current_spend_map_claim(
        self,
        conn,
        claim,
        transfer_hash,
        transfer_leaf_index,
        first_seen,
    ):
        normalized = self._current_claim_for_map(
            conn,
            claim,
            transfer_hash,
            transfer_leaf_index,
            first_seen,
        )
        conn.execute(
            """
            INSERT OR REPLACE INTO spend_map_claims_v3(
                spend_key, transfer_hash, transfer_leaf_index, claim_json
            ) VALUES (?, ?, ?, ?)
            """,
            (
                normalized["spend_key"],
                normalized["transfer_hash"],
                int(normalized["transfer_leaf_index"]),
                log_client.canonical_json(normalized),
            ),
        )
        return normalized

    def _update_current_spend_map_path(self, conn, spend_key):
        spend_key = log_client._hex32(spend_key, "spend key")
        empty_hashes = log_client._spend_map_empty_hashes()
        claims = self._claims_for_current_spend_key(conn, spend_key)
        if claims:
            current_hash = log_client._spend_map_slot_hash(spend_key, claims)
        else:
            current_hash = empty_hashes[log_client.SPEND_MAP_KEY_BITS]
        node_position = log_client._spend_key_position(spend_key)
        self._set_spend_map_node(
            conn,
            log_client.SPEND_MAP_KEY_BITS,
            node_position,
            current_hash,
        )
        for child_depth in range(log_client.SPEND_MAP_KEY_BITS, 0, -1):
            sibling_position = node_position ^ 1
            sibling_hash = self._spend_map_hash_at(conn, child_depth, sibling_position)
            if node_position % 2 == 0:
                current_hash = log_client._spend_map_branch_hash(current_hash, sibling_hash)
            else:
                current_hash = log_client._spend_map_branch_hash(sibling_hash, current_hash)
            node_position >>= 1
            self._set_spend_map_node(conn, child_depth - 1, node_position, current_hash)
        return current_hash

    def _record_current_spend_map_claim(
        self,
        conn,
        claim,
        transfer_hash,
        transfer_leaf_index,
        first_seen,
        increment_size=False,
    ):
        needs_rebuild = self._current_spend_map_needs_rebuild(conn)
        normalized = self._store_current_spend_map_claim(
            conn,
            claim,
            transfer_hash,
            transfer_leaf_index,
            first_seen,
        )
        if needs_rebuild:
            return self._rebuild_current_spend_map(conn)
        root_hash = self._update_current_spend_map_path(conn, normalized["spend_key"])
        self._set_spend_map_meta(conn, "algorithm", log_client.LOG_SPEND_MAP_ALGORITHM)
        self._set_spend_map_meta(conn, "map_size", self._spend_map_claim_count(conn))
        self._set_spend_map_meta(conn, "root_hash", root_hash)
        self._set_spend_map_meta(conn, "updated_at", int(time.time()))
        return root_hash, int(self._spend_map_meta(conn, "map_size", "0"))

    def _rebuild_current_spend_map(self, conn):
        claims = [
            log_client._normalize_spend_claim(claim)
            for claim in self._spend_claim_records(conn)
        ]
        levels, claims_by_key, total_claims = log_client._spend_map_levels(claims)
        root_hash = levels[0].get(0, log_client._spend_map_empty_root())
        conn.execute("DELETE FROM spend_map_nodes_v3")
        conn.execute("DELETE FROM spend_map_claims_v3")
        conn.execute("DELETE FROM spend_map_meta_v3")
        for claim in claims:
            conn.execute(
                """
                INSERT OR REPLACE INTO spend_map_claims_v3(
                    spend_key, transfer_hash, transfer_leaf_index, claim_json
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    claim["spend_key"],
                    claim["transfer_hash"],
                    int(claim["transfer_leaf_index"]),
                    log_client.canonical_json(claim),
                ),
            )
        for depth, nodes in enumerate(levels):
            for position, node_hash in nodes.items():
                self._set_spend_map_node(conn, depth, position, node_hash)
        self._set_spend_map_meta(conn, "algorithm", log_client.LOG_SPEND_MAP_ALGORITHM)
        self._set_spend_map_meta(conn, "map_size", total_claims)
        self._set_spend_map_meta(conn, "root_hash", root_hash)
        self._set_spend_map_meta(conn, "rebuilt_at", int(time.time()))
        self._set_spend_map_meta(conn, "updated_at", int(time.time()))
        del levels, claims_by_key, claims
        memory_pressure.maybe_collect_after_pressure("spend_map_rebuild")
        return root_hash, total_claims

    def _ensure_current_spend_map(self, conn):
        if self._current_spend_map_needs_rebuild(conn):
            return self._rebuild_current_spend_map(conn)
        return (
            self._spend_map_meta(conn, "root_hash"),
            int(self._spend_map_meta(conn, "map_size", "0")),
        )

    def _spend_claim_records(self, conn, tree_size=None):
        params = []
        where = "WHERE transfer_leaf_index IS NOT NULL"
        if tree_size is not None:
            where += " AND transfer_leaf_index < ?"
            params.append(int(tree_size))
        rows = conn.execute(
            f"""
            SELECT spend_claims.*,
                   log_entries.entry_hash AS stored_entry_hash,
                   log_entries.leaf_index AS stored_leaf_index,
                   log_entries.submitted_at AS stored_submitted_at,
                   log_entries.transfer_json AS stored_transfer_json
            FROM spend_claims
            LEFT JOIN log_entries
                ON log_entries.entry_hash = spend_claims.transfer_hash
                AND log_entries.leaf_index = spend_claims.transfer_leaf_index + 1
            {where}
            ORDER BY spend_key ASC, transfer_leaf_index ASC, transfer_hash ASC
            """,
            params,
        ).fetchall()
        claims = []
        for row in rows:
            claim = {
                "type": "ind.transparency_spend_claim.v3",
                "version": log_client.LOG_VERSION,
                "log_id": self.log_id,
                "spend_key": row["spend_key"],
                "token_id": row["token_id"],
                "previous_hash": row["previous_hash"],
                "sequence": int(row["sequence"]),
                "sender_address": row["sender_address"],
                "sender_public_key": row["sender_public_key"],
                "transfer_hash": row["transfer_hash"],
                "transfer_leaf_index": int(row["transfer_leaf_index"]),
                "accepted_at": int(row["first_seen"]),
            }
            stored_row = None
            if row["stored_entry_hash"] is not None:
                stored_row = {
                    "entry_hash": row["stored_entry_hash"],
                    "leaf_index": row["stored_leaf_index"],
                    "submitted_at": row["stored_submitted_at"],
                    "transfer_json": row["stored_transfer_json"],
                }
            claims.append(self._normalize_claim_with_stored_transfer(conn, claim, stored_row))
        return claims

    def _current_spend_map_proof_from_cache(self, conn, spend_key, tree_size):
        spend_key = log_client._hex32(spend_key, "spend key")
        _root_hash, map_size = self._ensure_current_spend_map(conn)
        claims = self._claims_for_current_spend_key(conn, spend_key)
        if not claims:
            raise log_client.InclusionProofError("spend key is not in the transparency spend map")
        audit_path = []
        node_position = log_client._spend_key_position(spend_key)
        for child_depth in range(log_client.SPEND_MAP_KEY_BITS, 0, -1):
            sibling_position = node_position ^ 1
            sibling_hash = self._spend_map_hash_at(conn, child_depth, sibling_position)
            side = "right" if node_position % 2 == 0 else "left"
            audit_path.append({"side": side, "hash": sibling_hash})
            node_position >>= 1
        return {
            "type": log_client.LOG_SPEND_MAP_PROOF_TYPE,
            "version": log_client.LOG_VERSION,
            "algorithm": log_client.LOG_SPEND_MAP_ALGORITHM,
            "spend_key": spend_key,
            "tree_size": int(tree_size),
            "map_size": int(map_size),
            "spend_claims": copy.deepcopy(claims),
            "audit_path": audit_path,
        }

    def _quarantine_unreconciled_transfer_entry(self, conn, row, reason, transfer=None):
        transfer = transfer if isinstance(transfer, dict) else {}
        conn.execute(
            """
            INSERT OR REPLACE INTO invalid_transfer_entries_v3(
                entry_hash, leaf_index, reason, transfer_type, token_id, first_seen, observed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                row["entry_hash"],
                int(row["leaf_index"]),
                str(reason),
                str(transfer.get("type", "")) if transfer else "",
                str(transfer.get("token_id", "")) if transfer else "",
                int(row["submitted_at"]),
                int(time.time()),
            ),
        )
        logger.warning(
            "quarantined unreconciled transparency transfer entry leaf=%s hash=%s reason=%s",
            int(row["leaf_index"]) - 1,
            str(row["entry_hash"])[:16],
            reason,
        )

    def _validated_v3_transfer_for_reconciliation(self, row):
        from . import protocol_v3

        try:
            transfer = json.loads(row["transfer_json"])
        except Exception as exc:
            raise LogServerError("stored transfer json is malformed") from exc
        if not isinstance(transfer, dict) or transfer.get("type") != protocol_v3.TRANSFER_TYPE:
            raise LogServerError("stored transfer is not a V3 transfer")
        try:
            protocol_v3._validate_transfer_shape(
                transfer,
                int(transfer["network_id"]),
            )
            protocol_v3.verify_transfer_signature(transfer)
            transfer_hash = protocol_v3.transfer_hash(transfer)
        except Exception as exc:
            raise LogServerError(f"stored V3 transfer is invalid: {exc}") from exc
        if transfer_hash != row["entry_hash"]:
            raise LogServerError("stored V3 transfer entry hash mismatch")
        return transfer, transfer_hash

    def _reconcile_transfer_spend_claims(self, conn):
        rows = conn.execute(
            """
            SELECT log_entries.entry_hash, log_entries.leaf_index,
                   log_entries.submitted_at, log_entries.transfer_json
            FROM log_entries
            LEFT JOIN spend_claims
                ON spend_claims.transfer_hash = log_entries.entry_hash
                AND spend_claims.transfer_leaf_index IS NOT NULL
            LEFT JOIN invalid_transfer_entries_v3
                ON invalid_transfer_entries_v3.entry_hash = log_entries.entry_hash
            WHERE log_entries.transfer_json IS NOT NULL
                AND spend_claims.transfer_hash IS NULL
                AND invalid_transfer_entries_v3.entry_hash IS NULL
            ORDER BY log_entries.leaf_index ASC
            """
        ).fetchall()
        reconciled = 0
        for row in rows:
            try:
                transfer, transfer_hash = self._validated_v3_transfer_for_reconciliation(row)
            except Exception as exc:
                transfer = None
                try:
                    transfer = json.loads(row["transfer_json"])
                except Exception:
                    transfer = None
                self._quarantine_unreconciled_transfer_entry(conn, row, str(exc), transfer)
                continue
            claim = self._spend_claim_from_transfer(transfer)
            self._record_spend_claim(
                conn,
                claim,
                transfer_hash,
                int(row["leaf_index"]) - 1,
                int(row["submitted_at"]),
            )
            reconciled += 1
        return reconciled

    def _conflicting_spend_claim(self, conn):
        return conn.execute(
            """
            SELECT spend_key, COUNT(DISTINCT transfer_hash) AS claim_count
            FROM spend_claims
            WHERE transfer_leaf_index IS NOT NULL
            GROUP BY spend_key
            HAVING claim_count > 1
            ORDER BY spend_key ASC
            LIMIT 1
            """
        ).fetchone()

    def spend_map_root(self, tree_size=None):
        latest_tree_size = self.tree_size()
        if tree_size is None or int(tree_size) == latest_tree_size:
            with self._connect() as conn:
                root_hash, map_size = self._ensure_current_spend_map(conn)
            return root_hash, int(map_size)
        with self._connect() as conn:
            claims = self._spend_claim_records(conn, tree_size=tree_size)
        return log_client.spend_map_root(claims), len(claims)

    def spend_map_proof(self, spend_key, tree_size=None):
        tree_size = self.tree_size() if tree_size is None else int(tree_size)
        if tree_size == self.tree_size():
            with self._connect() as conn:
                proof = self._current_spend_map_proof_from_cache(conn, str(spend_key), tree_size)
            try:
                signed_root = self.root_for_tree_size(tree_size)
            except LogServerError:
                return proof
            try:
                log_client.verify_spend_map_proof(proof, signed_root)
                return proof
            except Exception as first_exc:
                with self._connect() as conn:
                    self._rebuild_current_spend_map(conn)
                    proof = self._current_spend_map_proof_from_cache(
                        conn,
                        str(spend_key),
                        tree_size,
                    )
                try:
                    log_client.verify_spend_map_proof(proof, signed_root)
                except Exception as exc:
                    raise LogServerError(
                        "persisted spend-map proof does not match signed root"
                    ) from exc
                logger.warning("repaired current spend-map cache after proof mismatch: %s", first_exc)
                return proof
        with self._connect() as conn:
            claims = self._spend_claim_records(conn, tree_size=tree_size)
        return log_client.build_spend_map_proof(claims, str(spend_key), tree_size)

    def proof_archive(self, tree_size=None):
        tree_size = self.tree_size() if tree_size is None else int(tree_size)
        root = self.root_for_tree_size(tree_size)
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT entry_hash, leaf_index, submitted_at, entry_kind, entry_json FROM log_entries
                WHERE leaf_index <= ?
                ORDER BY leaf_index ASC
                """,
                (tree_size,),
            ).fetchall()
            claims = self._spend_claim_records(conn, tree_size=tree_size)
        entries = [
            {
                "leaf_index": int(row["leaf_index"]) - 1,
                "entry_hash": row["entry_hash"],
                "submitted_at": int(row["submitted_at"]),
                "entry_kind": row["entry_kind"],
                "entry": json.loads(row["entry_json"]) if row["entry_json"] else None,
            }
            for row in rows
        ]
        archive = log_client.make_proof_archive(root, entries, claims)
        log_client.verify_proof_archive(archive, root, operator_public_key=self.public_key)
        return archive

    def _entry_exists(self, entry_hash):
        with self._connect() as conn:
            row = conn.execute(
                "SELECT leaf_index FROM log_entries WHERE entry_hash = ?",
                (str(entry_hash).lower(),),
            ).fetchone()
        return int(row["leaf_index"]) - 1 if row else None

    # Decode a transfer announcement into append metadata without changing storage.
    def _transfer_details_from_announcement(self, announcement):
        if isinstance(announcement, bytes):
            announcement = announcement.decode("utf-8")
        if isinstance(announcement, str):
            announcement = ind_token.unpack_wire_message(announcement)
        from . import protocol_v3

        if not isinstance(announcement, dict):
            raise LogServerError("expected an IND transfer announcement")
        if announcement.get("type") != protocol_v3.TRANSFER_ANNOUNCEMENT_TYPE:
            raise LogServerError(protocol_policy.non_v3_disabled_message("non-V3 transfer append"))
        try:
            bill, _proof_bundle, _archive_segments = protocol_v3.decode_transfer_announcement(
                announcement
            )
        except Exception as exc:
            raise LogServerError(f"v3 transfer announcement is malformed: {exc}") from exc
        if not bill.get("recent_transfers"):
            raise LogServerError("TransferAnnouncementV3 requires a recent TransferV3")
        transfer = bill["recent_transfers"][-1]
        return {
            "message": announcement,
            "message_hash": ind_token.message_hash(announcement),
            "transfer": transfer,
            "transfer_hash": protocol_v3.transfer_hash(transfer),
            "transfer_timestamp": int(transfer["timestamp"]),
            "announced_at": int(announcement.get("announced_at", transfer["timestamp"])),
        }

    # Require recovery witnesses when a transfer is appended after the root-lag window.
    def _verify_late_recovery_witnesses(
        self,
        message_hash,
        transfer_timestamp,
        recovery_witnesses=None,
    ):
        log_client.recovery_witness_quorum(
            recovery_witnesses or [],
            message_hash,
            int(transfer_timestamp),
            min_witnesses=self.recovery_min_feeds,
            max_root_lag_seconds=self.max_root_lag_seconds,
        )
        return True

    # Normalize recovery root sources from URLs, paths, or already-built mirror clients.
    def _coerce_recovery_root_source(self, source):
        if isinstance(source, str):
            return log_client._coerce_mirror(source)
        return source

    # Persist a signed root discovered during recovery so future checks see it locally.
    def _store_signed_root(self, root):
        root_id = ind_token.sha3_hex(log_client.canonical_bytes(root))
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO signed_roots(root_id, tree_size, root_hash, timestamp, root_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    root_id,
                    int(root["tree_size"]),
                    root["root_hash"],
                    int(root["timestamp"]),
                    log_client.canonical_json(root),
                ),
            )

    # Rebuild local log entries from a complete proof archive for a signed prefix.
    def _restore_prefix_from_proof_archive(self, source, root):
        proof_archive = getattr(source, "proof_archive", None)
        if not callable(proof_archive):
            raise LogServerError("recovery source has no proof archive for signed prefix")
        archive = proof_archive(root)
        log_client.verify_proof_archive(archive, root, operator_public_key=self.public_key)
        target_tree_size = int(root["tree_size"])
        entries = sorted(archive.get("entries", []), key=lambda item: int(item["leaf_index"]))
        if len(entries) != target_tree_size:
            raise LogServerError("proof archive does not contain a complete signed prefix")
        local_tree_size = self.tree_size()
        for entry in entries[:local_tree_size]:
            local_entries = self.entries(
                start=int(entry["leaf_index"]),
                end=int(entry["leaf_index"]),
                limit=1,
            )
            if not local_entries or local_entries[0]["entry_hash"] != entry["entry_hash"]:
                raise LogServerError("proof archive prefix contradicts local log entries")
        for entry in entries[local_tree_size:]:
            if int(entry["leaf_index"]) != self.tree_size():
                raise LogServerError("proof archive entries are not contiguous at local tip")
            self.append_entry_hash(
                entry["entry_hash"],
                submitted_at=int(entry.get("submitted_at", time.time())),
                entry_kind=entry.get("entry_kind", "transfer"),
                entry=entry.get("entry"),
            )
        for claim in archive.get("spend_claims", []):
            transfer_hash = claim["transfer_hash"]
            transfer = claim.get("transfer")
            if transfer is not None:
                with self._connect() as conn:
                    conn.execute(
                        """
                        UPDATE log_entries
                        SET transfer_json = COALESCE(transfer_json, ?)
                        WHERE entry_hash = ?
                        """,
                        (log_client.canonical_json(transfer), transfer_hash),
                    )
            with self._connect() as conn:
                self._record_spend_claim(
                    conn,
                    claim,
                    transfer_hash,
                    int(claim["transfer_leaf_index"]),
                    int(claim["accepted_at"]),
                )
        if self.current_root_hash(target_tree_size) != root["root_hash"]:
            raise LogServerError("restored proof archive prefix does not match signed root")
        if "spend_map_root" in root:
            spend_root, _spend_size = self.spend_map_root(tree_size=target_tree_size)
            if spend_root != root["spend_map_root"]:
                raise LogServerError("restored proof archive spend map does not match signed root")
        self._store_signed_root(root)
        return target_tree_size

    # Check recovery mirrors and proof archives before accepting feed catch-up data.
    def verify_recovery_sources(self):
        local_tree_size = self.tree_size()
        checked = 0
        local_roots = self.roots(limit=max(1000, local_tree_size + 10))
        if local_roots:
            try:
                log_client.detect_mirror_disagreement(
                    local_roots, operator_public_key=self.public_key
                )
            except Exception as exc:
                raise LogServerError(f"local signed roots are contradictory: {exc}") from exc
        for root in local_roots:
            root_tree_size = int(root["tree_size"])
            if root_tree_size > local_tree_size:
                raise LogServerError("local signed root is ahead of the local log DB")
            if self.current_root_hash(root_tree_size) != root["root_hash"]:
                raise LogServerError(
                    "local signed root does not match the local log DB at tree size "
                    f"{root_tree_size}"
                )
        sources = list(self.recovery_mirrors) + list(self.recovery_proof_archives)
        sources.extend(str(path) for path in self.mirror_dirs)
        for source in sources:
            mirror = self._coerce_recovery_root_source(source)
            try:
                if callable(getattr(mirror, "roots", None)):
                    roots = mirror.roots()
                else:
                    roots = [mirror.latest_root()]
            except Exception as exc:
                raise LogServerError(f"recovery root source is unavailable: {exc}") from exc
            for root in sorted(roots, key=lambda item: int(item["tree_size"])):
                try:
                    log_client.verify_signed_root(root, operator_public_key=self.public_key)
                except Exception as exc:
                    raise LogServerError(f"recovery source has invalid signed root: {exc}") from exc
                if root.get("log_id") != self.log_id:
                    continue
                checked += 1
                root_tree_size = int(root["tree_size"])
                if root_tree_size > local_tree_size:
                    self._restore_prefix_from_proof_archive(mirror, root)
                    local_tree_size = self.tree_size()
                local_hash = self.current_root_hash(root_tree_size)
                if local_hash != root["root_hash"]:
                    raise LogServerError(
                        "same-operator recovery root mismatch at tree size "
                        f"{root_tree_size}"
                    )
        return checked

    # Read recovery manifests or segments from HTTP(S), files, or directories.
    def _read_recovery_text(self, base, relative=None):
        if isinstance(base, dict):
            base = base.get("url") or base.get("path") or base.get("base_url")
        base = str(base).strip()
        if base.startswith(("http://", "https://")):
            url = base.rstrip("/")
            if relative:
                url += "/" + str(relative).lstrip("/")
            request = urllib.request.Request(
                url,
                headers={"User-Agent": "International-Dollar-transparency-operator/1"},
            )
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.read().decode("utf-8")
        path = Path(base)
        if path.is_dir():
            path = path / (relative or "manifest.json")
        elif relative:
            path = path.parent / str(relative)
        return path.read_text(encoding="utf-8")

    # Verify the signed manifest that describes one recovery feed.
    def _verify_recovery_manifest(self, manifest, pinned_public_key=None):
        if not isinstance(manifest, dict):
            raise LogServerError("recovery manifest must be a JSON object")
        if manifest.get("type") != OPERATOR_RECOVERY_MANIFEST_TYPE:
            raise LogServerError("unsupported recovery manifest type")
        if int(manifest.get("version", 0)) != 1:
            raise LogServerError("unsupported recovery manifest version")
        if manifest.get("log_id") not in {None, self.log_id}:
            raise LogServerError("recovery manifest belongs to another operator log")
        feed_public_key = str(manifest.get("feed_public_key", "")).strip()
        if pinned_public_key and feed_public_key != str(pinned_public_key).strip():
            raise LogServerError("recovery manifest feed key does not match pinned key")
        signature = manifest.get("signature")
        if pinned_public_key or signature:
            if not feed_public_key or not signature:
                raise LogServerError("signed recovery manifest is required")
            unsigned = copy.deepcopy(manifest)
            unsigned.pop("signature", None)
            if not ind_token.b85_verify_domain(
                feed_public_key,
                signature,
                OPERATOR_RECOVERY_MANIFEST_SIGNATURE_DOMAIN,
                unsigned,
            ):
                raise LogServerError("invalid recovery manifest signature")
        return manifest

    # Load a recovery feed from an in-memory object, inline dict, or manifest location.
    def _load_recovery_feed(self, feed):
        if hasattr(feed, "recovery_entries") and callable(feed.recovery_entries):
            return feed.recovery_entries()
        if isinstance(feed, dict) and "entries" in feed:
            return {
                "feed_id": str(feed.get("feed_id") or feed.get("identity") or ""),
                "feed_public_key": str(feed.get("feed_public_key") or feed.get("public_key") or ""),
                "high_watermark": int(feed.get("high_watermark", int(time.time()))),
                "stable_at": int(feed.get("stable_at", 0)),
                "entries": list(feed.get("entries") or []),
            }

        pinned_public_key = feed.get("public_key") if isinstance(feed, dict) else None
        manifest_text = self._read_recovery_text(feed, "manifest.json")
        manifest = self._verify_recovery_manifest(
            json.loads(manifest_text), pinned_public_key=pinned_public_key
        )
        entries = []
        for segment in manifest.get("segments", []):
            segment_path = segment.get("path")
            if not segment_path:
                raise LogServerError("recovery manifest segment is missing path")
            segment_text = self._read_recovery_text(feed, segment_path)
            segment_hash = ind_token.sha3_hex(segment_text.encode("utf-8"))
            if segment.get("segment_hash") and segment["segment_hash"] != segment_hash:
                raise LogServerError("recovery segment hash mismatch")
            for line in segment_text.splitlines():
                if not line.strip():
                    continue
                record = json.loads(line)
                if isinstance(record, dict):
                    record.setdefault("source_segment_hash", segment_hash)
                entries.append(record)
        return {
            "feed_id": str(manifest.get("feed_id", "")),
            "feed_public_key": str(manifest.get("feed_public_key", "")),
            "high_watermark": int(manifest.get("high_watermark", 0)),
            "stable_at": int(manifest.get("stable_at", manifest.get("generated_at", 0))),
            "entries": entries,
        }

    # Normalize one recovery entry to the same append metadata used by live requests.
    def _normalize_recovery_feed_entry(self, feed_record, entry):
        if isinstance(entry, dict) and "message" in entry:
            message = entry["message"]
            witnesses = list(entry.get("witnesses") or [])
            if entry.get("witness"):
                witnesses.append(entry["witness"])
            source_segment_hash = entry.get("source_segment_hash") or "00" * 32
        else:
            message = entry
            witnesses = []
            source_segment_hash = "00" * 32
        details = self._transfer_details_from_announcement(message)
        return {
            "feed_id": str(feed_record.get("feed_id", "")),
            "feed_public_key": str(feed_record.get("feed_public_key", "")),
            "message": details["message"],
            "message_hash": details["message_hash"],
            "transfer_hash": details["transfer_hash"],
            "transfer_timestamp": details["transfer_timestamp"],
            "announced_at": int(details["announced_at"]),
            "source_segment_hash": str(source_segment_hash),
            "witnesses": witnesses,
        }

    # Append quorum-backed recovery feed entries up to the stable high-watermark.
    def catch_up_from_recovery_feeds(self):
        report = self._empty_recovery_report(phase=OPERATOR_STATE_CATCHING_UP)
        now = int(time.time())
        feed_records = []
        for feed in self.recovery_feeds:
            feed_record = self._load_recovery_feed(feed)
            feed_id = str(feed_record.get("feed_id") or feed_record.get("feed_public_key") or "")
            if not feed_id:
                raise LogServerError("recovery feed identity is not pinned")
            stable_at = int(feed_record.get("stable_at", 0))
            if stable_at and now - stable_at < self.recovery_stable_seconds:
                raise LogServerError("recovery feed high-watermark is not stable yet")
            feed_records.append(feed_record)
        identities = {
            (str(record.get("feed_id")), str(record.get("feed_public_key", "")))
            for record in feed_records
        }
        report["feeds_seen"] = len(identities)
        if len(identities) < self.recovery_min_feeds:
            raise LogServerError("recovery feed quorum is not available")
        high_watermarks = sorted(
            int(record.get("high_watermark", 0)) for record in feed_records
        )
        quorum_high_watermark = high_watermarks[-self.recovery_min_feeds]
        report["stable_high_watermarks"] = {
            str(record.get("feed_id")): int(record.get("high_watermark", 0))
            for record in feed_records
        }

        candidates = {}
        malformed = []
        for feed_record in feed_records:
            identity = (
                str(feed_record.get("feed_id")),
                str(feed_record.get("feed_public_key", "")),
            )
            for entry in feed_record.get("entries", []):
                try:
                    normalized = self._normalize_recovery_feed_entry(feed_record, entry)
                except Exception as exc:
                    malformed.append({"error": str(exc)})
                    continue
                if normalized["announced_at"] > quorum_high_watermark:
                    continue
                candidate = candidates.setdefault(
                    normalized["message_hash"],
                    {
                        "message": normalized["message"],
                        "transfer_hash": normalized["transfer_hash"],
                        "transfer_timestamp": normalized["transfer_timestamp"],
                        "announced_at": normalized["announced_at"],
                        "witnesses": [],
                        "feeds": set(),
                    },
                )
                candidate["feeds"].add(identity)
                candidate["witnesses"].extend(normalized["witnesses"])
        report["rejected"].extend(malformed)

        ordered = sorted(
            candidates.items(),
            key=lambda item: (
                int(item[1]["transfer_timestamp"]),
                int(item[1]["announced_at"]),
                item[0],
            ),
        )
        for message_hash, candidate in ordered:
            if len(candidate["feeds"]) < self.recovery_min_feeds:
                report["missing_feed_quorum"].append(
                    {
                        "message_hash": message_hash,
                        "feeds_seen": len(candidate["feeds"]),
                    }
                )
                continue
            existing_leaf = self._entry_exists(candidate["transfer_hash"])
            if existing_leaf is not None:
                report["duplicates"].append(
                    {
                        "message_hash": message_hash,
                        "entry_hash": candidate["transfer_hash"],
                        "leaf_index": existing_leaf,
                    }
                )
                continue
            try:
                append_result = self.append_transfer_announcement(
                    candidate["message"],
                    allow_recovery=True,
                    recovery_witnesses=candidate["witnesses"],
                )
                report["appended"].append(
                    {
                        "message_hash": message_hash,
                        "entry_hash": append_result["entry_hash"],
                        "leaf_index": append_result["leaf_index"],
                    }
                )
            except Exception as exc:
                bucket = (
                    "quarantined"
                    if "conflict" in str(exc).lower() or "contradict" in str(exc).lower()
                    else "rejected"
                )
                report[bucket].append({"message_hash": message_hash, "error": str(exc)})
        return report

    # Run source verification and feed catch-up, then activate or fail safe.
    def run_recovery(self):
        if self.operator_state() == OPERATOR_STATE_FAILED_SAFE:
            raise LogServerError("operator is failed safe")
        self._set_operator_state(
            OPERATOR_STATE_CATCHING_UP,
            report=self._empty_recovery_report(phase=OPERATOR_STATE_CATCHING_UP),
        )
        try:
            self.verify_recovery_sources()
            report = self.catch_up_from_recovery_feeds()
            self.activate(report=report)
            self.publish_root()
            return report
        except Exception as exc:
            report = self._empty_recovery_report(phase=OPERATOR_STATE_FAILED_SAFE)
            self.fail_safe(str(exc), report=report)
            raise

    # Validate a transfer announcement and append only its latest transfer hash.
    def append_transfer_announcement(
        self,
        announcement,
        allow_recovery=False,
        recovery_witnesses=None,
        submitted_at=None,
    ):
        if not allow_recovery and not self.is_active():
            raise LogServerError("operator_recovering")
        if isinstance(announcement, bytes):
            announcement = announcement.decode("utf-8")
        if isinstance(announcement, str):
            announcement = ind_token.unpack_wire_message(announcement)
        message_hash = ind_token.message_hash(announcement) if isinstance(announcement, dict) else ""
        from . import protocol_v3

        if not isinstance(announcement, dict) or announcement.get("type") != (
            protocol_v3.TRANSFER_ANNOUNCEMENT_TYPE
        ):
            raise LogServerError("expected an IND transfer announcement")
        if announcement.get("type") == protocol_v3.TRANSFER_ANNOUNCEMENT_TYPE:
            if "payload_encoding" not in announcement:
                raise LogServerError(
                    protocol_policy.non_v3_disabled_message("non-V3 transfer append")
                )
            try:
                decoded = self._verify_transfer_announcement_for_append(announcement)
            except Exception as exc:
                if isinstance(exc, LogServerError):
                    raise
                raise LogServerError(f"v3 transfer announcement is invalid: {exc}") from exc
            bill = decoded["bill"]
            state = decoded["state"]
            transfer = bill["recent_transfers"][-1]
            entry_hash = protocol_v3.transfer_hash(transfer)
        else:
            raise LogServerError(protocol_policy.non_v3_disabled_message("non-V3 transfer append"))
        if state.sequence == 0:
            raise LogServerError("genesis bill has no transfer to log")
        claim = self._spend_claim_from_transfer(transfer)
        submitted_at = int(submitted_at if submitted_at is not None else time.time())
        transfer_timestamp = int(transfer["timestamp"])
        if (
            self.enforce_late_witnesses
            and submitted_at - transfer_timestamp > self.max_root_lag_seconds
        ):
            self._verify_late_recovery_witnesses(
                message_hash,
                transfer_timestamp,
                recovery_witnesses=recovery_witnesses,
            )
        with self._append_lock:
            with self._connect() as conn:
                self.storage.lock_writer(conn)
                self._reject_conflicting_spend_claim(conn, claim, entry_hash)
                entry_bytes = bytes.fromhex(entry_hash)
                with self._tree() as tree:
                    leaf_hash = tree.hash_buff(entry_bytes)
                stored = self.storage.append_log_entry_conn(
                    conn,
                    entry_hash,
                    entry_bytes,
                    leaf_hash,
                    submitted_at,
                    "transfer",
                    None,
                    log_client.canonical_json(transfer),
                )
                result = {
                    "accepted": True,
                    "duplicate": bool(stored["duplicate"]),
                    "entry_hash": entry_hash,
                    "leaf_index": int(stored["leaf_index"]) - 1,
                    "tree_size": int(stored["tree_size"]),
                }
                self._record_spend_claim(
                    conn,
                    claim,
                    entry_hash,
                    result["leaf_index"],
                    submitted_at,
                )
            result["spend_key"] = claim["spend_key"]
            return result

    # Look up a previously logged checkpoint core by its canonical hash.
    def _checkpoint_core_by_hash(self, checkpoint_hash):
        checkpoint_hash = str(checkpoint_hash).lower()
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT entry_json FROM log_entries
                WHERE entry_hash = ? AND entry_kind = 'checkpoint'
                ORDER BY leaf_index DESC
                LIMIT 1
                """,
                (checkpoint_hash,),
            ).fetchone()
        if not row or not row["entry_json"]:
            return None
        from . import protocol_v3

        checkpoint = json.loads(row["entry_json"])
        if protocol_v3.checkpoint_core_hash(checkpoint) != checkpoint_hash:
            raise LogServerError("stored checkpoint hash mismatch")
        return checkpoint

    # Validate and append a compact bill checkpoint commitment.
    def append_checkpoint_announcement(self, announcement):
        if not self.is_active():
            raise LogServerError("operator_recovering")
        if isinstance(announcement, bytes):
            announcement = announcement.decode("utf-8")
        if isinstance(announcement, str):
            announcement = ind_token.unpack_wire_message(announcement)
        try:
            from . import protocol_v3

            if (
                not isinstance(announcement, dict)
                or announcement.get("type") != protocol_v3.CHECKPOINT_ANNOUNCEMENT_TYPE
            ):
                raise LogServerError("expected an IND checkpoint announcement")
            if "payload_encoding" not in announcement:
                raise LogServerError(
                    protocol_policy.non_v3_disabled_message("non-V3 checkpoint append")
                )
            decoded = protocol_v3.verify_checkpoint_announcement(
                announcement,
                previous_checkpoint_resolver=self._checkpoint_core_by_hash,
            )
            checkpoint = decoded["checkpoint_core"]
        except LogServerError:
            raise
        except Exception as exc:
            raise LogServerError(f"v3 checkpoint announcement is invalid: {exc}") from exc
        checkpoint_hash_value = checkpoint["checkpoint_hash"]
        expected_hash = protocol_v3.checkpoint_core_hash(checkpoint)
        if checkpoint_hash_value != expected_hash:
            raise LogServerError("checkpoint hash mismatch")
        submitted_at = int(time.time())
        with self._append_lock:
            result = self.append_entry_hash(
                checkpoint_hash_value,
                submitted_at=submitted_at,
                entry_kind="checkpoint",
                entry=checkpoint,
            )
            result["checkpoint_hash"] = checkpoint_hash_value
            return result

    # Sign and store the current tree root, then mirror it to configured dirs.
    def publish_root(self, timestamp=None):
        with self._append_lock:
            conflict_reason = None
            with self._connect() as conn:
                try:
                    self._reconcile_transfer_spend_claims(conn)
                except Exception as exc:
                    report = self._empty_recovery_report(phase=OPERATOR_STATE_FAILED_SAFE)
                    reason = f"spend-map reconciliation failed: {exc}"
                    self._set_operator_state(
                        OPERATOR_STATE_FAILED_SAFE,
                        reason=reason,
                        report=report,
                        conn=conn,
                    )
                    conflict_reason = reason
                if conflict_reason is None:
                    conflict = self._conflicting_spend_claim(conn)
                    if conflict is not None:
                        self._rebuild_current_spend_map(conn)
                        report = self._empty_recovery_report(phase=OPERATOR_STATE_FAILED_SAFE)
                        reason = (
                            "operator log contains conflicting spend claims for "
                            f"{conflict['spend_key']}"
                        )
                        self._set_operator_state(
                            OPERATOR_STATE_FAILED_SAFE,
                            reason=reason,
                            report=report,
                            conn=conn,
                        )
                        conflict_reason = reason
            if conflict_reason is not None:
                raise LogServerError(conflict_reason)
            timestamp = int(timestamp if timestamp is not None else time.time())
            latest = self.latest_root()
            if latest and timestamp <= int(latest["timestamp"]):
                timestamp = int(latest["timestamp"]) + 1
            tree_size = self.tree_size()
            root_hash = self.current_root_hash(tree_size)
            spend_map_root, spend_map_size = self.spend_map_root(tree_size=tree_size)
            root = log_client.make_signed_root(
                tree_size,
                root_hash,
                timestamp,
                self.private_key,
                self.public_key,
                spend_map_root=spend_map_root,
                spend_map_size=spend_map_size,
            )
            root_id = ind_token.sha3_hex(log_client.canonical_bytes(root))
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO signed_roots(root_id, tree_size, root_hash, timestamp, root_json)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (root_id, tree_size, root_hash, timestamp, log_client.canonical_json(root)),
                )
        try:
            self._mirror_root(root)
        finally:
            memory_pressure.maybe_collect_after_pressure("root_publish")
        return root

    # Publish a fresh signed root only when the configured interval has elapsed.
    def maybe_publish_root(self, interval_seconds=DEFAULT_ROOT_INTERVAL_SECONDS):
        if not self.is_active():
            latest = self.latest_root()
            if latest:
                return latest
            raise LogServerError("operator_recovering")
        latest = self.latest_root()
        now = int(time.time())
        if not latest or now - int(latest["timestamp"]) >= int(interval_seconds):
            return self.publish_root(now)
        return latest

    # Return the most recent signed root the operator has published.
    def latest_root(self):
        with self._connect() as conn:
            row = conn.execute("""
                SELECT root_json FROM signed_roots
                ORDER BY timestamp DESC, tree_size DESC
                LIMIT 1
                """).fetchone()
        return json.loads(row["root_json"]) if row else None

    # Return the signed root for an exact tree size.
    def root_for_tree_size(self, tree_size):
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT root_json FROM signed_roots
                WHERE tree_size = ?
                ORDER BY timestamp DESC
                LIMIT 1
                """,
                (int(tree_size),),
            ).fetchone()
        if not row:
            raise LogServerError("no signed root for tree size")
        return json.loads(row["root_json"])

    # Return the first signed root at or after timestamp.
    def root_at(self, timestamp):
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT root_json FROM signed_roots
                WHERE timestamp >= ?
                ORDER BY timestamp ASC, tree_size ASC
                LIMIT 1
                """,
                (int(timestamp),),
            ).fetchone()
        if not row:
            raise LogServerError("no signed root at or after timestamp")
        return json.loads(row["root_json"])

    # Return recent signed roots in chronological order for mirror/audit clients.
    def roots(self, limit=1000):
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT root_json FROM signed_roots
                ORDER BY timestamp DESC, tree_size DESC
                LIMIT ?
                """,
                (int(limit),),
            ).fetchall()
        roots = [json.loads(row["root_json"]) for row in rows]
        return sorted(roots, key=lambda root: (int(root["timestamp"]), int(root["tree_size"])))

    # Return logged transfer hashes by zero-based leaf index.
    def entries(self, start=0, end=None, limit=1000):
        start = max(0, int(start))
        if end is None:
            end = start + int(limit) - 1
        end = max(start, int(end))
        max_count = max(1, int(limit))
        count = min(max_count, end - start + 1)
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT entry_hash, leaf_index, submitted_at FROM log_entries
                WHERE leaf_index BETWEEN ? AND ?
                ORDER BY leaf_index ASC
                LIMIT ?
                """,
                (start + 1, start + count, count),
            ).fetchall()
        return [
            {
                "leaf_index": int(row["leaf_index"]) - 1,
                "entry_hash": row["entry_hash"],
                "submitted_at": int(row["submitted_at"]),
            }
            for row in rows
        ]

    # Return the Merkle inclusion proof for a leaf under a requested tree size.
    def inclusion_proof(self, entry_hash, tree_size):
        entry_hash = str(entry_hash).lower()
        tree_size = int(tree_size)
        with self._connect() as conn:
            row = conn.execute(
                "SELECT leaf_index FROM log_entries WHERE entry_hash = ?",
                (entry_hash,),
            ).fetchone()
        if not row:
            raise LogServerError("entry is not in the transparency log")
        leaf_index = int(row["leaf_index"])
        if leaf_index > tree_size:
            raise LogServerError("entry was appended after the requested root")
        with self._tree() as tree:
            try:
                proof = tree.prove_inclusion(leaf_index, tree_size)
            except InvalidChallenge as exc:
                raise LogServerError(str(exc)) from exc
        return {
            "type": log_client.LOG_INCLUSION_PROOF_TYPE,
            "version": log_client.LOG_VERSION,
            "log_id": self.log_id,
            "entry_hash": entry_hash,
            "leaf_hash": log_client.log_leaf_hash(entry_hash).hex(),
            "leaf_index": leaf_index - 1,
            "tree_size": tree_size,
            "proof": proof.serialize(),
        }

    # Return the Merkle consistency proof between two tree sizes.
    def consistency_proof(self, first_tree_size, second_tree_size):
        first_tree_size = int(first_tree_size)
        second_tree_size = int(second_tree_size)
        if first_tree_size == 0:
            return {
                "type": log_client.LOG_CONSISTENCY_PROOF_TYPE,
                "version": log_client.LOG_VERSION,
                "log_id": self.log_id,
                "first_tree_size": first_tree_size,
                "second_tree_size": second_tree_size,
                "proof": None,
            }
        with self._tree() as tree:
            try:
                proof = tree.prove_consistency(first_tree_size, second_tree_size)
            except InvalidChallenge as exc:
                raise LogServerError(str(exc)) from exc
        return {
            "type": log_client.LOG_CONSISTENCY_PROOF_TYPE,
            "version": log_client.LOG_VERSION,
            "log_id": self.log_id,
            "first_tree_size": first_tree_size,
            "second_tree_size": second_tree_size,
            "proof": proof.serialize(),
        }

    # Write signed roots and optional proof archives to configured static mirror dirs.
    def _mirror_root(self, root):
        for mirror_dir in self.mirror_dirs:
            mirror_dir.mkdir(parents=True, exist_ok=True)
            roots_dir = mirror_dir / "roots"
            roots_dir.mkdir(parents=True, exist_ok=True)
            filename = f"root_{int(root['timestamp'])}_{int(root['tree_size'])}.json"
            data = log_client.canonical_json(root) + "\n"
            target = roots_dir / filename
            target.write_text(data, encoding="utf-8")
            latest_target = mirror_dir / "latest.json"
            latest_tmp = mirror_dir / "latest.json.tmp"
            latest_tmp.write_text(data, encoding="utf-8")
            latest_tmp.replace(latest_target)
            with (mirror_dir / "roots.jsonl").open("a", encoding="utf-8") as handle:
                handle.write(data)
            if not WRITE_MIRROR_PROOF_ARCHIVES:
                continue
            archive_dir = mirror_dir / "proof_archives"
            archive_dir.mkdir(parents=True, exist_ok=True)
            archive = self.proof_archive(int(root["tree_size"]))
            archive_target = archive_dir / f"root_{int(root['tree_size']):012d}.json"
            archive_target.write_text(log_client.canonical_json(archive) + "\n", encoding="utf-8")


class TransparencyLogHandler(BaseHTTPRequestHandler):
    server_version = "INDTransparencyLog/1"

    # Return the URL path, rejecting traversal-shaped input before routing.
    def _request_path(self):
        path = urlparse(self.path).path
        decoded = path
        for _ in range(2):
            next_decoded = unquote(decoded)
            if next_decoded == decoded:
                break
            decoded = next_decoded
        if "\\" in decoded or any(segment == ".." for segment in decoded.split("/")):
            raise LogServerError("unsafe request path")
        return path

    def _send_json(self, status, data, headers=None):
        payload = log_client.canonical_json(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        for key, value in (headers or {}).items():
            self.send_header(str(key), str(value))
        self.end_headers()
        self.wfile.write(payload)

    def _send_error_json(self, status, message):
        self._send_json(status, {"error": message})

    def _send_method_not_allowed(self, methods):
        allowed = ", ".join(methods)
        self._send_json(
            405,
            {"error": "method not allowed"},
            headers={"Allow": allowed},
        )

    def _query(self):
        return parse_qs(urlparse(self.path).query)

    def _append_validation_queue(self):
        lane = getattr(self.server, "append_validation_queue", None)
        if lane is None:
            lane = AppendValidationQueue()
            self.server.append_validation_queue = lane
        return lane

    def _client_ip(self):
        try:
            return str(self.client_address[0])
        except Exception:
            return ""

    def do_GET(self):
        try:
            path = self._request_path()
            query = self._query()
            log = self.server.transparency_log
            if path == "/v3/append":
                self._send_method_not_allowed(["POST"])
                return
            if path == "/v3/status":
                self._send_json(200, log.status())
                return
            if path == "/v3/root":
                if log.is_active():
                    root = log.maybe_publish_root(self.server.root_interval_seconds)
                else:
                    root = log.latest_root()
                    if root is None:
                        raise LogServerError("operator_recovering")
                self._send_json(200, root)
                return
            if path == "/v3/root-at":
                timestamp = int(query.get("timestamp", [0])[0])
                self._send_json(200, log.root_at(timestamp))
                return
            if path == "/v3/roots":
                limit = int(query.get("limit", [1000])[0])
                self._send_json(200, {"roots": log.roots(limit=limit)})
                return
            if path == "/v3/entries":
                start = int(query.get("start", [0])[0])
                end_values = query.get("end")
                end = int(end_values[0]) if end_values else None
                limit = int(query.get("limit", [1000])[0])
                entries = log.entries(start=start, end=end, limit=limit)
                self._send_json(
                    200,
                    {
                        "entries": entries,
                        "start": start,
                        "end": entries[-1]["leaf_index"] if entries else start - 1,
                        "tree_size": log.tree_size(),
                    },
                )
                return
            if path == "/v3/proof":
                entry_hash = query.get("entry_hash", [""])[0]
                tree_size = int(query.get("tree_size", [log.tree_size()])[0])
                self._send_json(200, log.inclusion_proof(entry_hash, tree_size))
                return
            if path == "/v3/spend-proof":
                spend_key = query.get("spend_key", [""])[0]
                tree_size = int(query.get("tree_size", [log.tree_size()])[0])
                self._send_json(200, log.spend_map_proof(spend_key, tree_size))
                return
            if path == "/v3/proof-archive":
                tree_size = int(query.get("tree_size", [log.tree_size()])[0])
                self._send_json(200, log.proof_archive(tree_size))
                return
            if path == "/v3/consistency":
                first = int(query.get("first", [0])[0])
                second = int(query.get("second", [log.tree_size()])[0])
                self._send_json(200, log.consistency_proof(first, second))
                return
            self._send_error_json(404, "not found")
        except Exception as exc:
            self._send_error_json(400, str(exc))
        finally:
            memory_pressure.maybe_collect_after_pressure("transparency_get")

    def do_POST(self):
        raw = None
        payload = None
        append_operation = None
        try:
            path = self._request_path()
            if path != "/v3/append":
                self._send_error_json(404, "not found")
                return
            if self.headers.get_content_type() != "application/json":
                self._send_error_json(415, "append requests must use application/json")
                return
            log = self.server.transparency_log
            if not log.is_active():
                self._send_json(
                    503,
                    {
                        "error": "operator_recovering",
                        "state": log.operator_state(),
                        "retry_after_seconds": 5,
                    },
                    headers={"Retry-After": "5"},
                )
                return
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0:
                self._send_error_json(411, "missing request body")
                return
            if length > MAX_APPEND_BODY_BYTES:
                self._send_error_json(413, "request body is too large")
                return
            self.connection.settimeout(APPEND_BODY_READ_TIMEOUT_SECONDS)
            raw = self.rfile.read(length).decode("utf-8")
            payload = json.loads(raw)
            from . import protocol_v3

            if not isinstance(payload, dict):
                self._send_error_json(400, "append request must be a JSON object")
                return
            payload_type = payload.get("type")
            valid_append_types = {
                protocol_v3.TRANSFER_ANNOUNCEMENT_TYPE,
                protocol_v3.CHECKPOINT_ANNOUNCEMENT_TYPE,
            }
            if payload_type not in valid_append_types:
                self._send_error_json(400, "expected an IND V3 transfer or checkpoint announcement")
                return
            if "payload_encoding" not in payload:
                self._send_error_json(
                    400,
                    protocol_policy.non_v3_disabled_message("non-V3 append"),
                )
                return

            def append_operation():
                if payload_type == protocol_v3.CHECKPOINT_ANNOUNCEMENT_TYPE:
                    return log.append_checkpoint_announcement(payload)
                return log.append_transfer_announcement(payload)

            result = self._append_validation_queue().submit(
                self._client_ip(),
                payload,
                append_operation,
            )
            self._send_json(200, result)
        except AppendValidationBackpressure as exc:
            retry_after = str(exc.retry_after_seconds)
            self._send_json(
                503,
                {
                    "error": str(exc),
                    "retry_after_seconds": int(exc.retry_after_seconds),
                },
                headers={"Retry-After": retry_after},
            )
        except Exception as exc:
            self._send_error_json(400, str(exc))
        finally:
            raw = None
            payload = None
            append_operation = None
            memory_pressure.maybe_collect_after_pressure("transparency_append")

    def log_message(self, format, *args):
        return


def _root_publisher(log, interval_seconds, stop_event):
    while not stop_event.is_set():
        try:
            if log.is_active():
                log.maybe_publish_root(interval_seconds)
        except Exception as exc:
            logger.warning("background transparency root publishing failed: %s", exc)
        finally:
            memory_pressure.maybe_collect_after_pressure("root_publisher")
        stop_event.wait(interval_seconds)


def _recovery_worker(log, stop_event):
    if not log.recovery_required:
        return
    if log.operator_state() not in {OPERATOR_STATE_RECOVERING, OPERATOR_STATE_STARTING}:
        return
    try:
        log.run_recovery()
    except Exception as exc:
        logger.error("operator recovery failed safe: %s", exc)
    finally:
        stop_event.set()


# Run the HTTP transparency log operator.
def serve(log, host="127.0.0.1", port=8890, root_interval_seconds=DEFAULT_ROOT_INTERVAL_SECONDS):
    stop_event = threading.Event()
    recovery_stop = threading.Event()
    recovery = threading.Thread(
        target=_recovery_worker,
        args=(log, recovery_stop),
        daemon=True,
    )
    recovery.start()
    publisher = threading.Thread(
        target=_root_publisher,
        args=(log, int(root_interval_seconds), stop_event),
        daemon=True,
    )
    publisher.start()
    server = ThreadingHTTPServer((host, int(port)), TransparencyLogHandler)
    server.transparency_log = log
    server.root_interval_seconds = int(root_interval_seconds)
    server.append_validation_queue = AppendValidationQueue()
    try:
        server.serve_forever()
    finally:
        stop_event.set()
        recovery_stop.set()
        server.append_validation_queue.close()
        server.server_close()


def main():
    try:
        from . import settings as ind_settings

        security_settings = ind_settings.load_security_settings(validate_production=False)
        settings_recovery_feeds = ind_settings.operator_recovery_feeds(security_settings)
        settings_recovery_min_feeds = ind_settings.operator_recovery_min_feeds(security_settings)
        settings_recovery_stable_seconds = ind_settings.operator_recovery_stable_seconds(
            security_settings
        )
        settings_recovery_mirrors = ind_settings.trusted_root_mirrors(security_settings)
        settings_recovery_archives = ind_settings.transparency_proof_archives(security_settings)
        settings_max_root_lag = ind_settings.max_root_lag_seconds(security_settings)
        settings_operator_production = (
            ind_settings.security_role(security_settings) == "operator"
            and ind_settings.production_mode(security_settings)
        )
    except Exception:
        settings_recovery_feeds = []
        settings_recovery_min_feeds = DEFAULT_OPERATOR_RECOVERY_MIN_FEEDS
        settings_recovery_stable_seconds = DEFAULT_OPERATOR_RECOVERY_STABLE_SECONDS
        settings_recovery_mirrors = []
        settings_recovery_archives = []
        settings_max_root_lag = log_client.DEFAULT_MAX_ROOT_LAG_SECONDS
        settings_operator_production = False

    default_recovery_required = _env_bool(
        "IND_OPERATOR_RECOVERY_REQUIRED", settings_operator_production
    )
    parser = argparse.ArgumentParser(description="Run the IND transparency log operator")
    parser.add_argument("--db", default=os.environ.get("IND_LOG_DB", DEFAULT_LOG_DB))
    parser.add_argument("--host", default=os.environ.get("IND_LOG_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("IND_LOG_PORT", "8890")))
    parser.add_argument(
        "--private-key-file",
        default=os.environ.get("IND_LOG_PRIVATE_KEY_FILE", DEFAULT_LOG_PRIVATE_KEY),
    )
    parser.add_argument(
        "--public-key-file",
        default=os.environ.get("IND_LOG_PUBLIC_KEY_FILE", DEFAULT_LOG_PUBLIC_KEY),
    )
    parser.add_argument(
        "--mirror-dir",
        action="append",
        default=[item for item in os.environ.get("IND_LOG_MIRROR_DIRS", "").split(",") if item],
        help="directory to receive signed-root JSON files; pass multiple times for local mirror staging",
    )
    parser.add_argument(
        "--root-interval-seconds",
        type=int,
        default=int(os.environ.get("IND_LOG_ROOT_INTERVAL_SECONDS", DEFAULT_ROOT_INTERVAL_SECONDS)),
    )
    parser.add_argument(
        "--recovery-required",
        action="store_true",
        default=default_recovery_required,
        help="start read-only and run quorum catch-up before accepting appends",
    )
    parser.add_argument(
        "--recovery-feed",
        action="append",
        default=_env_list("IND_OPERATOR_RECOVERY_FEEDS") or settings_recovery_feeds,
        help="recovery feed base URL or manifest directory; pass multiple times",
    )
    parser.add_argument(
        "--recovery-min-feeds",
        type=int,
        default=int(
            os.environ.get("IND_OPERATOR_RECOVERY_MIN_FEEDS", settings_recovery_min_feeds)
        ),
    )
    parser.add_argument(
        "--recovery-stable-seconds",
        type=int,
        default=int(
            os.environ.get(
                "IND_OPERATOR_RECOVERY_STABLE_SECONDS",
                settings_recovery_stable_seconds,
            )
        ),
    )
    parser.add_argument(
        "--recovery-mirror",
        action="append",
        default=_env_list("IND_OPERATOR_RECOVERY_MIRRORS") or settings_recovery_mirrors,
    )
    parser.add_argument(
        "--recovery-proof-archive",
        action="append",
        default=_env_list("IND_OPERATOR_RECOVERY_PROOF_ARCHIVES")
        or settings_recovery_archives,
    )
    args = parser.parse_args()
    private_key, public_key = load_or_create_operator_keys(
        args.private_key_file, args.public_key_file
    )
    log = TransparencyLog(
        args.db,
        private_key,
        public_key,
        mirror_dirs=args.mirror_dir,
        recovery_required=args.recovery_required,
        recovery_feeds=args.recovery_feed,
        recovery_min_feeds=args.recovery_min_feeds,
        recovery_stable_seconds=args.recovery_stable_seconds,
        recovery_mirrors=args.recovery_mirror,
        recovery_proof_archives=args.recovery_proof_archive,
        max_root_lag_seconds=settings_max_root_lag,
        enforce_late_witnesses=args.recovery_required,
    )
    if log.is_active():
        log.publish_root()
    print(f"IND transparency log id: {log.log_id}")
    print(f"IND transparency operator public key: {public_key}")
    print(f"Operator state: {log.operator_state()}")
    print(f"Serving on http://{args.host}:{args.port}")
    serve(log, host=args.host, port=args.port, root_interval_seconds=args.root_interval_seconds)


if __name__ == "__main__":
    main()
