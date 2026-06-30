# SQLite-backed local state for IND bill gossip and settlement.

import contextlib
import json
import logging
import os
import sqlite3
import time
from pathlib import Path

from . import protocol_policy
from . import settings as ind_settings
from . import protocol as ind_token
from . import transparency_client as log_client
from .protocol import (
    BILL_TYPE,
    BILL_VERSION,
    CONFLICT_PROOF_TYPE,
    DEFAULT_LOG_SUBMISSION_VERIFY_TIMEOUT_SECONDS,
    FINALITY_BUFFER_SECONDS,
    STORED_MESSAGE_REF_TYPE,
    TOKEN_STATE_REF_TYPE,
    TOKEN_TYPE,
    TOKEN_VERSION,
    TRANSFER_ANNOUNCEMENT_TYPE,
    TRANSFER_ANNOUNCEMENT_V3_TYPE,
    TRANSPARENCY_EQUIVOCATION_PROOF_TYPE,
    TRANSPARENCY_OPERATOR_POLICY_VIOLATION_TYPE,
    TRANSPARENCY_ROOT_ANNOUNCEMENT_TYPE,
    ClosingConnection,
    ValidationError,
    _bill_history,
    _configured_transparency_submitter,
    _configured_transparency_verifier,
    _env_int,
    _env_true,
    _environment_transparency_verifier,
    _last_transfer,
    _load_json,
    _state_ref_from_state,
    _store_json,
    configure_sqlite_connection,
    conflict_proof_key,
    message_hash,
    transfer_hash,
    unpack_wire_message,
    verify_transparency_equivocation_proof,
    verify_transparency_operator_policy_violation_proof,
    verify_transparency_root_announcement,
)

STORE_SCHEMA_VERSION = 10
DEFAULT_FIRST_CHECKPOINT_AFTER_TRANSFERS = 10
DEFAULT_CHECKPOINT_INTERVAL_TRANSFERS = 10
DEFAULT_HIGH_VALUE_CHECKPOINT_THRESHOLD = 0
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())
BILL_V3_STATUS_RANK = {
    "pending": 2,
    "verified": 3,
    "settled": 3,
}
_INTERNAL_PREVERIFIED_SENTINEL = object()
V3_CONFLICT_ANCHOR_STATUSES = ("pending", "verified", "settled")
V3_LOG_PROVEN_STATUS = "log_proven"
V3_LOG_PENDING_STATUS = "log_pending"
V3_LOG_UNLOGGED_STATUS = "unlogged"
V3_LOG_PROOF_RETRY_INITIAL_SECONDS = max(1, _env_int("IND_V3_LOG_PROOF_RETRY_INITIAL_SECONDS", 60))
V3_LOG_PROOF_RETRY_MAX_SECONDS = max(1, _env_int("IND_V3_LOG_PROOF_RETRY_MAX_SECONDS", 3600))
V3_LOG_PROOF_STALE_HTTP_400_ATTEMPTS = max(
    1, _env_int("IND_V3_LOG_PROOF_STALE_HTTP_400_ATTEMPTS", 3)
)
WALLET_SYNC_DISPLAY_RANGE_LIMIT = max(0, _env_int("IND_WALLET_SYNC_DISPLAY_RANGE_LIMIT", 2048))
WALLET_SYNC_DISPLAY_RANGE_BYTES = max(
    16 * 1024,
    _env_int("IND_WALLET_SYNC_DISPLAY_RANGE_BYTES", 128 * 1024),
)
WALLET_SYNC_SERVER_SCAN_LIMIT = max(
    10_000,
    _env_int("IND_WALLET_SYNC_SERVER_SCAN_LIMIT", 100_000),
)


# Mark a conflict proof as already validated by the gossip layer before storage.
def preverified_conflict_proof_v3(proof, *, message_hash=None):
    return {
        "type": "conflict_proof_v3",
        "proof_hash": proof["proof_hash"],
        "network_id": int(proof["network_id"]),
        "message_hash": message_hash,
        "_sentinel": _INTERNAL_PREVERIFIED_SENTINEL,
    }


def _policy_int(value, default, minimum=0):
    try:
        result = int(value)
    except Exception:
        result = int(default)
    return max(int(minimum), result)


# Keep the stronger BillV3 status when duplicate rows are merged.
def _stronger_bill_v3_status(current, incoming):
    current = str(current or "")
    incoming = str(incoming or "")
    if BILL_V3_STATUS_RANK.get(current, 0) > BILL_V3_STATUS_RANK.get(incoming, 0):
        return current
    return incoming


# Reject wallet rows whose stored blob no longer matches its display id or token id.
def _bill_v3_record_has_allowed_value(record):
    try:
        from . import protocol_v3

        bill = protocol_v3.decode_bill(bytes(record["bill_blob"]))
        protocol_v3.validate_bill_display_id(bill)
        display_id = str(bill["checkpoint_core"]["display_id"])
        return str(record.get("display_id")) == display_id and str(record.get("token_id")) == str(
            bill["token_id"]
        )
    except Exception:
        logger.debug("filtering invalid BillV3 wallet record", exc_info=True)
        return False


# Reject wallet metadata rows with display ids unsupported by the active V3 parser.
def _bill_v3_record_has_supported_display_id(record):
    try:
        from . import protocol_v3

        protocol_v3.parse_display_id(str(record.get("display_id") or ""))
        return True
    except Exception:
        logger.debug("filtering unsupported BillV3 wallet display id", exc_info=True)
        return False


def _invalid_bill_v3_reason(record):
    try:
        from . import protocol_v3

        bill = protocol_v3.decode_bill(bytes(record["bill_blob"]))
        protocol_v3.validate_bill_display_id(bill)
        if str(record["display_id"]) != str(bill["checkpoint_core"]["display_id"]):
            return "stored display id does not match BillV3 checkpoint display id"
        if str(record["token_id"]) != str(bill["token_id"]):
            return "stored token id does not match BillV3 token id"
    except Exception as exc:
        return str(exc)
    return ""


# Extract the source archive segment hash carried by proof-bundle evidence.
def _source_archive_segment_hash_v3(bundle):
    if not isinstance(bundle, dict):
        return None
    source = bundle.get("source_evidence")
    if not isinstance(source, dict):
        return None
    segment_hash = str(source.get("archive_segment_hash") or "").strip().lower()
    return segment_hash or None


# SQLite-backed cache for verified bill tips, gossip messages, and conflicts.
class INDLocalStore:
    # Open or create a local IND gossip store.
    def __init__(
        self,
        db_path=None,
        transparency_verifier=None,
        transparency_submitter=None,
        require_transparency=None,
        transparency_submission_verify_timeout_seconds=None,
        first_checkpoint_after_transfers=None,
        checkpoint_interval_transfers=None,
        high_value_checkpoint_threshold=None,
    ):
        if db_path is None:
            db_path = ind_settings.default_store_path()
        self.db_path = str(Path(db_path))
        if require_transparency is None:
            try:
                self.require_transparency = ind_settings.require_transparency_log()
            except Exception:
                self.require_transparency = _env_true("IND_REQUIRE_TRANSPARENCY_LOG")
        else:
            self.require_transparency = bool(require_transparency)
        try:
            self.transparency_root_gossip = ind_settings.transparency_root_gossip()
        except Exception:
            self.transparency_root_gossip = os.environ.get(
                "IND_LOG_ROOT_GOSSIP", "1"
            ).strip().lower() not in {"0", "false", "no", "off"}
        self.transparency_verifier = transparency_verifier
        if self.require_transparency and self.transparency_verifier is None:
            self.transparency_verifier = _configured_transparency_verifier()
        self.transparency_submitter = transparency_submitter
        if self.transparency_submitter is None:
            self.transparency_submitter = _configured_transparency_submitter()
        if self.transparency_submitter is not None and self.transparency_verifier is None:
            try:
                self.transparency_verifier = _environment_transparency_verifier()
            except Exception:
                if self.require_transparency:
                    raise
                self.transparency_verifier = None
        if (
            self.require_transparency
            and self.transparency_root_gossip
            and self.transparency_verifier is None
        ):
            try:
                self.transparency_verifier = _environment_transparency_verifier()
            except Exception:
                if self.require_transparency:
                    raise
                self.transparency_verifier = None
        if transparency_submission_verify_timeout_seconds is None:
            self.transparency_submission_verify_timeout_seconds = _env_int(
                "IND_LOG_SUBMISSION_VERIFY_TIMEOUT_SECONDS",
                DEFAULT_LOG_SUBMISSION_VERIFY_TIMEOUT_SECONDS,
            )
        else:
            self.transparency_submission_verify_timeout_seconds = int(
                transparency_submission_verify_timeout_seconds
            )
        try:
            self.transparency_submit_async = ind_settings.transparency_submit_async()
        except Exception:
            self.transparency_submit_async = os.environ.get(
                "IND_TRANSPARENCY_SUBMIT_ASYNC", ""
            ).strip().lower() in {"1", "true", "yes", "on"}
        try:
            self.settlement_quorum_enabled = ind_settings.settlement_quorum_enabled()
        except Exception:
            self.settlement_quorum_enabled = os.environ.get(
                "IND_SETTLEMENT_QUORUM_ENABLED", ""
            ).strip().lower() in {"1", "true", "yes", "on"}
        self.first_checkpoint_after_transfers = _policy_int(
            (
                first_checkpoint_after_transfers
                if first_checkpoint_after_transfers is not None
                else _env_int(
                    "IND_FIRST_CHECKPOINT_AFTER_TRANSFERS", DEFAULT_FIRST_CHECKPOINT_AFTER_TRANSFERS
                )
            ),
            DEFAULT_FIRST_CHECKPOINT_AFTER_TRANSFERS,
            minimum=1,
        )
        self.checkpoint_interval_transfers = _policy_int(
            (
                checkpoint_interval_transfers
                if checkpoint_interval_transfers is not None
                else _env_int(
                    "IND_CHECKPOINT_INTERVAL_TRANSFERS", DEFAULT_CHECKPOINT_INTERVAL_TRANSFERS
                )
            ),
            DEFAULT_CHECKPOINT_INTERVAL_TRANSFERS,
            minimum=1,
        )
        self.high_value_checkpoint_threshold = _policy_int(
            (
                high_value_checkpoint_threshold
                if high_value_checkpoint_threshold is not None
                else _env_int(
                    "IND_HIGH_VALUE_CHECKPOINT_THRESHOLD", DEFAULT_HIGH_VALUE_CHECKPOINT_THRESHOLD
                )
            ),
            DEFAULT_HIGH_VALUE_CHECKPOINT_THRESHOLD,
            minimum=0,
        )
        try:
            settings = ind_settings.load_security_settings()
            self.operator_finality_min_proofs = _policy_int(
                ind_settings.operator_finality_min_proofs(settings),
                0,
                minimum=0,
            )
        except Exception:
            self.operator_finality_min_proofs = _env_int("IND_OPERATOR_FINALITY_MIN_PROOFS", 0)
        self._validate_operator_finality_policy_v3()
        self._init_db()

    def _reject_non_v3_bill_protocol(self, operation):
        raise ValidationError(protocol_policy.non_v3_disabled_message(operation))

    def _verify_bill_for_store(self, bill, **kwargs):
        self._reject_non_v3_bill_protocol("non-V3 bill validation")

    # Create a short-lived SQLite connection with row dictionaries enabled.
    def _connect(self):
        conn = sqlite3.connect(self.db_path, factory=ClosingConnection)
        configure_sqlite_connection(conn)
        conn.row_factory = sqlite3.Row
        return conn

    # Create the tables used for compact bill storage and local settlement.
    def _init_db(self):
        initial_version = 0
        with self._connect() as conn:
            initial_version = self._schema_version(conn)
            self._migrate_db(conn)
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS tokens (
                    token_id TEXT PRIMARY KEY,
                    display_id TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    owner_address TEXT NOT NULL,
                    last_transfer_hash TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    value INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    first_seen INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    finalized_at INTEGER
                );
                CREATE UNIQUE INDEX IF NOT EXISTS idx_tokens_display_id ON tokens(display_id);
                CREATE INDEX IF NOT EXISTS idx_tokens_owner_status ON tokens(owner_address, status);

                CREATE TABLE IF NOT EXISTS token_genesis (
                    token_id TEXT PRIMARY KEY,
                    display_id TEXT NOT NULL,
                    genesis_json TEXT NOT NULL,
                    value INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS genesis_manifests (
                    manifest_hash TEXT PRIMARY KEY,
                    manifest_json TEXT NOT NULL,
                    first_seen INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS transfers (
                    transfer_hash TEXT PRIMARY KEY,
                    token_id TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    sender_address TEXT NOT NULL,
                    recipient_address TEXT NOT NULL,
                    transfer_json TEXT NOT NULL,
                    token_payload TEXT NOT NULL,
                    status TEXT NOT NULL,
                    first_seen INTEGER NOT NULL,
                    finalized_at INTEGER
                );
                CREATE INDEX IF NOT EXISTS idx_transfers_conflict
                    ON transfers(token_id, previous_hash, sequence, sender_address);

                CREATE TABLE IF NOT EXISTS messages (
                    message_hash TEXT PRIMARY KEY,
                    message_type TEXT NOT NULL,
                    token_id TEXT,
                    recipient_address TEXT,
                    message_json TEXT NOT NULL,
                    first_seen INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_messages_recipient
                    ON messages(recipient_address, first_seen);

                CREATE TABLE IF NOT EXISTS conflicts (
                    proof_hash TEXT PRIMARY KEY,
                    conflict_key TEXT NOT NULL,
                    token_id TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    proof_json TEXT NOT NULL,
                    detected_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_conflicts_token ON conflicts(token_id);
                CREATE UNIQUE INDEX IF NOT EXISTS idx_conflicts_key ON conflicts(conflict_key);

                CREATE TABLE IF NOT EXISTS checkpoints (
                    checkpoint_hash TEXT PRIMARY KEY,
                    token_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    last_transfer_hash TEXT NOT NULL,
                    owner_address TEXT NOT NULL,
                    checkpoint_json TEXT NOT NULL,
                    root_json TEXT,
                    inclusion_proof_json TEXT,
                    spend_proof_json TEXT,
                    status TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_checkpoints_token_sequence
                    ON checkpoints(token_id, sequence);
                CREATE INDEX IF NOT EXISTS idx_checkpoints_token_transfer
                    ON checkpoints(token_id, last_transfer_hash);

                CREATE TABLE IF NOT EXISTS proof_bundles_v3 (
                    proof_bundle_hash TEXT PRIMARY KEY,
                    log_id TEXT NOT NULL,
                    signed_root_hash TEXT NOT NULL,
                    tree_size INTEGER NOT NULL,
                    algorithm INTEGER NOT NULL,
                    bundle_blob BLOB NOT NULL,
                    first_seen INTEGER NOT NULL,
                    last_verified INTEGER
                );
                CREATE INDEX IF NOT EXISTS idx_proof_bundles_v3_log_root
                    ON proof_bundles_v3(log_id, signed_root_hash);

                CREATE TABLE IF NOT EXISTS archive_segments_v3 (
                    segment_hash TEXT PRIMARY KEY,
                    token_id TEXT NOT NULL,
                    start_sequence INTEGER NOT NULL,
                    end_sequence INTEGER NOT NULL,
                    previous_segment_hash TEXT,
                    checkpoint_hash TEXT NOT NULL,
                    segment_blob BLOB NOT NULL,
                    first_seen INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_archive_segments_v3_token_range
                    ON archive_segments_v3(token_id, start_sequence, end_sequence);
                CREATE INDEX IF NOT EXISTS idx_archive_segments_v3_previous
                    ON archive_segments_v3(previous_segment_hash);

                CREATE TABLE IF NOT EXISTS bills_v3 (
                    bill_hash TEXT PRIMARY KEY,
                    token_id TEXT NOT NULL,
                    display_id TEXT,
                    owner_address TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    checkpoint_hash TEXT NOT NULL,
                    proof_bundle_hash TEXT,
                    bill_blob BLOB NOT NULL,
                    first_seen INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    status TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_bills_v3_token_sequence
                    ON bills_v3(token_id, sequence);
                CREATE INDEX IF NOT EXISTS idx_bills_v3_display_id
                    ON bills_v3(display_id);
                CREATE INDEX IF NOT EXISTS idx_bills_v3_owner_status
                    ON bills_v3(owner_address, status);
                CREATE INDEX IF NOT EXISTS idx_bills_v3_owner_updated
                    ON bills_v3(owner_address, updated_at DESC, sequence DESC, token_id DESC);
                CREATE INDEX IF NOT EXISTS idx_bills_v3_owner_status_updated
                    ON bills_v3(owner_address, status, updated_at DESC, sequence DESC, token_id DESC);
                CREATE INDEX IF NOT EXISTS idx_bills_v3_token_sequence_updated
                    ON bills_v3(token_id, sequence DESC, updated_at DESC);
                CREATE INDEX IF NOT EXISTS idx_bills_v3_proof_bundle
                    ON bills_v3(proof_bundle_hash);

                CREATE TABLE IF NOT EXISTS bill_tips_v3 (
                    bill_hash TEXT PRIMARY KEY,
                    token_id TEXT NOT NULL,
                    spend_key TEXT,
                    tip_transfer_hash TEXT,
                    previous_hash TEXT,
                    sequence INTEGER NOT NULL,
                    sender_address TEXT,
                    owner_address TEXT NOT NULL,
                    status TEXT NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_bill_tips_v3_spend
                    ON bill_tips_v3(spend_key, token_id, previous_hash, sequence, sender_address);
                CREATE INDEX IF NOT EXISTS idx_bill_tips_v3_token_sequence
                    ON bill_tips_v3(token_id, sequence DESC, updated_at DESC);

                CREATE TABLE IF NOT EXISTS conflicts_v3 (
                    proof_hash TEXT PRIMARY KEY,
                    conflict_key TEXT NOT NULL,
                    token_id TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    proof_json TEXT NOT NULL,
                    detected_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_conflicts_v3_token ON conflicts_v3(token_id);
                CREATE UNIQUE INDEX IF NOT EXISTS idx_conflicts_v3_key
                    ON conflicts_v3(conflict_key);

                CREATE TABLE IF NOT EXISTS transfer_log_status_v3 (
                    transfer_hash TEXT NOT NULL,
                    token_id TEXT NOT NULL,
                    spend_key TEXT NOT NULL,
                    log_id TEXT NOT NULL,
                    operator_public_key TEXT,
                    status TEXT NOT NULL,
                    entry_hash TEXT,
                    leaf_index INTEGER,
                    tree_size INTEGER,
                    error TEXT,
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY(transfer_hash, log_id)
                );
                CREATE INDEX IF NOT EXISTS idx_transfer_log_status_v3_token
                    ON transfer_log_status_v3(token_id, status);
                CREATE INDEX IF NOT EXISTS idx_transfer_log_status_v3_spend
                    ON transfer_log_status_v3(spend_key);

                CREATE TABLE IF NOT EXISTS transfer_log_retry_v3 (
                    transfer_hash TEXT NOT NULL,
                    log_id TEXT NOT NULL,
                    attempts INTEGER NOT NULL,
                    last_attempt_at INTEGER,
                    next_attempt_at INTEGER NOT NULL,
                    last_error TEXT,
                    terminal INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY(transfer_hash, log_id)
                );
                CREATE INDEX IF NOT EXISTS idx_transfer_log_retry_v3_next
                    ON transfer_log_retry_v3(next_attempt_at, terminal);

                CREATE TABLE IF NOT EXISTS issued_checkpoints_v3 (
                    token_id TEXT PRIMARY KEY,
                    display_id TEXT NOT NULL,
                    owner_address TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    checkpoint_hash TEXT NOT NULL,
                    proof_bundle_hash TEXT,
                    log_id TEXT,
                    operator_public_key TEXT,
                    status TEXT NOT NULL,
                    first_seen INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_issued_checkpoints_v3_display
                    ON issued_checkpoints_v3(display_id);
                """)
            self._set_schema_version(conn, STORE_SCHEMA_VERSION)
        if initial_version < 10:
            try:
                self.rebuild_bill_tips_v3()
            except Exception as exc:
                logger.warning("BillV3 tip-cache backfill failed; cache will rebuild lazily: %s", exc)

    def _schema_version(self, conn):
        try:
            row = conn.execute("PRAGMA user_version").fetchone()
            return int(row[0]) if row else 0
        except Exception:
            return 0

    def _set_schema_version(self, conn, version):
        conn.execute(f"PRAGMA user_version={int(version)}")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ind_schema (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            )
            """)
        conn.execute(
            """
            INSERT OR REPLACE INTO ind_schema(key, value, updated_at)
            VALUES ('schema_version', ?, ?)
            """,
            (str(int(version)), int(time.time())),
        )

    # Run one-way schema migrations before the current tables are ensured.
    def _migrate_db(self, conn):
        version = self._schema_version(conn)
        if version > STORE_SCHEMA_VERSION:
            raise ValidationError(
                f"IND store schema {version} is newer than this client supports ({STORE_SCHEMA_VERSION})"
            )
        if version < STORE_SCHEMA_VERSION:
            logger.info(
                "migrating IND local store schema from %s to %s", version, STORE_SCHEMA_VERSION
            )
        if version < 3:
            self._migrate_conflict_keys(conn)
        if version < 4:
            self._migrate_conflict_burn_status(conn)
        if version < 6:
            self._migrate_native_v3_binary_blobs(conn)
        if version < 7 or self._table_primary_key_columns(conn, "transfer_log_status_v3") not in (
            [],
            ["transfer_hash", "log_id"],
        ):
            self._migrate_transfer_log_status_v3_operator_rows(conn)
        if version < 8:
            self._migrate_receiptless_statuses(conn)
        if version < 9:
            self._migrate_remove_receipt_storage(conn)

    def _table_columns(self, conn, table_name):
        try:
            rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
        except sqlite3.OperationalError:
            return set()
        return {row["name"] if "name" in tuple(row.keys()) else row[1] for row in rows}

    def _table_primary_key_columns(self, conn, table_name):
        try:
            rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
        except sqlite3.OperationalError:
            return []
        pk_rows = []
        for row in rows:
            keys = tuple(row.keys())
            name = row["name"] if "name" in keys else row[1]
            pk_order = row["pk"] if "pk" in keys else row[5]
            if int(pk_order or 0) > 0:
                pk_rows.append((int(pk_order), name))
        return [name for _order, name in sorted(pk_rows)]

    def _migrate_transfer_log_status_v3_operator_rows(self, conn):
        exists = conn.execute("""
            SELECT 1 FROM sqlite_master
            WHERE type = 'table' AND name = 'transfer_log_status_v3'
            """).fetchone()
        if not exists:
            return
        if self._table_primary_key_columns(conn, "transfer_log_status_v3") == [
            "transfer_hash",
            "log_id",
        ]:
            return
        rows = conn.execute("SELECT * FROM transfer_log_status_v3").fetchall()
        conn.execute("ALTER TABLE transfer_log_status_v3 RENAME TO transfer_log_status_v3_legacy")
        conn.execute("""
            CREATE TABLE transfer_log_status_v3 (
                transfer_hash TEXT NOT NULL,
                token_id TEXT NOT NULL,
                spend_key TEXT NOT NULL,
                log_id TEXT NOT NULL,
                operator_public_key TEXT,
                status TEXT NOT NULL,
                entry_hash TEXT,
                leaf_index INTEGER,
                tree_size INTEGER,
                error TEXT,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY(transfer_hash, log_id)
            )
            """)
        for row in rows:
            record = dict(row)
            operator_public_key = str(record.get("operator_public_key") or "").strip()
            log_id = str(record.get("log_id") or "").strip()
            if not log_id and operator_public_key:
                log_id = log_client.log_id_from_public_key(operator_public_key)
            if not log_id:
                log_id = "legacy-single-operator"
            conn.execute(
                """
                INSERT OR REPLACE INTO transfer_log_status_v3(
                    transfer_hash, token_id, spend_key, log_id, operator_public_key,
                    status, entry_hash, leaf_index, tree_size, error, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(record.get("transfer_hash") or "").lower(),
                    record.get("token_id"),
                    record.get("spend_key"),
                    log_id,
                    operator_public_key,
                    record.get("status"),
                    record.get("entry_hash"),
                    record.get("leaf_index"),
                    record.get("tree_size"),
                    record.get("error"),
                    record.get("updated_at"),
                ),
            )
        conn.execute("DROP TABLE transfer_log_status_v3_legacy")

    def _migrate_conflict_keys(self, conn):
        exists = conn.execute("""
            SELECT 1 FROM sqlite_master
            WHERE type = 'table' AND name = 'conflicts'
            """).fetchone()
        if not exists:
            return
        columns = self._table_columns(conn, "conflicts")
        if "conflict_key" not in columns:
            conn.execute("ALTER TABLE conflicts ADD COLUMN conflict_key TEXT")
        rows = conn.execute("""
            SELECT rowid, proof_hash, proof_json FROM conflicts
            WHERE conflict_key IS NULL OR conflict_key = ''
            """).fetchall()
        for row in rows:
            try:
                key = conflict_proof_key(_load_json(row["proof_json"]))
            except Exception as exc:
                logger.warning(
                    "could not derive conflict key for stored proof %s: %s", row["proof_hash"], exc
                )
                key = f"legacy:{row['proof_hash']}"
            conn.execute(
                "UPDATE conflicts SET conflict_key = ? WHERE rowid = ?",
                (key, int(row["rowid"])),
            )
        conn.execute("""
            DELETE FROM conflicts
            WHERE rowid NOT IN (
                SELECT MIN(rowid) FROM conflicts GROUP BY conflict_key
            )
            """)
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_conflicts_key ON conflicts(conflict_key)"
        )

    # Undo legacy conflict burns: settled rows revive, unsettled conflict rows stay rejected.
    def _migrate_conflict_burn_status(self, conn):
        token_columns = self._table_columns(conn, "tokens")
        transfer_columns = self._table_columns(conn, "transfers")
        if {"status", "finalized_at"}.issubset(transfer_columns):
            conn.execute("""
                UPDATE transfers
                SET status = 'settled'
                WHERE status = 'invalid' AND finalized_at IS NOT NULL
                """)
            conn.execute("""
                UPDATE transfers
                SET status = 'rejected'
                WHERE status = 'invalid' AND finalized_at IS NULL
                """)
        if {"status", "finalized_at"}.issubset(token_columns):
            conn.execute("""
                UPDATE tokens
                SET status = 'settled'
                WHERE status = 'invalid' AND finalized_at IS NOT NULL
                """)
            conn.execute("""
                UPDATE tokens
                SET status = 'rejected'
                WHERE status = 'invalid' AND finalized_at IS NULL
                """)

    def _migrate_receiptless_statuses(self, conn):
        for table_name in ("tokens", "transfers", "bills_v3"):
            if "status" not in self._table_columns(conn, table_name):
                continue
            conn.execute(
                f"UPDATE {table_name} SET status = 'verified' WHERE status = 'unreceipted'"
            )

    def _migrate_remove_receipt_storage(self, conn):
        with contextlib.suppress(sqlite3.OperationalError):
            conn.execute("""
                DELETE FROM messages
                WHERE message_type = 'ind.receipt_announcement.v3'
                """)
        with contextlib.suppress(sqlite3.OperationalError):
            conn.execute("DROP TABLE IF EXISTS receipts_v3")

    def _migrate_native_v3_binary_blobs(self, conn):
        native_message_types = (
            TRANSFER_ANNOUNCEMENT_TYPE,
            "ind.proof_bundle_announcement.v3",
            "ind.archive_segment_announcement.v3",
            CONFLICT_PROOF_TYPE,
        )
        for table in (
            "bills_v3",
            "proof_bundles_v3",
            "archive_segments_v3",
            "conflicts_v3",
        ):
            with contextlib.suppress(sqlite3.OperationalError):
                conn.execute(f"DELETE FROM {table}")
        with contextlib.suppress(sqlite3.OperationalError):
            conn.execute(
                f"""
                DELETE FROM messages
                WHERE message_type IN ({",".join("?" for _ in native_message_types)})
                """,
                native_message_types,
            )

    # Retired JSON-bill genesis storage is no longer supported.
    def _store_genesis(self, conn, token, state):
        self._reject_non_v3_bill_protocol("non-V3 genesis storage")

    # Retired JSON-bill manifest compaction is no longer supported.
    def _compact_genesis_for_store(self, conn, genesis):
        self._reject_non_v3_bill_protocol("non-V3 genesis manifest compaction")

    # Retired JSON-bill genesis expansion is no longer supported.
    def _expand_genesis_from_store(self, conn, genesis):
        self._reject_non_v3_bill_protocol("non-V3 genesis expansion")

    # Persist one transparency-backed compact checkpoint.
    def _store_checkpoint(self, conn, checkpoint, status="settled"):
        self._reject_non_v3_bill_protocol("non-V3 checkpoint storage")

    # Resolve an ArchiveSegmentV3 body by content hash for V3 verification.
    def archive_segment_resolver_v3(self, segment_hash):
        return self.get_archive_segment_v3(segment_hash)

    # Resolve a ProofBundleV3 body by content hash for V3 verification.
    def proof_bundle_resolver_v3(self, proof_bundle_hash):
        return self.get_proof_bundle_v3(proof_bundle_hash)

    def _allow_embedded_operator_key_v3(self):
        return (
            not self.require_transparency
            and self.transparency_verifier is None
            and not ind_token._production_mode()
        )

    def _trusted_operator_key_from_proof_bundle_v3(self, proof_bundle):
        if not self._allow_embedded_operator_key_v3() or not isinstance(proof_bundle, dict):
            return None
        signed_root = proof_bundle.get("signed_root")
        if not isinstance(signed_root, dict):
            return None
        return str(signed_root.get("operator_public_key") or "").strip() or None

    def _trusted_operator_key_from_bill_v3(self, bill):
        if not self._allow_embedded_operator_key_v3() or not isinstance(bill, dict):
            return None
        ref = bill.get("proof_bundle_ref")
        if not isinstance(ref, dict):
            return None
        proof_bundle_hash = str(ref.get("proof_bundle_hash") or "").strip()
        if not proof_bundle_hash:
            return None
        return self._trusted_operator_key_from_proof_bundle_v3(
            self.get_proof_bundle_v3(proof_bundle_hash)
        )

    def _archive_segment_hashes_for_proof_bundle_v3(self, bundle, seen=None):
        seen = set(seen or set())
        segment_hash = _source_archive_segment_hash_v3(bundle)
        result = {segment_hash} if segment_hash else set()
        source = bundle.get("source_evidence") if isinstance(bundle, dict) else None
        previous_hash = None
        if isinstance(source, dict):
            previous_hash = str(source.get("previous_proof_bundle_hash") or "").strip().lower()
        if previous_hash and previous_hash not in seen:
            seen.add(previous_hash)
            previous_bundle = self.get_proof_bundle_v3(previous_hash)
            if previous_bundle is not None:
                result.update(
                    self._archive_segment_hashes_for_proof_bundle_v3(
                        previous_bundle,
                        seen=seen,
                    )
                )
        return result

    def _archive_segments_referenced_by_bundle_v3(self, archive_segments, bundle):
        if not archive_segments:
            return []
        referenced = self._archive_segment_hashes_for_proof_bundle_v3(bundle)
        if not referenced:
            return []
        from . import archive_segment_v3

        result = []
        seen = set()
        for segment in archive_segments:
            segment_hash = archive_segment_v3.archive_segment_hash_hex(segment)
            if segment_hash in referenced and segment_hash not in seen:
                result.append(segment)
                seen.add(segment_hash)
        return result

    # Return a stored ArchiveSegmentV3 by segment hash.
    def get_archive_segment_v3(self, segment_hash):
        from . import archive_segment_v3

        with self._connect() as conn:
            row = conn.execute(
                "SELECT segment_blob FROM archive_segments_v3 WHERE segment_hash = ?",
                (str(segment_hash).lower(),),
            ).fetchone()
        if not row:
            return None
        return archive_segment_v3.decode_archive_segment(bytes(row["segment_blob"]))

    # Verify and persist one ArchiveSegmentV3 BLOB.
    def store_archive_segment_v3(self, segment):
        from . import archive_segment_v3

        if isinstance(segment, bytes):
            segment = archive_segment_v3.decode_archive_segment(segment)
        checkpoint = archive_segment_v3.verify_archive_segment(
            segment,
            previous_segment_resolver=self.archive_segment_resolver_v3,
        )
        segment_hash = archive_segment_v3.archive_segment_hash_hex(segment)
        now = int(time.time())
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO archive_segments_v3(
                    segment_hash, token_id, start_sequence, end_sequence,
                    previous_segment_hash, checkpoint_hash, segment_blob, first_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    segment_hash,
                    segment["token_id"],
                    int(segment["start_sequence"]),
                    int(segment["end_sequence"]),
                    segment["previous_segment_hash"],
                    checkpoint["checkpoint_hash"],
                    archive_segment_v3.encode_archive_segment(segment),
                    now,
                ),
            )
            self._store_issued_checkpoint_v3_conn(
                conn,
                checkpoint,
                status="archive_segment",
            )
        return segment_hash

    def _store_issued_checkpoint_v3_conn(
        self,
        conn,
        checkpoint,
        *,
        proof_bundle=None,
        status="verified_checkpoint",
    ):
        signed_root = proof_bundle.get("signed_root") if isinstance(proof_bundle, dict) else {}
        proof_bundle_hash = (
            str(proof_bundle.get("proof_bundle_hash") or "").strip().lower()
            if isinstance(proof_bundle, dict)
            else None
        )
        now = int(time.time())
        existing = conn.execute(
            "SELECT first_seen, status FROM issued_checkpoints_v3 WHERE token_id = ?",
            (str(checkpoint["token_id"]),),
        ).fetchone()
        first_seen = int(existing["first_seen"]) if existing else now
        stored_status = status
        if existing and existing["status"] == "verified_checkpoint":
            stored_status = "verified_checkpoint"
        conn.execute(
            """
            INSERT OR REPLACE INTO issued_checkpoints_v3(
                token_id, display_id, owner_address, sequence, checkpoint_hash,
                proof_bundle_hash, log_id, operator_public_key, status, first_seen, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(checkpoint["token_id"]),
                str(checkpoint["display_id"]),
                str(checkpoint["owner_address"]),
                int(checkpoint["sequence"]),
                str(checkpoint["checkpoint_hash"]),
                proof_bundle_hash,
                str(proof_bundle.get("log_id") or "") if isinstance(proof_bundle, dict) else None,
                str(signed_root.get("operator_public_key") or "").strip() or None,
                stored_status,
                first_seen,
                now,
            ),
        )

    # Return a stored ProofBundleV3 by bundle hash.
    def get_proof_bundle_v3(self, proof_bundle_hash):
        from . import proof_bundle_v3

        with self._connect() as conn:
            row = conn.execute(
                "SELECT bundle_blob FROM proof_bundles_v3 WHERE proof_bundle_hash = ?",
                (str(proof_bundle_hash).lower(),),
            ).fetchone()
        if not row:
            return None
        return proof_bundle_v3.decode_proof_bundle(bytes(row["bundle_blob"]))

    # Verify and persist one ProofBundleV3 BLOB.
    def store_proof_bundle_v3(
        self,
        bundle,
        trusted_operator_public_key=None,
        transparency_verifier=None,
    ):
        from . import proof_bundle_v3

        if isinstance(bundle, bytes):
            bundle = proof_bundle_v3.decode_proof_bundle(bundle)
        source = bundle.get("source_evidence") if isinstance(bundle, dict) else None
        embedded_segment = source.get("archive_segment") if isinstance(source, dict) else None
        if embedded_segment is not None:
            embedded_hash = self.store_archive_segment_v3(embedded_segment)
            if source.get("archive_segment_hash") != embedded_hash:
                raise ValidationError("embedded archive segment hash mismatch")
        verifier = transparency_verifier or self.transparency_verifier
        checkpoint = proof_bundle_v3.verify_proof_bundle(
            bundle,
            transparency_verifier=verifier,
            trusted_operator_public_key=trusted_operator_public_key,
            archive_segment_resolver=self.archive_segment_resolver_v3,
            proof_bundle_resolver=self.proof_bundle_resolver_v3,
        )
        signed_root = bundle["signed_root"]
        now = int(time.time())
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO proof_bundles_v3(
                    proof_bundle_hash, log_id, signed_root_hash, tree_size, algorithm,
                    bundle_blob, first_seen, last_verified
                ) VALUES (
                    ?,
                    ?,
                    ?,
                    ?,
                    ?,
                    ?,
                    COALESCE(
                        (SELECT first_seen FROM proof_bundles_v3 WHERE proof_bundle_hash = ?),
                        ?
                    ),
                    ?
                )
                """,
                (
                    bundle["proof_bundle_hash"],
                    str(bundle["log_id"]),
                    log_client.signed_root_id(signed_root),
                    int(signed_root["tree_size"]),
                    int(bundle["algorithm"]),
                    proof_bundle_v3.encode_proof_bundle(bundle),
                    bundle["proof_bundle_hash"],
                    now,
                    now,
                ),
            )
            self._store_issued_checkpoint_v3_conn(
                conn,
                checkpoint,
                proof_bundle=bundle,
                status="verified_checkpoint",
            )
        return checkpoint

    def _proof_bundle_for_bill_v3(self, bill, proof_bundle=None):
        if proof_bundle is not None:
            return proof_bundle
        ref = bill.get("proof_bundle_ref") if isinstance(bill, dict) else None
        if not isinstance(ref, dict):
            return None
        proof_bundle_hash = str(ref.get("proof_bundle_hash") or "").strip().lower()
        if not proof_bundle_hash:
            return None
        return self.get_proof_bundle_v3(proof_bundle_hash)

    def _checkpoint_due_for_bill_v3(self, bill, force=False):
        recent_transfers = bill.get("recent_transfers") if isinstance(bill, dict) else None
        if not isinstance(recent_transfers, list) or not recent_transfers:
            return False
        if force:
            return True
        if self.high_value_checkpoint_threshold > 0 and int(bill["value"]) >= int(
            self.high_value_checkpoint_threshold
        ):
            return True
        base_sequence = int(bill["checkpoint_core"]["sequence"])
        threshold = (
            self.first_checkpoint_after_transfers
            if base_sequence <= 0
            else self.checkpoint_interval_transfers
        )
        return len(recent_transfers) >= int(threshold)

    def _submit_checkpoint_core_v3(
        self,
        checkpoint_core,
        archive_segment,
        latest_transfer,
        transparency_verifier=None,
    ):
        verifier = transparency_verifier or self.transparency_verifier
        if self.transparency_submitter is None or verifier is None:
            return None
        from . import protocol_v3, spend_map_v3

        expected_hash = checkpoint_core["checkpoint_hash"]
        announcement = protocol_v3.create_checkpoint_announcement(
            checkpoint_core,
            [archive_segment],
        )
        try:
            response = self.transparency_submitter.submit_checkpoint_announcement(announcement)
            if not isinstance(response, dict) or not response.get("accepted"):
                raise ValidationError("transparency log did not accept the V3 checkpoint")
            if str(response.get("entry_hash", "")).lower() != expected_hash:
                raise ValidationError("transparency log appended a different V3 checkpoint hash")
            leaf_index = int(response["leaf_index"])
        except Exception as exc:
            if self.require_transparency:
                raise ValidationError(
                    f"V3 checkpoint transparency submission failed: {exc}"
                ) from exc
            logger.warning(
                "V3 checkpoint transparency submission failed for %s: %s",
                expected_hash,
                exc,
            )
            return None

        timeout = max(0, int(self.transparency_submission_verify_timeout_seconds))
        deadline = time.monotonic() + timeout
        last_error = None
        while True:
            try:
                root = verifier.current_mirrored_root()
                if int(root["tree_size"]) < leaf_index + 1:
                    raise ValidationError(
                        "current transparency root does not contain V3 checkpoint"
                    )
                operator_key = root.get("operator_public_key") or getattr(
                    verifier,
                    "operator_public_key",
                    None,
                )
                inclusion_proof = verifier.operator.inclusion_proof(
                    expected_hash,
                    int(root["tree_size"]),
                )
                log_client.verify_inclusion_proof(
                    expected_hash,
                    inclusion_proof,
                    root,
                    operator_public_key=operator_key,
                )
                spend_proof = verifier.operator.spend_map_proof(
                    protocol_v3.spend_key_for_transfer(latest_transfer),
                    int(root["tree_size"]),
                )
                log_client.verify_spend_map_proof_for_transfer(
                    latest_transfer,
                    spend_proof,
                    root,
                    operator_public_key=operator_key,
                )
                compressed_spend_proof = spend_map_v3.compress_spend_map_proof(
                    spend_proof,
                    network_id=checkpoint_core["network_id"],
                )
                return {
                    "signed_root": root,
                    "checkpoint_inclusion_proof": inclusion_proof,
                    "compressed_spend_map_proof": compressed_spend_proof,
                }
            except Exception as exc:
                last_error = exc
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                time.sleep(min(1.0, remaining))
        if self.require_transparency:
            raise ValidationError(
                f"V3 checkpoint transparency proof was not available before timeout: {last_error}"
            )
        logger.warning(
            "V3 checkpoint transparency proof was not available for %s: %s",
            expected_hash,
            last_error,
        )
        return None

    def _compact_bill_v3(
        self,
        bill,
        proof_bundle=None,
        status="settled",
        force=False,
        require_proof=False,
        trusted_operator_public_key=None,
        transparency_verifier=None,
    ):
        from . import archive_segment_v3, proof_bundle_v3, protocol_v3

        if isinstance(bill, bytes):
            bill = protocol_v3.decode_bill(bill)
        if not self._checkpoint_due_for_bill_v3(bill, force=force):
            return bill if force and not bill.get("recent_transfers") else None
        verifier = transparency_verifier or self.transparency_verifier
        if self.transparency_submitter is None or verifier is None:
            if require_proof:
                raise ValidationError(
                    "native V3 compaction requires a transparency submitter and verifier"
                )
            return None
        proof_bundle = self._proof_bundle_for_bill_v3(bill, proof_bundle=proof_bundle)
        if proof_bundle is None:
            if require_proof:
                raise ValidationError("native V3 compaction requires the current proof bundle")
            return None
        state = protocol_v3.verify_bill(
            bill,
            proof_bundle=proof_bundle,
            proof_bundle_resolver=self.proof_bundle_resolver_v3,
            transparency_verifier=verifier,
            trusted_operator_public_key=trusted_operator_public_key,
            archive_segment_resolver=self.archive_segment_resolver_v3,
        )
        base_core = bill["checkpoint_core"]
        previous_segment_hash = None
        previous_checkpoint_hash = None
        previous_proof_bundle_hash = None
        if int(base_core["sequence"]) > 0:
            previous_segment_hash = _source_archive_segment_hash_v3(proof_bundle)
            if not previous_segment_hash:
                if require_proof:
                    raise ValidationError("current V3 proof bundle has no archive segment source")
                return None
            previous_checkpoint_hash = base_core["checkpoint_hash"]
            previous_proof_bundle_hash = bill["proof_bundle_ref"]["proof_bundle_hash"]
        archive_segment = archive_segment_v3.make_archive_segment(
            bill["token_id"],
            bill["genesis_ref"],
            protocol_v3._initial_state_from_checkpoint_core(base_core),
            bill["recent_transfers"],
            previous_segment_hash=previous_segment_hash,
            previous_checkpoint_hash=previous_checkpoint_hash,
            network_id=bill["network_id"],
        )
        checkpoint_core = archive_segment_v3.verify_archive_segment(
            archive_segment,
            expected_network_id=bill["network_id"],
            previous_segment_resolver=self.archive_segment_resolver_v3,
        )
        if checkpoint_core["last_transfer_hash"] != state.last_transfer_hash:
            raise ValidationError("V3 compact checkpoint does not match bill tip")
        proof_material = self._submit_checkpoint_core_v3(
            checkpoint_core,
            archive_segment,
            bill["recent_transfers"][-1],
            transparency_verifier=verifier,
        )
        if proof_material is None:
            if require_proof:
                raise ValidationError("native V3 compact checkpoint was not proven")
            return None
        self.store_archive_segment_v3(archive_segment)
        source_evidence = proof_bundle_v3.make_archive_segment_evidence(
            archive_segment,
            network_id=bill["network_id"],
            include_segment=False,
            previous_proof_bundle_hash=previous_proof_bundle_hash,
            previous_segment_resolver=self.archive_segment_resolver_v3,
        )
        compact_bundle = proof_bundle_v3.make_proof_bundle(
            checkpoint_core,
            proof_material["signed_root"],
            proof_material["checkpoint_inclusion_proof"],
            proof_material["compressed_spend_map_proof"],
            source_evidence,
            network_id=bill["network_id"],
            created_at=int(time.time()),
        )
        self.store_proof_bundle_v3(
            compact_bundle,
            trusted_operator_public_key=trusted_operator_public_key,
            transparency_verifier=verifier,
        )
        compact_bill = protocol_v3.create_bill_from_checkpoint_core(
            bill["genesis_ref"],
            checkpoint_core,
            compact_bundle,
            recent_transfers=[],
            network_id=bill["network_id"],
            transparency_verifier=verifier,
            trusted_operator_public_key=trusted_operator_public_key,
            archive_segment_resolver=self.archive_segment_resolver_v3,
            proof_bundle_resolver=self.proof_bundle_resolver_v3,
        )
        compact_state = protocol_v3.verify_bill(
            compact_bill,
            proof_bundle=compact_bundle,
            proof_bundle_resolver=self.proof_bundle_resolver_v3,
            transparency_verifier=verifier,
            trusted_operator_public_key=trusted_operator_public_key,
            archive_segment_resolver=self.archive_segment_resolver_v3,
        )
        with self._connect() as conn:
            self._store_bill_v3_conn(conn, compact_bill, compact_state, status)
        return compact_bill

    def _maybe_compact_bill_v3(
        self,
        bill,
        proof_bundle=None,
        status="settled",
        trusted_operator_public_key=None,
        transparency_verifier=None,
    ):
        try:
            return self._compact_bill_v3(
                bill,
                proof_bundle=proof_bundle,
                status=status,
                force=False,
                require_proof=False,
                trusted_operator_public_key=trusted_operator_public_key,
                transparency_verifier=transparency_verifier,
            )
        except Exception as exc:
            logger.warning("automatic native V3 compaction failed: %s", exc)
            return None

    def _bill_tip_record_v3(self, bill, state, status, bill_hash_value=None, updated_at=None):
        from . import protocol_v3

        if isinstance(bill, bytes):
            bill = protocol_v3.decode_bill(bill)
        bill_hash_value = bill_hash_value or protocol_v3.bill_hash(bill).hex()
        updated_at = int(updated_at if updated_at is not None else time.time())
        transfers = bill.get("recent_transfers") if isinstance(bill, dict) else None
        tip = transfers[-1] if transfers else None
        spend_key = None
        tip_transfer_hash = None
        previous_hash = None
        sender_address = None
        if tip is not None:
            spend_key = protocol_v3.spend_key_for_transfer(tip)
            tip_transfer_hash = protocol_v3.transfer_hash(tip)
            previous_hash = tip["previous_hash"]
            sender_address = tip["sender_address"]
        return {
            "bill_hash": bill_hash_value,
            "token_id": state.token_id,
            "spend_key": spend_key,
            "tip_transfer_hash": tip_transfer_hash,
            "previous_hash": previous_hash,
            "sequence": int(state.sequence),
            "sender_address": sender_address,
            "owner_address": state.owner_address,
            "status": str(status),
            "updated_at": updated_at,
        }

    def _store_bill_tip_v3_conn(self, conn, bill, state, status, bill_hash_value=None, updated_at=None):
        record = self._bill_tip_record_v3(
            bill,
            state,
            status,
            bill_hash_value=bill_hash_value,
            updated_at=updated_at,
        )
        conn.execute(
            """
            INSERT OR REPLACE INTO bill_tips_v3(
                bill_hash, token_id, spend_key, tip_transfer_hash, previous_hash,
                sequence, sender_address, owner_address, status, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record["bill_hash"],
                record["token_id"],
                record["spend_key"],
                record["tip_transfer_hash"],
                record["previous_hash"],
                int(record["sequence"]),
                record["sender_address"],
                record["owner_address"],
                record["status"],
                int(record["updated_at"]),
            ),
        )
        return record

    def rebuild_bill_tips_v3(self, *, verify=True, limit=None):
        """Rebuild the local BillV3 tip cache from stored bills.

        This table is an index/cache only. Deleting or rebuilding it must never
        change which bills are accepted; it only affects lookup speed.
        """

        from . import protocol_v3

        params = []
        limit_clause = ""
        if limit is not None:
            limit_clause = " LIMIT ?"
            params.append(max(0, int(limit)))
        rebuilt = 0
        skipped = 0
        with self._connect() as conn:
            if limit is None:
                conn.execute("DELETE FROM bill_tips_v3")
            rows = conn.execute(
                f"""
                SELECT bill_hash, bill_blob, status
                FROM bills_v3
                ORDER BY updated_at DESC{limit_clause}
                """,
                params,
            ).fetchall()
            for row in rows:
                try:
                    bill = protocol_v3.decode_bill(bytes(row["bill_blob"]))
                    if verify:
                        state = protocol_v3.verify_bill(
                            bill,
                            proof_bundle_resolver=self.proof_bundle_resolver_v3,
                            transparency_verifier=self.transparency_verifier,
                            trusted_operator_public_key=self._trusted_operator_key_from_bill_v3(bill),
                            archive_segment_resolver=self.archive_segment_resolver_v3,
                        )
                    else:
                        base_state = protocol_v3._initial_state_from_checkpoint_core(
                            bill["checkpoint_core"]
                        )
                        materialized_state = protocol_v3.verify_transfer_sequence_from_state(
                            bill["token_id"],
                            base_state,
                            bill.get("recent_transfers") or [],
                            network_id=int(bill.get("network_id", protocol_v3.DEFAULT_NETWORK_ID)),
                        )
                        state = protocol_v3._token_state_from_v3_state(
                            bill["token_id"], materialized_state
                        )
                    self._store_bill_tip_v3_conn(
                        conn,
                        bill,
                        state,
                        row["status"],
                        bill_hash_value=row["bill_hash"],
                    )
                    rebuilt += 1
                except Exception:
                    skipped += 1
                    logger.debug("skipping BillV3 during tip-cache rebuild", exc_info=True)
        return {"rebuilt": rebuilt, "skipped": skipped}

    def repair_bill_tips_v3(self, **kwargs):
        return self.rebuild_bill_tips_v3(**kwargs)

    def _store_bill_v3_conn(self, conn, bill, state, status):
        from . import protocol_v3

        now = int(time.time())
        bill_hash_value = protocol_v3.bill_hash(bill).hex()
        proof_bundle_hash_value = bill["proof_bundle_ref"]["proof_bundle_hash"]
        existing = conn.execute(
            "SELECT first_seen, sequence, status FROM bills_v3 WHERE bill_hash = ?",
            (bill_hash_value,),
        ).fetchone()
        first_seen = int(existing["first_seen"]) if existing else now
        stored_status = _stronger_bill_v3_status(
            existing["status"] if existing else None,
            status,
        )
        conn.execute(
            """
            INSERT OR REPLACE INTO bills_v3(
                bill_hash, token_id, display_id, owner_address, sequence,
                checkpoint_hash, proof_bundle_hash, bill_blob, first_seen, updated_at, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                bill_hash_value,
                state.token_id,
                state.display_id,
                state.owner_address,
                int(state.sequence),
                bill["checkpoint_core"]["checkpoint_hash"],
                proof_bundle_hash_value,
                protocol_v3.encode_bill(bill),
                first_seen,
                now,
                stored_status,
            ),
        )
        self._store_bill_tip_v3_conn(
            conn,
            bill,
            state,
            stored_status,
            bill_hash_value=bill_hash_value,
            updated_at=now,
        )
        return bill_hash_value

    # Verify and persist one BillV3 BLOB.
    def store_bill_v3(
        self,
        bill,
        proof_bundle=None,
        status="verified",
        trusted_operator_public_key=None,
        transparency_verifier=None,
    ):
        from . import protocol_v3

        if isinstance(bill, bytes):
            bill = protocol_v3.decode_bill(bill)
        if proof_bundle is not None:
            self.store_proof_bundle_v3(
                proof_bundle,
                trusted_operator_public_key=trusted_operator_public_key,
                transparency_verifier=transparency_verifier,
            )
        verifier = transparency_verifier or self.transparency_verifier
        state = protocol_v3.verify_bill(
            bill,
            proof_bundle=proof_bundle,
            proof_bundle_resolver=self.proof_bundle_resolver_v3,
            transparency_verifier=verifier,
            trusted_operator_public_key=trusted_operator_public_key,
            archive_segment_resolver=self.archive_segment_resolver_v3,
        )
        with self._connect() as conn:
            bill_hash_value = self._store_bill_v3_conn(conn, bill, state, status)
        if status in {"settled", "verified"}:
            self._maybe_compact_bill_v3(
                bill,
                proof_bundle=proof_bundle,
                status=status,
                trusted_operator_public_key=trusted_operator_public_key,
                transparency_verifier=verifier,
            )
        return bill_hash_value

    # Persist one locally-created BillV3 tip from an already-cached wallet state.
    def store_cached_bill_v3(self, bill, state, status="verified"):
        from . import protocol_v3

        if isinstance(bill, bytes):
            bill = protocol_v3.decode_bill(bill)
        if isinstance(state, dict):
            state = protocol_v3._token_state_from_v3_state(bill["token_id"], state)
        with self._connect() as conn:
            return self._store_bill_v3_conn(conn, bill, state, status)

    # Return a stored BillV3 by bill hash.
    def get_bill_v3(self, bill_hash):
        from . import protocol_v3

        with self._connect() as conn:
            row = conn.execute(
                "SELECT bill_blob FROM bills_v3 WHERE bill_hash = ?",
                (str(bill_hash).lower(),),
            ).fetchone()
        if not row:
            return None
        return protocol_v3.decode_bill(bytes(row["bill_blob"]))

    # Return the newest stored BillV3 for a token id.
    def get_bill_v3_by_token_id(self, token_id):
        from . import protocol_v3

        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT bill_blob FROM bills_v3
                WHERE token_id = ?
                ORDER BY sequence DESC, LENGTH(bill_blob) ASC, updated_at DESC
                LIMIT 1
                """,
                (str(token_id),),
            ).fetchone()
        if not row:
            return None
        return protocol_v3.decode_bill(bytes(row["bill_blob"]))

    # Return the newest stored BillV3 for a wallet display id.
    def get_bill_v3_by_display_id(self, display_id):
        from . import protocol_v3

        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT bill_blob FROM bills_v3
                WHERE display_id = ?
                ORDER BY sequence DESC, LENGTH(bill_blob) ASC, updated_at DESC
                LIMIT 1
                """,
                (str(display_id),),
            ).fetchone()
        if not row:
            return None
        return protocol_v3.decode_bill(bytes(row["bill_blob"]))

    # Return a stored BillV3 for a wallet display id at one exact sequence.
    def get_bill_v3_by_display_id_sequence(self, display_id, sequence):
        from . import protocol_v3

        try:
            sequence = int(sequence)
        except (TypeError, ValueError):
            return None
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT bill_blob FROM bills_v3
                WHERE display_id = ? AND sequence = ?
                ORDER BY LENGTH(bill_blob) ASC, updated_at DESC
                LIMIT 1
                """,
                (str(display_id), sequence),
            ).fetchone()
        if not row:
            return None
        return protocol_v3.decode_bill(bytes(row["bill_blob"]))

    # Remove one local, not-yet-settled BillV3 tip created for a cancelled outbound send.
    def discard_unsettled_bill_v3(
        self,
        bill_hash,
        *,
        display_id=None,
        owner_address=None,
        sequence=None,
    ):
        bill_hash = str(bill_hash or "").lower().strip()
        if not bill_hash:
            return False
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT display_id, owner_address, sequence, status
                FROM bills_v3
                WHERE bill_hash = ?
                """,
                (bill_hash,),
            ).fetchone()
            if not row or row["status"] == "settled":
                return False
            if display_id is not None and str(row["display_id"]) != str(display_id):
                return False
            if owner_address is not None and str(row["owner_address"]) != str(owner_address):
                return False
            if sequence is not None and int(row["sequence"]) != int(sequence):
                return False
            conn.execute(
                """
                DELETE FROM bills_v3
                WHERE bill_hash = ? AND status IN ('pending', 'verified')
                """,
                (bill_hash,),
            )
            deleted = int(conn.execute("SELECT changes() AS count_value").fetchone()["count_value"])
            if deleted:
                conn.execute("DELETE FROM bill_tips_v3 WHERE bill_hash = ?", (bill_hash,))
            return bool(deleted)

    def _bill_v3_row_tip_transfer_hash(self, row):
        from . import protocol_v3

        try:
            bill = protocol_v3.decode_bill(bytes(row["bill_blob"]))
        except Exception:
            return ""
        transfers = bill.get("recent_transfers") if isinstance(bill, dict) else None
        if not transfers:
            return ""
        return protocol_v3.transfer_hash(transfers[-1])

    def _newer_v3_branch_is_materialized_conn(self, conn, row):
        return str(row["status"]) in {"pending", "settled", "verified"}

    def _has_materialized_newer_v3_branch_conn(self, conn, token_id, sequence):
        row = conn.execute(
            """
            SELECT 1 FROM bills_v3
            WHERE token_id = ?
              AND sequence > ?
              AND status IN ('pending', 'settled', 'verified')
            LIMIT 1
            """,
            (str(token_id), int(sequence)),
        ).fetchone()
        return row is not None

    def spendable_bill_v3_statuses(self):
        if self.settlement_quorum_enabled:
            return ("settled",)
        return ("settled", "verified")

    # Return the newest locally spendable BillV3 for an owner/display id pair.
    def get_spendable_bill_v3_by_display_id(self, display_id, owner_address):
        from . import protocol_v3

        statuses = self.spendable_bill_v3_statuses()
        placeholders = ",".join("?" for _ in statuses)
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT * FROM bills_v3
                WHERE display_id = ?
                  AND owner_address = ?
                  AND status IN ({placeholders})
                ORDER BY sequence DESC,
                         CASE status WHEN 'settled' THEN 3 WHEN 'verified' THEN 2 ELSE 1 END DESC,
                         LENGTH(bill_blob) ASC, updated_at DESC
                """,
                (str(display_id), str(owner_address), *statuses),
            ).fetchall()
            for row in rows:
                if self._has_materialized_newer_v3_branch_conn(
                    conn,
                    row["token_id"],
                    int(row["sequence"]),
                ):
                    continue
                return protocol_v3.decode_bill(bytes(row["bill_blob"]))
        return None

    # Return display ids from a batch that currently have spendable local tips.
    def spendable_bill_v3_display_ids(self, owner_address, display_ids):
        display_ids = [str(display_id).strip() for display_id in display_ids if str(display_id).strip()]
        if not display_ids:
            return set()
        found = set()
        chunk_size = 800
        statuses = self.spendable_bill_v3_statuses()
        status_placeholders = ",".join("?" for _ in statuses)
        with self._connect() as conn:
            for offset in range(0, len(display_ids), chunk_size):
                chunk = display_ids[offset : offset + chunk_size]
                placeholders = ",".join("?" for _ in chunk)
                rows = conn.execute(
                    f"""
                    SELECT display_id, token_id, sequence
                    FROM bills_v3
                    WHERE owner_address = ?
                      AND status IN ({status_placeholders})
                      AND display_id IN ({placeholders})
                    ORDER BY display_id, sequence DESC,
                             CASE status WHEN 'settled' THEN 3 WHEN 'verified' THEN 2 ELSE 1 END DESC,
                             LENGTH(bill_blob) ASC, updated_at DESC
                    """,
                    (str(owner_address), *statuses, *chunk),
                ).fetchall()
                for row in rows:
                    display_id = str(row["display_id"])
                    if display_id in found:
                        continue
                    if self._has_materialized_newer_v3_branch_conn(
                        conn,
                        row["token_id"],
                        int(row["sequence"]),
                    ):
                        continue
                    found.add(display_id)
        return found

    # List stored BillV3 records for one owner address.
    def bill_v3_records_for_owner(self, owner_address, statuses=None, limit=1000, offset=0):
        statuses = tuple(statuses or ("verified", "settled", "pending"))
        placeholders = ",".join("?" for _ in statuses)
        params = [owner_address, *statuses]
        limit_clause = ""
        if limit is not None:
            limit_clause = "LIMIT ?"
            params.append(int(limit))
            if offset:
                limit_clause += " OFFSET ?"
                params.append(int(offset))
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT * FROM bills_v3
                WHERE owner_address = ? AND status IN ({placeholders})
                ORDER BY updated_at DESC
                {limit_clause}
                """,
                params,
            ).fetchall()
            records = []
            for row in rows:
                record = dict(row)
                if not _bill_v3_record_has_allowed_value(record):
                    continue
                if record["status"] in {
                    "settled",
                    "verified",
                } and self._has_materialized_newer_v3_branch_conn(
                    conn, record["token_id"], int(record["sequence"])
                ):
                    continue
                records.append(record)
        return records

    # List lightweight BillV3 row metadata for one owner without loading bill blobs.
    def bill_v3_metadata_records_for_owner(self, owner_address, statuses=None, limit=None, offset=0):
        statuses = tuple(statuses or ("verified", "settled", "pending"))
        placeholders = ",".join("?" for _ in statuses)
        params = [str(owner_address), *statuses]
        limit_clause = ""
        if limit is not None:
            limit_clause = "LIMIT ?"
            params.append(int(limit))
            if offset:
                limit_clause += " OFFSET ?"
                params.append(int(offset))
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT bill_hash, token_id, display_id, owner_address, sequence, status,
                       first_seen, updated_at
                FROM bills_v3
                WHERE owner_address = ? AND status IN ({placeholders})
                ORDER BY updated_at DESC
                {limit_clause}
                """,
                params,
            ).fetchall()
            records = []
            for row in rows:
                record = dict(row)
                if not _bill_v3_record_has_supported_display_id(record):
                    continue
                if record["status"] in {
                    "settled",
                    "verified",
                } and self._has_materialized_newer_v3_branch_conn(
                    conn, record["token_id"], int(record["sequence"])
                ):
                    continue
                records.append(record)
        return records

    # Count locally visible BillV3 rows for one owner without loading bill blobs.
    def bill_v3_count_records_for_owner(self, owner_address, statuses=None):
        return self.bill_v3_metadata_records_for_owner(owner_address, statuses=statuses)

    # Verify and persist one ConflictProofV3.
    def store_conflict_proof_v3(self, proof, expected_network_id=None):
        with self._connect() as conn:
            record = self._store_conflict_proof_v3_conn(
                conn,
                proof,
                expected_network_id=expected_network_id,
            )
        return record["proof_hash"]

    def _latest_checkpoint_row(self, conn, token_id):
        return conn.execute(
            """
            SELECT checkpoint_json FROM checkpoints
            WHERE token_id = ? AND status = 'settled'
            ORDER BY sequence DESC, created_at DESC
            LIMIT 1
            """,
            (token_id,),
        ).fetchone()

    def _latest_checkpoint_sequence(self, conn, token_id):
        row = self._latest_checkpoint_row(conn, token_id)
        if not row:
            return 0
        try:
            return int(_load_json(row["checkpoint_json"])["sequence"])
        except Exception:
            return 0

    def _checkpoint_for_transfer(self, conn, token_id, last_transfer_hash):
        return conn.execute(
            """
            SELECT checkpoint_json FROM checkpoints
            WHERE token_id = ? AND last_transfer_hash = ? AND status = 'settled'
            ORDER BY sequence DESC, created_at DESC
            LIMIT 1
            """,
            (token_id, last_transfer_hash),
        ).fetchone()

    def _checkpoint_before_sequence(self, conn, token_id, sequence):
        return conn.execute(
            """
            SELECT checkpoint_json FROM checkpoints
            WHERE token_id = ? AND status = 'settled' AND sequence < ?
            ORDER BY sequence DESC, created_at DESC
            LIMIT 1
            """,
            (token_id, int(sequence)),
        ).fetchone()

    def _checkpoint_at_or_before_sequence(self, conn, token_id, sequence):
        return conn.execute(
            """
            SELECT checkpoint_json FROM checkpoints
            WHERE token_id = ? AND status = 'settled' AND sequence <= ?
            ORDER BY sequence DESC, created_at DESC
            LIMIT 1
            """,
            (token_id, int(sequence)),
        ).fetchone()

    def _compact_bill_from_checkpoint_row(self, conn, token_id, row):
        if not row:
            return None
        genesis_row = conn.execute(
            "SELECT genesis_json FROM token_genesis WHERE token_id = ?",
            (token_id,),
        ).fetchone()
        if not genesis_row:
            return None
        genesis = self._expand_genesis_from_store(conn, _load_json(genesis_row["genesis_json"]))
        checkpoint = _load_json(row["checkpoint_json"])
        return {
            "type": BILL_TYPE,
            "version": BILL_VERSION,
            "token_id": token_id,
            "genesis": genesis,
            "checkpoint": checkpoint,
            "recent_history": [],
        }

    def _compact_bill_from_latest_checkpoint(self, conn, token_id):
        return self._compact_bill_from_checkpoint_row(
            conn, token_id, self._latest_checkpoint_row(conn, token_id)
        )

    def _compact_bill_for_sequence(self, conn, token_id, sequence):
        checkpoint_row = self._checkpoint_at_or_before_sequence(conn, token_id, sequence)
        bill = self._compact_bill_from_checkpoint_row(conn, token_id, checkpoint_row)
        if not bill:
            return None
        transfer_rows = conn.execute(
            """
            SELECT transfer_json FROM transfers
            WHERE token_id = ? AND sequence > ? AND sequence <= ?
            ORDER BY sequence ASC
            """,
            (
                token_id,
                int(bill["checkpoint"]["sequence"]),
                int(sequence),
            ),
        ).fetchall()
        bill["recent_history"] = [_load_json(item["transfer_json"]) for item in transfer_rows]
        return bill

    def _bill_for_settled_transfer_row(self, conn, row):
        full = self._rebuild_token_from_store(
            conn,
            row["token_id"],
            row["transfer_hash"],
            int(row["sequence"]),
        )
        if full:
            return full
        return self._compact_bill_for_sequence(conn, row["token_id"], int(row["sequence"]))

    # Reconstruct a full bearer bill from normalized genesis and transfer rows.
    def _rebuild_token_from_store(self, conn, token_id, last_transfer_hash=None, sequence=None):
        self._reject_non_v3_bill_protocol("non-V3 token rebuild")

    # Resolve either a compact state reference or a full bill payload.
    def _token_from_payload(self, conn, payload, token_id=None):
        data = _load_json(payload)
        if isinstance(data, dict) and data.get("type") == TOKEN_STATE_REF_TYPE:
            rebuilt = self._rebuild_token_from_store(
                conn,
                data["token_id"],
                data.get("last_transfer_hash"),
                data.get("sequence"),
            )
            if rebuilt:
                return rebuilt
            return self._compact_bill_for_sequence(
                conn, data["token_id"], int(data.get("sequence", 0))
            )
        if isinstance(data, dict) and data.get("type") in {TOKEN_TYPE, BILL_TYPE}:
            return data
        if token_id:
            return self._rebuild_token_from_store(conn, token_id)
        return None

    # Store gossip messages as compact references when the bill is already known.
    def _stored_message_payload(self, message, state=None):
        if (
            state
            and message.get("type")
            in {
                TRANSFER_ANNOUNCEMENT_V3_TYPE,
            }
            and ("payload_encoding" in message or "network_id" in message)
        ):
            return message
        if state and message.get("type") in {
            TRANSFER_ANNOUNCEMENT_TYPE,
            TRANSFER_ANNOUNCEMENT_V3_TYPE,
        }:
            ref = {
                "type": STORED_MESSAGE_REF_TYPE,
                "version": TOKEN_VERSION,
                "message_type": message["type"],
                "token_id": state.token_id,
                "recipient_address": state.owner_address,
                "last_transfer_hash": state.last_transfer_hash,
                "sequence": int(state.sequence),
                "announced_at": int(message.get("announced_at", time.time())),
            }
            return ref
        return message

    # Expand a stored message reference back into the wire-level gossip object.
    def _expand_stored_message(self, conn, stored_payload):
        message = _load_json(stored_payload)
        if not isinstance(message, dict) or message.get("type") != STORED_MESSAGE_REF_TYPE:
            return message

        if message["message_type"] == TRANSFER_ANNOUNCEMENT_V3_TYPE:
            target_sequence = int(message.get("sequence", 0))
            checkpoint_row = self._checkpoint_before_sequence(
                conn, message["token_id"], target_sequence
            )
            token = self._compact_bill_from_checkpoint_row(
                conn, message["token_id"], checkpoint_row
            )
            if token:
                transfer_rows = conn.execute(
                    """
                    SELECT transfer_hash, transfer_json FROM transfers
                    WHERE token_id = ? AND sequence > ?
                    ORDER BY sequence ASC
                    """,
                    (message["token_id"], int(token["checkpoint"]["sequence"])),
                ).fetchall()
                recent = [_load_json(row["transfer_json"]) for row in transfer_rows]
                token["recent_history"] = [
                    transfer for transfer in recent if int(transfer["sequence"]) <= target_sequence
                ]
        else:
            token = self._rebuild_token_from_store(
                conn,
                message["token_id"],
                message.get("last_transfer_hash"),
                message.get("sequence"),
            )
        if not token:
            return None
        if message["message_type"] == TRANSFER_ANNOUNCEMENT_TYPE:
            expanded = {
                "type": TRANSFER_ANNOUNCEMENT_TYPE,
                "version": TOKEN_VERSION,
                "token": token,
                "announced_at": int(message.get("announced_at", time.time())),
            }
            return expanded
        if message["message_type"] == TRANSFER_ANNOUNCEMENT_V3_TYPE:
            return {
                "type": TRANSFER_ANNOUNCEMENT_V3_TYPE,
                "version": BILL_VERSION,
                "bill": token,
                "announced_at": int(message.get("announced_at", time.time())),
            }
        return None

    # Persist a deduplicated gossip message and return its canonical hash.
    def _record_message(self, conn, message, state=None):
        mh = message_hash(message)
        token_id = state.token_id if state else message.get("token_id")
        recipient_address = state.owner_address if state else None
        stored_payload = self._stored_message_payload(message, state)
        conn.execute(
            """
            INSERT OR IGNORE INTO messages(
                message_hash, message_type, token_id, recipient_address, message_json, first_seen
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                mh,
                message["type"],
                token_id,
                recipient_address,
                _store_json(stored_payload),
                int(time.time()),
            ),
        )
        return mh

    # Submit a validated transfer announcement to the configured public log.
    def _submit_to_transparency_log(self, message, token):
        if not self.transparency_submitter or message.get("type") not in {
            TRANSFER_ANNOUNCEMENT_TYPE,
            TRANSFER_ANNOUNCEMENT_V3_TYPE,
        }:
            return None
        latest_transfer = _last_transfer(token)
        expected_entry_hash = transfer_hash(latest_transfer)
        try:
            response = self.transparency_submitter.submit_transfer_announcement(message)
            leaf_index, _tree_size = self._validate_transparency_append_response(
                response,
                expected_entry_hash,
                log_client.spend_key_for_transfer(latest_transfer),
            )
            if self.transparency_verifier is None:
                raise ValidationError(
                    "transparency submission cannot be verified without root mirrors"
                )
            self._verify_transparency_submission(token, expected_entry_hash, leaf_index)
            return response
        except Exception as exc:
            if "conflicting spend" in str(exc).lower():
                raise ValidationError(
                    f"transparency log rejected conflicting transfer: {exc}"
                ) from exc
            if self.require_transparency:
                raise ValidationError(f"transparency log submission failed: {exc}") from exc
            logger.warning(
                "transparency log submission failed for %s: %s", expected_entry_hash, exc
            )
            return {"accepted": False, "status": "unlogged", "error": str(exc)}

    def _proof_bundle_operator_identity_v3(self, proof_bundle):
        if not isinstance(proof_bundle, dict):
            return {"log_id": "", "operator_public_key": ""}
        signed_root = proof_bundle.get("signed_root")
        if not isinstance(signed_root, dict):
            signed_root = {}
        return {
            "log_id": str(proof_bundle.get("log_id") or signed_root.get("log_id") or "").strip(),
            "operator_public_key": str(signed_root.get("operator_public_key") or "").strip(),
        }

    def _verifier_for_proof_bundle_v3(self, proof_bundle):
        verifier = self.transparency_verifier
        if verifier is None or not isinstance(proof_bundle, dict):
            return verifier
        selector = getattr(verifier, "verifier_for_signed_root", None)
        if callable(selector):
            return selector(proof_bundle["signed_root"])
        return verifier

    def _operator_identity_from_response_v3(self, response=None, operator_identity=None):
        identity = dict(operator_identity or {})
        response = response or {}
        response_log_id = ""
        response_public_key = ""
        if isinstance(response, dict):
            response_log_id = str(response.get("log_id") or "").strip()
            response_public_key = str(response.get("operator_public_key") or "").strip()
        operator_public_key = str(
            identity.get("operator_public_key") or response_public_key
        ).strip()
        log_id = str(identity.get("log_id") or response_log_id).strip()
        if not log_id and operator_public_key:
            log_id = log_client.log_id_from_public_key(operator_public_key)
        if not log_id:
            log_id = "single-operator"
        return {"log_id": log_id, "operator_public_key": operator_public_key}

    def _append_operator_identities_v3(self):
        submitter = self.transparency_submitter
        if submitter is None:
            return []
        identities_method = getattr(submitter, "operator_identities", None)
        if callable(identities_method):
            identities = identities_method()
        else:
            identities = [log_client.operator_identity(submitter)]
        deduped = []
        seen = set()
        for identity in identities:
            normalized = self._operator_identity_from_response_v3(operator_identity=identity)
            key = normalized["log_id"]
            if key in seen or key == "single-operator":
                continue
            seen.add(key)
            deduped.append(normalized)
        return deduped

    def _validate_operator_finality_policy_v3(self):
        if not self.require_transparency:
            return
        operator_count = self._append_operator_target_count_v3()
        configured = int(self.operator_finality_min_proofs or 0)
        if operator_count > 0 and configured and configured > operator_count:
            raise ValidationError(
                "IND_OPERATOR_FINALITY_MIN_PROOFS must not exceed the selected "
                "append-capable operator fanout; use 0 to derive the threshold"
            )

    def _append_operator_target_count_v3(self):
        submitter = self.transparency_submitter
        if submitter is None:
            return 0
        target_method = getattr(submitter, "operator_append_target_count", None)
        if callable(target_method):
            return int(target_method())
        return len(self._append_operator_identities_v3())

    def _operator_finality_required_proofs_v3(self):
        configured = int(self.operator_finality_min_proofs or 0)
        if configured > 0:
            return configured
        operator_count = self._append_operator_target_count_v3()
        if operator_count <= 0:
            return 1
        return operator_count // 2 + 1

    def _submit_v3_transfer_to_all_operators(self, message):
        if self.transparency_submitter is None:
            return []
        submit_all = getattr(
            self.transparency_submitter, "submit_transfer_announcement_to_all", None
        )
        if callable(submit_all):
            return submit_all(message)
        identity = log_client.operator_identity(self.transparency_submitter)
        try:
            response = self.transparency_submitter.submit_transfer_announcement(message)
            return [
                {
                    **self._operator_identity_from_response_v3(
                        response=response,
                        operator_identity=identity,
                    ),
                    "accepted": bool(isinstance(response, dict) and response.get("accepted")),
                    "response": response,
                    "error": "",
                }
            ]
        except Exception as exc:
            return [
                {
                    **self._operator_identity_from_response_v3(operator_identity=identity),
                    "accepted": False,
                    "response": None,
                    "error": str(exc),
                }
            ]

    def _record_v3_transfer_log_status_conn(
        self,
        conn,
        transfer,
        *,
        proof_bundle=None,
        operator_identity=None,
        status,
        response=None,
        error="",
    ):
        from . import protocol_v3

        identity = self._operator_identity_from_response_v3(
            response=response,
            operator_identity=operator_identity
            or self._proof_bundle_operator_identity_v3(proof_bundle),
        )
        transfer_hash_value = protocol_v3.transfer_hash(transfer)
        spend_key = protocol_v3.spend_key_for_transfer(transfer)
        response = response or {}
        now = int(time.time())
        existing = conn.execute(
            """
            SELECT status
            FROM transfer_log_status_v3
            WHERE transfer_hash = ? AND log_id = ?
            """,
            (transfer_hash_value, identity["log_id"]),
        ).fetchone()
        status_rank = {
            V3_LOG_UNLOGGED_STATUS: 0,
            V3_LOG_PENDING_STATUS: 1,
            V3_LOG_PROVEN_STATUS: 2,
        }
        if existing is not None and status_rank.get(status, 0) < status_rank.get(
            existing["status"], 0
        ):
            return
        conn.execute(
            """
            INSERT OR REPLACE INTO transfer_log_status_v3(
                transfer_hash, token_id, spend_key, log_id, operator_public_key,
                status, entry_hash, leaf_index, tree_size, error, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                transfer_hash_value,
                transfer["token_id"],
                spend_key,
                identity["log_id"],
                identity["operator_public_key"],
                status,
                str(response.get("entry_hash") or transfer_hash_value).lower(),
                int(response["leaf_index"]) if "leaf_index" in response else None,
                int(response["tree_size"]) if "tree_size" in response else None,
                str(error or ""),
                now,
            ),
        )
        if status in {V3_LOG_PROVEN_STATUS, V3_LOG_UNLOGGED_STATUS}:
            self._clear_v3_log_proof_retry(conn, transfer_hash_value, identity["log_id"])

    def _v3_transfer_log_statuses(self, transfer_hash_value, statuses=None):
        params = [str(transfer_hash_value).lower()]
        status_clause = ""
        if statuses:
            statuses = tuple(statuses)
            status_clause = f" AND status IN ({','.join('?' for _ in statuses)})"
            params.extend(statuses)
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT * FROM transfer_log_status_v3
                WHERE transfer_hash = ?{status_clause}
                ORDER BY updated_at DESC
                """,
                params,
            ).fetchall()
        return [dict(row) for row in rows]

    def _v3_transfer_log_status(self, transfer_hash_value):
        rows = self._v3_transfer_log_statuses(transfer_hash_value)
        return rows[0] if rows else None

    def _v3_log_proof_retry_due(self, transfer_hash_value, log_id, now=None):
        now = int(time.time() if now is None else now)
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT next_attempt_at, terminal
                FROM transfer_log_retry_v3
                WHERE transfer_hash = ? AND log_id = ?
                """,
                (str(transfer_hash_value).lower(), str(log_id or "")),
            ).fetchone()
        if row is None:
            return True
        if int(row["terminal"] or 0):
            return False
        return int(row["next_attempt_at"] or 0) <= now

    def _v3_log_proof_retry_delay(self, attempts):
        exponent = min(max(0, int(attempts) - 1), 10)
        delay = int(V3_LOG_PROOF_RETRY_INITIAL_SECONDS) * (2**exponent)
        return min(int(V3_LOG_PROOF_RETRY_MAX_SECONDS), delay)

    def _v3_log_proof_error_is_stale_http_400(self, exc):
        try:
            if int(getattr(exc, "code", 0) or 0) == 400:
                return True
        except Exception:
            pass
        text = str(exc).lower()
        return "http error 400" in text or "http 400" in text or "status 400" in text

    def _record_v3_log_proof_retry_failure(self, transfer_hash_value, log_id, exc, now=None):
        now = int(time.time() if now is None else now)
        transfer_hash_value = str(transfer_hash_value).lower()
        log_id = str(log_id or "")
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT attempts
                FROM transfer_log_retry_v3
                WHERE transfer_hash = ? AND log_id = ?
                """,
                (transfer_hash_value, log_id),
            ).fetchone()
            attempts = int(row["attempts"] if row else 0) + 1
            terminal = self._v3_log_proof_error_is_stale_http_400(exc) and attempts >= int(
                V3_LOG_PROOF_STALE_HTTP_400_ATTEMPTS
            )
            next_attempt_at = 0 if terminal else now + self._v3_log_proof_retry_delay(attempts)
            conn.execute(
                """
                INSERT OR REPLACE INTO transfer_log_retry_v3(
                    transfer_hash, log_id, attempts, last_attempt_at, next_attempt_at,
                    last_error, terminal
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    transfer_hash_value,
                    log_id,
                    attempts,
                    now,
                    next_attempt_at,
                    str(exc),
                    1 if terminal else 0,
                ),
            )
        return {"attempts": attempts, "terminal": terminal, "next_attempt_at": next_attempt_at}

    def _clear_v3_log_proof_retry(self, conn, transfer_hash_value, log_id):
        conn.execute(
            """
            DELETE FROM transfer_log_retry_v3
            WHERE transfer_hash = ? AND log_id = ?
            """,
            (str(transfer_hash_value).lower(), str(log_id or "")),
        )

    def _verifier_for_operator_identity_v3(self, identity, proof_bundle=None):
        verifier = self.transparency_verifier
        if verifier is None:
            return None
        selector = getattr(verifier, "verifier_for_operator", None)
        if callable(selector):
            return selector(
                operator_public_key=identity.get("operator_public_key") or None,
                log_id=identity.get("log_id") or None,
            )
        operator_key = str(getattr(verifier, "operator_public_key", "") or "").strip()
        if identity.get("operator_public_key") and operator_key:
            if identity["operator_public_key"] != operator_key:
                return None
        elif (
            identity.get("log_id")
            and operator_key
            and identity["log_id"] != log_client.log_id_from_public_key(operator_key)
        ):
            return None
        return verifier

    def _verify_v3_transfer_log_proof_for_operator(self, transfer, identity, record=None):
        from . import protocol_v3
        from . import transparency_client as log_client

        transfer_hash_value = protocol_v3.transfer_hash(transfer)
        identity = self._operator_identity_from_response_v3(operator_identity=identity)
        verifier = self._verifier_for_operator_identity_v3(identity)
        if verifier is None:
            return False
        root = verifier.current_mirrored_root()
        if identity["log_id"] and root.get("log_id") != identity["log_id"]:
            raise ValidationError("current transparency root is for a different operator")
        leaf_index = (
            int(record["leaf_index"]) if record and record["leaf_index"] is not None else None
        )
        if leaf_index is not None and int(root["tree_size"]) < leaf_index + 1:
            raise ValidationError("current transparency root does not contain V3 transfer")
        proof = verifier.operator.inclusion_proof(transfer_hash_value, int(root["tree_size"]))
        log_client.verify_inclusion_proof(
            transfer_hash_value,
            proof,
            root,
            operator_public_key=root.get("operator_public_key"),
        )
        spend_proof = verifier.operator.spend_map_proof(
            protocol_v3.spend_key_for_transfer(transfer),
            int(root["tree_size"]),
        )
        log_client.verify_spend_map_proof_for_transfer(
            transfer,
            spend_proof,
            root,
            operator_public_key=root.get("operator_public_key"),
        )
        with self._connect() as conn:
            self._record_v3_transfer_log_status_conn(
                conn,
                transfer,
                operator_identity={
                    "log_id": root.get("log_id") or identity["log_id"],
                    "operator_public_key": root.get("operator_public_key")
                    or identity.get("operator_public_key", ""),
                },
                status=V3_LOG_PROVEN_STATUS,
                response={
                    "entry_hash": transfer_hash_value,
                    "leaf_index": int(proof.get("leaf_index", leaf_index or 0)),
                    "tree_size": int(root["tree_size"]),
                },
            )
        return True

    def _verify_v3_transfer_log_proof_once(self, transfer, proof_bundle):
        from . import protocol_v3

        transfer_hash_value = protocol_v3.transfer_hash(transfer)
        now = int(time.time())
        statuses = self._v3_transfer_log_statuses(transfer_hash_value)
        proven_log_ids = {
            row["log_id"] for row in statuses if row["status"] == V3_LOG_PROVEN_STATUS
        }
        for row in statuses:
            if row["status"] == V3_LOG_PROVEN_STATUS:
                continue
            if not self._v3_log_proof_retry_due(transfer_hash_value, row["log_id"], now=now):
                continue
            try:
                if self._verify_v3_transfer_log_proof_for_operator(transfer, row, record=row):
                    proven_log_ids.add(row["log_id"])
            except Exception as exc:
                retry = self._record_v3_log_proof_retry_failure(
                    transfer_hash_value,
                    row["log_id"],
                    exc,
                    now=now,
                )
                if retry["terminal"]:
                    logger.info(
                        "stopped retrying stale V3 transparency proof for %s via %s: %s",
                        transfer_hash_value,
                        row["log_id"],
                        exc,
                    )
                else:
                    logger.debug(
                        "V3 transfer proof recovery failed for %s; retry after %s",
                        row["log_id"],
                        retry["next_attempt_at"],
                        exc_info=True,
                    )
        for identity in self._append_operator_identities_v3():
            if identity["log_id"] in proven_log_ids:
                continue
            if not self._v3_log_proof_retry_due(transfer_hash_value, identity["log_id"], now=now):
                continue
            try:
                if self._verify_v3_transfer_log_proof_for_operator(transfer, identity):
                    proven_log_ids.add(identity["log_id"])
            except Exception as exc:
                retry = self._record_v3_log_proof_retry_failure(
                    transfer_hash_value,
                    identity["log_id"],
                    exc,
                    now=now,
                )
                if retry["terminal"]:
                    logger.info(
                        "stopped retrying stale V3 transparency proof for %s via %s: %s",
                        transfer_hash_value,
                        identity["log_id"],
                        exc,
                    )
                else:
                    logger.debug(
                        "V3 transfer proof recovery failed for %s",
                        identity["log_id"],
                        exc_info=True,
                    )
        if not statuses and not self._append_operator_identities_v3() and proof_bundle:
            identity = self._proof_bundle_operator_identity_v3(proof_bundle)
            if not self._v3_log_proof_retry_due(transfer_hash_value, identity["log_id"], now=now):
                return len(proven_log_ids) >= self._operator_finality_required_proofs_v3()
            try:
                if self._verify_v3_transfer_log_proof_for_operator(transfer, identity):
                    proven_log_ids.add(identity["log_id"])
            except Exception as exc:
                retry = self._record_v3_log_proof_retry_failure(
                    transfer_hash_value,
                    identity["log_id"],
                    exc,
                    now=now,
                )
                if retry["terminal"]:
                    logger.info(
                        "stopped retrying stale legacy V3 transparency proof for %s via %s: %s",
                        transfer_hash_value,
                        identity["log_id"],
                        exc,
                    )
                else:
                    logger.debug("legacy V3 transfer proof recovery failed", exc_info=True)
        return len(proven_log_ids) >= self._operator_finality_required_proofs_v3()

    def _v3_spend_key_has_witness_divergence(self, transfer):
        from . import protocol_v3

        transfer_hash_value = protocol_v3.transfer_hash(transfer)
        spend_key = protocol_v3.spend_key_for_transfer(transfer)
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT 1 FROM transfer_log_status_v3
                WHERE spend_key = ?
                  AND transfer_hash != ?
                  AND status IN (?, ?)
                LIMIT 1
                """,
                (spend_key, transfer_hash_value, V3_LOG_PENDING_STATUS, V3_LOG_PROVEN_STATUS),
            ).fetchone()
        return row is not None

    # Return whether the bill tip has enough independent operator log proofs.
    def _bill_v3_tip_log_proven(self, bill):
        from . import protocol_v3

        transfers = bill.get("recent_transfers") if isinstance(bill, dict) else None
        if not transfers:
            return True
        transfer = transfers[-1]
        if self._v3_spend_key_has_witness_divergence(transfer):
            return False
        statuses = self._v3_transfer_log_statuses(
            protocol_v3.transfer_hash(transfer),
            statuses=(V3_LOG_PROVEN_STATUS,),
        )
        proven_log_ids = {row["log_id"] for row in statuses}
        return len(proven_log_ids) >= self._operator_finality_required_proofs_v3()

    # Return read-only proof/finality progress for wallet display. This does not
    # retry proof recovery or promote bill state.
    def bill_v3_finality_progress(self, bill, status=None):
        from . import protocol_v3

        status_value = str(status or "").strip().lower()
        spendable_statuses = set(self.spendable_bill_v3_statuses())
        progress = {
            "status": status_value,
            "required_proofs": 0,
            "proven_proofs": 0,
            "pending_proofs": 0,
            "failed_proofs": 0,
            "awaiting_transparency": False,
            "divergent_witness": False,
            "spendable": bool(status_value and status_value in spendable_statuses),
        }
        transfers = bill.get("recent_transfers") if isinstance(bill, dict) else None
        if not transfers:
            return progress

        transfer = transfers[-1]
        transfer_hash_value = protocol_v3.transfer_hash(transfer)
        rows = self._v3_transfer_log_statuses(transfer_hash_value)

        def row_identity(row):
            return str(row.get("log_id") or row.get("operator_public_key") or "").strip()

        proven = {
            row_identity(row)
            for row in rows
            if row.get("status") == V3_LOG_PROVEN_STATUS and row_identity(row)
        }
        pending = {
            row_identity(row)
            for row in rows
            if row.get("status") == V3_LOG_PENDING_STATUS and row_identity(row)
        }
        failed = {
            row_identity(row)
            for row in rows
            if row.get("status") == V3_LOG_UNLOGGED_STATUS and row_identity(row)
        }
        required = self._operator_finality_required_proofs_v3()
        divergent = self._v3_spend_key_has_witness_divergence(transfer)
        progress.update(
            {
                "transfer_hash": transfer_hash_value,
                "required_proofs": required,
                "proven_proofs": len(proven),
                "pending_proofs": len(pending - proven),
                "failed_proofs": len(failed - proven - pending),
                "awaiting_transparency": bool(required and len(proven) < required and not divergent),
                "divergent_witness": divergent,
                "spendable": bool(progress["spendable"] and not divergent),
            }
        )
        return progress

    # Submit a native V3 transfer to append-capable operators and record each result.
    def _submit_v3_transfer_to_transparency_log(self, message, decoded):
        from . import protocol_v3

        if not self.transparency_submitter:
            return None
        bill = decoded["bill"]
        if not isinstance(bill.get("recent_transfers"), list) or not bill["recent_transfers"]:
            raise ValidationError("native V3 transfer announcement has no transfer tip")
        latest_transfer = bill["recent_transfers"][-1]
        expected_entry_hash = protocol_v3.transfer_hash(latest_transfer)
        expected_spend_key = protocol_v3.spend_key_for_transfer(latest_transfer)
        results = self._submit_v3_transfer_to_all_operators(message)
        accepted = []
        errors = []
        conflict_error = None
        for result in results:
            identity = {
                "log_id": result.get("log_id", ""),
                "operator_public_key": result.get("operator_public_key", ""),
            }
            response = result.get("response") if isinstance(result, dict) else None
            error = str(result.get("error") or "") if isinstance(result, dict) else ""
            if result.get("accepted"):
                try:
                    leaf_index, _tree_size = self._validate_transparency_append_response(
                        response,
                        expected_entry_hash,
                        expected_spend_key,
                    )
                    with self._connect() as conn:
                        self._record_v3_transfer_log_status_conn(
                            conn,
                            latest_transfer,
                            operator_identity=identity,
                            status=V3_LOG_PENDING_STATUS,
                            response=response,
                        )
                    if not self.transparency_submit_async:
                        if self.transparency_verifier is None:
                            raise ValidationError(
                                "transparency submission cannot be verified without root mirrors"
                            )
                        self._verify_v3_transfer_log_proof_for_operator(
                            latest_transfer,
                            identity,
                            record={"leaf_index": leaf_index},
                        )
                    accepted.append(response)
                    continue
                except Exception as exc:
                    error = str(exc)
            with self._connect() as conn:
                self._record_v3_transfer_log_status_conn(
                    conn,
                    latest_transfer,
                    operator_identity=identity,
                    status=V3_LOG_UNLOGGED_STATUS,
                    response=response if isinstance(response, dict) else None,
                    error=error,
                )
            if "conflicting spend" in error.lower():
                conflict_error = error
            if error:
                errors.append(error)
        if conflict_error:
            raise ValidationError(
                f"transparency log rejected conflicting transfer: {conflict_error}"
            )
        if accepted:
            return {"accepted": True, "operator_results": results, "responses": accepted}
        detail = "; ".join(errors) if errors else "no append-capable operator accepted transfer"
        if self.require_transparency:
            raise ValidationError(f"transparency log submission failed: {detail}")
        logger.warning("transparency log submission failed for %s: %s", expected_entry_hash, detail)
        return {"accepted": False, "status": "unlogged", "error": detail}

    # Require the operator append response to identify the exact logged leaf.
    def _validate_transparency_append_response(
        self, response, expected_entry_hash, expected_spend_key
    ):
        if not isinstance(response, dict) or not response.get("accepted"):
            raise ValidationError("transparency log did not accept the transfer")
        required = {"entry_hash", "leaf_index", "tree_size", "spend_key"}
        if not required.issubset(response):
            raise ValidationError("transparency log append response is missing verification fields")
        entry_hash = str(response["entry_hash"]).lower()
        if entry_hash != expected_entry_hash:
            raise ValidationError("transparency log appended a different transfer hash")
        if str(response["spend_key"]) != expected_spend_key:
            raise ValidationError("transparency log accepted a different spend key")
        leaf_index = int(response["leaf_index"])
        tree_size = int(response["tree_size"])
        if leaf_index < 0 or tree_size < leaf_index + 1:
            raise ValidationError("transparency log append response has invalid tree position")
        return leaf_index, tree_size

    # Retry proof verification until timeout to tolerate normal root mirror lag.
    def _verify_transparency_submission(self, token, entry_hash, leaf_index):
        from . import transparency_client as log_client

        transfer_timestamp = int(_last_transfer(token)["timestamp"])
        timeout = max(0, int(self.transparency_submission_verify_timeout_seconds))
        deadline = time.monotonic() + timeout
        last_error = None
        while True:
            try:
                root = self.transparency_verifier.mirrored_root_containing_leaf(
                    transfer_timestamp, leaf_index
                )
                proof = self.transparency_verifier.operator.inclusion_proof(
                    entry_hash, int(root["tree_size"])
                )
                log_client.verify_inclusion_proof(
                    entry_hash,
                    proof,
                    root,
                    operator_public_key=self.transparency_verifier.operator_public_key,
                )
                latest_transfer = _last_transfer(token)
                spend_proof = self.transparency_verifier.operator.spend_map_proof(
                    log_client.spend_key_for_transfer(latest_transfer),
                    int(root["tree_size"]),
                )
                log_client.verify_spend_map_proof_for_transfer(
                    latest_transfer,
                    spend_proof,
                    root,
                    operator_public_key=self.transparency_verifier.operator_public_key,
                )
                return True
            except Exception as exc:
                last_error = exc
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                time.sleep(min(1.0, remaining))
        raise ValidationError(
            f"transparency log append was not proven by a mirror before timeout: {last_error}"
        )

    # Retry native V3 proof verification until timeout to tolerate mirror lag.
    def _verify_transparency_submission_v3(self, transfer, entry_hash, leaf_index, verifier=None):
        from . import protocol_v3
        from . import transparency_client as log_client

        verifier = verifier or self.transparency_verifier
        if verifier is None:
            raise ValidationError("transparency verifier is required")
        transfer_timestamp = int(transfer["timestamp"])
        timeout = max(0, int(self.transparency_submission_verify_timeout_seconds))
        deadline = time.monotonic() + timeout
        last_error = None
        while True:
            try:
                root = verifier.mirrored_root_containing_leaf(transfer_timestamp, leaf_index)
                proof = verifier.operator.inclusion_proof(entry_hash, int(root["tree_size"]))
                log_client.verify_inclusion_proof(
                    entry_hash,
                    proof,
                    root,
                    operator_public_key=getattr(verifier, "operator_public_key", None),
                )
                spend_proof = verifier.operator.spend_map_proof(
                    protocol_v3.spend_key_for_transfer(transfer),
                    int(root["tree_size"]),
                )
                log_client.verify_spend_map_proof_for_transfer(
                    transfer,
                    spend_proof,
                    root,
                    operator_public_key=getattr(verifier, "operator_public_key", None),
                )
                return True
            except Exception as exc:
                last_error = exc
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                time.sleep(min(1.0, remaining))
        raise ValidationError(
            f"transparency log append was not proven by a mirror before timeout: {last_error}"
        )

    # Submit a compact checkpoint and return embedded transparency proof material.
    def _submit_checkpoint_to_transparency_log(self, checkpoint, bill):
        self._reject_non_v3_bill_protocol("non-V3 compact checkpoint")

    # Return whether policy says this settled bill should be compacted now.
    def _checkpoint_due_for_bill(self, conn, bill, state=None, force=False):
        self._reject_non_v3_bill_protocol("non-V3 compact checkpoint policy")

    # Create, prove, store, and return a compact checkpoint bill when policy allows.
    def _store_compact_checkpoint_for_bill(self, conn, bill, force=False, require_proof=False):
        self._reject_non_v3_bill_protocol("non-V3 compact checkpoint")

    # Persist the latest known valid state for a bill without downgrading it.
    def _store_token_tip(self, conn, token, state, status):
        now = int(time.time())
        self._store_genesis(conn, token, state)
        if isinstance(token, dict) and token.get("type") == BILL_TYPE:
            self._store_checkpoint(conn, token["checkpoint"], status="settled")
        existing = conn.execute(
            "SELECT first_seen, status, finalized_at, sequence, last_transfer_hash FROM tokens WHERE token_id = ?",
            (state.token_id,),
        ).fetchone()
        if existing and int(existing["sequence"]) > int(state.sequence):
            return
        first_seen = existing["first_seen"] if existing else now
        finalized_at = existing["finalized_at"] if existing else None
        if (
            existing
            and existing["status"] == "settled"
            and existing["last_transfer_hash"] == state.last_transfer_hash
        ):
            status = "settled"
        conn.execute(
            """
            INSERT OR REPLACE INTO tokens(
                token_id, display_id, payload, owner_address, last_transfer_hash, sequence,
                value, status, first_seen, updated_at, finalized_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                state.token_id,
                state.display_id,
                _store_json(_state_ref_from_state(state)),
                state.owner_address,
                state.last_transfer_hash,
                state.sequence,
                state.value,
                status,
                first_seen,
                now,
                finalized_at,
            ),
        )

    # Persist new transfers from a bill history, preserving older settled rows.
    def _store_transfer(self, conn, token, state, status):
        if state.sequence == 0:
            return None
        self._store_genesis(conn, token, state)
        now = int(time.time())
        last_hash = None
        transfers_to_store = []
        for transfer in reversed(_bill_history(token)):
            th = transfer_hash(transfer)
            existing_tip = th == state.last_transfer_hash
            existing = conn.execute(
                "SELECT 1 FROM transfers WHERE transfer_hash = ?",
                (th,),
            ).fetchone()
            if existing and not existing_tip:
                break
            transfers_to_store.append((transfer, th))

        for transfer, th in reversed(transfers_to_store):
            last_hash = th
            transfer_status = status if th == state.last_transfer_hash else "settled"
            existing = conn.execute(
                "SELECT first_seen, status, finalized_at FROM transfers WHERE transfer_hash = ?",
                (th,),
            ).fetchone()
            first_seen = existing["first_seen"] if existing else now
            finalized_at = existing["finalized_at"] if existing else None
            if existing and existing["status"] == "settled":
                transfer_status = "settled"
            conn.execute(
                """
                INSERT OR REPLACE INTO transfers(
                    transfer_hash, token_id, previous_hash, sequence, sender_address,
                    recipient_address, transfer_json, token_payload, status, first_seen, finalized_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    th,
                    state.token_id,
                    transfer["previous_hash"],
                    int(transfer["sequence"]),
                    transfer["sender_address"],
                    transfer["recipient_address"],
                    _store_json(transfer),
                    _store_json(_state_ref_from_state(state)),
                    transfer_status,
                    first_seen,
                    finalized_at,
                ),
            )
        return last_hash

    # Search stored sibling transfers for a double-spend anywhere in this bill branch.
    def _find_conflict(self, conn, token):
        self._reject_non_v3_bill_protocol("non-V3 conflict detection")

    # Store verified double-spend evidence without invalidating the bill.
    def _record_conflict(self, conn, proof):
        self._reject_non_v3_bill_protocol("non-V3 conflict proof")

    # Reject a branch that conflicts with an already known local branch.
    def _reject_conflicting_transfer(self, conn, token):
        conflict = self._find_conflict(conn, token)
        if not conflict:
            return None
        raise ValidationError("conflicting transfer rejected")

    # Drain pending transparency-gossip evidence from the verifier into node gossip.
    def _drain_transparency_gossip(self):
        if self.transparency_verifier is None:
            return []
        drain = getattr(self.transparency_verifier, "consume_pending_gossip_messages", None)
        if not callable(drain):
            return []
        return drain()

    # Return persisted equivocation evidence produced by transparency verification.
    def transparency_equivocation_messages(self, limit=100):
        if self.transparency_verifier is None:
            return []
        persisted = getattr(self.transparency_verifier, "persisted_equivocation_messages", None)
        if not callable(persisted):
            return []
        return persisted(limit=limit)

    # Return persisted operator-policy evidence produced by transparency verification.
    def transparency_operator_policy_violation_messages(self, limit=100):
        if self.transparency_verifier is None:
            return []
        persisted = getattr(
            self.transparency_verifier, "persisted_operator_policy_violation_messages", None
        )
        if not callable(persisted):
            return []
        return persisted(limit=limit)

    def _load_conflict_proof_v3_row(self, row):
        if not row:
            return None
        from . import protocol_v3

        proof = _load_json(row["proof_json"])
        protocol_v3.verify_conflict_proof(proof)
        return proof

    def _post_settlement_conflict_v3_settled_row(self, conn, proof):
        return conn.execute(
            """
            SELECT bill_hash, token_id, display_id, owner_address, sequence, updated_at, status
            FROM bills_v3
            WHERE token_id = ?
              AND status = 'settled'
              AND sequence >= ?
            ORDER BY sequence DESC, updated_at DESC
            LIMIT 1
            """,
            (str(proof["token_id"]), int(proof["sequence"])),
        ).fetchone()

    def _is_post_settlement_conflict_v3(self, conn, proof):
        return self._post_settlement_conflict_v3_settled_row(conn, proof) is not None

    # Return whether a stored bill tip can anchor this conflict proof locally.
    def _bill_v3_matches_conflict_anchor(self, bill, state, proof):
        from . import protocol_v3

        branch_hashes = {
            str(proof.get("transfer_hash_a") or ""),
            str(proof.get("transfer_hash_b") or ""),
        } - {""}
        for transfer in bill.get("recent_transfers") or []:
            try:
                if protocol_v3.transfer_hash(transfer) in branch_hashes:
                    return True
            except Exception:
                logger.debug("skipping invalid V3 transfer while anchoring conflict", exc_info=True)
        return (
            int(getattr(state, "sequence", -1)) == int(proof["sequence"]) - 1
            and str(getattr(state, "last_transfer_hash", "")) == str(proof["previous_hash"])
            and str(getattr(state, "owner_address", "")) == str(proof["sender_address"])
        )

    # Search locally known BillV3 tips for evidence that the conflict belongs here.
    def _conflict_proof_has_local_v3_anchor(self, conn, proof):
        from . import protocol_v3

        rows = conn.execute(
            f"""
            SELECT *
            FROM bills_v3
            WHERE token_id = ?
              AND status IN ({",".join("?" for _ in V3_CONFLICT_ANCHOR_STATUSES)})
            ORDER BY sequence DESC, updated_at DESC
            """,
            (str(proof["token_id"]), *V3_CONFLICT_ANCHOR_STATUSES),
        ).fetchall()
        for row in rows:
            record = dict(row)
            try:
                bill = protocol_v3.decode_bill(bytes(row["bill_blob"]))
                invalid_reason = _invalid_bill_v3_reason(record)
                if invalid_reason:
                    raise ValidationError(invalid_reason)
                state = protocol_v3.verify_bill(
                    bill,
                    proof_bundle_resolver=self.proof_bundle_resolver_v3,
                    transparency_verifier=self.transparency_verifier,
                    trusted_operator_public_key=self._trusted_operator_key_from_bill_v3(bill),
                    archive_segment_resolver=self.archive_segment_resolver_v3,
                )
                if self._bill_v3_matches_conflict_anchor(bill, state, proof):
                    return True
            except Exception:
                logger.debug(
                    "stored BillV3 row did not anchor conflict proof %s",
                    proof.get("proof_hash", ""),
                    exc_info=True,
                )
        return False

    # Reject conflict proof gossip unless it is anchored to local bill history.
    def _require_conflict_proof_v3_anchor(self, conn, proof):
        if not self._conflict_proof_has_local_v3_anchor(conn, proof):
            raise ValidationError("unanchored V3 conflict proof")

    # Verify, anchor, dedupe, and persist one ConflictProofV3 row.
    def _store_conflict_proof_v3_conn(
        self,
        conn,
        proof,
        *,
        expected_network_id=None,
        preverified=None,
    ):
        from . import protocol_v3

        if expected_network_id is None:
            expected_network_id = protocol_v3.DEFAULT_NETWORK_ID
        already_verified = (
            isinstance(preverified, dict)
            and preverified.get("_sentinel") is _INTERNAL_PREVERIFIED_SENTINEL
            and preverified.get("type") == "conflict_proof_v3"
            and preverified.get("proof_hash") == proof.get("proof_hash")
            and int(preverified.get("network_id", -1)) == int(expected_network_id)
            and int(proof.get("network_id", -2)) == int(expected_network_id)
        )
        if not already_verified:
            protocol_v3.verify_conflict_proof(proof, expected_network_id=expected_network_id)
        self._require_conflict_proof_v3_anchor(conn, proof)
        proof_hash_value = proof["proof_hash"]
        conflict_key_value = protocol_v3.conflict_proof_key(proof)
        if self._is_post_settlement_conflict_v3(conn, proof):
            return {
                "proof": proof,
                "inserted": False,
                "ignored": True,
                "proof_hash": proof_hash_value,
                "conflict_key": conflict_key_value,
            }
        existing = conn.execute(
            "SELECT proof_hash FROM conflicts_v3 WHERE conflict_key = ?",
            (conflict_key_value,),
        ).fetchone()
        inserted = existing is None
        if inserted:
            conn.execute(
                """
                INSERT OR IGNORE INTO conflicts_v3(
                    proof_hash, conflict_key, token_id, previous_hash, proof_json, detected_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    proof_hash_value,
                    conflict_key_value,
                    proof["token_id"],
                    proof["previous_hash"],
                    _store_json(proof),
                    int(time.time()),
                ),
            )
        return {
            "proof": proof,
            "inserted": bool(inserted),
            "ignored": False,
            "proof_hash": proof_hash_value,
            "conflict_key": conflict_key_value,
        }

    def _latest_conflict_proof_v3_for_token(self, conn, token_id):
        rows = conn.execute(
            """
            SELECT proof_hash, proof_json FROM conflicts_v3
            WHERE token_id = ?
            ORDER BY detected_at DESC, proof_hash DESC
            """,
            (str(token_id),),
        ).fetchall()
        for row in rows:
            try:
                proof = self._load_conflict_proof_v3_row(row)
                self._require_conflict_proof_v3_anchor(conn, proof)
                if self._is_post_settlement_conflict_v3(conn, proof):
                    continue
                return proof
            except Exception as exc:
                conn.execute(
                    "DELETE FROM conflicts_v3 WHERE proof_hash = ?",
                    (row["proof_hash"],),
                )
                logger.info(
                    "dropped invalid stored V3 conflict proof %s: %s",
                    row["proof_hash"],
                    exc,
                )
        return None

    def _display_id_for_v3_token(self, conn, token_id):
        row = conn.execute(
            """
            SELECT display_id FROM bills_v3
            WHERE token_id = ?
            ORDER BY sequence DESC, updated_at DESC
            LIMIT 1
            """,
            (str(token_id),),
        ).fetchone()
        if row:
            return row["display_id"]
        row = conn.execute(
            """
            SELECT display_id FROM issued_checkpoints_v3
            WHERE token_id = ?
            ORDER BY sequence DESC, updated_at DESC
            LIMIT 1
            """,
            (str(token_id),),
        ).fetchone()
        return row["display_id"] if row else None

    def _conflict_status_record_v3(self, ref, token_id, proof, *, display_id=None):
        transfer_a = proof.get("transfer_a") if isinstance(proof, dict) else {}
        transfer_b = proof.get("transfer_b") if isinstance(proof, dict) else {}
        owners = sorted(
            {
                str(transfer.get("recipient_address") or "")
                for transfer in (transfer_a, transfer_b)
                if isinstance(transfer, dict) and transfer.get("recipient_address")
            }
        )
        transfer_hashes = sorted(
            {
                str(proof.get("transfer_hash_a") or ""),
                str(proof.get("transfer_hash_b") or ""),
            }
            - {""}
        )
        return {
            "ref": ref,
            "display_id": display_id or ref,
            "token_id": str(token_id),
            "owner_address": "",
            "sequence": int(proof["sequence"]),
            "status": "conflict",
            "conflict_proof_hash": proof["proof_hash"],
            "conflicting_owner_addresses": owners,
            "transfer_hashes": transfer_hashes,
        }

    def cleanup_invalid_conflicts_v3(self, *, dry_run=True, limit=None):
        from . import protocol_v3

        invalid = []
        params = []
        limit_clause = ""
        if limit is not None:
            limit_clause = " LIMIT ?"
            params.append(max(0, int(limit)))
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT proof_hash, proof_json FROM conflicts_v3
                ORDER BY detected_at DESC{limit_clause}
                """,
                params,
            ).fetchall()
            for row in rows:
                try:
                    protocol_v3.verify_conflict_proof(_load_json(row["proof_json"]))
                except Exception as exc:
                    invalid.append({"proof_hash": row["proof_hash"], "reason": str(exc)})
            if invalid and not dry_run:
                conn.executemany(
                    "DELETE FROM conflicts_v3 WHERE proof_hash = ?",
                    [(item["proof_hash"],) for item in invalid],
                )
        return {
            "checked": len(rows),
            "invalid": len(invalid),
            "deleted": 0 if dry_run else len(invalid),
            "dry_run": bool(dry_run),
            "invalid_proofs": invalid,
        }

    def cleanup_invalid_bills_v3(self, *, dry_run=True, limit=None):
        invalid = []
        params = []
        limit_clause = ""
        if limit is not None:
            limit_clause = " LIMIT ?"
            params.append(max(0, int(limit)))
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT bill_hash, token_id, display_id, sequence, bill_blob
                FROM bills_v3
                ORDER BY updated_at DESC{limit_clause}
                """,
                params,
            ).fetchall()
            for row in rows:
                record = dict(row)
                reason = _invalid_bill_v3_reason(record)
                if reason:
                    invalid.append(
                        {
                            "bill_hash": record["bill_hash"],
                            "token_id": record["token_id"],
                            "display_id": record["display_id"],
                            "sequence": int(record["sequence"]),
                            "reason": reason,
                        }
                    )
            deleted_bills = 0
            deleted_messages = 0
            if invalid and not dry_run:
                token_ids = sorted({item["token_id"] for item in invalid})
                for item in invalid:
                    conn.execute("DELETE FROM bills_v3 WHERE bill_hash = ?", (item["bill_hash"],))
                    deleted_bills += conn.execute("SELECT changes() AS count_value").fetchone()[
                        "count_value"
                    ]
                    conn.execute(
                        "DELETE FROM bill_tips_v3 WHERE bill_hash = ?",
                        (item["bill_hash"],),
                    )
                for token_id in token_ids:
                    conn.execute("DELETE FROM messages WHERE token_id = ?", (token_id,))
                    deleted_messages += conn.execute("SELECT changes() AS count_value").fetchone()[
                        "count_value"
                    ]
        return {
            "checked": len(rows),
            "invalid": len(invalid),
            "deleted": 0 if dry_run else deleted_bills,
            "deleted_messages": 0 if dry_run else deleted_messages,
            "dry_run": bool(dry_run),
            "invalid_bills": invalid,
        }

    # Return recently stored verified V3 conflict proofs for durable rebroadcast.
    def conflict_messages(self, limit=100):
        messages = []
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT proof_hash, proof_json FROM conflicts_v3
                ORDER BY detected_at DESC
                LIMIT ?
                """,
                (max(0, int(limit)),),
            ).fetchall()
            for row in rows:
                try:
                    proof = self._load_conflict_proof_v3_row(row)
                    self._require_conflict_proof_v3_anchor(conn, proof)
                    if self._is_post_settlement_conflict_v3(conn, proof):
                        continue
                    messages.append(proof)
                except Exception as exc:
                    conn.execute(
                        "DELETE FROM conflicts_v3 WHERE proof_hash = ?",
                        (row["proof_hash"],),
                    )
                    logger.info(
                        "dropped invalid stored V3 conflict proof %s: %s",
                        row["proof_hash"],
                        exc,
                    )
        return [message for message in messages if message]

    def _token_row_for_ref(self, conn, ref):
        row = conn.execute("SELECT * FROM tokens WHERE token_id = ?", (ref,)).fetchone()
        if row:
            return row
        return conn.execute("SELECT * FROM tokens WHERE display_id = ?", (ref,)).fetchone()

    def _bill_v3_row_for_ref(self, conn, ref):
        row = conn.execute(
            """
            SELECT * FROM bills_v3
            WHERE token_id = ?
            ORDER BY sequence DESC,
                     CASE status WHEN 'settled' THEN 3 WHEN 'verified' THEN 2 WHEN 'pending' THEN 1 ELSE 0 END DESC,
                     LENGTH(bill_blob) ASC, updated_at DESC
            LIMIT 1
            """,
            (ref,),
        ).fetchone()
        if row:
            return row
        return conn.execute(
            """
            SELECT * FROM bills_v3
            WHERE display_id = ?
            ORDER BY sequence DESC,
                     CASE status WHEN 'settled' THEN 3 WHEN 'verified' THEN 2 WHEN 'pending' THEN 1 ELSE 0 END DESC,
                     LENGTH(bill_blob) ASC, updated_at DESC
            LIMIT 1
            """,
            (ref,),
        ).fetchone()

    def _issued_checkpoint_v3_row_for_ref(self, conn, ref):
        row = conn.execute(
            """
            SELECT * FROM issued_checkpoints_v3
            WHERE token_id = ?
            LIMIT 1
            """,
            (ref,),
        ).fetchone()
        if row:
            return row
        return conn.execute(
            """
            SELECT * FROM issued_checkpoints_v3
            WHERE display_id = ?
            LIMIT 1
            """,
            (ref,),
        ).fetchone()

    def _status_record_for_issued_checkpoint_v3_row(self, ref, row):
        status = "verified_checkpoint" if row["status"] == "verified_checkpoint" else "issued"
        return {
            "ref": ref,
            "display_id": row["display_id"],
            "token_id": row["token_id"],
            "owner_address": row["owner_address"],
            "sequence": int(row["sequence"]),
            "status": status,
            "checkpoint_hash": row["checkpoint_hash"],
        }

    def _status_record_for_bill_v3_row(self, ref, row, *, min_settled_seconds=0):
        with self._connect() as conn:
            conflict_proof = self._latest_conflict_proof_v3_for_token(conn, row["token_id"])
        if conflict_proof and row["status"] != "settled":
            return self._conflict_status_record_v3(
                ref,
                row["token_id"],
                conflict_proof,
                display_id=row["display_id"],
            )
        invalid_reason = _invalid_bill_v3_reason(dict(row))
        if invalid_reason:
            return {
                "ref": ref,
                "display_id": row["display_id"],
                "token_id": row["token_id"],
                "owner_address": "",
                "sequence": int(row["sequence"]),
                "status": "invalid",
            }
        if row["status"] in {"invalid", "rejected"}:
            return {
                "ref": ref,
                "display_id": row["display_id"],
                "token_id": row["token_id"],
                "owner_address": "",
                "sequence": int(row["sequence"]),
                "status": row["status"],
            }
        confidence = self.bill_v3_confidence(
            row["token_id"],
            expected_owner=row["owner_address"],
            min_settled_seconds=min_settled_seconds,
        )
        return {
            "ref": ref,
            "display_id": row["display_id"],
            "token_id": row["token_id"],
            "owner_address": row["owner_address"],
            "sequence": int(row["sequence"]),
            "status": confidence.get("level", row["status"]),
        }

    # Return one compact local status record for a bill id or display id.
    def status_record_for_ref(self, ref, *, min_settled_seconds=0):
        ref = str(ref).strip()
        if not ref:
            return None
        with self._connect() as conn:
            bill_v3_row = self._bill_v3_row_for_ref(conn, ref)
            if bill_v3_row:
                return self._status_record_for_bill_v3_row(
                    ref,
                    bill_v3_row,
                    min_settled_seconds=min_settled_seconds,
                )
            conflict_proof = self._latest_conflict_proof_v3_for_token(conn, ref)
            if conflict_proof:
                return self._conflict_status_record_v3(
                    ref,
                    ref,
                    conflict_proof,
                    display_id=self._display_id_for_v3_token(conn, ref),
                )
            issued_checkpoint_row = self._issued_checkpoint_v3_row_for_ref(conn, ref)
            if issued_checkpoint_row:
                conflict_proof = self._latest_conflict_proof_v3_for_token(
                    conn,
                    issued_checkpoint_row["token_id"],
                )
                if conflict_proof:
                    return self._conflict_status_record_v3(
                        ref,
                        issued_checkpoint_row["token_id"],
                        conflict_proof,
                        display_id=issued_checkpoint_row["display_id"],
                    )
                return self._status_record_for_issued_checkpoint_v3_row(
                    ref,
                    issued_checkpoint_row,
                )
            token_row = self._token_row_for_ref(conn, ref)
            if not token_row:
                return None
            return {
                "ref": ref,
                "display_id": token_row["display_id"],
                "token_id": token_row["token_id"],
                "owner_address": "",
                "sequence": int(token_row["sequence"]),
                "status": "invalid",
            }

    def _ingest_transfer_announcement(self, conn, message):
        self._reject_non_v3_bill_protocol("non-V3 transfer announcement ingest")

    def _find_conflicting_bill_v3(self, conn, bill, *, trusted_operator_public_key=None):
        from . import protocol_v3

        incoming_hash = protocol_v3.bill_hash(bill).hex()
        tried_hashes = {incoming_hash}
        incoming_operator_key = trusted_operator_public_key or self._trusted_operator_key_from_bill_v3(
            bill
        )

        def try_stored_bill(row):
            row_hash = str(row["bill_hash"])
            if row_hash in tried_hashes:
                return None
            tried_hashes.add(row_hash)
            try:
                existing = protocol_v3.decode_bill(bytes(row["bill_blob"]))
            except Exception:
                logger.debug(
                    "skipping invalid stored V3 bill while checking conflicts", exc_info=True
                )
                return None
            operator_key = incoming_operator_key or self._trusted_operator_key_from_bill_v3(existing)
            try:
                return protocol_v3.create_conflict_proof(
                    existing,
                    bill,
                    proof_bundle_resolver=self.proof_bundle_resolver_v3,
                    transparency_verifier=self.transparency_verifier,
                    trusted_operator_public_key=operator_key,
                    archive_segment_resolver=self.archive_segment_resolver_v3,
                )
            except Exception:
                logger.debug("stored V3 bill is not a conflicting branch", exc_info=True)
                return None

        transfers = bill.get("recent_transfers") if isinstance(bill, dict) else None
        if transfers:
            try:
                incoming_tip = transfers[-1]
                incoming_spend_key = protocol_v3.spend_key_for_transfer(incoming_tip)
                incoming_tip_hash = protocol_v3.transfer_hash(incoming_tip)
                rows = conn.execute(
                    """
                    SELECT bills_v3.bill_hash, bills_v3.bill_blob
                    FROM bill_tips_v3
                    JOIN bills_v3 ON bills_v3.bill_hash = bill_tips_v3.bill_hash
                    WHERE bill_tips_v3.token_id = ?
                      AND bill_tips_v3.spend_key = ?
                      AND bill_tips_v3.tip_transfer_hash IS NOT NULL
                      AND bill_tips_v3.tip_transfer_hash != ?
                    ORDER BY bill_tips_v3.sequence DESC, bill_tips_v3.updated_at DESC
                    LIMIT 25
                    """,
                    (
                        str(bill["token_id"]),
                        incoming_spend_key,
                        incoming_tip_hash,
                    ),
                ).fetchall()
                for row in rows:
                    proof = try_stored_bill(row)
                    if proof:
                        return proof
            except Exception:
                logger.debug("BillV3 tip-cache conflict prefilter failed", exc_info=True)

        rows = conn.execute(
            """
            SELECT bill_hash, bill_blob FROM bills_v3
            WHERE token_id = ?
            ORDER BY sequence DESC, updated_at DESC
            """,
            (str(bill["token_id"]),),
        ).fetchall()
        for row in rows:
            proof = try_stored_bill(row)
            if proof:
                return proof
        return None

    def _ingest_transfer_announcement_v3(self, conn, message):
        from . import protocol_v3

        _bill, embedded_bundle, _archive_segments = protocol_v3.decode_transfer_announcement(
            message
        )
        trusted_operator_public_key = self._trusted_operator_key_from_proof_bundle_v3(
            embedded_bundle
        )
        decoded = protocol_v3.verify_transfer_announcement(
            message,
            proof_bundle_resolver=self.proof_bundle_resolver_v3,
            transparency_verifier=self.transparency_verifier,
            trusted_operator_public_key=trusted_operator_public_key,
            archive_segment_resolver=self.archive_segment_resolver_v3,
        )
        bundle_for_segments = decoded["proof_bundle"]
        if bundle_for_segments is None:
            ref = decoded["bill"].get("proof_bundle_ref")
            if isinstance(ref, dict):
                bundle_for_segments = self.get_proof_bundle_v3(ref.get("proof_bundle_hash"))
        for segment in self._archive_segments_referenced_by_bundle_v3(
            decoded["archive_segments"],
            bundle_for_segments,
        ):
            self.store_archive_segment_v3(segment)
        if decoded["proof_bundle"] is not None:
            self.store_proof_bundle_v3(
                decoded["proof_bundle"],
                trusted_operator_public_key=trusted_operator_public_key,
                transparency_verifier=self.transparency_verifier,
            )
        existing_conflict = self._latest_conflict_proof_v3_for_token(
            conn,
            decoded["state"].token_id,
        )
        if existing_conflict:
            self._store_bill_v3_conn(conn, decoded["bill"], decoded["state"], "verified")
            self._record_message(conn, message, decoded["state"])
            return {
                "accepted": True,
                "status": "conflict",
                "state": decoded["state"],
                "duplicate_conflict": True,
                "gossip_messages": self._drain_transparency_gossip(),
            }
        conflict_proof = self._find_conflicting_bill_v3(
            conn,
            decoded["bill"],
            trusted_operator_public_key=trusted_operator_public_key,
        )
        if conflict_proof:
            conflict_record = self._store_conflict_proof_v3_conn(conn, conflict_proof)
            if conflict_record.get("ignored"):
                return {
                    "accepted": True,
                    "status": "ignored_conflict",
                    "state": decoded["state"],
                    "duplicate_conflict": not conflict_record["inserted"],
                    "ignored_conflict": True,
                    "relay": False,
                    "gossip_messages": self._drain_transparency_gossip(),
                }
            self._store_bill_v3_conn(conn, decoded["bill"], decoded["state"], "verified")
            self._record_message(conn, message, decoded["state"])
            result = {
                "accepted": True,
                "status": "conflict",
                "state": decoded["state"],
                "duplicate_conflict": not conflict_record["inserted"],
                "gossip_messages": self._drain_transparency_gossip(),
            }
            if conflict_record["inserted"]:
                result["conflict_proof"] = conflict_record["proof"]
            return result
        self._submit_v3_transfer_to_transparency_log(message, decoded)
        accepted_status = "pending" if self.settlement_quorum_enabled else "verified"
        self._store_bill_v3_conn(conn, decoded["bill"], decoded["state"], accepted_status)
        self._record_message(conn, message, decoded["state"])
        conn.commit()
        if accepted_status == "verified":
            self._maybe_compact_bill_v3(
                decoded["bill"],
                proof_bundle=bundle_for_segments,
                status=accepted_status,
                trusted_operator_public_key=trusted_operator_public_key,
                transparency_verifier=self.transparency_verifier,
            )
        return {
            "accepted": True,
            "status": accepted_status,
            "state": decoded["state"],
            "gossip_messages": self._drain_transparency_gossip(),
        }

    def _ingest_proof_bundle_announcement_v3(self, conn, message):
        from . import protocol_v3

        decoded = protocol_v3.verify_proof_bundle_announcement(
            message,
            transparency_verifier=self.transparency_verifier,
            archive_segment_resolver=self.archive_segment_resolver_v3,
            proof_bundle_resolver=self.proof_bundle_resolver_v3,
        )
        self.store_proof_bundle_v3(
            decoded["proof_bundle"],
            transparency_verifier=self.transparency_verifier,
        )
        self._record_message(conn, message)
        return {
            "accepted": True,
            "status": "proof_bundle_v3",
            "gossip_messages": self._drain_transparency_gossip(),
        }

    def _ingest_archive_segment_announcement_v3(self, conn, message):
        from . import protocol_v3

        decoded = protocol_v3.verify_archive_segment_announcement(
            message,
            previous_segment_resolver=self.archive_segment_resolver_v3,
        )
        self.store_archive_segment_v3(decoded["archive_segment"])
        self._record_message(conn, message)
        return {
            "accepted": True,
            "status": "archive_segment_v3",
            "gossip_messages": self._drain_transparency_gossip(),
        }

    def _ingest_conflict_proof(self, conn, message):
        self._reject_non_v3_bill_protocol("non-V3 conflict proof ingest")

    def _ingest_conflict_proof_v3(self, conn, message, *, preverified=None):
        conflict_record = self._store_conflict_proof_v3_conn(
            conn,
            message,
            preverified=preverified,
        )
        if conflict_record.get("ignored"):
            return {
                "accepted": True,
                "status": "ignored_conflict",
                "duplicate_conflict": not conflict_record["inserted"],
                "relay": False,
                "ignored_conflict": True,
            }
        self._record_message(conn, message)
        result = {
            "accepted": True,
            "status": "conflict",
            "duplicate_conflict": not conflict_record["inserted"],
            "relay": bool(conflict_record["inserted"]),
        }
        if conflict_record["inserted"]:
            result["conflict_proof"] = message
        return result

    def _ingest_transparency_root(self, conn, message, peer_id=None):
        verify_transparency_root_announcement(message)
        if self.transparency_root_gossip and self.transparency_verifier is not None:
            try:
                self.transparency_verifier.process_root_announcement(
                    message,
                    peer_id=peer_id,
                    message_hash=message_hash(message),
                )
            except Exception as exc:
                if exc.__class__.__name__ != "MirrorDisagreementError":
                    raise
        self._record_message(conn, message)
        return {
            "accepted": True,
            "status": "transparency_root",
            "gossip_messages": self._drain_transparency_gossip(),
        }

    def _ingest_transparency_equivocation(self, conn, message, peer_id=None):
        verify_transparency_equivocation_proof(message)
        if self.transparency_root_gossip and self.transparency_verifier is not None:
            self.transparency_verifier.process_equivocation_proof(
                message,
                peer_id=peer_id,
                message_hash=message_hash(message),
            )
        self._record_message(conn, message)
        return {
            "accepted": True,
            "status": "transparency_equivocation",
            "high_priority": True,
            "gossip_messages": self._drain_transparency_gossip(),
        }

    def _ingest_transparency_operator_policy_violation(self, conn, message, peer_id=None):
        verify_transparency_operator_policy_violation_proof(message)
        if self.transparency_root_gossip and self.transparency_verifier is not None:
            self.transparency_verifier.process_operator_policy_violation_proof(
                message,
                peer_id=peer_id,
                message_hash=message_hash(message),
            )
        self._record_message(conn, message)
        return {
            "accepted": True,
            "status": "transparency_operator_policy_violation",
            "high_priority": True,
            "gossip_messages": self._drain_transparency_gossip(),
        }

    # Validate one gossip message, update local state, and emit conflicts if found.
    def ingest_message(self, message, peer_id=None, preverified=None):
        from . import protocol_v3

        if isinstance(message, bytes):
            message = message.decode("utf-8")
        if isinstance(message, str):
            message = _load_json(message)
        if not isinstance(message, dict) or "type" not in message:
            raise ValidationError("malformed gossip message")

        with self._connect() as conn:
            message_type = message["type"]
            # Keep each gossip family on its own validation path; they update different tables.
            if message_type == protocol_v3.TRANSFER_ANNOUNCEMENT_TYPE:
                if "payload_encoding" not in message:
                    self._reject_non_v3_bill_protocol("non-V3 transfer announcement ingest")
                return self._ingest_transfer_announcement_v3(conn, message)

            if message_type == protocol_v3.PROOF_BUNDLE_ANNOUNCEMENT_TYPE:
                return self._ingest_proof_bundle_announcement_v3(conn, message)

            if message_type == protocol_v3.ARCHIVE_SEGMENT_ANNOUNCEMENT_TYPE:
                return self._ingest_archive_segment_announcement_v3(conn, message)

            if message_type == protocol_v3.CONFLICT_PROOF_TYPE:
                if "network_id" not in message:
                    self._reject_non_v3_bill_protocol("non-V3 conflict proof ingest")
                return self._ingest_conflict_proof_v3(
                    conn,
                    message,
                    preverified=preverified,
                )

            if message_type == TRANSPARENCY_ROOT_ANNOUNCEMENT_TYPE:
                return self._ingest_transparency_root(conn, message, peer_id=peer_id)

            if message_type == TRANSPARENCY_EQUIVOCATION_PROOF_TYPE:
                return self._ingest_transparency_equivocation(conn, message, peer_id=peer_id)

            if message_type == TRANSPARENCY_OPERATOR_POLICY_VIOLATION_TYPE:
                return self._ingest_transparency_operator_policy_violation(
                    conn, message, peer_id=peer_id
                )

        raise ValidationError("unsupported gossip message type")

    # Accept a raw peer payload and pass the decoded message into the store.
    def ingest_wire_message(self, raw, peer_id=None):
        if not raw:
            return {"accepted": False, "status": "empty"}
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        raw = raw.strip()
        if not raw:
            return {"accepted": False, "status": "empty"}
        return self.ingest_message(unpack_wire_message(raw), peer_id=peer_id)

    def _v3_settlement_query_for_bill(self, bill, bill_hash_value=None):
        from . import protocol_v3

        if not isinstance(bill.get("recent_transfers"), list) or not bill["recent_transfers"]:
            return None
        transfer = bill["recent_transfers"][-1]
        proof_bundle = self._proof_bundle_for_bill_v3(bill)
        identity = self._proof_bundle_operator_identity_v3(proof_bundle)
        return {
            "type": "ind.peer_settlement_query.v3",
            "version": 1,
            "network_id": int(bill["network_id"]),
            "token_id": bill["token_id"],
            "display_id": bill["checkpoint_core"]["display_id"],
            "bill_hash": bill_hash_value or protocol_v3.bill_hash(bill).hex(),
            "transfer_hash": protocol_v3.transfer_hash(transfer),
            "previous_hash": transfer["previous_hash"],
            "sequence": int(transfer["sequence"]),
            "spend_key": protocol_v3.spend_key_for_transfer(transfer),
            "operator_log_id": identity["log_id"],
            "operator_public_key": identity["operator_public_key"],
        }

    def pending_v3_settlement_candidates(self, now=None, buffer_seconds=FINALITY_BUFFER_SECONDS):
        from . import protocol_v3

        now = int(now or time.time())
        cutoff = now - int(buffer_seconds)
        candidates = []
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT bill_hash, token_id, bill_blob, first_seen, updated_at
                FROM bills_v3
                WHERE status = 'pending' AND first_seen <= ?
                ORDER BY first_seen ASC, updated_at ASC
                """,
                (cutoff,),
            ).fetchall()
        for row in rows:
            try:
                bill = protocol_v3.decode_bill(bytes(row["bill_blob"]))
                query = self._v3_settlement_query_for_bill(bill, row["bill_hash"])
                if query is None:
                    continue
                candidates.append(
                    {
                        "bill_hash": row["bill_hash"],
                        "token_id": row["token_id"],
                        "bill": bill,
                        "query": query,
                    }
                )
            except Exception:
                logger.debug("skipping invalid pending V3 settlement candidate", exc_info=True)
        return candidates

    def _v3_messages_for_token(self, conn, token_id, *, spend_key=None, limit=100):
        from . import protocol_v3

        rows = conn.execute(
            """
            SELECT message_json FROM messages
            WHERE token_id = ?
            ORDER BY first_seen DESC
            LIMIT ?
            """,
            (str(token_id), int(limit)),
        ).fetchall()
        messages = []
        for row in rows:
            message = self._expand_stored_message(conn, row["message_json"])
            if not isinstance(message, dict):
                continue
            if message.get("type") == protocol_v3.TRANSFER_ANNOUNCEMENT_TYPE:
                try:
                    bill, _bundle, _segments = protocol_v3.decode_transfer_announcement(message)
                    transfer = bill["recent_transfers"][-1]
                    if spend_key and protocol_v3.spend_key_for_transfer(transfer) != spend_key:
                        continue
                except Exception:
                    continue
            if message.get("type") == protocol_v3.CONFLICT_PROOF_TYPE:
                continue
            messages.append(message)
        return messages

    def peer_settlement_response_v3(self, query, *, limit=100):
        from . import protocol_v3

        if isinstance(query, str):
            query = _load_json(query)
        if not isinstance(query, dict) or query.get("type") != "ind.peer_settlement_query.v3":
            raise ValidationError("malformed V3 settlement query")
        token_id = str(query.get("token_id") or "").strip()
        spend_key = str(query.get("spend_key") or "").strip()
        transfer_hash_value = str(query.get("transfer_hash") or "").strip().lower()
        if not token_id:
            raise ValidationError("V3 settlement query is missing token id")
        with self._connect() as conn:
            conflict_proof = self._latest_conflict_proof_v3_for_token(conn, token_id)
            row = conn.execute(
                """
                SELECT bill_blob FROM bills_v3
                WHERE token_id = ?
                ORDER BY sequence DESC, updated_at DESC
                LIMIT 1
                """,
                (token_id,),
            ).fetchone()
            messages = self._v3_messages_for_token(
                conn,
                token_id,
                spend_key=spend_key or None,
                limit=limit,
            )
        status = self.status_record_for_ref(token_id) or {
            "display_id": query.get("display_id") or token_id,
            "owner_address": "",
            "sequence": None,
            "status": "unknown",
        }
        local_tip_hash = ""
        if row:
            try:
                bill = protocol_v3.decode_bill(bytes(row["bill_blob"]))
                if bill.get("recent_transfers"):
                    local_tip_hash = protocol_v3.transfer_hash(bill["recent_transfers"][-1])
            except Exception:
                local_tip_hash = ""
        if conflict_proof:
            messages.append(conflict_proof)
        packed_messages = []
        for message in messages:
            try:
                packed_messages.append(ind_token.pack_wire_message(message))
            except Exception:
                logger.debug("could not pack V3 settlement message", exc_info=True)
        return {
            "type": "ind.peer_settlement_response.v3",
            "version": 1,
            "network_id": int(query.get("network_id", 0) or 0),
            "token_id": token_id,
            "display_id": status.get("display_id") or query.get("display_id") or token_id,
            "status": status.get("status", "unknown"),
            "owner_address": status.get("owner_address", ""),
            "sequence": status.get("sequence"),
            "local_transfer_hash": local_tip_hash,
            "matches_query": bool(transfer_hash_value and local_tip_hash == transfer_hash_value),
            "conflict": bool(conflict_proof),
            "conflict_proof_hash": conflict_proof.get("proof_hash", "") if conflict_proof else "",
            "messages": packed_messages,
        }

    # Settle policy-pending V3 transfers that satisfied local finality checks.
    def finalize_pending(
        self,
        now=None,
        buffer_seconds=FINALITY_BUFFER_SECONDS,
        settlement_reconciler=None,
        require_v3_log_proof=False,
    ):
        now = int(now or time.time())
        if self.settlement_quorum_enabled:
            require_v3_log_proof = True
        finalized = []
        compact_candidates = []
        v3_rows = self.pending_v3_settlement_candidates(now=now, buffer_seconds=buffer_seconds)
        for row in v3_rows:
            bill = row["bill"]
            if require_v3_log_proof and not self._bill_v3_tip_log_proven(bill):
                proof_bundle = self._proof_bundle_for_bill_v3(bill)
                try:
                    self._verify_v3_transfer_log_proof_once(
                        bill["recent_transfers"][-1], proof_bundle
                    )
                except Exception as exc:
                    logger.info(
                        "V3 settlement awaiting transparency proof for %s: %s", row["token_id"], exc
                    )
                    continue
                if not self._bill_v3_tip_log_proven(bill):
                    continue
            if self.settlement_quorum_enabled and settlement_reconciler is None:
                logger.info(
                    "V3 settlement awaiting operator-node quorum reconciler for %s",
                    row["token_id"],
                )
                continue
            if settlement_reconciler is not None:
                decision = settlement_reconciler(row)
                if not isinstance(decision, dict) or decision.get("decision") != "settle":
                    continue
            with self._connect() as conn:
                conflict_proof = self._latest_conflict_proof_v3_for_token(conn, row["token_id"])
                if conflict_proof:
                    continue
                conn.execute(
                    """
                    UPDATE bills_v3
                    SET status = 'settled', updated_at = ?
                    WHERE bill_hash = ? AND status = 'pending'
                    """,
                    (now, row["bill_hash"]),
                )
                changed = conn.execute("SELECT changes() AS count_value").fetchone()["count_value"]
                if changed:
                    finalized.append(row["token_id"])
                    compact_candidates.append(bill)
        for bill in compact_candidates:
            self._maybe_compact_bill_v3(bill, status="settled")
        return finalized

    # Force a native V3 compact checkpoint for one locally settled bill.
    def compact_bill_v3_now(self, token_id=None, display_id=None):
        if not token_id and not display_id:
            raise ValidationError("compact now requires a bill id or display id")
        from . import protocol_v3

        with self._connect() as conn:
            if display_id:
                row = conn.execute(
                    """
                    SELECT * FROM bills_v3
                    WHERE display_id = ? AND status IN ('settled', 'verified')
                    ORDER BY sequence DESC, LENGTH(bill_blob) ASC, updated_at DESC
                    LIMIT 1
                    """,
                    (display_id,),
                ).fetchone()
                unsettled = None
                if row is None:
                    unsettled = conn.execute(
                        """
                        SELECT 1 FROM bills_v3
                        WHERE display_id = ? AND status = 'pending'
                        LIMIT 1
                        """,
                        (display_id,),
                    ).fetchone()
            else:
                row = conn.execute(
                    """
                    SELECT * FROM bills_v3
                    WHERE token_id = ? AND status IN ('settled', 'verified')
                    ORDER BY sequence DESC, LENGTH(bill_blob) ASC, updated_at DESC
                    LIMIT 1
                    """,
                    (token_id,),
                ).fetchone()
                unsettled = None
                if row is None:
                    unsettled = conn.execute(
                        """
                        SELECT 1 FROM bills_v3
                        WHERE token_id = ? AND status = 'pending'
                        LIMIT 1
                        """,
                        (token_id,),
                    ).fetchone()
            if not row:
                if unsettled:
                    raise ValidationError("BillV3 must be locally settled before compacting")
                raise ValidationError("BillV3 not found")
            bill = protocol_v3.decode_bill(bytes(row["bill_blob"]))
        proof_bundle = self.get_proof_bundle_v3(bill["proof_bundle_ref"]["proof_bundle_hash"])
        compact_bill = self._compact_bill_v3(
            bill,
            proof_bundle=proof_bundle,
            status=row["status"],
            force=True,
            require_proof=True,
            transparency_verifier=self.transparency_verifier,
        )
        if not compact_bill:
            raise ValidationError("native V3 compact checkpoint was not created")
        return compact_bill

    # Force a compact checkpoint for one locally settled bill.
    def compact_bill_now(self, token_id=None, display_id=None):
        return self.compact_bill_v3_now(token_id=token_id, display_id=display_id)

    # Return a rebuilt bearer bill by protocol bill id.
    def get_token(self, token_id):
        with self._connect() as conn:
            row = conn.execute(
                "SELECT payload FROM tokens WHERE token_id = ?", (token_id,)
            ).fetchone()
            if not row:
                return None
            return self._token_from_payload(conn, row["payload"], token_id)

    # Return a rebuilt bearer bill by wallet display id.
    def get_token_by_display_id(self, display_id):
        with self._connect() as conn:
            row = conn.execute(
                "SELECT token_id, payload FROM tokens WHERE display_id = ?", (display_id,)
            ).fetchone()
            if not row:
                return None
            return self._token_from_payload(conn, row["payload"], row["token_id"])

    # Return a compact V3 bill for a wallet display id when a checkpoint exists.
    def get_compact_bill_by_display_id(self, display_id):
        from . import protocol_v3

        with self._connect() as conn:
            bill_row = conn.execute(
                """
                SELECT bill_blob FROM bills_v3
                WHERE display_id = ? AND status IN ('settled', 'verified')
                ORDER BY sequence DESC, LENGTH(bill_blob) ASC, updated_at DESC
                LIMIT 1
                """,
                (display_id,),
            ).fetchone()
            if bill_row:
                bill = protocol_v3.decode_bill(bytes(bill_row["bill_blob"]))
                if not bill["recent_transfers"]:
                    return bill
            return None

    # Return a compact V3 bill by protocol bill id when a checkpoint exists.
    def get_compact_bill(self, token_id):
        from . import protocol_v3

        with self._connect() as conn:
            bill_row = conn.execute(
                """
                SELECT bill_blob FROM bills_v3
                WHERE token_id = ? AND status IN ('settled', 'verified')
                ORDER BY sequence DESC, LENGTH(bill_blob) ASC, updated_at DESC
                LIMIT 1
                """,
                (token_id,),
            ).fetchone()
            if bill_row:
                bill = protocol_v3.decode_bill(bytes(bill_row["bill_blob"]))
                if not bill["recent_transfers"]:
                    return bill
            return None

    # Return the stored bill row used by UI and tests.
    def get_token_record(self, token_id):
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM tokens WHERE token_id = ?", (token_id,)).fetchone()
        return dict(row) if row else None

    # List locally known bill records for an owner address.
    def token_records_for_owner(self, owner_address, settled_only=True, limit=1000):
        statuses = ("settled", "verified") if settled_only else ("pending", "settled", "verified")
        placeholders = ",".join("?" for _ in statuses)
        params = [owner_address, *statuses, int(limit)]
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT * FROM tokens
                WHERE owner_address = ? AND status IN ({placeholders})
                ORDER BY updated_at DESC
                LIMIT ?
                """,
                params,
            ).fetchall()
        return [dict(row) for row in rows]

    # Report whether a bill is locally acceptable for a recipient.
    def token_confidence(
        self, token_id, expected_owner=None, min_settled_seconds=FINALITY_BUFFER_SECONDS, now=None
    ):
        now = int(now or time.time())
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM tokens WHERE token_id = ?", (token_id,)).fetchone()
            if not row:
                return {"accepted": False, "level": "unknown", "reason": "bill not found"}
            record = dict(row)
        if record["status"] in {"invalid", "rejected"}:
            return {
                "accepted": False,
                "level": record["status"],
                "reason": f"bill is marked {record['status']}",
            }
        if expected_owner and record["owner_address"] != expected_owner:
            return {
                "accepted": False,
                "level": "wrong_owner",
                "reason": "bill owner does not match expected owner",
            }
        if record["status"] == "verified":
            return {
                "accepted": True,
                "level": "verified",
                "finality": "local_verified",
                "reason": "bill is verified locally",
                "settled_age": 0,
                "sequence": int(record["sequence"]),
            }
        if record["status"] != "settled" or not record.get("finalized_at"):
            return {"accepted": False, "level": record["status"], "reason": "bill is not settled"}
        settled_age = now - int(record["finalized_at"])
        if settled_age < int(min_settled_seconds):
            return {
                "accepted": False,
                "level": "settled_fresh",
                "reason": "bill is settled but below requested confidence age",
                "settled_age": settled_age,
            }
        return {
            "accepted": True,
            "level": "strong_local",
            "finality": "local_confidence",
            "reason": "bill is settled locally",
            "settled_age": settled_age,
            "sequence": int(record["sequence"]),
        }

    def bill_v3_confidence(
        self, token_id, expected_owner=None, min_settled_seconds=FINALITY_BUFFER_SECONDS, now=None
    ):
        now = int(now or time.time())
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM bills_v3
                WHERE token_id = ?
                ORDER BY sequence DESC,
                         CASE status WHEN 'settled' THEN 3 WHEN 'verified' THEN 2 WHEN 'pending' THEN 1 ELSE 0 END DESC,
                         updated_at DESC
                LIMIT 1
                """,
                (str(token_id),),
            ).fetchone()
            if not row:
                return {"accepted": False, "level": "unknown", "reason": "V3 bill not found"}
            record = dict(row)
            if expected_owner and record["owner_address"] != expected_owner:
                fallback = conn.execute(
                    """
                    SELECT * FROM bills_v3
                    WHERE token_id = ?
                      AND owner_address = ?
                      AND status IN ('settled', 'verified')
                    ORDER BY sequence DESC,
                             CASE status WHEN 'settled' THEN 3 WHEN 'verified' THEN 2 ELSE 1 END DESC,
                             LENGTH(bill_blob) ASC, updated_at DESC
                    LIMIT 1
                    """,
                    (str(token_id), str(expected_owner)),
                ).fetchone()
                if fallback and not self._has_materialized_newer_v3_branch_conn(
                    conn,
                    token_id,
                    int(fallback["sequence"]),
                ):
                    record = dict(fallback)
            conflict_proof = self._latest_conflict_proof_v3_for_token(conn, token_id)
            if conflict_proof and record["status"] != "settled":
                return {
                    "accepted": False,
                    "level": "conflict",
                    "reason": "V3 bill has a stored conflict proof before local settlement",
                    "sequence": int(conflict_proof["sequence"]),
                    "conflict_proof_hash": conflict_proof["proof_hash"],
                }
        settled_age = now - int(record["updated_at"])
        invalid_reason = _invalid_bill_v3_reason(record)
        if invalid_reason:
            return {
                "accepted": False,
                "level": "invalid",
                "reason": invalid_reason,
            }
        if record["status"] in {"invalid", "rejected"}:
            return {
                "accepted": False,
                "level": record["status"],
                "reason": f"V3 bill is marked {record['status']}",
            }
        if expected_owner and record["owner_address"] != expected_owner:
            return {
                "accepted": False,
                "level": "wrong_owner",
                "reason": "V3 bill owner does not match expected owner",
            }
        if record["status"] not in {"settled", "verified"}:
            return {
                "accepted": False,
                "level": record["status"],
                "reason": "V3 bill is not locally spendable",
            }
        if record["status"] == "verified" and self.settlement_quorum_enabled:
            return {
                "accepted": False,
                "level": "verified",
                "reason": "V3 bill is verified but awaiting settlement quorum",
                "settled_age": 0,
                "sequence": int(record["sequence"]),
            }
        if record["status"] == "settled" and settled_age < int(min_settled_seconds):
            return {
                "accepted": False,
                "level": "settled_fresh",
                "reason": "V3 bill is settled but below requested confidence age",
                "settled_age": settled_age,
            }
        return {
            "accepted": True,
            "level": "strong_local" if record["status"] == "settled" else "verified",
            "finality": "local_v3_confidence",
            "reason": f"V3 bill is {record['status']} locally",
            "settled_age": settled_age,
            "sequence": int(record["sequence"]),
        }

    def wallet_known_token_sequences(self, owner_address, statuses=None, limit=None):
        if limit is None:
            limit_clause = ""
            params_limit = []
        else:
            try:
                limit = max(0, min(100000, int(limit)))
            except (TypeError, ValueError):
                limit = 5000
            limit_clause = "LIMIT ?"
            params_limit = [limit]
        statuses = tuple(statuses or ("settled", "verified"))
        placeholders = ",".join("?" for _ in statuses)
        params = [str(owner_address), *statuses, *params_limit]
        sequences = {}
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT token_id, MAX(sequence) AS max_sequence
                FROM bills_v3
                WHERE owner_address = ? AND status IN ({placeholders})
                GROUP BY token_id
                ORDER BY MAX(updated_at) DESC
                {limit_clause}
                """,
                params,
            ).fetchall()
            for row in rows:
                sequences[str(row["token_id"])] = int(row["max_sequence"])
        return sequences

    def wallet_known_display_ranges(
        self,
        owner_address,
        statuses=None,
        *,
        max_ranges=WALLET_SYNC_DISPLAY_RANGE_LIMIT,
        max_bytes=WALLET_SYNC_DISPLAY_RANGE_BYTES,
    ):
        from . import protocol_v3

        try:
            max_ranges = max(0, int(max_ranges))
        except (TypeError, ValueError):
            max_ranges = WALLET_SYNC_DISPLAY_RANGE_LIMIT
        try:
            max_bytes = max(0, int(max_bytes))
        except (TypeError, ValueError):
            max_bytes = WALLET_SYNC_DISPLAY_RANGE_BYTES
        if max_ranges <= 0 or max_bytes <= 0:
            return []
        points = []
        for record in self.bill_v3_metadata_records_for_owner(
            owner_address,
            statuses=statuses or ("settled", "verified"),
            limit=None,
        ):
            try:
                parsed = protocol_v3.parse_display_id(str(record.get("display_id") or ""))
                sequence = int(record.get("sequence"))
            except Exception:
                continue
            if sequence <= 0:
                continue
            points.append((int(parsed["value"]), int(sequence), int(parsed["serial"])))
        if not points:
            return []
        points.sort()
        ranges = []
        current_value = None
        current_sequence = None
        current_start = None
        current_end = None
        for value, sequence, serial in points:
            if (
                value == current_value
                and sequence == current_sequence
                and serial <= current_end + 1
            ):
                current_end = max(current_end, serial)
                continue
            if current_value is not None:
                ranges.append([current_value, current_start, current_end, current_sequence])
            current_value = value
            current_sequence = sequence
            current_start = serial
            current_end = serial
        if current_value is not None:
            ranges.append([current_value, current_start, current_end, current_sequence])

        # Prefer the widest spans when the wallet is too fragmented to fit the request budget.
        ranges.sort(key=lambda item: (item[2] - item[1] + 1, -item[0], -item[3], -item[1]), reverse=True)
        selected = []
        used_bytes = 2
        for item in ranges:
            encoded = json.dumps(item, separators=(",", ":"))
            extra = len(encoded.encode("utf-8")) + (1 if selected else 0)
            if len(selected) >= max_ranges or used_bytes + extra > max_bytes:
                break
            selected.append(item)
            used_bytes += extra
        selected.sort(key=lambda item: (item[0], item[3], item[1], item[2]))
        return selected

    def wallet_sync_updated_at_cursor(self, owner_address, statuses=None):
        statuses = tuple(statuses or ("settled", "verified"))
        placeholders = ",".join("?" for _ in statuses)
        with self._connect() as conn:
            row = conn.execute(
                f"""
                SELECT MAX(updated_at) AS cursor
                FROM bills_v3
                WHERE owner_address = ? AND status IN ({placeholders})
                """,
                [str(owner_address), *statuses],
            ).fetchone()
        return int(row["cursor"] or 0) if row else 0

    def wallet_sync_page_cursor(self, owner_address, statuses=None, newest=True):
        statuses = tuple(statuses or ("settled", "verified"))
        placeholders = ",".join("?" for _ in statuses)
        order = "DESC" if newest else "ASC"
        with self._connect() as conn:
            row = conn.execute(
                f"""
                SELECT updated_at, sequence, token_id
                FROM bills_v3
                WHERE owner_address = ? AND status IN ({placeholders})
                ORDER BY updated_at {order}, sequence {order}, token_id {order}
                LIMIT 1
                """,
                [str(owner_address), *statuses],
            ).fetchone()
        if not row:
            return None
        return {
            "updated_at": int(row["updated_at"]),
            "sequence": int(row["sequence"]),
            "token_id": str(row["token_id"]),
        }

    def wallet_delta_sync_request(
        self,
        owner_address,
        *,
        token_limit=0,
        response_limit=100,
        direction="backfill",
        page_cursor=None,
        display_range_limit=WALLET_SYNC_DISPLAY_RANGE_LIMIT,
        display_range_bytes=WALLET_SYNC_DISPLAY_RANGE_BYTES,
    ):
        direction = str(direction or "backfill").lower()
        if direction not in {"newer", "backfill", "reconcile"}:
            direction = "backfill"
        cursor = page_cursor
        if cursor is None and direction != "reconcile":
            cursor = self.wallet_sync_page_cursor(
                owner_address,
                newest=(direction == "newer"),
            )
        request = {
            "type": "ind.wallet_bill_sync_request.v3",
            "version": 3,
            "address": str(owner_address),
            "direction": direction,
            "limit": int(response_limit),
        }
        if cursor:
            request["cursor"] = dict(cursor)
            if direction == "newer":
                request["after_updated_at"] = int(cursor["updated_at"])
            else:
                request["before_updated_at"] = int(cursor["updated_at"])
        try:
            token_limit = int(token_limit)
        except (TypeError, ValueError):
            token_limit = 0
        if token_limit > 0:
            request["known_tokens"] = self.wallet_known_token_sequences(
                owner_address,
                limit=token_limit,
            )
        known_display_ranges = self.wallet_known_display_ranges(
            owner_address,
            max_ranges=display_range_limit,
            max_bytes=display_range_bytes,
        )
        if known_display_ranges:
            request["known_display_ranges"] = known_display_ranges
        return request

    def _parse_known_token_sequences_v3(self, known_token_sequences):
        parsed = {}
        for token_id, sequence in (known_token_sequences or {}).items():
            token_id = str(token_id)
            if not token_id:
                continue
            try:
                parsed[token_id] = int(sequence)
            except (TypeError, ValueError):
                continue
        return parsed

    def _parse_known_display_ranges_v3(self, known_display_ranges):
        from . import protocol_v3

        parsed = {}
        if not isinstance(known_display_ranges, list):
            return parsed
        for item in known_display_ranges[:WALLET_SYNC_DISPLAY_RANGE_LIMIT]:
            try:
                if isinstance(item, dict):
                    value = item.get("value", item.get("v"))
                    start = item.get("start", item.get("s"))
                    end = item.get("end", item.get("e", start))
                    sequence = item.get("sequence", item.get("q"))
                elif isinstance(item, (list, tuple)) and len(item) >= 4:
                    value, start, end, sequence = item[:4]
                else:
                    continue
                value = int(value)
                start = int(start)
                end = int(end)
                sequence = int(sequence)
                if start > end or sequence <= 0:
                    continue
                protocol_v3.canonical_display_id(value, start)
                protocol_v3.canonical_display_id(value, end)
            except Exception:
                continue
            parsed.setdefault(value, []).append((start, end, sequence))
        for value in list(parsed):
            parsed[value].sort(key=lambda entry: (entry[0], entry[1], entry[2]))
        return parsed

    def _display_id_covered_by_known_ranges_v3(self, display_id, sequence, known_display_ranges):
        if not known_display_ranges:
            return False
        try:
            from . import protocol_v3

            parsed = protocol_v3.parse_display_id(str(display_id or ""))
            serial = int(parsed["serial"])
            ranges = known_display_ranges.get(int(parsed["value"])) or []
            sequence = int(sequence)
        except Exception:
            return False
        for start, end, known_sequence in ranges:
            if start > serial:
                break
            if serial <= end and sequence <= int(known_sequence):
                return True
        return False

    def _parse_wallet_sync_cursor_v3(self, request, direction):
        cursor = request.get("cursor") if isinstance(request, dict) else None
        cursor = cursor if isinstance(cursor, dict) else {}
        if direction == "newer":
            updated_at = cursor.get("updated_at", request.get("after_updated_at"))
        else:
            updated_at = cursor.get("updated_at", request.get("before_updated_at"))
        try:
            updated_at = int(updated_at)
        except (TypeError, ValueError):
            return None
        try:
            sequence = int(cursor.get("sequence", request.get("sequence", 0)) or 0)
        except (TypeError, ValueError):
            sequence = 0
        return {
            "updated_at": updated_at,
            "sequence": sequence,
            "token_id": str(cursor.get("token_id", request.get("token_id", "")) or ""),
        }

    def _archive_segments_for_wallet_sync_bundle_v3(self, bundle):
        if bundle is None:
            return []
        segments = []
        seen = set()
        for segment_hash in sorted(self._archive_segment_hashes_for_proof_bundle_v3(bundle)):
            if not segment_hash or segment_hash in seen:
                continue
            segment = self.get_archive_segment_v3(segment_hash)
            if segment is not None:
                segments.append(segment)
                seen.add(segment_hash)
        return segments

    def _wallet_sync_record_from_bill_row_v3(self, row):
        from . import protocol_v3

        bill = protocol_v3.decode_bill(bytes(row["bill_blob"]))
        proof_bundle_hash = str(row["proof_bundle_hash"] or "").strip().lower()
        if not proof_bundle_hash:
            ref = bill.get("proof_bundle_ref") if isinstance(bill, dict) else None
            if isinstance(ref, dict):
                proof_bundle_hash = str(ref.get("proof_bundle_hash") or "").strip().lower()
        proof_bundle = self.get_proof_bundle_v3(proof_bundle_hash) if proof_bundle_hash else None
        return {
            "type": "ind.wallet_bill_sync_record.v3",
            "version": 1,
            "token_id": str(row["token_id"]),
            "display_id": str(row["display_id"]),
            "owner_address": str(row["owner_address"]),
            "sequence": int(row["sequence"]),
            "status": str(row["status"]),
            "updated_at": int(row["updated_at"]),
            "bill": bill,
            "proof_bundle": proof_bundle,
            "archive_segments": self._archive_segments_for_wallet_sync_bundle_v3(proof_bundle),
        }

    # Return owner-addressed BillV3 records not already covered by local wallet state.
    def wallet_bill_sync_page(
        self,
        owner_address,
        *,
        known_token_sequences=None,
        known_display_ranges=None,
        after_updated_at=None,
        before_updated_at=None,
        direction=None,
        cursor=None,
        limit=100,
    ):
        known_token_sequences = self._parse_known_token_sequences_v3(known_token_sequences)
        known_display_ranges = self._parse_known_display_ranges_v3(known_display_ranges)
        try:
            limit = max(1, min(500, int(limit)))
        except (TypeError, ValueError):
            limit = 100
        direction = str(direction or "").lower()
        if direction not in {"newer", "backfill", "reconcile"}:
            direction = "newer" if after_updated_at and not before_updated_at else "backfill"
        request_cursor = {"cursor": cursor or {}}
        if after_updated_at is not None:
            request_cursor["after_updated_at"] = after_updated_at
        if before_updated_at is not None:
            request_cursor["before_updated_at"] = before_updated_at
        parsed_cursor = self._parse_wallet_sync_cursor_v3(request_cursor, direction)
        batch_size = max(limit, 250)
        offset = 0
        scanned = 0
        scan_limit = max(WALLET_SYNC_SERVER_SCAN_LIMIT, limit * 100)
        records = []
        next_cursor = None
        order = "ASC" if direction == "newer" else "DESC"
        cursor_clause = ""
        cursor_params = []
        if parsed_cursor is not None:
            updated_at = int(parsed_cursor["updated_at"])
            sequence = int(parsed_cursor["sequence"])
            token_id = str(parsed_cursor["token_id"])
            if direction == "newer":
                cursor_clause = """
                    AND (
                        updated_at > ?
                        OR (updated_at = ? AND sequence > ?)
                        OR (updated_at = ? AND sequence = ? AND token_id > ?)
                    )
                """
            else:
                cursor_clause = """
                    AND (
                        updated_at < ?
                        OR (updated_at = ? AND sequence < ?)
                        OR (updated_at = ? AND sequence = ? AND token_id < ?)
                    )
                """
            cursor_params = [updated_at, updated_at, sequence, updated_at, sequence, token_id]
        with self._connect() as conn:
            while len(records) < limit and scanned < scan_limit:
                rows = conn.execute(
                    f"""
                    SELECT bill_hash, token_id, display_id, owner_address, sequence, status,
                           first_seen, updated_at
                    FROM bills_v3
                    WHERE owner_address = ? AND status IN ('settled', 'verified', 'pending')
                    {cursor_clause}
                    ORDER BY updated_at {order}, sequence {order}, token_id {order}
                    LIMIT ? OFFSET ?
                    """,
                    [str(owner_address), *cursor_params, batch_size, offset],
                ).fetchall()
                if not rows:
                    break
                offset += len(rows)
                scanned += len(rows)
                for row in rows:
                    token_id = str(row["token_id"])
                    known_sequence = known_token_sequences.get(token_id)
                    if known_sequence is not None and int(row["sequence"]) <= int(known_sequence):
                        continue
                    if self._display_id_covered_by_known_ranges_v3(
                        row["display_id"],
                        int(row["sequence"]),
                        known_display_ranges,
                    ):
                        continue
                    if self._has_materialized_newer_v3_branch_conn(
                        conn,
                        row["token_id"],
                        int(row["sequence"]),
                    ):
                        continue
                    full_row = conn.execute(
                        """
                        SELECT *
                        FROM bills_v3
                        WHERE bill_hash = ?
                        LIMIT 1
                        """,
                        (row["bill_hash"],),
                    ).fetchone()
                    if not full_row:
                        continue
                    record = dict(full_row)
                    if not _bill_v3_record_has_allowed_value(record):
                        continue
                    try:
                        records.append(self._wallet_sync_record_from_bill_row_v3(full_row))
                        next_cursor = {
                            "updated_at": int(row["updated_at"]),
                            "sequence": int(row["sequence"]),
                            "token_id": str(row["token_id"]),
                        }
                    except Exception:
                        logger.debug("skipping invalid BillV3 wallet sync record", exc_info=True)
                    if len(records) >= limit:
                        break
        return {
            "records": records,
            "has_more": len(records) >= limit,
            "next_cursor": next_cursor if len(records) >= limit else None,
            "direction": direction,
        }

    def wallet_bill_sync_records(
        self,
        owner_address,
        *,
        known_token_sequences=None,
        known_display_ranges=None,
        after_updated_at=None,
        before_updated_at=None,
        direction=None,
        cursor=None,
        limit=100,
    ):
        return self.wallet_bill_sync_page(
            owner_address,
            known_token_sequences=known_token_sequences,
            known_display_ranges=known_display_ranges,
            after_updated_at=after_updated_at,
            before_updated_at=before_updated_at,
            direction=direction,
            cursor=cursor,
            limit=limit,
        )["records"]

    def wallet_bill_sync_response(self, request_or_address, *, limit=100):
        if isinstance(request_or_address, str):
            try:
                request = _load_json(request_or_address)
            except Exception:
                request = {"address": request_or_address}
        elif isinstance(request_or_address, dict):
            request = request_or_address
        else:
            request = {}
        address = str(request.get("address") or request.get("owner_address") or "").strip()
        if not address:
            raise ValidationError("wallet bill sync request is missing address")
        requested_limit = request.get("limit", limit)
        page = self.wallet_bill_sync_page(
            address,
            known_token_sequences=request.get("known_tokens") or {},
            known_display_ranges=request.get("known_display_ranges") or [],
            after_updated_at=request.get("after_updated_at"),
            before_updated_at=request.get("before_updated_at"),
            direction=request.get("direction"),
            cursor=request.get("cursor"),
            limit=requested_limit,
        )
        return {
            "type": "ind.wallet_bill_sync_response.v3",
            "version": 2,
            "address": address,
            "direction": page["direction"],
            "records": page["records"],
            "has_more": page["has_more"],
            "next_cursor": page["next_cursor"],
        }

    def ingest_wallet_bill_sync_record(self, record):
        from . import protocol_v3

        if isinstance(record, str):
            record = _load_json(record)
        if not isinstance(record, dict):
            raise ValidationError("malformed wallet bill sync record")
        if record.get("type") not in {None, "ind.wallet_bill_sync_record.v3"}:
            raise ValidationError("unsupported wallet bill sync record")
        bill = record.get("bill")
        if not isinstance(bill, dict):
            raise ValidationError("wallet bill sync record is missing BillV3")
        for segment in record.get("archive_segments") or []:
            self.store_archive_segment_v3(segment)
        proof_bundle = record.get("proof_bundle")
        trusted_operator_public_key = self._trusted_operator_key_from_proof_bundle_v3(proof_bundle)
        status = str(record.get("status") or "verified")
        if status not in {"verified", "settled", "pending"}:
            status = "verified"
        state = self.store_bill_v3(
            bill,
            proof_bundle=proof_bundle,
            status=status,
            trusted_operator_public_key=trusted_operator_public_key,
        )
        return {
            "accepted": True,
            "status": status,
            "state": state,
            "bill_hash": protocol_v3.bill_hash(bill).hex(),
        }

    # Return the newest locally stored gossip messages for rebroadcast.
    def recent_messages(self, limit=100):
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT message_json FROM messages
                ORDER BY first_seen DESC
                LIMIT ?
                """,
                (int(limit),),
            ).fetchall()
            messages = []
            for row in rows:
                message = self._expand_stored_message(conn, row["message_json"])
                if message:
                    messages.append(message)
            return messages
