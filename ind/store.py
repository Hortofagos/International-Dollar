"""SQLite-backed local state for IND bill gossip and settlement."""

import copy
import logging
import os
import sqlite3
import time
from pathlib import Path

from .protocol import (
    BILL_TYPE,
    BILL_VERSION,
    CONFLICT_PROOF_FIELDS,
    CONFLICT_PROOF_TYPE,
    DEFAULT_LOG_SUBMISSION_VERIFY_TIMEOUT_SECONDS,
    FINALITY_BUFFER_SECONDS,
    GENESIS_MANIFEST_REF_TYPE,
    RECEIPT_ANNOUNCEMENT_FIELDS,
    RECEIPT_ANNOUNCEMENT_TYPE,
    RECEIPT_ANNOUNCEMENT_V2_FIELDS,
    RECEIPT_ANNOUNCEMENT_V2_TYPE,
    STORED_MESSAGE_REF_TYPE,
    TOKEN_STATE_REF_TYPE,
    TOKEN_TYPE,
    TOKEN_VERSION,
    TRANSFER_ANNOUNCEMENT_FIELDS,
    TRANSFER_ANNOUNCEMENT_OPTIONAL_FIELDS,
    TRANSFER_ANNOUNCEMENT_TYPE,
    TRANSFER_ANNOUNCEMENT_V2_FIELDS,
    TRANSFER_ANNOUNCEMENT_V2_TYPE,
    TRANSPARENCY_EQUIVOCATION_PROOF_TYPE,
    TRANSPARENCY_OPERATOR_POLICY_VIOLATION_TYPE,
    TRANSPARENCY_ROOT_ANNOUNCEMENT_TYPE,
    ClosingConnection,
    ValidationError,
    _bill_history,
    _configured_transparency_submitter,
    _configured_transparency_verifier,
    _conflicting_transfers,
    _env_int,
    _env_true,
    _environment_transparency_verifier,
    _last_transfer,
    _load_json,
    _require_exact_fields,
    _require_int,
    _state_ref_from_state,
    _store_json,
    configure_sqlite_connection,
    create_bill_checkpoint,
    create_checkpoint_announcement,
    create_compact_bill,
    create_conflict_proof,
    conflict_proof_key,
    genesis_manifest_hash,
    message_hash,
    transfer_hash,
    unpack_wire_message,
    verify_bill,
    verify_checkpoint_for_genesis,
    verify_conflict_proof,
    verify_receipt_announcement,
    verify_token,
    verify_transparency_equivocation_proof,
    verify_transparency_operator_policy_violation_proof,
    verify_transparency_root_announcement,
)
from .protocol import (
    _bill_history,
    _conflicting_transfers,
    _configured_transparency_submitter,
    _configured_transparency_verifier,
    _env_int,
    _env_true,
    _environment_transparency_verifier,
    _last_transfer,
    _load_json,
    _require_exact_fields,
    _require_int,
    _state_ref_from_state,
    _store_json,
)
from . import settings as ind_settings
from . import transparency_client as log_client

STORE_SCHEMA_VERSION = 4
DEFAULT_FIRST_CHECKPOINT_AFTER_TRANSFERS = 10
DEFAULT_CHECKPOINT_INTERVAL_TRANSFERS = 10
DEFAULT_HIGH_VALUE_CHECKPOINT_THRESHOLD = 0
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


def _policy_int(value, default, minimum=0):
    try:
        result = int(value)
    except Exception:
        result = int(default)
    return max(int(minimum), result)


class INDLocalStore:
    """SQLite-backed cache for verified bill tips, gossip messages, and conflicts."""

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
        """Open or create a local IND gossip store."""

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
            self.transparency_root_gossip = os.environ.get("IND_LOG_ROOT_GOSSIP", "1").strip().lower() not in {"0", "false", "no", "off"}
        self.transparency_verifier = transparency_verifier
        if self.require_transparency and self.transparency_verifier is None:
            self.transparency_verifier = _configured_transparency_verifier()
        self.transparency_submitter = transparency_submitter
        if self.transparency_submitter is None:
            self.transparency_submitter = _configured_transparency_submitter()
        if self.transparency_submitter is not None and self.transparency_verifier is None:
            self.transparency_verifier = _environment_transparency_verifier()
        if self.transparency_root_gossip and self.transparency_verifier is None:
            self.transparency_verifier = _environment_transparency_verifier()
        if transparency_submission_verify_timeout_seconds is None:
            self.transparency_submission_verify_timeout_seconds = _env_int(
                "IND_LOG_SUBMISSION_VERIFY_TIMEOUT_SECONDS",
                DEFAULT_LOG_SUBMISSION_VERIFY_TIMEOUT_SECONDS,
            )
        else:
            self.transparency_submission_verify_timeout_seconds = int(transparency_submission_verify_timeout_seconds)
        self.first_checkpoint_after_transfers = _policy_int(
            first_checkpoint_after_transfers
            if first_checkpoint_after_transfers is not None
            else _env_int("IND_FIRST_CHECKPOINT_AFTER_TRANSFERS", DEFAULT_FIRST_CHECKPOINT_AFTER_TRANSFERS),
            DEFAULT_FIRST_CHECKPOINT_AFTER_TRANSFERS,
            minimum=1,
        )
        self.checkpoint_interval_transfers = _policy_int(
            checkpoint_interval_transfers
            if checkpoint_interval_transfers is not None
            else _env_int("IND_CHECKPOINT_INTERVAL_TRANSFERS", DEFAULT_CHECKPOINT_INTERVAL_TRANSFERS),
            DEFAULT_CHECKPOINT_INTERVAL_TRANSFERS,
            minimum=1,
        )
        self.high_value_checkpoint_threshold = _policy_int(
            high_value_checkpoint_threshold
            if high_value_checkpoint_threshold is not None
            else _env_int("IND_HIGH_VALUE_CHECKPOINT_THRESHOLD", DEFAULT_HIGH_VALUE_CHECKPOINT_THRESHOLD),
            DEFAULT_HIGH_VALUE_CHECKPOINT_THRESHOLD,
            minimum=0,
        )
        self._init_db()

    def _connect(self):
        """Create a short-lived SQLite connection with row dictionaries enabled."""

        conn = sqlite3.connect(self.db_path, factory=ClosingConnection)
        configure_sqlite_connection(conn)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Create the tables used for compact bill storage and local settlement."""

        with self._connect() as conn:
            self._migrate_db(conn)
            conn.executescript(
                """
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
                """
            )
            self._set_schema_version(conn, STORE_SCHEMA_VERSION)

    def _schema_version(self, conn):
        try:
            row = conn.execute("PRAGMA user_version").fetchone()
            return int(row[0]) if row else 0
        except Exception:
            return 0

    def _set_schema_version(self, conn, version):
        conn.execute(f"PRAGMA user_version={int(version)}")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ind_schema (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            INSERT OR REPLACE INTO ind_schema(key, value, updated_at)
            VALUES ('schema_version', ?, ?)
            """,
            (str(int(version)), int(time.time())),
        )

    def _migrate_db(self, conn):
        version = self._schema_version(conn)
        if version > STORE_SCHEMA_VERSION:
            raise ValidationError(
                f"IND store schema {version} is newer than this client supports ({STORE_SCHEMA_VERSION})"
            )
        if version < STORE_SCHEMA_VERSION:
            logger.info("migrating IND local store schema from %s to %s", version, STORE_SCHEMA_VERSION)
        if version < 3:
            self._migrate_conflict_keys(conn)
        if version < 4:
            self._migrate_conflict_burn_status(conn)

    def _table_columns(self, conn, table_name):
        try:
            rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
        except sqlite3.OperationalError:
            return set()
        return {row["name"] if "name" in row.keys() else row[1] for row in rows}

    def _migrate_conflict_keys(self, conn):
        exists = conn.execute(
            """
            SELECT 1 FROM sqlite_master
            WHERE type = 'table' AND name = 'conflicts'
            """
        ).fetchone()
        if not exists:
            return
        columns = self._table_columns(conn, "conflicts")
        if "conflict_key" not in columns:
            conn.execute("ALTER TABLE conflicts ADD COLUMN conflict_key TEXT")
        rows = conn.execute(
            """
            SELECT rowid, proof_hash, proof_json FROM conflicts
            WHERE conflict_key IS NULL OR conflict_key = ''
            """
        ).fetchall()
        for row in rows:
            try:
                key = conflict_proof_key(_load_json(row["proof_json"]))
            except Exception as exc:
                logger.warning("could not derive conflict key for stored proof %s: %s", row["proof_hash"], exc)
                key = f"legacy:{row['proof_hash']}"
            conn.execute(
                "UPDATE conflicts SET conflict_key = ? WHERE rowid = ?",
                (key, int(row["rowid"])),
            )
        conn.execute(
            """
            DELETE FROM conflicts
            WHERE rowid NOT IN (
                SELECT MIN(rowid) FROM conflicts GROUP BY conflict_key
            )
            """
        )
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_conflicts_key ON conflicts(conflict_key)")

    def _migrate_conflict_burn_status(self, conn):
        """Undo legacy conflict burns: settled rows revive, unsettled conflict rows stay rejected."""

        token_columns = self._table_columns(conn, "tokens")
        transfer_columns = self._table_columns(conn, "transfers")
        if {"status", "finalized_at"}.issubset(transfer_columns):
            conn.execute(
                """
                UPDATE transfers
                SET status = 'settled'
                WHERE status = 'invalid' AND finalized_at IS NOT NULL
                """
            )
            conn.execute(
                """
                UPDATE transfers
                SET status = 'rejected'
                WHERE status = 'invalid' AND finalized_at IS NULL
                """
            )
        if {"status", "finalized_at"}.issubset(token_columns):
            conn.execute(
                """
                UPDATE tokens
                SET status = 'settled'
                WHERE status = 'invalid' AND finalized_at IS NOT NULL
                """
            )
            conn.execute(
                """
                UPDATE tokens
                SET status = 'rejected'
                WHERE status = 'invalid' AND finalized_at IS NULL
                """
            )

    def _store_genesis(self, conn, token, state):
        """Store a bill genesis once, keeping lazy manifests in a shared table."""

        genesis = self._compact_genesis_for_store(conn, token["genesis"])
        conn.execute(
            """
            INSERT OR IGNORE INTO token_genesis(token_id, display_id, genesis_json, value)
            VALUES (?, ?, ?, ?)
            """,
            (
                state.token_id,
                state.display_id,
                _store_json(genesis),
                int(state.value),
            ),
        )

    def _compact_genesis_for_store(self, conn, genesis):
        """Replace embedded lazy manifests with hash references before persistence."""

        manifest_ref = genesis.get("manifest_ref") if isinstance(genesis, dict) else None
        if not isinstance(manifest_ref, dict) or "manifest" not in manifest_ref:
            return genesis
        manifest = manifest_ref["manifest"]
        manifest_hash_value = genesis_manifest_hash(manifest)
        conn.execute(
            """
            INSERT OR IGNORE INTO genesis_manifests(manifest_hash, manifest_json, first_seen)
            VALUES (?, ?, ?)
            """,
            (manifest_hash_value, _store_json(manifest), int(time.time())),
        )
        compact = copy.deepcopy(genesis)
        compact["manifest_ref"] = {
            "type": GENESIS_MANIFEST_REF_TYPE,
            "manifest_hash": manifest_hash_value,
        }
        return compact

    def _expand_genesis_from_store(self, conn, genesis):
        """Restore a compact stored genesis record to the full verifiable form."""

        manifest_ref = genesis.get("manifest_ref") if isinstance(genesis, dict) else None
        if not isinstance(manifest_ref, dict) or "manifest" in manifest_ref:
            return genesis
        manifest_hash_value = manifest_ref.get("manifest_hash")
        row = conn.execute(
            "SELECT manifest_json FROM genesis_manifests WHERE manifest_hash = ?",
            (manifest_hash_value,),
        ).fetchone()
        if not row:
            return genesis
        expanded = copy.deepcopy(genesis)
        expanded["manifest_ref"] = {
            "type": GENESIS_MANIFEST_REF_TYPE,
            "manifest_hash": manifest_hash_value,
            "manifest": _load_json(row["manifest_json"]),
        }
        return expanded

    def _store_checkpoint(self, conn, checkpoint, status="settled"):
        """Persist one transparency-backed compact checkpoint."""

        now = int(time.time())
        transparency = checkpoint.get("transparency") if isinstance(checkpoint, dict) else None
        root = transparency.get("root") if isinstance(transparency, dict) else None
        inclusion_proof = transparency.get("inclusion_proof") if isinstance(transparency, dict) else None
        spend_proof = transparency.get("spend_proof") if isinstance(transparency, dict) else None
        conn.execute(
            """
            INSERT OR REPLACE INTO checkpoints(
                checkpoint_hash, token_id, sequence, last_transfer_hash, owner_address,
                checkpoint_json, root_json, inclusion_proof_json, spend_proof_json, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                checkpoint["checkpoint_hash"],
                checkpoint["token_id"],
                int(checkpoint["sequence"]),
                checkpoint["last_transfer_hash"],
                checkpoint["owner_address"],
                _store_json(checkpoint),
                _store_json(root) if root is not None else None,
                _store_json(inclusion_proof) if inclusion_proof is not None else None,
                _store_json(spend_proof) if spend_proof is not None else None,
                status,
                now,
            ),
        )

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
        return self._compact_bill_from_checkpoint_row(conn, token_id, self._latest_checkpoint_row(conn, token_id))

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

    def _rebuild_token_from_store(self, conn, token_id, last_transfer_hash=None, sequence=None):
        """Reconstruct a full bearer bill from normalized genesis and transfer rows."""

        token_row = conn.execute(
            "SELECT last_transfer_hash, sequence FROM tokens WHERE token_id = ?",
            (token_id,),
        ).fetchone()
        genesis_row = conn.execute(
            "SELECT genesis_json FROM token_genesis WHERE token_id = ?",
            (token_id,),
        ).fetchone()
        if not token_row or not genesis_row:
            return None

        genesis = self._expand_genesis_from_store(conn, _load_json(genesis_row["genesis_json"]))
        target_hash = last_transfer_hash or token_row["last_transfer_hash"]
        target_sequence = int(sequence if sequence is not None else token_row["sequence"])
        if target_sequence == 0:
            return {
                "type": TOKEN_TYPE,
                "version": TOKEN_VERSION,
                "token_id": token_id,
                "genesis": genesis,
                "history": [],
            }

        transfer_rows = conn.execute(
            "SELECT transfer_hash, transfer_json FROM transfers WHERE token_id = ?",
            (token_id,),
        ).fetchall()
        transfers_by_hash = {
            row["transfer_hash"]: _load_json(row["transfer_json"])
            for row in transfer_rows
        }
        history_reversed = []
        current_hash = target_hash
        for _ in range(target_sequence):
            transfer = transfers_by_hash.get(current_hash)
            if not transfer:
                return None
            history_reversed.append(transfer)
            current_hash = transfer["previous_hash"]
        history_reversed.reverse()
        token = {
            "type": TOKEN_TYPE,
            "version": TOKEN_VERSION,
            "token_id": token_id,
            "genesis": genesis,
            "history": history_reversed,
        }
        verify_token(token)
        return token

    def _token_from_payload(self, conn, payload, token_id=None):
        """Resolve either a compact state reference or a full bill payload."""

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
            return self._compact_bill_for_sequence(conn, data["token_id"], int(data.get("sequence", 0)))
        if isinstance(data, dict) and data.get("type") in {TOKEN_TYPE, BILL_TYPE}:
            return data
        if token_id:
            return self._rebuild_token_from_store(conn, token_id)
        return None

    def _stored_message_payload(self, message, state=None):
        """Store gossip messages as compact references when the bill is already known."""

        if state and message.get("type") in {
            TRANSFER_ANNOUNCEMENT_TYPE,
            RECEIPT_ANNOUNCEMENT_TYPE,
            TRANSFER_ANNOUNCEMENT_V2_TYPE,
            RECEIPT_ANNOUNCEMENT_V2_TYPE,
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
            if message["type"] in {RECEIPT_ANNOUNCEMENT_TYPE, RECEIPT_ANNOUNCEMENT_V2_TYPE}:
                ref["receipt"] = message["receipt"]
            return ref
        return message

    def _expand_stored_message(self, conn, stored_payload):
        """Expand a stored message reference back into the wire-level gossip object."""

        message = _load_json(stored_payload)
        if not isinstance(message, dict) or message.get("type") != STORED_MESSAGE_REF_TYPE:
            return message

        if message["message_type"] in {TRANSFER_ANNOUNCEMENT_V2_TYPE, RECEIPT_ANNOUNCEMENT_V2_TYPE}:
            target_sequence = int(message.get("sequence", 0))
            checkpoint_row = self._checkpoint_before_sequence(conn, message["token_id"], target_sequence)
            token = self._compact_bill_from_checkpoint_row(conn, message["token_id"], checkpoint_row)
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
        if message["message_type"] == TRANSFER_ANNOUNCEMENT_V2_TYPE:
            return {
                "type": TRANSFER_ANNOUNCEMENT_V2_TYPE,
                "version": BILL_VERSION,
                "bill": token,
                "announced_at": int(message.get("announced_at", time.time())),
            }
        if message["message_type"] == RECEIPT_ANNOUNCEMENT_TYPE:
            return {
                "type": RECEIPT_ANNOUNCEMENT_TYPE,
                "version": TOKEN_VERSION,
                "token": token,
                "receipt": message["receipt"],
                "announced_at": int(message.get("announced_at", time.time())),
            }
        if message["message_type"] == RECEIPT_ANNOUNCEMENT_V2_TYPE:
            return {
                "type": RECEIPT_ANNOUNCEMENT_V2_TYPE,
                "version": BILL_VERSION,
                "bill": token,
                "receipt": message["receipt"],
                "announced_at": int(message.get("announced_at", time.time())),
            }
        return None

    def _record_message(self, conn, message, state=None):
        """Persist a deduplicated gossip message and return its canonical hash."""

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
            (mh, message["type"], token_id, recipient_address, _store_json(stored_payload), int(time.time())),
        )
        return mh

    def _submit_to_transparency_log(self, message, token):
        """Submit a validated transfer announcement to the configured public log."""

        if not self.transparency_submitter or message.get("type") not in {TRANSFER_ANNOUNCEMENT_TYPE, TRANSFER_ANNOUNCEMENT_V2_TYPE}:
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
                raise ValidationError("transparency submission cannot be verified without root mirrors")
            self._verify_transparency_submission(token, expected_entry_hash, leaf_index)
            return response
        except Exception as exc:
            if "conflicting spend" in str(exc).lower():
                raise ValidationError(f"transparency log rejected conflicting transfer: {exc}") from exc
            if self.require_transparency:
                raise ValidationError(f"transparency log submission failed: {exc}") from exc
            logger.warning("transparency log submission failed for %s: %s", expected_entry_hash, exc)
            return {"accepted": False, "status": "unlogged", "error": str(exc)}

    def _validate_transparency_append_response(self, response, expected_entry_hash, expected_spend_key):
        """Require the operator append response to identify the exact logged leaf."""

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

    def _verify_transparency_submission(self, token, entry_hash, leaf_index):
        """Retry proof verification until timeout to tolerate normal root mirror lag."""

        from . import transparency_client as log_client

        transfer_timestamp = int(_last_transfer(token)["timestamp"])
        timeout = max(0, int(self.transparency_submission_verify_timeout_seconds))
        deadline = time.monotonic() + timeout
        last_error = None
        while True:
            try:
                root = self.transparency_verifier.mirrored_root_containing_leaf(transfer_timestamp, leaf_index)
                proof = self.transparency_verifier.operator.inclusion_proof(entry_hash, int(root["tree_size"]))
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
        raise ValidationError(f"transparency log append was not proven by a mirror before timeout: {last_error}")

    def _submit_checkpoint_to_transparency_log(self, checkpoint, bill):
        """Submit a compact checkpoint and return embedded transparency proof material."""

        if self.transparency_submitter is None or self.transparency_verifier is None:
            return None
        from . import transparency_client as log_client

        announcement = create_checkpoint_announcement(checkpoint, bill=bill)
        latest_transfer = _last_transfer(bill)
        genesis = bill["genesis"]
        expected_hash = checkpoint["checkpoint_hash"]
        try:
            response = self.transparency_submitter.submit_checkpoint_announcement(announcement)
            if not isinstance(response, dict) or not response.get("accepted"):
                raise ValidationError("transparency log did not accept the checkpoint")
            if str(response.get("entry_hash", "")).lower() != expected_hash:
                raise ValidationError("transparency log appended a different checkpoint hash")
            leaf_index = int(response["leaf_index"])
        except Exception as exc:
            if self.require_transparency:
                raise ValidationError(f"checkpoint transparency submission failed: {exc}") from exc
            logger.warning("checkpoint transparency submission failed for %s: %s", expected_hash, exc)
            return None

        timeout = max(0, int(self.transparency_submission_verify_timeout_seconds))
        deadline = time.monotonic() + timeout
        last_error = None
        while True:
            try:
                root = self.transparency_verifier.current_mirrored_root()
                if int(root["tree_size"]) < leaf_index + 1:
                    raise ValidationError("current transparency root does not contain checkpoint")
                inclusion_proof = self.transparency_verifier.operator.inclusion_proof(expected_hash, int(root["tree_size"]))
                log_client.verify_inclusion_proof(
                    expected_hash,
                    inclusion_proof,
                    root,
                    operator_public_key=root.get("operator_public_key"),
                )
                spend_proof = self.transparency_verifier.operator.spend_map_proof(
                    log_client.spend_key_for_transfer(latest_transfer),
                    int(root["tree_size"]),
                )
                checkpoint_for_proof = copy.deepcopy(checkpoint)
                checkpoint_for_proof["transparency"] = {
                    "type": "ind.checkpoint_transparency.v2",
                    "version": BILL_VERSION,
                    "root": root,
                    "inclusion_proof": inclusion_proof,
                    "spend_proof": spend_proof,
                }
                verify_checkpoint_for_genesis(
                    checkpoint_for_proof,
                    genesis,
                    require_transparency=True,
                )
                return checkpoint_for_proof["transparency"]
            except Exception as exc:
                last_error = exc
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                time.sleep(min(1.0, remaining))
        if self.require_transparency:
            raise ValidationError(f"checkpoint transparency proof was not available before timeout: {last_error}")
        logger.warning("checkpoint transparency proof was not available for %s: %s", expected_hash, last_error)
        return None

    def _checkpoint_due_for_bill(self, conn, bill, state=None, force=False):
        """Return whether policy says this settled bill should be compacted now."""

        state = state or verify_bill(bill, require_recent_transparency=False)
        if int(state.sequence) <= 0:
            return False
        if force:
            return True
        if (
            self.high_value_checkpoint_threshold > 0
            and int(state.value) >= int(self.high_value_checkpoint_threshold)
        ):
            return True
        latest_sequence = self._latest_checkpoint_sequence(conn, state.token_id)
        if latest_sequence <= 0:
            return int(state.sequence) >= int(self.first_checkpoint_after_transfers)
        return int(state.sequence) - int(latest_sequence) >= int(self.checkpoint_interval_transfers)

    def _store_compact_checkpoint_for_bill(self, conn, bill, force=False, require_proof=False):
        """Create, prove, store, and return a compact checkpoint bill when policy allows."""

        state = verify_bill(bill, require_recent_transparency=False)
        if not self._checkpoint_due_for_bill(conn, bill, state=state, force=force):
            return None
        existing = self._checkpoint_for_transfer(conn, state.token_id, state.last_transfer_hash)
        if existing:
            compact_bill = self._compact_bill_from_checkpoint_row(conn, state.token_id, existing)
            if compact_bill:
                compact_state = verify_bill(compact_bill)
                self._store_token_tip(conn, compact_bill, compact_state, "settled")
            return compact_bill

        checkpoint = create_bill_checkpoint(bill)
        transparency = self._submit_checkpoint_to_transparency_log(checkpoint, bill)
        if not transparency:
            if require_proof:
                raise ValidationError("compact checkpoint requires transparency submission and mirrored proof")
            return None
        checkpoint["transparency"] = transparency
        verify_checkpoint_for_genesis(
            checkpoint,
            bill["genesis"],
            require_transparency=True,
        )
        self._store_checkpoint(conn, checkpoint, status="settled")
        compact_bill = create_compact_bill(bill, checkpoint)
        compact_state = verify_bill(compact_bill)
        self._store_token_tip(conn, compact_bill, compact_state, "settled")
        return compact_bill

    def _store_token_tip(self, conn, token, state, status):
        """Persist the latest known valid state for a bill without downgrading it."""

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
        if existing and existing["status"] == "settled" and existing["last_transfer_hash"] == state.last_transfer_hash:
            status = "settled"
        elif existing and existing["status"] == "pending" and status == "unreceipted":
            status = "pending"
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

    def _store_transfer(self, conn, token, state, status):
        """Persist new transfers from a bill history, preserving older settled rows."""

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
            if existing and existing["status"] == "pending" and transfer_status == "unreceipted":
                transfer_status = "pending"
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

    def _find_conflict(self, conn, token):
        """Search stored sibling transfers for a double-spend anywhere in this bill branch."""

        state = verify_token(token)
        if state.sequence == 0:
            return None
        for transfer in _bill_history(token):
            current_hash = transfer_hash(transfer)
            rows = conn.execute(
                """
                SELECT transfer_hash, sequence FROM transfers
                WHERE token_id = ?
                  AND previous_hash = ?
                  AND sequence = ?
                  AND sender_address = ?
                  AND transfer_hash != ?
                """,
                (
                    state.token_id,
                    transfer["previous_hash"],
                    int(transfer["sequence"]),
                    transfer["sender_address"],
                    current_hash,
                ),
            ).fetchall()
            for row in rows:
                other_token = self._rebuild_token_from_store(
                    conn,
                    state.token_id,
                    last_transfer_hash=row["transfer_hash"],
                    sequence=int(row["sequence"]),
                )
                if other_token and _conflicting_transfers(token, other_token):
                    logger.warning("detected IND bill conflict for %s at sequence %s", state.token_id, transfer["sequence"])
                    return create_conflict_proof(token, other_token)
        return None

    def _record_conflict(self, conn, proof):
        """Store verified double-spend evidence without invalidating the bill."""

        verify_conflict_proof(proof)
        proof_hash_value = proof["proof_hash"]
        proof_key = conflict_proof_key(proof)
        existing = conn.execute(
            """
            SELECT proof_json FROM conflicts
            WHERE conflict_key = ?
            LIMIT 1
            """,
            (proof_key,),
        ).fetchone()
        inserted = existing is None
        stored_proof = proof
        if inserted:
            logger.warning("recording IND conflict proof %s for bill %s", proof_hash_value, proof["token_id"])
            conn.execute(
                """
                INSERT OR IGNORE INTO conflicts(
                    proof_hash, conflict_key, token_id, previous_hash, proof_json, detected_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    proof_hash_value,
                    proof_key,
                    proof["token_id"],
                    proof["previous_hash"],
                    _store_json(proof),
                    int(time.time()),
                ),
            )
        else:
            try:
                stored_proof = self._load_conflict_proof_row(existing)
            except Exception as exc:
                logger.warning("stored conflict proof could not be reloaded: %s", exc)
                stored_proof = proof
            logger.debug("deduped IND conflict proof %s for bill %s", proof_hash_value, proof["token_id"])
        return {
            "inserted": bool(inserted),
            "conflict_key": proof_key,
            "proof_hash": stored_proof.get("proof_hash", proof_hash_value),
            "proof": stored_proof,
        }

    def _reject_conflicting_transfer(self, conn, token):
        """Reject a branch that conflicts with an already known local branch."""

        conflict = self._find_conflict(conn, token)
        if not conflict:
            return None
        raise ValidationError("conflicting transfer rejected")

    def _drain_transparency_gossip(self):
        if self.transparency_verifier is None:
            return []
        drain = getattr(self.transparency_verifier, "consume_pending_gossip_messages", None)
        if not callable(drain):
            return []
        return drain()

    def transparency_equivocation_messages(self, limit=100):
        if self.transparency_verifier is None:
            return []
        persisted = getattr(self.transparency_verifier, "persisted_equivocation_messages", None)
        if not callable(persisted):
            return []
        return persisted(limit=limit)

    def transparency_operator_policy_violation_messages(self, limit=100):
        if self.transparency_verifier is None:
            return []
        persisted = getattr(self.transparency_verifier, "persisted_operator_policy_violation_messages", None)
        if not callable(persisted):
            return []
        return persisted(limit=limit)

    def _load_conflict_proof_row(self, row):
        if not row:
            return None
        proof = _load_json(row["proof_json"])
        verify_conflict_proof(proof)
        return proof

    def conflict_messages(self, limit=100):
        """Return recently stored verified conflict proofs for durable rebroadcast."""

        messages = []
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT proof_json FROM conflicts
                ORDER BY detected_at DESC
                LIMIT ?
                """,
                (max(0, int(limit)),),
            ).fetchall()
            for row in rows:
                try:
                    messages.append(self._load_conflict_proof_row(row))
                except Exception as exc:
                    logger.warning("stored conflict proof could not be reloaded: %s", exc)
        return [message for message in messages if message]

    def _token_row_for_ref(self, conn, ref):
        row = conn.execute("SELECT * FROM tokens WHERE token_id = ?", (ref,)).fetchone()
        if row:
            return row
        return conn.execute("SELECT * FROM tokens WHERE display_id = ?", (ref,)).fetchone()

    def status_record_for_ref(self, ref, *, min_settled_seconds=0):
        """Return one compact local status record for a bill id or display id."""

        ref = str(ref).strip()
        if not ref:
            return None
        with self._connect() as conn:
            token_row = self._token_row_for_ref(conn, ref)
            if not token_row:
                return None
            if token_row["status"] == "invalid":
                return {
                    "ref": ref,
                    "display_id": token_row["display_id"],
                    "token_id": token_row["token_id"],
                    "owner_address": "",
                    "sequence": int(token_row["sequence"]),
                    "status": "invalid",
                }
            token = self._token_from_payload(conn, token_row["payload"], token_row["token_id"])
        if not token:
            return {
                "ref": ref,
                "display_id": token_row["display_id"],
                "token_id": token_row["token_id"],
                "owner_address": "",
                "sequence": int(token_row["sequence"]),
                "status": "invalid",
            }
        try:
            state = verify_bill(token, require_recent_transparency=False)
            confidence = self.token_confidence(
                state.token_id,
                expected_owner=state.owner_address,
                min_settled_seconds=min_settled_seconds,
            )
            status = confidence.get("level", token_row["status"])
            return {
                "ref": ref,
                "display_id": state.display_id,
                "token_id": state.token_id,
                "owner_address": state.owner_address,
                "sequence": int(state.sequence),
                "status": status,
            }
        except ValidationError:
            return {
                "ref": ref,
                "display_id": token_row["display_id"],
                "token_id": token_row["token_id"],
                "owner_address": "",
                "sequence": int(token_row["sequence"]),
                "status": "invalid",
            }

    def _ingest_transfer_announcement(self, conn, message):
        if message.get("type") == TRANSFER_ANNOUNCEMENT_V2_TYPE:
            _require_exact_fields(message, TRANSFER_ANNOUNCEMENT_V2_FIELDS, "v2 transfer announcement")
            if _require_int(message["version"], "v2 transfer announcement version") != BILL_VERSION:
                raise ValidationError("unsupported v2 transfer announcement version")
            token = message["bill"]
            state = verify_bill(token, require_recent_transparency=False)
        else:
            _require_exact_fields(
                message,
                TRANSFER_ANNOUNCEMENT_FIELDS,
                "transfer announcement",
                optional=TRANSFER_ANNOUNCEMENT_OPTIONAL_FIELDS,
            )
            if _require_int(message["version"], "transfer announcement version") != TOKEN_VERSION:
                raise ValidationError("unsupported transfer announcement version")
            token = message["token"]
            state = verify_token(token)
        _require_int(message["announced_at"], "transfer announcement announced_at", minimum=0)
        self._reject_conflicting_transfer(conn, token)
        self._store_transfer(conn, token, state, "unreceipted")
        self._submit_to_transparency_log(message, token)
        if self.require_transparency:
            verify_bill(token, transparency_verifier=self.transparency_verifier, require_transparency=True)
        self._store_token_tip(conn, token, state, "unreceipted")
        self._record_message(conn, message, state)
        return {
            "accepted": True,
            "status": "unreceipted",
            "state": state,
            "gossip_messages": self._drain_transparency_gossip(),
        }

    def _ingest_receipt_announcement(self, conn, message):
        if message.get("type") == RECEIPT_ANNOUNCEMENT_V2_TYPE:
            _require_exact_fields(message, RECEIPT_ANNOUNCEMENT_V2_FIELDS, "v2 receipt announcement")
            if _require_int(message["version"], "v2 receipt announcement version") != BILL_VERSION:
                raise ValidationError("unsupported v2 receipt announcement version")
            token = message["bill"]
        else:
            _require_exact_fields(message, RECEIPT_ANNOUNCEMENT_FIELDS, "receipt announcement")
            if _require_int(message["version"], "receipt announcement version") != TOKEN_VERSION:
                raise ValidationError("unsupported receipt announcement version")
            token = message["token"]
        _require_int(message["announced_at"], "receipt announcement announced_at", minimum=0)
        state = verify_receipt_announcement(
            message,
            transparency_verifier=self.transparency_verifier if self.require_transparency else None,
            require_transparency=self.require_transparency,
        )
        self._reject_conflicting_transfer(conn, token)
        self._store_transfer(conn, token, state, "pending")
        self._store_token_tip(conn, token, state, "pending")
        self._record_message(conn, message, state)
        return {
            "accepted": True,
            "status": "pending",
            "state": state,
            "gossip_messages": self._drain_transparency_gossip(),
        }

    def _ingest_conflict_proof(self, conn, message):
        _require_exact_fields(message, CONFLICT_PROOF_FIELDS, "conflict proof")
        conflict_record = self._record_conflict(conn, message)
        result = {
            "accepted": True,
            "status": "conflict",
            "duplicate_conflict": not conflict_record["inserted"],
            "relay": bool(conflict_record["inserted"]),
        }
        if conflict_record["inserted"]:
            result["conflict_proof"] = conflict_record["proof"]
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

    def ingest_message(self, message, peer_id=None):
        """Validate one gossip message, update local state, and emit conflicts if found."""

        if isinstance(message, bytes):
            message = message.decode("utf-8")
        if isinstance(message, str):
            message = _load_json(message)
        if not isinstance(message, dict) or "type" not in message:
            raise ValidationError("malformed gossip message")

        with self._connect() as conn:
            message_type = message["type"]
            # Keep each gossip family on its own validation path; they update different tables.
            if message_type in {TRANSFER_ANNOUNCEMENT_TYPE, TRANSFER_ANNOUNCEMENT_V2_TYPE}:
                return self._ingest_transfer_announcement(conn, message)

            if message_type in {RECEIPT_ANNOUNCEMENT_TYPE, RECEIPT_ANNOUNCEMENT_V2_TYPE}:
                return self._ingest_receipt_announcement(conn, message)

            if message_type == CONFLICT_PROOF_TYPE:
                return self._ingest_conflict_proof(conn, message)

            if message_type == TRANSPARENCY_ROOT_ANNOUNCEMENT_TYPE:
                return self._ingest_transparency_root(conn, message, peer_id=peer_id)

            if message_type == TRANSPARENCY_EQUIVOCATION_PROOF_TYPE:
                return self._ingest_transparency_equivocation(conn, message, peer_id=peer_id)

            if message_type == TRANSPARENCY_OPERATOR_POLICY_VIOLATION_TYPE:
                return self._ingest_transparency_operator_policy_violation(conn, message, peer_id=peer_id)

        raise ValidationError("unsupported gossip message type")

    def ingest_wire_message(self, raw, peer_id=None):
        """Accept a raw peer payload and pass the decoded message into the store."""

        if not raw:
            return {"accepted": False, "status": "empty"}
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        raw = raw.strip()
        if not raw:
            return {"accepted": False, "status": "empty"}
        return self.ingest_message(unpack_wire_message(raw), peer_id=peer_id)

    def finalize_pending(self, now=None, buffer_seconds=FINALITY_BUFFER_SECONDS):
        """Settle receipt-backed transfers that survived the local finality buffer."""

        now = int(now or time.time())
        cutoff = now - int(buffer_seconds)
        finalized = []
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM transfers
                WHERE status = 'pending' AND first_seen <= ?
                """,
                (cutoff,),
            ).fetchall()
            for row in rows:
                # A sibling transfer means this pending branch never becomes spendable.
                siblings = conn.execute(
                    """
                    SELECT COUNT(*) AS count_value FROM transfers
                    WHERE token_id = ?
                      AND previous_hash = ?
                      AND sequence = ?
                      AND sender_address = ?
                    """,
                    (row["token_id"], row["previous_hash"], row["sequence"], row["sender_address"]),
                ).fetchone()
                if int(siblings["count_value"]) > 1:
                    conn.execute(
                        "UPDATE transfers SET status = 'rejected' WHERE transfer_hash = ?",
                        (row["transfer_hash"],),
                    )
                    conn.execute(
                        """
                        UPDATE tokens
                        SET status = 'rejected', updated_at = ?
                        WHERE token_id = ? AND last_transfer_hash = ?
                        """,
                        (now, row["token_id"], row["transfer_hash"]),
                    )
                    continue
                # Settlement and compact checkpointing are separate so old full bills still rebuild.
                conn.execute(
                    "UPDATE transfers SET status = 'settled', finalized_at = ? WHERE transfer_hash = ?",
                    (now, row["transfer_hash"]),
                )
                conn.execute(
                    """
                    UPDATE tokens
                    SET status = 'settled', finalized_at = ?, updated_at = ?
                    WHERE token_id = ? AND last_transfer_hash = ?
                    """,
                    (now, now, row["token_id"], row["transfer_hash"]),
                )
                if not self._checkpoint_for_transfer(conn, row["token_id"], row["transfer_hash"]):
                    try:
                        bill_for_checkpoint = self._bill_for_settled_transfer_row(conn, row)
                        if bill_for_checkpoint:
                            self._store_compact_checkpoint_for_bill(conn, bill_for_checkpoint)
                    except Exception as exc:
                        if self.require_transparency:
                            raise
                        logger.warning("could not create compact checkpoint for %s: %s", row["token_id"], exc)
                finalized.append(row["token_id"])
        return finalized

    def compact_bill_now(self, token_id=None, display_id=None):
        """Force a compact checkpoint for one locally settled bill."""

        if not token_id and not display_id:
            raise ValidationError("compact now requires a bill id or display id")
        with self._connect() as conn:
            if display_id:
                row = conn.execute(
                    "SELECT * FROM tokens WHERE display_id = ?",
                    (display_id,),
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT * FROM tokens WHERE token_id = ?",
                    (token_id,),
                ).fetchone()
            if not row:
                raise ValidationError("bill not found")
            if row["status"] != "settled":
                raise ValidationError("bill must be locally settled before compacting")
            if int(row["sequence"]) <= 0:
                raise ValidationError("genesis bill cannot be checkpointed")
            existing = self._checkpoint_for_transfer(conn, row["token_id"], row["last_transfer_hash"])
            if existing:
                compact_bill = self._compact_bill_from_checkpoint_row(conn, row["token_id"], existing)
                if compact_bill:
                    return compact_bill
            bill = self._bill_for_settled_transfer_row(
                conn,
                {
                    "token_id": row["token_id"],
                    "transfer_hash": row["last_transfer_hash"],
                    "sequence": int(row["sequence"]),
                },
            )
            if not bill:
                raise ValidationError("settled bill history is unavailable for checkpointing")
            compact_bill = self._store_compact_checkpoint_for_bill(
                conn,
                bill,
                force=True,
                require_proof=True,
            )
            if not compact_bill:
                raise ValidationError("compact checkpoint was not created")
            return compact_bill

    def get_token(self, token_id):
        """Return a rebuilt bearer bill by protocol bill id."""

        with self._connect() as conn:
            row = conn.execute("SELECT payload FROM tokens WHERE token_id = ?", (token_id,)).fetchone()
            if not row:
                return None
            return self._token_from_payload(conn, row["payload"], token_id)

    def get_token_by_display_id(self, display_id):
        """Return a rebuilt bearer bill by wallet display id."""

        with self._connect() as conn:
            row = conn.execute("SELECT token_id, payload FROM tokens WHERE display_id = ?", (display_id,)).fetchone()
            if not row:
                return None
            return self._token_from_payload(conn, row["payload"], row["token_id"])

    def get_compact_bill_by_display_id(self, display_id):
        """Return a v2 compact bill for a wallet display id when a checkpoint exists."""

        with self._connect() as conn:
            row = conn.execute("SELECT token_id FROM tokens WHERE display_id = ?", (display_id,)).fetchone()
            if not row:
                return None
            return self._compact_bill_from_latest_checkpoint(conn, row["token_id"])

    def get_compact_bill(self, token_id):
        """Return a v2 compact bill by protocol bill id when a checkpoint exists."""

        with self._connect() as conn:
            return self._compact_bill_from_latest_checkpoint(conn, token_id)

    def get_token_record(self, token_id):
        """Return the stored bill row used by UI and tests."""

        with self._connect() as conn:
            row = conn.execute("SELECT * FROM tokens WHERE token_id = ?", (token_id,)).fetchone()
        return dict(row) if row else None

    def token_records_for_owner(self, owner_address, settled_only=True, limit=1000):
        """List locally known bill records for an owner address."""

        statuses = ("settled",) if settled_only else ("unreceipted", "pending", "settled")
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

    def token_confidence(self, token_id, expected_owner=None, min_settled_seconds=FINALITY_BUFFER_SECONDS, now=None):
        """Report whether a bill is locally acceptable for a recipient."""

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
            return {"accepted": False, "level": "wrong_owner", "reason": "bill owner does not match expected owner"}
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

    def messages_for_recipient(self, recipient_address, limit=100):
        """Return recent expanded gossip messages addressed to a wallet."""

        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT message_json FROM messages
                WHERE recipient_address = ?
                ORDER BY first_seen DESC
                LIMIT ?
                """,
                (recipient_address, int(limit)),
            ).fetchall()
            messages = []
            for row in rows:
                message = self._expand_stored_message(conn, row["message_json"])
                if message:
                    messages.append(message)
            return messages

    def recent_messages(self, limit=100):
        """Return the newest locally stored gossip messages for rebroadcast."""

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
