# SQLite-backed local state for IND bill gossip and settlement.

import copy
import logging
import os
import sqlite3
import time
from pathlib import Path

from . import protocol_policy
from . import settings as ind_settings
from . import transparency_client as log_client
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
    conflict_proof_key,
    create_bill_checkpoint,
    create_checkpoint_announcement,
    create_compact_bill,
    create_conflict_proof,
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

STORE_SCHEMA_VERSION = 5
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
            self.transparency_verifier = _environment_transparency_verifier()
        if self.transparency_root_gossip and self.transparency_verifier is None:
            self.transparency_verifier = _environment_transparency_verifier()
        if transparency_submission_verify_timeout_seconds is None:
            self.transparency_submission_verify_timeout_seconds = _env_int(
                "IND_LOG_SUBMISSION_VERIFY_TIMEOUT_SECONDS",
                DEFAULT_LOG_SUBMISSION_VERIFY_TIMEOUT_SECONDS,
            )
        else:
            self.transparency_submission_verify_timeout_seconds = int(
                transparency_submission_verify_timeout_seconds
            )
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
        self._init_db()

    def _require_legacy_bill_protocol(self, operation):
        raise ValidationError(protocol_policy.legacy_disabled_message(operation))

    def _verify_bill_for_store(self, bill, **kwargs):
        if isinstance(bill, dict) and bill.get("type") == BILL_TYPE:
            kwargs.setdefault("transparency_verifier", self.transparency_verifier)
        return verify_bill(bill, **kwargs)

    # Create a short-lived SQLite connection with row dictionaries enabled.
    def _connect(self):
        conn = sqlite3.connect(self.db_path, factory=ClosingConnection)
        configure_sqlite_connection(conn)
        conn.row_factory = sqlite3.Row
        return conn

    # Create the tables used for compact bill storage and local settlement.
    def _init_db(self):
        with self._connect() as conn:
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
                CREATE INDEX IF NOT EXISTS idx_bills_v3_proof_bundle
                    ON bills_v3(proof_bundle_hash);

                CREATE TABLE IF NOT EXISTS receipts_v3 (
                    receipt_hash TEXT PRIMARY KEY,
                    token_id TEXT NOT NULL,
                    transfer_hash TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    recipient_address TEXT NOT NULL,
                    receipt_json TEXT NOT NULL,
                    first_seen INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_receipts_v3_token_sequence
                    ON receipts_v3(token_id, sequence);

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
                """)
            self._set_schema_version(conn, STORE_SCHEMA_VERSION)

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

    def _table_columns(self, conn, table_name):
        try:
            rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
        except sqlite3.OperationalError:
            return set()
        return {row["name"] if "name" in tuple(row.keys()) else row[1] for row in rows}

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

    # Store a bill genesis once, keeping lazy manifests in a shared table.
    def _store_genesis(self, conn, token, state):
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

    # Replace embedded lazy manifests with hash references before persistence.
    def _compact_genesis_for_store(self, conn, genesis):
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

    # Restore a compact stored genesis record to the full verifiable form.
    def _expand_genesis_from_store(self, conn, genesis):
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

    # Persist one transparency-backed compact checkpoint.
    def _store_checkpoint(self, conn, checkpoint, status="settled"):
        now = int(time.time())
        transparency = checkpoint.get("transparency") if isinstance(checkpoint, dict) else None
        root = transparency.get("root") if isinstance(transparency, dict) else None
        inclusion_proof = (
            transparency.get("inclusion_proof") if isinstance(transparency, dict) else None
        )
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

    # Resolve an ArchiveSegmentV3 body by content hash for V3 verification.
    def archive_segment_resolver_v3(self, segment_hash):
        return self.get_archive_segment_v3(segment_hash)

    # Resolve a ProofBundleV3 body by content hash for V3 verification.
    def proof_bundle_resolver_v3(self, proof_bundle_hash):
        return self.get_proof_bundle_v3(proof_bundle_hash)

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
        return segment_hash

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
        return checkpoint

    def _store_bill_v3_conn(self, conn, bill, state, status):
        from . import protocol_v3

        now = int(time.time())
        bill_hash_value = protocol_v3.bill_hash(bill).hex()
        proof_bundle_hash_value = bill["proof_bundle_ref"]["proof_bundle_hash"]
        existing = conn.execute(
            "SELECT first_seen, sequence FROM bills_v3 WHERE bill_hash = ?",
            (bill_hash_value,),
        ).fetchone()
        first_seen = int(existing["first_seen"]) if existing else now
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
                str(status),
            ),
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
                ORDER BY sequence DESC, updated_at DESC
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
                ORDER BY sequence DESC, updated_at DESC
                LIMIT 1
                """,
                (str(display_id),),
            ).fetchone()
        if not row:
            return None
        return protocol_v3.decode_bill(bytes(row["bill_blob"]))

    # List stored BillV3 records for one owner address.
    def bill_v3_records_for_owner(self, owner_address, statuses=None, limit=1000):
        statuses = tuple(statuses or ("verified", "settled", "pending", "unreceipted"))
        placeholders = ",".join("?" for _ in statuses)
        params = [owner_address, *statuses, int(limit)]
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT * FROM bills_v3
                WHERE owner_address = ? AND status IN ({placeholders})
                ORDER BY updated_at DESC
                LIMIT ?
                """,
                params,
            ).fetchall()
        return [dict(row) for row in rows]

    # Verify and persist one ReceiptV3.
    def store_receipt_v3(
        self,
        bill,
        receipt,
        proof_bundle=None,
        trusted_operator_public_key=None,
        transparency_verifier=None,
    ):
        from . import protocol_v3

        verifier = transparency_verifier or self.transparency_verifier
        state = protocol_v3.verify_receipt(
            bill,
            receipt,
            proof_bundle=proof_bundle,
            proof_bundle_resolver=self.proof_bundle_resolver_v3,
            transparency_verifier=verifier,
            trusted_operator_public_key=trusted_operator_public_key,
            archive_segment_resolver=self.archive_segment_resolver_v3,
        )
        receipt_hash_value = protocol_v3.receipt_hash(receipt)
        now = int(time.time())
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO receipts_v3(
                    receipt_hash, token_id, transfer_hash, sequence,
                    recipient_address, receipt_json, first_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    receipt_hash_value,
                    state.token_id,
                    receipt["transfer_hash"],
                    int(receipt["sequence"]),
                    receipt["recipient_address"],
                    _store_json(receipt),
                    now,
                ),
            )
        return receipt_hash_value

    # Verify and persist one ConflictProofV3.
    def store_conflict_proof_v3(self, proof, expected_network_id=None):
        from . import protocol_v3

        if expected_network_id is None:
            expected_network_id = protocol_v3.DEFAULT_NETWORK_ID
        protocol_v3.verify_conflict_proof(proof, expected_network_id=expected_network_id)
        proof_hash_value = proof["proof_hash"]
        conflict_key_value = protocol_v3.conflict_proof_key(proof)
        now = int(time.time())
        with self._connect() as conn:
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
                    now,
                ),
            )
        return proof_hash_value

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
            row["transfer_hash"]: _load_json(row["transfer_json"]) for row in transfer_rows
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

    # Expand a stored message reference back into the wire-level gossip object.
    def _expand_stored_message(self, conn, stored_payload):
        message = _load_json(stored_payload)
        if not isinstance(message, dict) or message.get("type") != STORED_MESSAGE_REF_TYPE:
            return message

        if message["message_type"] in {TRANSFER_ANNOUNCEMENT_V2_TYPE, RECEIPT_ANNOUNCEMENT_V2_TYPE}:
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
            TRANSFER_ANNOUNCEMENT_V2_TYPE,
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

    # Submit a compact checkpoint and return embedded transparency proof material.
    def _submit_checkpoint_to_transparency_log(self, checkpoint, bill):
        if self.transparency_submitter is None or self.transparency_verifier is None:
            return None
        from . import transparency_client as log_client

        announcement = create_checkpoint_announcement(
            checkpoint,
            bill=bill,
            transparency_verifier=self.transparency_verifier,
        )
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
            logger.warning(
                "checkpoint transparency submission failed for %s: %s", expected_hash, exc
            )
            return None

        timeout = max(0, int(self.transparency_submission_verify_timeout_seconds))
        deadline = time.monotonic() + timeout
        last_error = None
        while True:
            try:
                root = self.transparency_verifier.current_mirrored_root()
                if int(root["tree_size"]) < leaf_index + 1:
                    raise ValidationError("current transparency root does not contain checkpoint")
                inclusion_proof = self.transparency_verifier.operator.inclusion_proof(
                    expected_hash, int(root["tree_size"])
                )
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
                    transparency_verifier=self.transparency_verifier,
                )
                return checkpoint_for_proof["transparency"]
            except Exception as exc:
                last_error = exc
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                time.sleep(min(1.0, remaining))
        if self.require_transparency:
            raise ValidationError(
                f"checkpoint transparency proof was not available before timeout: {last_error}"
            )
        logger.warning(
            "checkpoint transparency proof was not available for %s: %s", expected_hash, last_error
        )
        return None

    # Return whether policy says this settled bill should be compacted now.
    def _checkpoint_due_for_bill(self, conn, bill, state=None, force=False):
        state = state or self._verify_bill_for_store(bill, require_recent_transparency=False)
        if int(state.sequence) <= 0:
            return False
        if force:
            return True
        if self.high_value_checkpoint_threshold > 0 and int(state.value) >= int(
            self.high_value_checkpoint_threshold
        ):
            return True
        latest_sequence = self._latest_checkpoint_sequence(conn, state.token_id)
        if latest_sequence <= 0:
            return int(state.sequence) >= int(self.first_checkpoint_after_transfers)
        return int(state.sequence) - int(latest_sequence) >= int(self.checkpoint_interval_transfers)

    # Create, prove, store, and return a compact checkpoint bill when policy allows.
    def _store_compact_checkpoint_for_bill(self, conn, bill, force=False, require_proof=False):
        state = self._verify_bill_for_store(bill, require_recent_transparency=False)
        if not self._checkpoint_due_for_bill(conn, bill, state=state, force=force):
            return None
        existing = self._checkpoint_for_transfer(conn, state.token_id, state.last_transfer_hash)
        if existing:
            compact_bill = self._compact_bill_from_checkpoint_row(conn, state.token_id, existing)
            if compact_bill:
                compact_state = verify_bill(
                    compact_bill,
                    transparency_verifier=self.transparency_verifier,
                )
                self._store_token_tip(conn, compact_bill, compact_state, "settled")
            return compact_bill

        checkpoint = create_bill_checkpoint(bill)
        transparency = self._submit_checkpoint_to_transparency_log(checkpoint, bill)
        if not transparency:
            if require_proof:
                raise ValidationError(
                    "compact checkpoint requires transparency submission and mirrored proof"
                )
            return None
        checkpoint["transparency"] = transparency
        verify_checkpoint_for_genesis(
            checkpoint,
            bill["genesis"],
            require_transparency=True,
            transparency_verifier=self.transparency_verifier,
        )
        self._store_checkpoint(conn, checkpoint, status="settled")
        compact_bill = create_compact_bill(bill, checkpoint)
        compact_state = verify_bill(
            compact_bill,
            transparency_verifier=self.transparency_verifier,
        )
        self._store_token_tip(conn, compact_bill, compact_state, "settled")
        return compact_bill

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

    # Search stored sibling transfers for a double-spend anywhere in this bill branch.
    def _find_conflict(self, conn, token):
        state = self._verify_bill_for_store(token, require_recent_transparency=False)
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
                    logger.warning(
                        "detected IND bill conflict for %s at sequence %s",
                        state.token_id,
                        transfer["sequence"],
                    )
                    return create_conflict_proof(token, other_token)
        return None

    # Store verified double-spend evidence without invalidating the bill.
    def _record_conflict(self, conn, proof):
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
            logger.warning(
                "recording IND conflict proof %s for bill %s", proof_hash_value, proof["token_id"]
            )
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
            logger.debug(
                "deduped IND conflict proof %s for bill %s", proof_hash_value, proof["token_id"]
            )
        return {
            "inserted": bool(inserted),
            "conflict_key": proof_key,
            "proof_hash": stored_proof.get("proof_hash", proof_hash_value),
            "proof": stored_proof,
        }

    # Reject a branch that conflicts with an already known local branch.
    def _reject_conflicting_transfer(self, conn, token):
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
        persisted = getattr(
            self.transparency_verifier, "persisted_operator_policy_violation_messages", None
        )
        if not callable(persisted):
            return []
        return persisted(limit=limit)

    def _load_conflict_proof_row(self, row):
        if not row:
            return None
        proof = _load_json(row["proof_json"])
        verify_conflict_proof(proof)
        return proof

    # Return recently stored verified conflict proofs for durable rebroadcast.
    def conflict_messages(self, limit=100):
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

    # Return one compact local status record for a bill id or display id.
    def status_record_for_ref(self, ref, *, min_settled_seconds=0):
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
            state = self._verify_bill_for_store(token, require_recent_transparency=False)
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
            _require_exact_fields(
                message, TRANSFER_ANNOUNCEMENT_V2_FIELDS, "v2 transfer announcement"
            )
            if _require_int(message["version"], "v2 transfer announcement version") != BILL_VERSION:
                raise ValidationError("unsupported v2 transfer announcement version")
            token = message["bill"]
            state = self._verify_bill_for_store(token, require_recent_transparency=False)
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
            verify_bill(
                token, transparency_verifier=self.transparency_verifier, require_transparency=True
            )
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
            _require_exact_fields(
                message, RECEIPT_ANNOUNCEMENT_V2_FIELDS, "v2 receipt announcement"
            )
            if _require_int(message["version"], "v2 receipt announcement version") != BILL_VERSION:
                raise ValidationError("unsupported v2 receipt announcement version")
            token = message["bill"]
        else:
            _require_exact_fields(message, RECEIPT_ANNOUNCEMENT_FIELDS, "receipt announcement")
            if _require_int(message["version"], "receipt announcement version") != TOKEN_VERSION:
                raise ValidationError("unsupported receipt announcement version")
            token = message["token"]
        _require_int(message["announced_at"], "receipt announcement announced_at", minimum=0)
        receipt_verifier = self.transparency_verifier
        if message.get("type") != RECEIPT_ANNOUNCEMENT_V2_TYPE and not self.require_transparency:
            receipt_verifier = None
        state = verify_receipt_announcement(
            message,
            transparency_verifier=receipt_verifier,
            require_transparency=self.require_transparency,
            require_recent_transparency=False,
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

    def _ingest_receipt_announcement_v3(self, conn, message):
        from . import protocol_v3

        state = protocol_v3.verify_receipt_announcement(
            message,
            proof_bundle_resolver=self.proof_bundle_resolver_v3,
            transparency_verifier=self.transparency_verifier,
            archive_segment_resolver=self.archive_segment_resolver_v3,
        )
        self._store_bill_v3_conn(conn, message["bill"], state, "pending")
        conn.execute(
            """
            INSERT OR IGNORE INTO receipts_v3(
                receipt_hash, token_id, transfer_hash, sequence,
                recipient_address, receipt_json, first_seen
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                protocol_v3.receipt_hash(message["receipt"]),
                state.token_id,
                message["receipt"]["transfer_hash"],
                int(message["receipt"]["sequence"]),
                message["receipt"]["recipient_address"],
                _store_json(message["receipt"]),
                int(time.time()),
            ),
        )
        self._record_message(conn, message, state)
        return {
            "accepted": True,
            "status": "pending",
            "state": state,
            "gossip_messages": self._drain_transparency_gossip(),
        }

    def _ingest_transfer_announcement_v3(self, conn, message):
        from . import protocol_v3

        decoded = protocol_v3.verify_transfer_announcement(
            message,
            proof_bundle_resolver=self.proof_bundle_resolver_v3,
            transparency_verifier=self.transparency_verifier,
            archive_segment_resolver=self.archive_segment_resolver_v3,
        )
        for segment in decoded["archive_segments"]:
            self.store_archive_segment_v3(segment)
        if decoded["proof_bundle"] is not None:
            self.store_proof_bundle_v3(
                decoded["proof_bundle"],
                transparency_verifier=self.transparency_verifier,
            )
        self._store_bill_v3_conn(conn, decoded["bill"], decoded["state"], "unreceipted")
        self._record_message(conn, message, decoded["state"])
        return {
            "accepted": True,
            "status": "unreceipted",
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

    def _ingest_conflict_proof_v3(self, conn, message):
        from . import protocol_v3

        protocol_v3.verify_conflict_proof(message)
        proof_hash_value = message["proof_hash"]
        conflict_key_value = protocol_v3.conflict_proof_key(message)
        inserted = (
            conn.execute(
                "SELECT 1 FROM conflicts_v3 WHERE conflict_key = ?",
                (conflict_key_value,),
            ).fetchone()
            is None
        )
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
                    message["token_id"],
                    message["previous_hash"],
                    _store_json(message),
                    int(time.time()),
                ),
            )
        self._record_message(conn, message)
        result = {
            "accepted": True,
            "status": "conflict",
            "duplicate_conflict": not inserted,
            "relay": bool(inserted),
        }
        if inserted:
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
    def ingest_message(self, message, peer_id=None):
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
            if message_type in {TRANSFER_ANNOUNCEMENT_TYPE, TRANSFER_ANNOUNCEMENT_V2_TYPE}:
                self._require_legacy_bill_protocol("legacy transfer announcement ingest")
                return self._ingest_transfer_announcement(conn, message)

            if message_type == protocol_v3.TRANSFER_ANNOUNCEMENT_TYPE:
                return self._ingest_transfer_announcement_v3(conn, message)

            if message_type in {RECEIPT_ANNOUNCEMENT_TYPE, RECEIPT_ANNOUNCEMENT_V2_TYPE}:
                self._require_legacy_bill_protocol("legacy receipt announcement ingest")
                return self._ingest_receipt_announcement(conn, message)

            if message_type == protocol_v3.RECEIPT_ANNOUNCEMENT_TYPE:
                return self._ingest_receipt_announcement_v3(conn, message)

            if message_type == protocol_v3.PROOF_BUNDLE_ANNOUNCEMENT_TYPE:
                return self._ingest_proof_bundle_announcement_v3(conn, message)

            if message_type == protocol_v3.ARCHIVE_SEGMENT_ANNOUNCEMENT_TYPE:
                return self._ingest_archive_segment_announcement_v3(conn, message)

            if message_type == CONFLICT_PROOF_TYPE:
                self._require_legacy_bill_protocol("legacy conflict proof ingest")
                return self._ingest_conflict_proof(conn, message)

            if message_type == protocol_v3.CONFLICT_PROOF_TYPE:
                return self._ingest_conflict_proof_v3(conn, message)

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

    # Settle receipt-backed transfers that survived the local finality buffer.
    def finalize_pending(self, now=None, buffer_seconds=FINALITY_BUFFER_SECONDS):
        now = int(now or time.time())
        cutoff = now - int(buffer_seconds)
        finalized = []
        with self._connect() as conn:
            v3_rows = conn.execute(
                """
                SELECT bill_hash, token_id FROM bills_v3
                WHERE status = 'pending' AND first_seen <= ?
                """,
                (cutoff,),
            ).fetchall()
            for row in v3_rows:
                conn.execute(
                    """
                    UPDATE bills_v3
                    SET status = 'settled', updated_at = ?
                    WHERE bill_hash = ? AND status = 'pending'
                    """,
                    (now, row["bill_hash"]),
                )
                finalized.append(row["token_id"])
            return finalized
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
                        logger.warning(
                            "could not create compact checkpoint for %s: %s", row["token_id"], exc
                        )
                finalized.append(row["token_id"])
        return finalized

    # Force a compact checkpoint for one locally settled bill.
    def compact_bill_now(self, token_id=None, display_id=None):
        self._require_legacy_bill_protocol("legacy compact checkpoint")
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
            existing = self._checkpoint_for_transfer(
                conn, row["token_id"], row["last_transfer_hash"]
            )
            if existing:
                compact_bill = self._compact_bill_from_checkpoint_row(
                    conn, row["token_id"], existing
                )
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

    # Return a v2 compact bill for a wallet display id when a checkpoint exists.
    def get_compact_bill_by_display_id(self, display_id):
        with self._connect() as conn:
            row = conn.execute(
                "SELECT token_id FROM tokens WHERE display_id = ?", (display_id,)
            ).fetchone()
            if not row:
                return None
            return self._compact_bill_from_latest_checkpoint(conn, row["token_id"])

    # Return a v2 compact bill by protocol bill id when a checkpoint exists.
    def get_compact_bill(self, token_id):
        with self._connect() as conn:
            return self._compact_bill_from_latest_checkpoint(conn, token_id)

    # Return the stored bill row used by UI and tests.
    def get_token_record(self, token_id):
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM tokens WHERE token_id = ?", (token_id,)).fetchone()
        return dict(row) if row else None

    # List locally known bill records for an owner address.
    def token_records_for_owner(self, owner_address, settled_only=True, limit=1000):
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
                ORDER BY sequence DESC, updated_at DESC
                LIMIT 1
                """,
                (str(token_id),),
            ).fetchone()
            if not row:
                return {"accepted": False, "level": "unknown", "reason": "V3 bill not found"}
            record = dict(row)
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
        settled_age = now - int(record["updated_at"])
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

    # Return recent expanded gossip messages addressed to a wallet.
    def messages_for_recipient(self, recipient_address, limit=100):
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
