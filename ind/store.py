"""SQLite-backed local state for IND token gossip and settlement."""

import copy
import logging
import os
import sqlite3
import time

from .protocol import *
from .protocol import (
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

STORE_SCHEMA_VERSION = 1
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class INDLocalStore:
    """SQLite-backed cache for verified token tips, gossip messages, and conflicts."""

    def __init__(
        self,
        db_path=None,
        transparency_verifier=None,
        transparency_submitter=None,
        require_transparency=None,
        transparency_submission_verify_timeout_seconds=None,
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
        self._init_db()

    def _connect(self):
        """Create a short-lived SQLite connection with row dictionaries enabled."""

        conn = sqlite3.connect(self.db_path, factory=ClosingConnection)
        configure_sqlite_connection(conn)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Create the tables used for compact token storage and local settlement."""

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
                    token_id TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    proof_json TEXT NOT NULL,
                    detected_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_conflicts_token ON conflicts(token_id);
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

    def _store_genesis(self, conn, token, state):
        """Store a token genesis once, keeping lazy manifests in a shared table."""

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

    def _rebuild_token_from_store(self, conn, token_id, last_transfer_hash=None, sequence=None):
        """Reconstruct a full bearer token from normalized genesis and transfer rows."""

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
        """Resolve either a compact state reference or a full token payload."""

        data = _load_json(payload)
        if isinstance(data, dict) and data.get("type") == TOKEN_STATE_REF_TYPE:
            return self._rebuild_token_from_store(
                conn,
                data["token_id"],
                data.get("last_transfer_hash"),
                data.get("sequence"),
            )
        if isinstance(data, dict) and data.get("type") == TOKEN_TYPE:
            return data
        if token_id:
            return self._rebuild_token_from_store(conn, token_id)
        return None

    def _stored_message_payload(self, message, state=None):
        """Store gossip messages as compact references when the token is already known."""

        if state and message.get("type") in {TRANSFER_ANNOUNCEMENT_TYPE, RECEIPT_ANNOUNCEMENT_TYPE}:
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
            if message["type"] == RECEIPT_ANNOUNCEMENT_TYPE:
                ref["receipt"] = message["receipt"]
            return ref
        return message

    def _expand_stored_message(self, conn, stored_payload):
        """Expand a stored message reference back into the wire-level gossip object."""

        message = _load_json(stored_payload)
        if not isinstance(message, dict) or message.get("type") != STORED_MESSAGE_REF_TYPE:
            return message

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
        if message["message_type"] == RECEIPT_ANNOUNCEMENT_TYPE:
            return {
                "type": RECEIPT_ANNOUNCEMENT_TYPE,
                "version": TOKEN_VERSION,
                "token": token,
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

        if not self.transparency_submitter or message.get("type") != TRANSFER_ANNOUNCEMENT_TYPE:
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
            # Duplicate append responses are still operator claims. Verify them
            # against a mirror instead of trusting "duplicate": true.
            self._verify_transparency_submission(token, expected_entry_hash, leaf_index)
            return response
        except Exception as exc:
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

    def _store_token_tip(self, conn, token, state, status):
        """Persist the latest known valid state for a token without downgrading it."""

        now = int(time.time())
        self._store_genesis(conn, token, state)
        existing = conn.execute(
            "SELECT first_seen, status, finalized_at, sequence, last_transfer_hash FROM tokens WHERE token_id = ?",
            (state.token_id,),
        ).fetchone()
        hard_dissent = conn.execute(
            """
            SELECT proof_hash FROM conflicts WHERE token_id = ?
            LIMIT 1
            """,
            (state.token_id,),
        ).fetchone()
        if existing and int(existing["sequence"]) > int(state.sequence):
            return
        first_seen = existing["first_seen"] if existing else now
        finalized_at = existing["finalized_at"] if existing else None
        if hard_dissent:
            status = "invalid"
        elif existing and existing["status"] == "invalid":
            status = "invalid"
        elif existing and existing["status"] == "settled" and existing["last_transfer_hash"] == state.last_transfer_hash:
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
        """Persist new transfers from a token history, preserving older settled rows."""

        if state.sequence == 0:
            return None
        self._store_genesis(conn, token, state)
        now = int(time.time())
        last_hash = None
        transfers_to_store = []
        for transfer in reversed(token.get("history", [])):
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
            hard_dissent = conn.execute(
                """
                SELECT proof_hash FROM conflicts WHERE token_id = ?
                LIMIT 1
                """,
                (state.token_id,),
            ).fetchone()
            if hard_dissent:
                transfer_status = "invalid"
            existing = conn.execute(
                "SELECT first_seen, status, finalized_at FROM transfers WHERE transfer_hash = ?",
                (th,),
            ).fetchone()
            first_seen = existing["first_seen"] if existing else now
            finalized_at = existing["finalized_at"] if existing else None
            if existing and existing["status"] == "settled":
                transfer_status = "settled"
            if existing and existing["status"] == "invalid":
                transfer_status = "invalid"
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
        """Search stored sibling transfers for a double-spend anywhere in this token branch."""

        state = verify_token(token)
        if state.sequence == 0:
            return None
        for transfer in token.get("history", []):
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
                    logger.warning("detected IND token conflict for %s at sequence %s", state.token_id, transfer["sequence"])
                    return create_conflict_proof(token, other_token)
        return None

    def _record_conflict(self, conn, proof):
        """Store a verified conflict proof and mark the affected token invalid."""

        verify_conflict_proof(proof)
        proof_hash_value = proof["proof_hash"]
        logger.warning("recording IND conflict proof %s for token %s", proof_hash_value, proof["token_id"])
        conn.execute(
            """
            INSERT OR IGNORE INTO conflicts(proof_hash, token_id, previous_hash, proof_json, detected_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                proof_hash_value,
                proof["token_id"],
                proof["previous_hash"],
                _store_json(proof),
                int(time.time()),
            ),
        )
        conn.execute("UPDATE tokens SET status = 'invalid', updated_at = ? WHERE token_id = ?", (int(time.time()), proof["token_id"]))
        conn.execute("UPDATE transfers SET status = 'invalid' WHERE token_id = ?", (proof["token_id"],))

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
            if message_type == TRANSFER_ANNOUNCEMENT_TYPE:
                _require_exact_fields(
                    message,
                    TRANSFER_ANNOUNCEMENT_FIELDS,
                    "transfer announcement",
                    optional=TRANSFER_ANNOUNCEMENT_OPTIONAL_FIELDS,
                )
                if _require_int(message["version"], "transfer announcement version") != TOKEN_VERSION:
                    raise ValidationError("unsupported transfer announcement version")
                _require_int(message["announced_at"], "transfer announcement announced_at", minimum=0)
                token = message["token"]
                state = verify_token(token)
                self._submit_to_transparency_log(message, token)
                if self.require_transparency:
                    verify_token_transparency(token, self.transparency_verifier)
                self._store_transfer(conn, token, state, "unreceipted")
                conflict = self._find_conflict(conn, token)
                if conflict:
                    self._record_conflict(conn, conflict)
                    self._record_message(conn, message, state)
                    return {
                        "accepted": True,
                        "status": "conflict",
                        "conflict_proof": conflict,
                        "gossip_messages": self._drain_transparency_gossip(),
                    }
                self._store_token_tip(conn, token, state, "unreceipted")
                self._record_message(conn, message, state)
                return {
                    "accepted": True,
                    "status": "unreceipted",
                    "state": state,
                    "gossip_messages": self._drain_transparency_gossip(),
                }

            if message_type == RECEIPT_ANNOUNCEMENT_TYPE:
                _require_exact_fields(message, RECEIPT_ANNOUNCEMENT_FIELDS, "receipt announcement")
                if _require_int(message["version"], "receipt announcement version") != TOKEN_VERSION:
                    raise ValidationError("unsupported receipt announcement version")
                _require_int(message["announced_at"], "receipt announcement announced_at", minimum=0)
                state = verify_receipt_announcement(
                    message,
                    transparency_verifier=self.transparency_verifier,
                    require_transparency=self.require_transparency,
                )
                token = message["token"]
                self._store_transfer(conn, token, state, "pending")
                conflict = self._find_conflict(conn, token)
                if conflict:
                    self._record_conflict(conn, conflict)
                    self._record_message(conn, message, state)
                    return {
                        "accepted": True,
                        "status": "conflict",
                        "conflict_proof": conflict,
                        "gossip_messages": self._drain_transparency_gossip(),
                    }
                self._store_token_tip(conn, token, state, "pending")
                self._record_message(conn, message, state)
                return {
                    "accepted": True,
                    "status": "pending",
                    "state": state,
                    "gossip_messages": self._drain_transparency_gossip(),
                }

            if message_type == CONFLICT_PROOF_TYPE:
                _require_exact_fields(message, CONFLICT_PROOF_FIELDS, "conflict proof")
                self._record_conflict(conn, message)
                return {"accepted": True, "status": "conflict"}

            if message_type == TRANSPARENCY_ROOT_ANNOUNCEMENT_TYPE:
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

            if message_type == TRANSPARENCY_EQUIVOCATION_PROOF_TYPE:
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
                conflict = conn.execute(
                    """
                    SELECT proof_hash FROM conflicts
                    WHERE token_id = ? AND previous_hash = ?
                    LIMIT 1
                    """,
                    (row["token_id"], row["previous_hash"]),
                ).fetchone()
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
                if conflict or int(siblings["count_value"]) > 1:
                    conn.execute("UPDATE transfers SET status = 'invalid' WHERE token_id = ?", (row["token_id"],))
                    conn.execute("UPDATE tokens SET status = 'invalid', updated_at = ? WHERE token_id = ?", (now, row["token_id"]))
                    continue
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
                finalized.append(row["token_id"])
        return finalized

    def get_token(self, token_id):
        """Return a rebuilt bearer token by protocol token id."""

        with self._connect() as conn:
            row = conn.execute("SELECT payload FROM tokens WHERE token_id = ?", (token_id,)).fetchone()
            if not row:
                return None
            return self._token_from_payload(conn, row["payload"], token_id)

    def get_token_by_display_id(self, display_id):
        """Return a rebuilt bearer token by wallet display id."""

        with self._connect() as conn:
            row = conn.execute("SELECT token_id, payload FROM tokens WHERE display_id = ?", (display_id,)).fetchone()
            if not row:
                return None
            return self._token_from_payload(conn, row["payload"], row["token_id"])

    def get_token_record(self, token_id):
        """Return the stored token row used by UI and tests."""

        with self._connect() as conn:
            row = conn.execute("SELECT * FROM tokens WHERE token_id = ?", (token_id,)).fetchone()
        return dict(row) if row else None

    def token_records_for_owner(self, owner_address, settled_only=True, limit=1000):
        """List locally known token records for an owner address."""

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
        """Report whether a token is locally acceptable for a recipient."""

        now = int(now or time.time())
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM tokens WHERE token_id = ?", (token_id,)).fetchone()
            if not row:
                return {"accepted": False, "level": "unknown", "reason": "token not found"}
            record = dict(row)
            conflict = conn.execute(
                "SELECT proof_hash FROM conflicts WHERE token_id = ? LIMIT 1",
                (token_id,),
            ).fetchone()
        if conflict or record["status"] == "invalid":
            reason = "token has a known conflict proof"
            return {"accepted": False, "level": "conflict", "reason": reason}
        if expected_owner and record["owner_address"] != expected_owner:
            return {"accepted": False, "level": "wrong_owner", "reason": "token owner does not match expected owner"}
        if record["status"] != "settled" or not record.get("finalized_at"):
            return {"accepted": False, "level": record["status"], "reason": "token is not settled"}
        settled_age = now - int(record["finalized_at"])
        if settled_age < int(min_settled_seconds):
            return {
                "accepted": False,
                "level": "settled_fresh",
                "reason": "token is settled but below requested confidence age",
                "settled_age": settled_age,
            }
        return {
            "accepted": True,
            "level": "strong_local",
            "finality": "local_confidence",
            "reason": "token is settled locally with no known conflict",
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
