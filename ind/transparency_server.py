import argparse
import base64
import json
import os
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import ecdsa
from pymerkle.concrete.sqlite import SqliteTree
from pymerkle.core import InvalidChallenge

from . import token as ind_token
from . import transparency_client as log_client


DEFAULT_LOG_DB = "files/ind_transparency_log.db"
DEFAULT_LOG_PRIVATE_KEY = "files/log_operator_private_key.json"
DEFAULT_LOG_PUBLIC_KEY = "files/log_operator_public_key.json"
DEFAULT_ROOT_INTERVAL_SECONDS = 60
DEFAULT_MAX_APPEND_BODY_BYTES = 16 * 1024 * 1024
DEFAULT_APPEND_BODY_READ_TIMEOUT_SECONDS = 10


def _env_int(name, default):
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return int(default)


MAX_APPEND_BODY_BYTES = max(1024, _env_int("IND_LOG_MAX_APPEND_BODY_BYTES", DEFAULT_MAX_APPEND_BODY_BYTES))
APPEND_BODY_READ_TIMEOUT_SECONDS = max(
    1,
    _env_int("IND_LOG_APPEND_BODY_READ_TIMEOUT_SECONDS", DEFAULT_APPEND_BODY_READ_TIMEOUT_SECONDS),
)


class LogServerError(Exception):
    """Raised when the transparency log operator cannot serve a request."""


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
    tmp_path = path.with_name(path.name + ".tmp")
    tmp_path.write_text(
        json.dumps({field: value}, sort_keys=True, indent=2, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    os.replace(tmp_path, path)


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


def load_or_create_operator_keys(private_key_path=DEFAULT_LOG_PRIVATE_KEY, public_key_path=DEFAULT_LOG_PUBLIC_KEY):
    """Load or create the ECDSA key pair used to sign log roots."""

    private_key_path = Path(private_key_path)
    public_key_path = Path(public_key_path)
    private_key = _read_key_json_or_legacy(private_key_path, "private_key")
    public_key = _read_key_json_or_legacy(public_key_path, "public_key")
    if private_key and public_key:
        if not private_key_path.exists():
            _write_key_json(private_key_path, "private_key", private_key)
        if not public_key_path.exists():
            _write_key_json(public_key_path, "public_key", public_key)
        return private_key, public_key

    private_key_path.parent.mkdir(parents=True, exist_ok=True)
    public_key_path.parent.mkdir(parents=True, exist_ok=True)
    signing_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1, hashfunc=ind_token.sha3_256)
    verifying_key = signing_key.get_verifying_key()
    private_key = base64.b85encode(signing_key.to_string()).decode("utf-8")
    public_key = base64.b85encode(verifying_key.to_string()).decode("utf-8")
    _write_key_json(private_key_path, "private_key", private_key)
    _write_key_json(public_key_path, "public_key", public_key)
    return private_key, public_key


class TransparencyLog:
    """Persistent CT-style SHA3-256 append-only log of IND transfer hashes."""

    def __init__(
        self,
        db_path,
        private_key_base85,
        public_key_base85,
        mirror_dirs=None,
    ):
        self.db_path = str(Path(db_path))
        self.private_key = private_key_base85
        self.public_key = public_key_base85
        self.log_id = log_client.log_id_from_public_key(public_key_base85)
        self.mirror_dirs = [Path(path) for path in (mirror_dirs or [])]
        self._append_lock = threading.RLock()
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self):
        conn = sqlite3.connect(self.db_path, factory=ind_token.ClosingConnection)
        ind_token.configure_sqlite_connection(conn)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with SqliteTree(self.db_path, algorithm=log_client.LOG_HASH_ALGORITHM):
            pass
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS log_entries (
                    entry_hash TEXT PRIMARY KEY,
                    leaf_index INTEGER NOT NULL UNIQUE,
                    submitted_at INTEGER NOT NULL,
                    transfer_json TEXT
                );

                CREATE TABLE IF NOT EXISTS signed_roots (
                    root_id TEXT PRIMARY KEY,
                    tree_size INTEGER NOT NULL,
                    root_hash TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    root_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_signed_roots_timestamp
                    ON signed_roots(timestamp, tree_size);

                CREATE TABLE IF NOT EXISTS spend_claims (
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
                CREATE INDEX IF NOT EXISTS idx_spend_claims_token
                    ON spend_claims(token_id, sequence, previous_hash, sender_address);
                """
            )
            self._ensure_log_entry_columns(conn)
            self._ensure_spend_claim_columns(conn)

    def _ensure_log_entry_columns(self, conn):
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(log_entries)").fetchall()}
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
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS spend_claims_v2 (
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
                INSERT OR IGNORE INTO spend_claims_v2(
                    spend_key, token_id, previous_hash, sequence, sender_address,
                    sender_public_key, transfer_hash, transfer_leaf_index, first_seen
                )
                SELECT spend_key, token_id, previous_hash, sequence, sender_address,
                    sender_public_key, transfer_hash, transfer_leaf_index, first_seen
                FROM spend_claims;
                DROP TABLE spend_claims;
                ALTER TABLE spend_claims_v2 RENAME TO spend_claims;
                """
            )
            columns = {row["name"] for row in conn.execute("PRAGMA table_info(spend_claims)").fetchall()}
        if "transfer_leaf_index" not in columns:
            conn.execute("ALTER TABLE spend_claims ADD COLUMN transfer_leaf_index INTEGER")

    def _tree(self):
        return SqliteTree(self.db_path, algorithm=log_client.LOG_HASH_ALGORITHM)

    def tree_size(self):
        with self._tree() as tree:
            return int(tree.get_size())

    def current_root_hash(self, tree_size=None):
        with self._tree() as tree:
            size = tree.get_size() if tree_size is None else int(tree_size)
            return tree.get_state(size).hex()

    def append_entry_hash(self, entry_hash, submitted_at=None, transfer=None):
        """Append a transfer hash to the log, idempotently."""

        entry_hash = str(entry_hash).lower()
        try:
            entry_bytes = bytes.fromhex(entry_hash)
        except ValueError as exc:
            raise LogServerError("invalid transfer entry hash") from exc
        if len(entry_bytes) != 32:
            raise LogServerError("invalid transfer entry hash length")

        submitted_at = int(submitted_at if submitted_at is not None else time.time())
        transfer_json = log_client.canonical_json(transfer) if transfer is not None else None
        with self._append_lock:
            with self._connect() as conn:
                existing = conn.execute(
                    "SELECT leaf_index FROM log_entries WHERE entry_hash = ?",
                    (entry_hash,),
                ).fetchone()
                if existing:
                    if transfer_json is not None:
                        conn.execute(
                            """
                            UPDATE log_entries
                            SET transfer_json = COALESCE(transfer_json, ?)
                            WHERE entry_hash = ?
                            """,
                            (transfer_json, entry_hash),
                        )
                    return {
                        "accepted": True,
                        "duplicate": True,
                        "entry_hash": entry_hash,
                        "leaf_index": int(existing["leaf_index"]) - 1,
                        "tree_size": self.tree_size(),
                    }

            with self._tree() as tree:
                leaf_index = tree.append_entry(entry_bytes)

            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO log_entries(entry_hash, leaf_index, submitted_at, transfer_json)
                    VALUES (?, ?, ?, ?)
                    """,
                    (entry_hash, int(leaf_index), submitted_at, transfer_json),
                )
        return {
            "accepted": True,
            "duplicate": False,
            "entry_hash": entry_hash,
            "leaf_index": int(leaf_index) - 1,
            "tree_size": self.tree_size(),
        }

    def _spend_claim_from_transfer(self, transfer):
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
        return None

    def _record_spend_claim(
        self,
        conn,
        claim,
        transfer_hash,
        transfer_leaf_index,
        first_seen,
    ):
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

    def _spend_claim_records(self, conn, tree_size=None):
        params = []
        where = "WHERE transfer_leaf_index IS NOT NULL"
        if tree_size is not None:
            where += " AND transfer_leaf_index < ?"
            params.append(int(tree_size))
        rows = conn.execute(
            f"""
            SELECT spend_claims.*, log_entries.transfer_json
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
                "type": "ind.transparency_spend_claim.v1",
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
            if row["transfer_json"]:
                claim["transfer"] = json.loads(row["transfer_json"])
            claims.append(claim)
        return claims

    def spend_map_root(self, tree_size=None):
        with self._connect() as conn:
            claims = self._spend_claim_records(conn, tree_size=tree_size)
        return log_client.spend_map_root(claims), len(claims)

    def spend_map_proof(self, spend_key, tree_size=None):
        tree_size = self.tree_size() if tree_size is None else int(tree_size)
        with self._connect() as conn:
            claims = self._spend_claim_records(conn, tree_size=tree_size)
        return log_client.build_spend_map_proof(claims, str(spend_key), tree_size)

    def proof_archive(self, tree_size=None):
        tree_size = self.tree_size() if tree_size is None else int(tree_size)
        root = self.root_for_tree_size(tree_size)
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT entry_hash, leaf_index, submitted_at FROM log_entries
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
            }
            for row in rows
        ]
        archive = log_client.make_proof_archive(root, entries, claims)
        log_client.verify_proof_archive(archive, root, operator_public_key=self.public_key)
        return archive

    def append_transfer_announcement(self, announcement):
        """Validate a transfer announcement and append only its latest transfer hash."""

        if isinstance(announcement, bytes):
            announcement = announcement.decode("utf-8")
        if isinstance(announcement, str):
            announcement = ind_token.unpack_wire_message(announcement)
        if not isinstance(announcement, dict) or announcement.get("type") != ind_token.TRANSFER_ANNOUNCEMENT_TYPE:
            raise LogServerError("expected an IND transfer announcement")
        ind_token._require_exact_fields(
            announcement,
            ind_token.TRANSFER_ANNOUNCEMENT_FIELDS,
            "transfer announcement",
            optional=ind_token.TRANSFER_ANNOUNCEMENT_OPTIONAL_FIELDS,
        )
        token = announcement.get("token")
        state = ind_token.verify_token(token)
        if state.sequence == 0:
            raise LogServerError("genesis token has no transfer to log")
        transfer = token["history"][-1]
        entry_hash = ind_token.transfer_hash(transfer)
        claim = self._spend_claim_from_transfer(transfer)
        submitted_at = int(time.time())
        with self._append_lock:
            result = self.append_entry_hash(entry_hash, submitted_at=submitted_at, transfer=transfer)
            with self._connect() as conn:
                self._record_spend_claim(
                    conn,
                    claim,
                    entry_hash,
                    result["leaf_index"],
                    submitted_at,
                )
            result["spend_key"] = claim["spend_key"]
            return result

    def publish_root(self, timestamp=None):
        """Sign and store the current tree root, then mirror it to configured dirs."""

        with self._append_lock:
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
        self._mirror_root(root)
        return root

    def maybe_publish_root(self, interval_seconds=DEFAULT_ROOT_INTERVAL_SECONDS):
        latest = self.latest_root()
        now = int(time.time())
        if not latest or now - int(latest["timestamp"]) >= int(interval_seconds):
            return self.publish_root(now)
        return latest

    def latest_root(self):
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT root_json FROM signed_roots
                ORDER BY timestamp DESC, tree_size DESC
                LIMIT 1
                """
            ).fetchone()
        return json.loads(row["root_json"]) if row else None

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

    def root_at(self, timestamp):
        """Return the first signed root at or after timestamp."""

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

    def roots(self, limit=1000):
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT root_json FROM signed_roots
                ORDER BY timestamp ASC, tree_size ASC
                LIMIT ?
                """,
                (int(limit),),
            ).fetchall()
        return [json.loads(row["root_json"]) for row in rows]

    def entries(self, start=0, end=None, limit=1000):
        """Return logged transfer hashes by zero-based leaf index."""

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

    def _mirror_root(self, root):
        for mirror_dir in self.mirror_dirs:
            mirror_dir.mkdir(parents=True, exist_ok=True)
            roots_dir = mirror_dir / "roots"
            roots_dir.mkdir(parents=True, exist_ok=True)
            filename = f"root_{int(root['timestamp'])}_{int(root['tree_size'])}.json"
            data = log_client.canonical_json(root) + "\n"
            target = roots_dir / filename
            target.write_text(data, encoding="utf-8")
            with (mirror_dir / "roots.jsonl").open("a", encoding="utf-8") as handle:
                handle.write(data)
            archive_dir = mirror_dir / "proof_archives"
            archive_dir.mkdir(parents=True, exist_ok=True)
            archive = self.proof_archive(int(root["tree_size"]))
            archive_target = archive_dir / f"root_{int(root['tree_size']):012d}.json"
            archive_target.write_text(log_client.canonical_json(archive) + "\n", encoding="utf-8")


class TransparencyLogHandler(BaseHTTPRequestHandler):
    server_version = "INDTransparencyLog/1"

    def _send_json(self, status, data):
        payload = log_client.canonical_json(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _send_error_json(self, status, message):
        self._send_json(status, {"error": message})

    def _query(self):
        return parse_qs(urlparse(self.path).query)

    def do_GET(self):
        try:
            path = urlparse(self.path).path
            query = self._query()
            log = self.server.transparency_log
            if path == "/v1/root":
                self._send_json(200, log.maybe_publish_root(self.server.root_interval_seconds))
                return
            if path == "/v1/root-at":
                timestamp = int(query.get("timestamp", [0])[0])
                self._send_json(200, log.root_at(timestamp))
                return
            if path == "/v1/roots":
                limit = int(query.get("limit", [1000])[0])
                self._send_json(200, {"roots": log.roots(limit=limit)})
                return
            if path == "/v1/entries":
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
            if path == "/v1/proof":
                entry_hash = query.get("entry_hash", [""])[0]
                tree_size = int(query.get("tree_size", [log.tree_size()])[0])
                self._send_json(200, log.inclusion_proof(entry_hash, tree_size))
                return
            if path == "/v1/spend-proof":
                spend_key = query.get("spend_key", [""])[0]
                tree_size = int(query.get("tree_size", [log.tree_size()])[0])
                self._send_json(200, log.spend_map_proof(spend_key, tree_size))
                return
            if path == "/v1/proof-archive":
                tree_size = int(query.get("tree_size", [log.tree_size()])[0])
                self._send_json(200, log.proof_archive(tree_size))
                return
            if path == "/v1/consistency":
                first = int(query.get("first", [0])[0])
                second = int(query.get("second", [log.tree_size()])[0])
                self._send_json(200, log.consistency_proof(first, second))
                return
            self._send_error_json(404, "not found")
        except Exception as exc:
            self._send_error_json(400, str(exc))

    def do_POST(self):
        try:
            path = urlparse(self.path).path
            if path != "/v1/append":
                self._send_error_json(404, "not found")
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
            result = self.server.transparency_log.append_transfer_announcement(payload)
            self._send_json(200, result)
        except Exception as exc:
            self._send_error_json(400, str(exc))

    def log_message(self, format, *args):
        return


def _root_publisher(log, interval_seconds, stop_event):
    while not stop_event.is_set():
        try:
            log.maybe_publish_root(interval_seconds)
        except Exception:
            pass
        stop_event.wait(interval_seconds)


def serve(log, host="127.0.0.1", port=8890, root_interval_seconds=DEFAULT_ROOT_INTERVAL_SECONDS):
    """Run the HTTP transparency log operator."""

    stop_event = threading.Event()
    publisher = threading.Thread(
        target=_root_publisher,
        args=(log, int(root_interval_seconds), stop_event),
        daemon=True,
    )
    publisher.start()
    server = ThreadingHTTPServer((host, int(port)), TransparencyLogHandler)
    server.transparency_log = log
    server.root_interval_seconds = int(root_interval_seconds)
    try:
        server.serve_forever()
    finally:
        stop_event.set()
        server.server_close()


def main():
    parser = argparse.ArgumentParser(description="Run the IND transparency log operator")
    parser.add_argument("--db", default=os.environ.get("IND_LOG_DB", DEFAULT_LOG_DB))
    parser.add_argument("--host", default=os.environ.get("IND_LOG_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("IND_LOG_PORT", "8890")))
    parser.add_argument("--private-key-file", default=os.environ.get("IND_LOG_PRIVATE_KEY_FILE", DEFAULT_LOG_PRIVATE_KEY))
    parser.add_argument("--public-key-file", default=os.environ.get("IND_LOG_PUBLIC_KEY_FILE", DEFAULT_LOG_PUBLIC_KEY))
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
    args = parser.parse_args()
    private_key, public_key = load_or_create_operator_keys(args.private_key_file, args.public_key_file)
    log = TransparencyLog(
        args.db,
        private_key,
        public_key,
        mirror_dirs=args.mirror_dir,
    )
    log.publish_root()
    print(f"IND transparency log id: {log.log_id}")
    print(f"IND transparency operator public key: {public_key}")
    print(f"Serving on http://{args.host}:{args.port}")
    serve(log, host=args.host, port=args.port, root_interval_seconds=args.root_interval_seconds)


if __name__ == "__main__":
    main()
