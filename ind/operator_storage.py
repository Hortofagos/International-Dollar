"""Storage backends for append-capable IND transparency operators."""

import os
import re
import sqlite3
from pathlib import Path

from pymerkle.core import BaseMerkleTree

from . import env as ind_env
from . import token as ind_token
from . import transparency_client as log_client

SCHEMA_VERSION = 1
BACKEND_SQLITE = "sqlite"
BACKEND_MARIADB = "mariadb"
VALID_BACKENDS = {BACKEND_SQLITE, BACKEND_MARIADB}


class OperatorStorageError(RuntimeError):
    pass


_env_bool = ind_env.bool_value


# Read an optional MariaDB password file without accepting missing or directory paths.
def _read_password_file(path):
    if not path:
        return ""
    path = Path(path)
    if not path.exists() or path.is_dir():
        raise OperatorStorageError(f"MariaDB password file does not exist: {path}")
    return path.read_text(encoding="utf-8").lstrip("\ufeff").strip()


# Return whether a database host is constrained to the local machine.
def _is_loopback_host(host):
    host = str(host or "").strip().lower().strip("[]")
    return host in {"localhost", "127.0.0.1", "::1"}


# Resolve and validate the configured operator storage backend name.
def configured_backend(value=None):
    backend = str(value or os.environ.get("IND_LOG_BACKEND", BACKEND_SQLITE)).strip().lower()
    if not backend:
        backend = BACKEND_SQLITE
    if backend not in VALID_BACKENDS:
        raise OperatorStorageError(f"unsupported operator storage backend: {backend}")
    return backend


# Construct the storage backend used by the transparency operator.
def create_operator_storage(db_path, backend=None):
    backend = configured_backend(backend)
    if backend == BACKEND_SQLITE:
        return SQLiteOperatorStorage(db_path)
    return MariaDBOperatorStorage.from_environment()


class OperatorMerkleTree(BaseMerkleTree):
    """pymerkle tree backed by an operator storage backend."""

    def __init__(self, storage, algorithm=log_client.LOG_HASH_ALGORITHM, **opts):
        self.storage = storage
        super().__init__(algorithm, **opts)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def _encode_entry(self, data):
        if not isinstance(data, bytes):
            raise ValueError("Provided data is not binary")
        return data

    def _store_leaf(self, data, digest):
        return self.storage.store_leaf(data, digest)

    def _get_leaf(self, index):
        return self.storage.get_leaf_hash(index)

    def _get_leaves(self, offset, width):
        return self.storage.get_leaf_hashes(offset, width)

    def _get_size(self):
        return self.storage.get_leaf_count()

    def get_entry(self, index):
        return self.storage.get_leaf_entry(index)


# SQLite implementation used by local and testnet transparency operators.
class SQLiteOperatorStorage:
    backend_name = BACKEND_SQLITE

    # Open or create the SQLite database path used for log storage.
    def __init__(self, db_path):
        self.db_path = str(Path(db_path))
        self.display_path = self.db_path
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

    # Return a configured SQLite connection with row dictionaries enabled.
    def connect(self):
        conn = sqlite3.connect(self.db_path, factory=ind_token.ClosingConnection)
        ind_token.configure_sqlite_connection(conn)
        conn.row_factory = sqlite3.Row
        return conn

    # Expose the storage rows through the pymerkle tree adapter.
    def tree(self):
        return OperatorMerkleTree(self)

    # Create or migrate the tables that back log leaves, roots, and spend claims.
    def init_schema(self):
        with self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS leaf(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entry BLOB,
                    hash BLOB
                );

                CREATE TABLE IF NOT EXISTS operator_storage_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS log_entries (
                    entry_hash TEXT PRIMARY KEY,
                    leaf_index INTEGER NOT NULL UNIQUE,
                    submitted_at INTEGER NOT NULL,
                    entry_kind TEXT NOT NULL DEFAULT 'transfer',
                    entry_json TEXT,
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

                CREATE TABLE IF NOT EXISTS spend_map_nodes_v3 (
                    depth INTEGER NOT NULL,
                    position TEXT NOT NULL,
                    node_hash TEXT NOT NULL,
                    PRIMARY KEY(depth, position)
                );

                CREATE TABLE IF NOT EXISTS spend_map_claims_v3 (
                    spend_key TEXT NOT NULL,
                    transfer_hash TEXT NOT NULL,
                    transfer_leaf_index INTEGER NOT NULL,
                    claim_json TEXT NOT NULL,
                    PRIMARY KEY(spend_key, transfer_hash)
                );

                CREATE TABLE IF NOT EXISTS spend_map_meta_v3 (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS invalid_transfer_entries_v3 (
                    entry_hash TEXT PRIMARY KEY,
                    leaf_index INTEGER NOT NULL,
                    reason TEXT NOT NULL,
                    transfer_type TEXT,
                    token_id TEXT,
                    first_seen INTEGER NOT NULL,
                    observed_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_invalid_transfer_entries_v3_leaf
                    ON invalid_transfer_entries_v3(leaf_index);

                CREATE TABLE IF NOT EXISTS operator_recovery_state (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )
            self._ensure_log_entry_columns(conn)
            self._ensure_spend_claim_columns(conn)
            conn.execute(
                """
                INSERT OR REPLACE INTO operator_storage_meta(key, value)
                VALUES ('schema_version', ?)
                """,
                (str(SCHEMA_VERSION),),
            )

    # Add log-entry metadata columns for older SQLite operator databases.
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

    # Upgrade legacy spend claims so multiple rejected branches can be tracked safely.
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
            conn.execute("DROP INDEX IF EXISTS idx_spend_claims_token")
            conn.execute("ALTER TABLE spend_claims RENAME TO spend_claims_legacy")
            conn.execute(
                """
                CREATE TABLE spend_claims (
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
                )
                """
            )
            conn.execute(
                """
                INSERT OR IGNORE INTO spend_claims(
                    spend_key, token_id, previous_hash, sequence,
                    sender_address, sender_public_key, transfer_hash,
                    transfer_leaf_index, first_seen
                )
                SELECT spend_key, token_id, previous_hash, sequence,
                       sender_address, sender_public_key, transfer_hash,
                       transfer_leaf_index, first_seen
                FROM spend_claims_legacy
                """
            )
            conn.execute("DROP TABLE spend_claims_legacy")
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_spend_claims_token
                    ON spend_claims(token_id, sequence, previous_hash, sender_address)
                """
            )
            return
        if "transfer_leaf_index" not in columns:
            conn.execute("ALTER TABLE spend_claims ADD COLUMN transfer_leaf_index INTEGER")

    def store_leaf(self, data, digest):
        with self.connect() as conn:
            cursor = conn.execute("INSERT INTO leaf(entry, hash) VALUES (?, ?)", (data, digest))
            return cursor.lastrowid

    def lock_writer(self, _conn):
        return None

    def get_leaf_hash(self, index):
        with self.connect() as conn:
            row = conn.execute("SELECT hash FROM leaf WHERE id = ?", (int(index),)).fetchone()
        return row["hash"] if row else None

    def get_leaf_hashes(self, offset, width):
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT hash FROM leaf WHERE id BETWEEN ? AND ? ORDER BY id ASC",
                (int(offset) + 1, int(offset) + int(width)),
            ).fetchall()
        return [row["hash"] for row in rows]

    def get_leaf_count(self):
        with self.connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS count_value FROM leaf").fetchone()
        return int(row["count_value"])

    def get_leaf_entry(self, index):
        with self.connect() as conn:
            row = conn.execute("SELECT entry FROM leaf WHERE id = ?", (int(index),)).fetchone()
        return row["entry"] if row else None

    # Append a log entry under a writer lock and return duplicate/tree-size metadata.
    def append_log_entry(
        self,
        entry_hash,
        entry_bytes,
        leaf_hash,
        submitted_at,
        entry_kind,
        entry_json,
        transfer_json,
    ):
        with self.connect() as conn:
            self.lock_writer(conn)
            return self.append_log_entry_conn(
                conn,
                entry_hash,
                entry_bytes,
                leaf_hash,
                submitted_at,
                entry_kind,
                entry_json,
                transfer_json,
            )

    # Insert one leaf and metadata row, or return the existing leaf for duplicate appends.
    def append_log_entry_conn(
        self,
        conn,
        entry_hash,
        entry_bytes,
        leaf_hash,
        submitted_at,
        entry_kind,
        entry_json,
        transfer_json,
    ):
        existing = conn.execute(
            "SELECT leaf_index FROM log_entries WHERE entry_hash = ?",
            (entry_hash,),
        ).fetchone()
        if existing:
            if transfer_json is not None or entry_json is not None:
                conn.execute(
                    """
                    UPDATE log_entries
                    SET transfer_json = COALESCE(transfer_json, ?),
                        entry_json = COALESCE(entry_json, ?),
                        entry_kind = COALESCE(entry_kind, ?)
                    WHERE entry_hash = ?
                    """,
                    (transfer_json, entry_json, entry_kind, entry_hash),
                )
            return {
                "duplicate": True,
                "leaf_index": int(existing["leaf_index"]),
                "tree_size": self._leaf_count_conn(conn),
            }
        cursor = conn.execute(
            "INSERT INTO leaf(entry, hash) VALUES (?, ?)",
            (entry_bytes, leaf_hash),
        )
        leaf_index = int(cursor.lastrowid)
        conn.execute(
            """
            INSERT INTO log_entries(
                entry_hash, leaf_index, submitted_at, entry_kind, entry_json, transfer_json
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                entry_hash,
                leaf_index,
                int(submitted_at),
                entry_kind,
                entry_json,
                transfer_json,
            ),
        )
        return {
            "duplicate": False,
            "leaf_index": leaf_index,
            "tree_size": self._leaf_count_conn(conn),
        }

    def _leaf_count_conn(self, conn):
        row = conn.execute("SELECT COUNT(*) AS count_value FROM leaf").fetchone()
        return int(row["count_value"])

    # Return lightweight backend health information for operator status endpoints.
    def health(self):
        try:
            return {
                "ok": True,
                "backend": self.backend_name,
                "database": self.display_path,
                "schema_version": self.schema_version(),
            }
        except Exception as exc:
            return {
                "ok": False,
                "backend": self.backend_name,
                "database": self.display_path,
                "error": str(exc),
            }

    # Read the storage schema version recorded during initialization.
    def schema_version(self):
        with self.connect() as conn:
            row = conn.execute(
                "SELECT value FROM operator_storage_meta WHERE key = 'schema_version'"
            ).fetchone()
        return int(row["value"]) if row else 0


# Thin adapter that makes mariadb cursors look like the sqlite cursors this module expects.
class MariaDBCursor:
    def __init__(self, cursor):
        self._cursor = cursor

    @property
    def lastrowid(self):
        return self._cursor.lastrowid

    @property
    def rowcount(self):
        return self._cursor.rowcount

    def fetchone(self):
        return self._cursor.fetchone()

    def fetchall(self):
        return self._cursor.fetchall()


# Transaction wrapper that mirrors sqlite context-manager commit and rollback behavior.
class MariaDBConnection:
    def __init__(self, connection):
        self._connection = connection

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            if exc_type is None:
                self._connection.commit()
            else:
                self._connection.rollback()
        finally:
            self._connection.close()
        return False

    def execute(self, sql, params=()):
        cursor = self._connection.cursor(dictionary=True)
        cursor.execute(_translate_sql(sql), tuple(params or ()))
        return MariaDBCursor(cursor)

    def commit(self):
        self._connection.commit()

    def rollback(self):
        self._connection.rollback()


# Translate the small SQLite SQL subset used here into MariaDB-compatible syntax.
def _translate_sql(sql):
    sql = re.sub(r"\bINSERT\s+OR\s+IGNORE\s+INTO\b", "INSERT IGNORE INTO", sql, flags=re.I)
    sql = re.sub(r"\bINSERT\s+OR\s+REPLACE\s+INTO\b", "REPLACE INTO", sql, flags=re.I)
    sql = re.sub(
        r"\b(INTO\s+(?:operator_recovery_state|spend_map_meta_v3)\s*)\(\s*key\s*,",
        r"\1(`key`,",
        sql,
        flags=re.I,
    )
    sql = re.sub(r"\b(WHERE|AND|OR)\s+key\s*=", r"\1 `key` =", sql, flags=re.I)
    return sql


# MariaDB implementation for production operators that outgrow the local SQLite backend.
class MariaDBOperatorStorage:
    backend_name = BACKEND_MARIADB

    # Validate connection settings and enforce local-only database access.
    def __init__(
        self,
        *,
        host="127.0.0.1",
        port=3306,
        database="",
        user="",
        password="",
        unix_socket="",
        tls=False,
        ssl_ca="",
        connect_timeout=10,
    ):
        if not database:
            raise OperatorStorageError("IND_LOG_MARIADB_DATABASE is required")
        if not user:
            raise OperatorStorageError("IND_LOG_MARIADB_USER is required")
        self.host = str(host or "127.0.0.1")
        self.port = int(port or 3306)
        self.database = str(database)
        self.user = str(user)
        self.password = str(password)
        self.unix_socket = str(unix_socket or "")
        if not self.unix_socket and not _is_loopback_host(self.host):
            raise OperatorStorageError(
                "MariaDB operator backend must connect through 127.0.0.1, localhost, ::1, "
                "or a Unix socket; use SSH tunnels for remote administration"
            )
        self.tls = bool(tls)
        self.ssl_ca = str(ssl_ca or "")
        self.connect_timeout = int(connect_timeout or 10)
        endpoint = self.unix_socket or f"{self.host}:{self.port}"
        self.display_path = f"mariadb://{self.user}@{endpoint}/{self.database}"

    # Build MariaDB storage settings from IND_LOG_MARIADB_* environment variables.
    @classmethod
    def from_environment(cls):
        password_file = os.environ.get("IND_LOG_MARIADB_PASSWORD_FILE", "").strip()
        password = _read_password_file(password_file) if password_file else os.environ.get(
            "IND_LOG_MARIADB_PASSWORD", ""
        )
        return cls(
            host=os.environ.get("IND_LOG_MARIADB_HOST", "127.0.0.1"),
            port=int(os.environ.get("IND_LOG_MARIADB_PORT", "3306") or 3306),
            database=os.environ.get("IND_LOG_MARIADB_DATABASE", ""),
            user=os.environ.get("IND_LOG_MARIADB_USER", ""),
            password=password,
            unix_socket=os.environ.get("IND_LOG_MARIADB_UNIX_SOCKET", ""),
            tls=_env_bool("IND_LOG_MARIADB_TLS", False),
            ssl_ca=os.environ.get("IND_LOG_MARIADB_SSL_CA", ""),
            connect_timeout=int(os.environ.get("IND_LOG_MARIADB_CONNECT_TIMEOUT", "10") or 10),
        )

    # Import the optional MariaDB driver only when that backend is selected.
    def _mariadb(self):
        try:
            import mariadb
        except ImportError as exc:
            raise OperatorStorageError(
                "MariaDB operator backend requires the optional 'mariadb' Python package"
            ) from exc
        return mariadb

    # Open a MariaDB connection wrapped in the sqlite-like adapter used by callers.
    def connect(self):
        mariadb = self._mariadb()
        kwargs = {
            "user": self.user,
            "password": self.password,
            "database": self.database,
            "connect_timeout": self.connect_timeout,
            "autocommit": False,
        }
        if self.unix_socket:
            kwargs["unix_socket"] = self.unix_socket
        else:
            kwargs["host"] = self.host
            kwargs["port"] = self.port
        if self.tls:
            kwargs["ssl"] = True
            if self.ssl_ca:
                kwargs["ssl_ca"] = self.ssl_ca
        return MariaDBConnection(mariadb.connect(**kwargs))

    def tree(self):
        return OperatorMerkleTree(self)

    # Create the MariaDB schema with the same logical tables as the SQLite backend.
    def init_schema(self):
        statements = [
            """
            CREATE TABLE IF NOT EXISTS operator_storage_meta (
                `key` VARCHAR(191) NOT NULL PRIMARY KEY,
                `value` LONGTEXT NOT NULL
            ) ENGINE=InnoDB
            """,
            """
            CREATE TABLE IF NOT EXISTS operator_write_lock (
                id TINYINT NOT NULL PRIMARY KEY,
                touched_at BIGINT NOT NULL
            ) ENGINE=InnoDB
            """,
            """
            CREATE TABLE IF NOT EXISTS leaf (
                id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
                entry LONGBLOB NOT NULL,
                hash VARBINARY(64) NOT NULL
            ) ENGINE=InnoDB
            """,
            """
            CREATE TABLE IF NOT EXISTS log_entries (
                entry_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
                leaf_index BIGINT NOT NULL UNIQUE,
                submitted_at BIGINT NOT NULL,
                entry_kind VARCHAR(32) NOT NULL DEFAULT 'transfer',
                entry_json LONGTEXT NULL,
                transfer_json LONGTEXT NULL
            ) ENGINE=InnoDB
            """,
            """
            CREATE TABLE IF NOT EXISTS signed_roots (
                root_id CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
                tree_size BIGINT NOT NULL,
                root_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
                timestamp BIGINT NOT NULL,
                root_json LONGTEXT NOT NULL,
                INDEX idx_signed_roots_timestamp(timestamp, tree_size)
            ) ENGINE=InnoDB
            """,
            """
            CREATE TABLE IF NOT EXISTS spend_claims (
                spend_key CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
                token_id CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
                previous_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
                sequence BIGINT NOT NULL,
                sender_address VARCHAR(128) NOT NULL,
                sender_public_key VARCHAR(256) NOT NULL,
                transfer_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
                transfer_leaf_index BIGINT NULL,
                first_seen BIGINT NOT NULL,
                PRIMARY KEY(spend_key, transfer_hash),
                INDEX idx_spend_claims_token(token_id, sequence, previous_hash, sender_address)
            ) ENGINE=InnoDB
            """,
            """
            CREATE TABLE IF NOT EXISTS spend_map_nodes_v3 (
                depth INT NOT NULL,
                position VARCHAR(80) NOT NULL,
                node_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
                PRIMARY KEY(depth, position)
            ) ENGINE=InnoDB
            """,
            """
            CREATE TABLE IF NOT EXISTS spend_map_claims_v3 (
                spend_key CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
                transfer_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
                transfer_leaf_index BIGINT NOT NULL,
                claim_json LONGTEXT NOT NULL,
                PRIMARY KEY(spend_key, transfer_hash)
            ) ENGINE=InnoDB
            """,
            """
            CREATE TABLE IF NOT EXISTS spend_map_meta_v3 (
                `key` VARCHAR(191) NOT NULL PRIMARY KEY,
                `value` LONGTEXT NOT NULL
            ) ENGINE=InnoDB
            """,
            """
            CREATE TABLE IF NOT EXISTS invalid_transfer_entries_v3 (
                entry_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
                leaf_index BIGINT NOT NULL,
                reason LONGTEXT NOT NULL,
                transfer_type VARCHAR(128) NULL,
                token_id CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
                first_seen BIGINT NOT NULL,
                observed_at BIGINT NOT NULL,
                INDEX idx_invalid_transfer_entries_v3_leaf(leaf_index)
            ) ENGINE=InnoDB
            """,
            """
            CREATE TABLE IF NOT EXISTS operator_recovery_state (
                `key` VARCHAR(191) NOT NULL PRIMARY KEY,
                `value` LONGTEXT NOT NULL
            ) ENGINE=InnoDB
            """,
        ]
        with self.connect() as conn:
            for statement in statements:
                conn.execute(statement)
            conn.execute("INSERT IGNORE INTO operator_write_lock(id, touched_at) VALUES (1, 0)")
            conn.execute(
                """
                REPLACE INTO operator_storage_meta(`key`, `value`)
                VALUES ('schema_version', ?)
                """,
                (str(SCHEMA_VERSION),),
            )

    # Lock the single-writer row so concurrent MariaDB appends keep leaf order stable.
    def _lock_writer(self, conn):
        conn.execute("SELECT id FROM operator_write_lock WHERE id = 1 FOR UPDATE").fetchone()

    # Acquire the backend writer lock for callers that append through shared code paths.
    def lock_writer(self, conn):
        self._lock_writer(conn)

    # Store one raw log leaf while holding the MariaDB writer lock.
    def store_leaf(self, data, digest):
        with self.connect() as conn:
            self._lock_writer(conn)
            cursor = conn.execute("INSERT INTO leaf(entry, hash) VALUES (?, ?)", (data, digest))
            return cursor.lastrowid

    def get_leaf_hash(self, index):
        with self.connect() as conn:
            row = conn.execute("SELECT hash FROM leaf WHERE id = ?", (int(index),)).fetchone()
        return row["hash"] if row else None

    def get_leaf_hashes(self, offset, width):
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT hash FROM leaf WHERE id BETWEEN ? AND ? ORDER BY id ASC",
                (int(offset) + 1, int(offset) + int(width)),
            ).fetchall()
        return [row["hash"] for row in rows]

    def get_leaf_count(self):
        with self.connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS count_value FROM leaf").fetchone()
        return int(row["count_value"])

    def get_leaf_entry(self, index):
        with self.connect() as conn:
            row = conn.execute("SELECT entry FROM leaf WHERE id = ?", (int(index),)).fetchone()
        return row["entry"] if row else None

    # Append one log entry transactionally and return duplicate/tree-size metadata.
    def append_log_entry(
        self,
        entry_hash,
        entry_bytes,
        leaf_hash,
        submitted_at,
        entry_kind,
        entry_json,
        transfer_json,
    ):
        with self.connect() as conn:
            self._lock_writer(conn)
            return self.append_log_entry_conn(
                conn,
                entry_hash,
                entry_bytes,
                leaf_hash,
                submitted_at,
                entry_kind,
                entry_json,
                transfer_json,
            )

    # Insert one MariaDB leaf and metadata row, or reuse the existing duplicate entry.
    def append_log_entry_conn(
        self,
        conn,
        entry_hash,
        entry_bytes,
        leaf_hash,
        submitted_at,
        entry_kind,
        entry_json,
        transfer_json,
    ):
        existing = conn.execute(
            "SELECT leaf_index FROM log_entries WHERE entry_hash = ? FOR UPDATE",
            (entry_hash,),
        ).fetchone()
        if existing:
            if transfer_json is not None or entry_json is not None:
                conn.execute(
                    """
                    UPDATE log_entries
                    SET transfer_json = COALESCE(transfer_json, ?),
                        entry_json = COALESCE(entry_json, ?),
                        entry_kind = COALESCE(entry_kind, ?)
                    WHERE entry_hash = ?
                    """,
                    (transfer_json, entry_json, entry_kind, entry_hash),
                )
            return {
                "duplicate": True,
                "leaf_index": int(existing["leaf_index"]),
                "tree_size": self._leaf_count_conn(conn),
            }
        cursor = conn.execute(
            "INSERT INTO leaf(entry, hash) VALUES (?, ?)",
            (entry_bytes, leaf_hash),
        )
        leaf_index = int(cursor.lastrowid)
        conn.execute(
            """
            INSERT INTO log_entries(
                entry_hash, leaf_index, submitted_at, entry_kind, entry_json, transfer_json
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                entry_hash,
                leaf_index,
                int(submitted_at),
                entry_kind,
                entry_json,
                transfer_json,
            ),
        )
        return {
            "duplicate": False,
            "leaf_index": leaf_index,
            "tree_size": self._leaf_count_conn(conn),
        }

    def _leaf_count_conn(self, conn):
        row = conn.execute("SELECT COUNT(*) AS count_value FROM leaf").fetchone()
        return int(row["count_value"])

    # Return lightweight MariaDB connectivity and schema health for status endpoints.
    def health(self):
        try:
            with self.connect() as conn:
                row = conn.execute("SELECT 1 AS healthy").fetchone()
            return {
                "ok": bool(row and int(row["healthy"]) == 1),
                "backend": self.backend_name,
                "database": self.display_path,
                "schema_version": self.schema_version(),
            }
        except Exception as exc:
            return {
                "ok": False,
                "backend": self.backend_name,
                "database": self.display_path,
                "error": str(exc),
            }

    # Read the MariaDB storage schema version recorded during initialization.
    def schema_version(self):
        with self.connect() as conn:
            row = conn.execute(
                "SELECT `value` FROM operator_storage_meta WHERE `key` = 'schema_version'"
            ).fetchone()
        return int(row["value"]) if row else 0
