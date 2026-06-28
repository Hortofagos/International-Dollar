#!/usr/bin/env python3
"""Safe operator-storage migration and verification helpers."""

import argparse
import json
import sqlite3
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from ind import operator_storage
from ind import transparency_client as log_client

CANONICAL_TABLES = [
    (
        "leaf",
        ("id", "entry", "hash"),
        "id",
    ),
    (
        "log_entries",
        ("entry_hash", "leaf_index", "submitted_at", "entry_kind", "entry_json", "transfer_json"),
        "leaf_index",
    ),
    (
        "signed_roots",
        ("root_id", "tree_size", "root_hash", "timestamp", "root_json"),
        "timestamp, tree_size",
    ),
    (
        "spend_claims",
        (
            "spend_key",
            "token_id",
            "previous_hash",
            "sequence",
            "sender_address",
            "sender_public_key",
            "transfer_hash",
            "transfer_leaf_index",
            "first_seen",
        ),
        "spend_key, transfer_hash",
    ),
    (
        "spend_map_nodes_v3",
        ("depth", "position", "node_hash"),
        "depth, position",
    ),
    (
        "spend_map_claims_v3",
        ("spend_key", "transfer_hash", "transfer_leaf_index", "claim_json"),
        "spend_key, transfer_hash",
    ),
    ("spend_map_meta_v3", ("key", "value"), "key"),
    (
        "invalid_transfer_entries_v3",
        (
            "entry_hash",
            "leaf_index",
            "reason",
            "transfer_type",
            "token_id",
            "first_seen",
            "observed_at",
        ),
        "leaf_index, entry_hash",
    ),
    ("operator_recovery_state", ("key", "value"), "key"),
]


class ReadOnlySQLiteStorage(operator_storage.SQLiteOperatorStorage):
    def __init__(self, db_path):
        self.db_path = str(Path(db_path))
        self.display_path = self.db_path

    def connect(self):
        uri = Path(self.db_path).resolve().as_uri() + "?mode=ro"
        conn = sqlite3.connect(uri, uri=True)
        conn.row_factory = sqlite3.Row
        return conn

    def init_schema(self):
        return None


def _json(data):
    return json.dumps(data, sort_keys=True, indent=2, ensure_ascii=True) + "\n"


def _columns_sql(columns):
    return ", ".join(columns)


def _placeholders(columns):
    return ", ".join("?" for _ in columns)


def _source_rows(source_conn, table, columns, order_by):
    query = f"SELECT {_columns_sql(columns)} FROM {table} ORDER BY {order_by}"
    return source_conn.execute(query).fetchall()


def _target_insert(target_conn, table, columns, row):
    values = [row[column] for column in columns]
    target_conn.execute(
        f"INSERT OR IGNORE INTO {table}({_columns_sql(columns)}) "
        f"VALUES ({_placeholders(columns)})",
        values,
    )


def _canonical_row_count(storage):
    total = 0
    with storage.connect() as conn:
        for table, _columns, _order_by in CANONICAL_TABLES:
            row = conn.execute(f"SELECT COUNT(*) AS count_value FROM {table}").fetchone()
            total += int(row["count_value"])
    return total


def _copy_tables(source_conn, target_storage):
    copied = {}
    with target_storage.connect() as target_conn:
        for table, columns, order_by in CANONICAL_TABLES:
            rows = _source_rows(source_conn, table, columns, order_by)
            for row in rows:
                _target_insert(target_conn, table, columns, row)
            copied[table] = len(rows)
    return copied


def _tree_root(storage, tree_size):
    tree_size = int(tree_size)
    if tree_size == 0:
        return log_client.LOG_EMPTY_ROOT_HASH
    with storage.tree() as tree:
        return tree.get_state(tree_size).hex()


def verify_storage(storage, operator_public_key=None):
    size = int(storage.get_leaf_count())
    signed_roots = []
    mismatches = []
    with storage.connect() as conn:
        rows = conn.execute(
            """
            SELECT root_id, tree_size, root_hash, timestamp, root_json
            FROM signed_roots
            ORDER BY timestamp ASC, tree_size ASC
            """
        ).fetchall()
    for row in rows:
        root = json.loads(row["root_json"])
        if operator_public_key:
            log_client.verify_signed_root(root, operator_public_key=operator_public_key)
        computed = _tree_root(storage, int(row["tree_size"]))
        if computed != row["root_hash"] or computed != root["root_hash"]:
            mismatches.append(
                {
                    "tree_size": int(row["tree_size"]),
                    "stored_root_hash": row["root_hash"],
                    "signed_root_hash": root["root_hash"],
                    "computed_root_hash": computed,
                }
            )
        signed_roots.append(
            {
                "tree_size": int(row["tree_size"]),
                "timestamp": int(row["timestamp"]),
                "root_hash": row["root_hash"],
            }
        )
    latest = signed_roots[-1] if signed_roots else None
    return {
        "ok": not mismatches,
        "backend": storage.backend_name,
        "database": storage.display_path,
        "tree_size": size,
        "signed_root_count": len(signed_roots),
        "latest_signed_root": latest,
        "mismatches": mismatches,
    }


def _mainnet_guard(args):
    if args.network != "mainnet":
        return
    if not args.allow_mainnet_read_only_copy:
        raise SystemExit(
            "mainnet operator storage may only be read with "
            "--allow-mainnet-read-only-copy; this tool never deletes mainnet data"
        )


def _empty_target_guard(storage, allow_nonempty_target=False):
    count = _canonical_row_count(storage)
    if count and not allow_nonempty_target:
        raise SystemExit(
            f"target {storage.display_path} already has {count} canonical row(s); "
            "refusing to overwrite or merge implicitly"
        )


def cmd_sqlite_to_mariadb(args):
    _mainnet_guard(args)
    source = ReadOnlySQLiteStorage(args.sqlite_db)
    target = operator_storage.MariaDBOperatorStorage.from_environment()
    target.init_schema()
    _empty_target_guard(target, args.allow_nonempty_target)
    with source.connect() as source_conn:
        copied = _copy_tables(source_conn, target)
    verification = verify_storage(target, args.operator_public_key or None)
    result = {
        "ok": verification["ok"],
        "operation": "sqlite-to-mariadb",
        "network": args.network,
        "source_sqlite": str(Path(args.sqlite_db)),
        "target": target.display_path,
        "copied": copied,
        "verification": verification,
    }
    print(_json(result), end="")
    return 0 if result["ok"] else 1


def cmd_mariadb_to_sqlite(args):
    _mainnet_guard(args)
    output = Path(args.output_sqlite)
    if output.exists() and not args.allow_overwrite_output:
        raise SystemExit(f"refusing to overwrite existing SQLite output: {output}")
    if output.exists() and args.network == "mainnet":
        raise SystemExit("refusing to overwrite any existing SQLite file during mainnet copy")
    if output.exists():
        output.unlink()
    source = operator_storage.MariaDBOperatorStorage.from_environment()
    target = operator_storage.SQLiteOperatorStorage(output)
    target.init_schema()
    _empty_target_guard(target)
    with source.connect() as source_conn:
        copied = _copy_tables(source_conn, target)
    verification = verify_storage(target, args.operator_public_key or None)
    result = {
        "ok": verification["ok"],
        "operation": "mariadb-to-sqlite",
        "network": args.network,
        "source": source.display_path,
        "output_sqlite": str(output),
        "copied": copied,
        "verification": verification,
    }
    print(_json(result), end="")
    return 0 if result["ok"] else 1


def cmd_verify(args):
    if args.backend == operator_storage.BACKEND_SQLITE:
        storage = ReadOnlySQLiteStorage(args.sqlite_db)
    else:
        storage = operator_storage.MariaDBOperatorStorage.from_environment()
    result = verify_storage(storage, args.operator_public_key or None)
    print(_json(result), end="")
    return 0 if result["ok"] else 1


def cmd_init_mariadb(args):
    storage = operator_storage.MariaDBOperatorStorage.from_environment()
    storage.init_schema()
    health = storage.health()
    result = {
        "ok": bool(health.get("ok")),
        "operation": "init-mariadb",
        "target": storage.display_path,
        "health": health,
    }
    print(_json(result), end="")
    return 0 if result["ok"] else 1


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    init = subparsers.add_parser("init-mariadb")
    init.set_defaults(func=cmd_init_mariadb)

    verify = subparsers.add_parser("verify")
    verify.add_argument("--backend", choices=sorted(operator_storage.VALID_BACKENDS), required=True)
    verify.add_argument("--sqlite-db", type=Path)
    verify.add_argument("--operator-public-key", default="")
    verify.set_defaults(func=cmd_verify)

    to_mariadb = subparsers.add_parser("sqlite-to-mariadb")
    to_mariadb.add_argument("--sqlite-db", type=Path, required=True)
    to_mariadb.add_argument("--network", choices=("testnet", "mainnet"), default="testnet")
    to_mariadb.add_argument("--operator-public-key", default="")
    to_mariadb.add_argument("--allow-nonempty-target", action="store_true")
    to_mariadb.add_argument("--allow-mainnet-read-only-copy", action="store_true")
    to_mariadb.set_defaults(func=cmd_sqlite_to_mariadb)

    to_sqlite = subparsers.add_parser("mariadb-to-sqlite")
    to_sqlite.add_argument("--output-sqlite", type=Path, required=True)
    to_sqlite.add_argument("--network", choices=("testnet", "mainnet"), default="testnet")
    to_sqlite.add_argument("--operator-public-key", default="")
    to_sqlite.add_argument("--allow-overwrite-output", action="store_true")
    to_sqlite.add_argument("--allow-mainnet-read-only-copy", action="store_true")
    to_sqlite.set_defaults(func=cmd_mariadb_to_sqlite)
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if getattr(args, "backend", None) == operator_storage.BACKEND_SQLITE and not args.sqlite_db:
        raise SystemExit("--sqlite-db is required when --backend=sqlite")
    try:
        return args.func(args)
    except (
        operator_storage.OperatorStorageError,
        sqlite3.Error,
        OSError,
        json.JSONDecodeError,
        log_client.TransparencyLogError,
    ) as exc:
        print(_json({"ok": False, "error": str(exc)}), file=sys.stderr, end="")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
