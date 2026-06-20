#!/usr/bin/env python3
"""Remove invalid stored V3 rows from an IND SQLite store."""

import argparse
import json
import shutil
import sys
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from ind import settings as ind_settings
from ind import token as ind_token


def parse_args():
    parser = argparse.ArgumentParser(
        description="Validate V3 conflict/bill rows and optionally delete invalid cache data."
    )
    parser.add_argument(
        "--db",
        default=str(ind_settings.default_store_path()),
        help="SQLite store path; defaults to the configured IND store path.",
    )
    parser.add_argument(
        "--backup-dir",
        default="",
        help="directory where the database is copied before --apply.",
    )
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--apply", action="store_true", help="delete invalid rows")
    parser.add_argument(
        "--skip-bills",
        action="store_true",
        help="only validate conflicts_v3; do not scan bills_v3.",
    )
    parser.add_argument(
        "--skip-conflicts",
        action="store_true",
        help="only validate bills_v3; do not scan conflicts_v3.",
    )
    return parser.parse_args()


def backup_db(db_path, backup_dir):
    backup_dir = Path(backup_dir)
    backup_dir.mkdir(parents=True, exist_ok=True)
    target = backup_dir / db_path.name
    shutil.copy2(db_path, target)
    return target


def main():
    args = parse_args()
    db_path = Path(args.db)
    if not db_path.exists():
        raise SystemExit(f"database does not exist: {db_path}")
    backup_path = None
    if args.apply:
        if not args.backup_dir:
            raise SystemExit("--backup-dir is required with --apply")
        backup_path = backup_db(db_path, args.backup_dir)
    store = ind_token.INDLocalStore(db_path=db_path, require_transparency=False)
    result = {}
    if not args.skip_conflicts:
        result["conflicts_v3"] = store.cleanup_invalid_conflicts_v3(
            dry_run=not args.apply,
            limit=args.limit,
        )
    if not args.skip_bills:
        result["bills_v3"] = store.cleanup_invalid_bills_v3(
            dry_run=not args.apply,
            limit=args.limit,
        )
    result.update(
        {
            "type": "ind.cleanup_invalid_v3_rows.v3",
            "db": str(db_path),
            "backup": str(backup_path) if backup_path else "",
            "timestamp": int(time.time()),
        }
    )
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
