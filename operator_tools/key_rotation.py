import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ind import transparency_client as log_client
from operator_tools import hash_log_exporter

EMERGENCY_REVOCATION_WARNING = (
    "WARNING: emergency revocation only works after clients have already accepted the referenced "
    "rotation record. First-rotation compromise cannot be cleanly recovered through this protocol; "
    "operators should perform a scheduled rotation early to establish a successor key as a recovery anchor."
)


def _read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _write_or_print(record, output=None):
    text = log_client.canonical_json(record) + "\n"
    if output:
        Path(output).parent.mkdir(parents=True, exist_ok=True)
        Path(output).write_text(text, encoding="utf-8")
    else:
        print(text, end="")


def _read_private(path):
    value = hash_log_exporter.read_key_file(path, "private_key")
    if not value:
        raise SystemExit(f"missing private key: {path}")
    return value


def _read_public(path):
    value = hash_log_exporter.read_key_file(path, "public_key")
    if not value:
        raise SystemExit(f"missing public key: {path}")
    return value


def cmd_create_rotation(args):
    rotation_timestamp = int(args.rotation_timestamp or time.time())
    overlap_until = int(
        args.overlap_until_timestamp or (rotation_timestamp + int(args.overlap_days * 86400))
    )
    record = log_client.make_key_rotation(
        _read_private(args.old_private_key_file),
        _read_public(args.old_public_key_file),
        _read_private(args.new_private_key_file),
        _read_public(args.new_public_key_file),
        rotation_timestamp=rotation_timestamp,
        effective_from_tree_size=args.effective_from_tree_size,
        overlap_until_timestamp=overlap_until,
        reason=args.reason,
    )
    _write_or_print(record, args.output)
    return 0


def cmd_verify_rotation(args):
    record = _read_json(args.record)
    log_client.verify_key_rotation(record)
    print("OK: operator key rotation record verifies")
    return 0


def cmd_create_revocation(args):
    print(EMERGENCY_REVOCATION_WARNING, file=sys.stderr)
    rotation = _read_json(args.rotation_record)
    record = log_client.make_key_revocation(
        _read_private(args.new_private_key_file),
        rotation,
        revocation_timestamp=int(args.revocation_timestamp or time.time()),
        reason=args.reason,
    )
    _write_or_print(record, args.output)
    return 0


def cmd_verify_revocation(args):
    record = _read_json(args.record)
    rotation = _read_json(args.rotation_record) if args.rotation_record else None
    log_client.verify_key_revocation(record, rotation_record=rotation)
    print("OK: operator key revocation record verifies")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Create and verify IND transparency operator key rotation records"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create-rotation")
    create.add_argument("--old-private-key-file", required=True)
    create.add_argument("--old-public-key-file", required=True)
    create.add_argument("--new-private-key-file", required=True)
    create.add_argument("--new-public-key-file", required=True)
    create.add_argument("--effective-from-tree-size", type=int, required=True)
    create.add_argument("--rotation-timestamp", type=int, default=0)
    create.add_argument("--overlap-days", type=float, default=7.0)
    create.add_argument("--overlap-until-timestamp", type=int, default=0)
    create.add_argument("--reason", default="scheduled")
    create.add_argument("--output", default="")
    create.set_defaults(func=cmd_create_rotation)

    verify = subparsers.add_parser("verify-rotation")
    verify.add_argument("--record", required=True)
    verify.set_defaults(func=cmd_verify_rotation)

    revoke = subparsers.add_parser("create-revocation")
    revoke.add_argument("--rotation-record", required=True)
    revoke.add_argument("--new-private-key-file", required=True)
    revoke.add_argument("--revocation-timestamp", type=int, default=0)
    revoke.add_argument("--reason", default="compromise")
    revoke.add_argument("--output", default="")
    revoke.set_defaults(func=cmd_create_revocation)

    verify_revoke = subparsers.add_parser("verify-revocation")
    verify_revoke.add_argument("--record", required=True)
    verify_revoke.add_argument("--rotation-record", default="")
    verify_revoke.set_defaults(func=cmd_verify_revocation)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
