import argparse
import json
import sys
import urllib.parse
import urllib.request
from pathlib import Path

from pymerkle.concrete.inmemory import InmemoryTree

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import log_client
from operator_tools import hash_log_exporter


# Raised when an archive is available but cryptographically invalid.
class ArchiveAuditVerificationError(Exception):
    pass


# Raised when archive inputs cannot be loaded.
class ArchiveAuditIOError(Exception):
    pass


def _is_url(location):
    return str(location).startswith(("http://", "https://"))


def _read_bytes(location):
    location = str(location)
    try:
        if _is_url(location):
            request = urllib.request.Request(
                location,
                headers={"User-Agent": "International-Dollar-transparency-auditor/1"},
            )
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.read()
        return Path(location).read_bytes()
    except Exception as exc:
        raise ArchiveAuditIOError(f"could not read {location}: {exc}") from exc


def _read_json(location):
    try:
        return json.loads(_read_bytes(location).decode("utf-8"))
    except ArchiveAuditIOError:
        raise
    except Exception as exc:
        raise ArchiveAuditVerificationError(f"could not parse JSON from {location}: {exc}") from exc


def _segment_location(base, relative_path):
    relative_path = str(relative_path)
    if _is_url(relative_path) or Path(relative_path).is_absolute():
        return relative_path
    if not base:
        return relative_path
    base = str(base)
    if _is_url(base):
        return urllib.parse.urljoin(base.rstrip("/") + "/", relative_path)
    return str(Path(base) / relative_path)


def _entries_from_segment(data):
    try:
        entries = [json.loads(line) for line in data.decode("utf-8").splitlines() if line.strip()]
    except Exception as exc:
        raise ArchiveAuditVerificationError(f"could not parse segment JSONL: {exc}") from exc
    expected = None
    for entry in entries:
        if not isinstance(entry, dict) or not {"leaf_index", "entry_hash", "submitted_at"}.issubset(
            entry
        ):
            raise ArchiveAuditVerificationError("segment contains a malformed hash-log entry")
        leaf_index = int(entry["leaf_index"])
        if expected is None:
            expected = leaf_index
        if leaf_index != expected:
            raise ArchiveAuditVerificationError("segment leaf indices are not contiguous")
        entry_hash = str(entry["entry_hash"]).lower()
        if len(entry_hash) != 64:
            raise ArchiveAuditVerificationError("segment entry hash has invalid length")
        try:
            bytes.fromhex(entry_hash)
        except ValueError as exc:
            raise ArchiveAuditVerificationError("segment entry hash is not hex") from exc
        expected += 1
    return entries


def _compute_archive_root(entries, tree_size):
    tree = InmemoryTree(algorithm=log_client.LOG_HASH_ALGORITHM)
    for entry in entries:
        tree.append_entry(bytes.fromhex(entry["entry_hash"]))
    if tree.get_size() != int(tree_size):
        raise ArchiveAuditVerificationError(
            f"archive contains {tree.get_size()} entries but signed root tree_size is {tree_size}"
        )
    return tree.get_state(int(tree_size)).hex()


def _mirror_root_matches(mirror, signed_root):
    if isinstance(mirror, Path):
        mirror = str(mirror)
    mirror_client = log_client._coerce_mirror(mirror)
    mirrored = mirror_client.root_at(int(signed_root["timestamp"]))
    log_client.verify_signed_root(mirrored, operator_public_key=signed_root["operator_public_key"])
    return (
        int(mirrored["tree_size"]) == int(signed_root["tree_size"])
        and mirrored["root_hash"] == signed_root["root_hash"]
        and int(mirrored["timestamp"]) == int(signed_root["timestamp"])
    )


def verify_archive(
    manifest_location, archive_base=None, operator_public_key=None, mirror=None, strict=False
):
    if strict and not mirror:
        raise ArchiveAuditIOError("strict hash-log archive audit requires --mirror")
    manifest = _read_json(manifest_location)
    try:
        hash_log_exporter.verify_manifest_signature(
            manifest, operator_public_key=operator_public_key
        )
    except Exception as exc:
        raise ArchiveAuditVerificationError(str(exc)) from exc

    entries = []
    expected_leaf = 0
    for segment in manifest["segments"]:
        location = _segment_location(archive_base, segment["path"])
        data = _read_bytes(location)
        actual_hash = hash_log_exporter.segment_hash(data, manifest["segment_hash_algorithm"])
        if actual_hash != segment["segment_hash"]:
            raise ArchiveAuditVerificationError(f"segment hash mismatch for {segment['path']}")
        if len(data) != int(segment["byte_length"]):
            raise ArchiveAuditVerificationError(
                f"segment byte length mismatch for {segment['path']}"
            )
        segment_entries = _entries_from_segment(data)
        if not segment_entries:
            raise ArchiveAuditVerificationError(
                f"empty segment listed in manifest: {segment['path']}"
            )
        if int(segment_entries[0]["leaf_index"]) != int(segment["first_leaf_index"]):
            raise ArchiveAuditVerificationError(
                f"segment first_leaf_index mismatch for {segment['path']}"
            )
        if int(segment_entries[-1]["leaf_index"]) != int(segment["last_leaf_index"]):
            raise ArchiveAuditVerificationError(
                f"segment last_leaf_index mismatch for {segment['path']}"
            )
        if len(segment_entries) != int(segment["entry_count"]):
            raise ArchiveAuditVerificationError(
                f"segment entry_count mismatch for {segment['path']}"
            )
        if int(segment_entries[0]["leaf_index"]) != expected_leaf:
            raise ArchiveAuditVerificationError(
                "archive segment ranges are not contiguous from leaf 0"
            )
        expected_leaf = int(segment_entries[-1]["leaf_index"]) + 1
        entries.extend(segment_entries)

    signed_root = manifest["signed_root"]
    computed_root = _compute_archive_root(entries, int(signed_root["tree_size"]))
    if computed_root != signed_root["root_hash"]:
        raise ArchiveAuditVerificationError(
            "archive entries do not produce the manifest signed root"
        )

    mirror_cross_checked = False
    if mirror:
        if not _mirror_root_matches(mirror, signed_root):
            raise ArchiveAuditVerificationError("mirror does not contain the manifest signed root")
        mirror_cross_checked = True

    return {
        "archive_valid": True,
        "mirror_cross_checked": mirror_cross_checked,
        "log_id": manifest["log_id"],
        "tree_size": int(signed_root["tree_size"]),
        "root_hash": signed_root["root_hash"],
        "segment_count": len(manifest["segments"]),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Audit an IND transparency hash-log archive")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--archive-base", default="")
    parser.add_argument("--operator-public-key", required=True)
    parser.add_argument("--mirror", default="")
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    try:
        result = verify_archive(
            args.manifest,
            archive_base=args.archive_base or str(Path(args.manifest).parent),
            operator_public_key=args.operator_public_key,
            mirror=args.mirror or None,
            strict=args.strict,
        )
        if not args.mirror:
            print(
                "WARNING: mirror cross-check skipped; archive-only verification proves correspondence "
                "to a signed root, not public publication.",
                file=sys.stderr,
            )
        if args.json:
            print(log_client.canonical_json(result))
        else:
            print(
                f"PASS: archive verifies against signed root {result['root_hash']} "
                f"at tree_size {result['tree_size']}"
            )
        return 0
    except ArchiveAuditVerificationError as exc:
        result = {
            "archive_valid": False,
            "mirror_cross_checked": bool(args.mirror),
            "error": str(exc),
        }
        if args.json:
            print(log_client.canonical_json(result))
        else:
            print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        result = {"archive_valid": False, "mirror_cross_checked": False, "error": str(exc)}
        if args.json:
            print(log_client.canonical_json(result))
        else:
            print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
