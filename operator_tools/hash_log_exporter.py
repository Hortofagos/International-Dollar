import argparse
import json
import os
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import ind_token
import log_client

DEFAULT_OPERATOR_URL = "http://127.0.0.1:8890"
DEFAULT_ARCHIVE_DIR = "operator_tools/hash-log-archive"
DEFAULT_STATE_FILE = "operator_tools/hash_log_export_state.json"
DEFAULT_PAGE_SIZE = 10000
DEFAULT_POLL_SECONDS = 300
DEFAULT_PRIVATE_KEY_PATH = "files/log_operator_private_key.json"
DEFAULT_PUBLIC_KEY_PATH = "files/log_operator_public_key.json"
ARCHIVE_MANIFEST_TYPE = "ind.transparency_hash_log_archive_manifest.v3"
SEGMENT_HASH_ALGORITHM = "sha3_256"
ARCHIVE_MANIFEST_SIGNATURE_DOMAIN = "IND_TRANSPARENCY_HASH_LOG_ARCHIVE_MANIFEST_V3"
SUPPORTED_SEGMENT_HASH_ALGORITHMS = {SEGMENT_HASH_ALGORITHM}


# Raised when transfer-hash log export fails.
class HashLogExportError(Exception):
    pass


def read_key_file(path, field):
    path = Path(path)
    if not path.exists():
        return ""
    text = path.read_text(encoding="utf-8").strip()
    if path.suffix == ".json":
        try:
            return str(json.loads(text).get(field, "")).strip()
        except json.JSONDecodeError:
            return ""
    return text


def atomic_write_text(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(path.name + ".tmp")
    temp_path.write_text(text, encoding="utf-8")
    temp_path.replace(path)


def load_state(path):
    path = Path(path)
    if not path.exists():
        return {"next_leaf_index": 0}
    return json.loads(path.read_text(encoding="utf-8"))


def save_state(path, state):
    atomic_write_text(path, log_client.canonical_json(state) + "\n")


# Fetch transfer-hash log entries from a running operator.
class OperatorEntrySource:
    def __init__(self, operator_url=DEFAULT_OPERATOR_URL, timeout=30):
        self.operator_url = operator_url.rstrip("/")
        self.timeout = int(timeout)

    def entries(self, start, end, limit):
        query = urllib.parse.urlencode({"start": int(start), "end": int(end), "limit": int(limit)})
        url = f"{self.operator_url}/v3/entries?{query}"
        with urllib.request.urlopen(url, timeout=self.timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
        return payload.get("entries", []), int(payload.get("tree_size", 0))

    def latest_root(self):
        with urllib.request.urlopen(
            f"{self.operator_url}/v3/root", timeout=self.timeout
        ) as response:
            return json.loads(response.read().decode("utf-8"))


def segment_hash(data, algorithm=SEGMENT_HASH_ALGORITHM):
    if algorithm != SEGMENT_HASH_ALGORITHM:
        raise HashLogExportError(f"unsupported segment hash algorithm: {algorithm}")
    return ind_token.sha3_hex(data)


def manifest_signature_payload(manifest):
    unsigned = dict(manifest)
    unsigned.pop("signature", None)
    return ind_token.signature_payload(ARCHIVE_MANIFEST_SIGNATURE_DOMAIN, unsigned)


def sign_manifest(manifest, operator_private_key):
    if not operator_private_key:
        raise HashLogExportError("operator private key is required to sign archive manifest")
    signed = dict(manifest)
    signed["signature"] = log_client._sign_operator_payload(
        operator_private_key, manifest_signature_payload(signed)
    )
    return signed


def archive_id_for(
    log_id, signed_root_tree_size, signed_root_hash, segments, segment_hash_algorithm
):
    return ind_token.sha3_hex(
        log_client.canonical_bytes(
            {
                "log_id": log_id,
                "signed_root_tree_size": int(signed_root_tree_size),
                "signed_root_hash": signed_root_hash,
                "segment_hash_algorithm": segment_hash_algorithm,
                "segments": segments,
            }
        )
    )


def verify_manifest_signature(manifest, operator_public_key=None):
    required = {
        "type",
        "version",
        "archive_id",
        "log_id",
        "operator_public_key",
        "tree_algorithm",
        "hash_algorithm",
        "segment_hash_algorithm",
        "signature_algorithm",
        "signed_root",
        "signed_root_tree_size",
        "signed_root_hash",
        "signed_root_timestamp",
        "archived_entry_count",
        "segments",
        "manifest_timestamp",
        "signature",
    }
    if not isinstance(manifest, dict) or not required.issubset(manifest):
        raise HashLogExportError("malformed hash-log archive manifest")
    if manifest["type"] != ARCHIVE_MANIFEST_TYPE or int(manifest["version"]) != 1:
        raise HashLogExportError("unsupported hash-log archive manifest version")
    if manifest["segment_hash_algorithm"] not in SUPPORTED_SEGMENT_HASH_ALGORITHMS:
        raise HashLogExportError("unsupported segment hash algorithm")
    if manifest["signature_algorithm"] not in log_client._signature_algorithms_for_verification():
        raise HashLogExportError("unsupported manifest signature algorithm")

    public_key = manifest["operator_public_key"].strip()
    if operator_public_key and public_key != operator_public_key.strip():
        raise HashLogExportError("archive manifest was signed by an unexpected operator")
    if manifest["log_id"] != log_client.log_id_from_public_key(public_key):
        raise HashLogExportError("archive manifest log id does not match operator key")

    signed_root = manifest["signed_root"]
    log_client.verify_signed_root(signed_root, operator_public_key=public_key)
    if manifest["log_id"] != signed_root["log_id"]:
        raise HashLogExportError("archive manifest log id does not match embedded signed root")
    if public_key != signed_root["operator_public_key"].strip():
        raise HashLogExportError(
            "archive manifest operator key does not match embedded signed root"
        )
    if manifest["tree_algorithm"] != signed_root["tree_algorithm"]:
        raise HashLogExportError(
            "archive manifest tree_algorithm does not match embedded signed root"
        )
    if manifest["hash_algorithm"] != signed_root["hash_algorithm"]:
        raise HashLogExportError(
            "archive manifest hash_algorithm does not match embedded signed root"
        )
    if int(manifest["signed_root_tree_size"]) != int(signed_root["tree_size"]):
        raise HashLogExportError(
            "archive manifest signed_root_tree_size does not match embedded signed root"
        )
    if manifest["signed_root_hash"] != signed_root["root_hash"]:
        raise HashLogExportError(
            "archive manifest signed_root_hash does not match embedded signed root"
        )
    if int(manifest["signed_root_timestamp"]) != int(signed_root["timestamp"]):
        raise HashLogExportError(
            "archive manifest signed_root_timestamp does not match embedded signed root"
        )
    if int(manifest["archived_entry_count"]) != int(signed_root["tree_size"]):
        raise HashLogExportError(
            "archive manifest entry count does not match signed root tree size"
        )
    expected_archive_id = archive_id_for(
        manifest["log_id"],
        manifest["signed_root_tree_size"],
        manifest["signed_root_hash"],
        manifest["segments"],
        manifest["segment_hash_algorithm"],
    )
    if manifest["archive_id"] != expected_archive_id:
        raise HashLogExportError(
            "archive manifest archive_id does not match signed root and segments"
        )
    if not log_client._verify_operator_payload(
        public_key,
        manifest["signature"],
        manifest_signature_payload(manifest),
        manifest["signature_algorithm"],
    ):
        raise HashLogExportError("invalid archive manifest signature")
    return True


# Write transfer-hash log pages to static files for auditors.
class StaticHashLogArchive:
    def __init__(self, archive_dir, operator_private_key=None, operator_public_key=None):
        self.archive_dir = Path(archive_dir)
        self.operator_private_key = operator_private_key
        self.operator_public_key = operator_public_key

    def write_segment(self, entries):
        if not entries:
            return None
        self._validate_entries(entries)
        first = int(entries[0]["leaf_index"])
        last = int(entries[-1]["leaf_index"])
        segment_path = self.archive_dir / "entries" / f"entries_{first:012d}_{last:012d}.jsonl"
        text = "".join(log_client.canonical_json(entry) + "\n" for entry in entries)
        atomic_write_text(segment_path, text)
        return segment_path

    def write_manifest(self, signed_root, manifest_timestamp=None):
        log_client.verify_signed_root(signed_root, operator_public_key=self.operator_public_key)
        tree_size = int(signed_root["tree_size"])
        segments = self.segment_manifest_entries(tree_size)
        archived_count = sum(int(segment["entry_count"]) for segment in segments)
        if archived_count != tree_size:
            raise HashLogExportError("hash log archive does not cover the signed root tree size")
        archive_id = archive_id_for(
            signed_root["log_id"],
            tree_size,
            signed_root["root_hash"],
            segments,
            SEGMENT_HASH_ALGORITHM,
        )
        manifest = {
            "type": ARCHIVE_MANIFEST_TYPE,
            "version": 1,
            "archive_id": archive_id,
            "log_id": signed_root["log_id"],
            "operator_public_key": signed_root["operator_public_key"],
            "tree_algorithm": signed_root["tree_algorithm"],
            "hash_algorithm": signed_root["hash_algorithm"],
            "segment_hash_algorithm": SEGMENT_HASH_ALGORITHM,
            "signature_algorithm": log_client.LOG_SIGNATURE_ALGORITHM,
            "signed_root": signed_root,
            "signed_root_tree_size": tree_size,
            "signed_root_hash": signed_root["root_hash"],
            "signed_root_timestamp": int(signed_root["timestamp"]),
            "archived_entry_count": tree_size,
            "segments": segments,
            "manifest_timestamp": int(manifest_timestamp or time.time()),
        }
        manifest = sign_manifest(manifest, self.operator_private_key)
        verify_manifest_signature(manifest, operator_public_key=self.operator_public_key)
        atomic_write_text(
            self.archive_dir / "manifest.json", log_client.canonical_json(manifest) + "\n"
        )
        return manifest

    def segment_manifest_entries(self, tree_size):
        tree_size = int(tree_size)
        if tree_size == 0:
            return []
        entries_dir = self.archive_dir / "entries"
        files = sorted(entries_dir.glob("entries_*.jsonl")) if entries_dir.exists() else []
        segments = []
        expected = 0
        for file_path in files:
            data = file_path.read_bytes()
            entries = self._entries_from_segment_bytes(data)
            if not entries:
                continue
            first = int(entries[0]["leaf_index"])
            last = int(entries[-1]["leaf_index"])
            if first != expected:
                raise HashLogExportError("hash log archive segments are not contiguous from leaf 0")
            if last >= tree_size:
                raise HashLogExportError(
                    "hash log archive segment extends beyond signed root tree size"
                )
            relative_path = file_path.relative_to(self.archive_dir).as_posix()
            segments.append(
                {
                    "path": relative_path,
                    "first_leaf_index": first,
                    "last_leaf_index": last,
                    "entry_count": len(entries),
                    "segment_hash": segment_hash(data, SEGMENT_HASH_ALGORITHM),
                    "byte_length": len(data),
                }
            )
            expected = last + 1
            if expected == tree_size:
                break
        if expected != tree_size:
            raise HashLogExportError(
                "hash log archive does not contain a complete prefix for signed root"
            )
        return segments

    def _validate_entries(self, entries):
        expected = int(entries[0]["leaf_index"])
        for entry in entries:
            leaf_index = int(entry["leaf_index"])
            if leaf_index != expected:
                raise HashLogExportError("hash log entries are not contiguous")
            entry_hash = str(entry["entry_hash"])
            if len(entry_hash) != 64:
                raise HashLogExportError("hash log entry has invalid hash length")
            bytes.fromhex(entry_hash)
            expected += 1

    def _entries_from_segment_bytes(self, data):
        text = data.decode("utf-8")
        entries = [json.loads(line) for line in text.splitlines() if line.strip()]
        if entries:
            self._validate_entries(entries)
        return entries


def export_once(source, archive, state_path, page_size=DEFAULT_PAGE_SIZE):
    state = load_state(state_path)
    signed_root = source.latest_root()
    log_client.verify_signed_root(signed_root, operator_public_key=archive.operator_public_key)
    tree_size = int(signed_root["tree_size"])
    start = int(state.get("next_leaf_index", 0))
    if start >= tree_size:
        archive.write_manifest(signed_root)
        state["updated_at"] = int(time.time())
        save_state(state_path, state)
        return 0

    end = min(start + int(page_size) - 1, tree_size - 1)
    entries, tree_size = source.entries(start, end, page_size)
    if not entries:
        raise HashLogExportError("operator did not return entries required for signed root archive")

    archive.write_segment(entries)
    next_leaf_index = int(entries[-1]["leaf_index"]) + 1
    if next_leaf_index >= int(signed_root["tree_size"]):
        archive.write_manifest(signed_root)
    state["next_leaf_index"] = next_leaf_index
    state["updated_at"] = int(time.time())
    save_state(state_path, state)
    return len(entries)


def export_loop(
    source, archive, state_path, page_size=DEFAULT_PAGE_SIZE, poll_seconds=DEFAULT_POLL_SECONDS
):
    while True:
        exported = export_once(source, archive, state_path, page_size=page_size)
        print(f"exported {exported} transfer-hash log entrie(s)")
        time.sleep(int(poll_seconds))


def main():
    parser = argparse.ArgumentParser(
        description="Export the full IND transparency hash log for auditors"
    )
    parser.add_argument(
        "--operator-url", default=os.environ.get("IND_LOG_OPERATOR_URL", DEFAULT_OPERATOR_URL)
    )
    parser.add_argument(
        "--archive-dir", default=os.environ.get("IND_HASH_LOG_ARCHIVE_DIR", DEFAULT_ARCHIVE_DIR)
    )
    parser.add_argument(
        "--state-file", default=os.environ.get("IND_HASH_LOG_EXPORT_STATE", DEFAULT_STATE_FILE)
    )
    parser.add_argument(
        "--operator-private-key", default=os.environ.get("IND_LOG_OPERATOR_PRIVATE_KEY", "")
    )
    parser.add_argument(
        "--operator-private-key-file",
        default=os.environ.get("IND_LOG_OPERATOR_PRIVATE_KEY_FILE", DEFAULT_PRIVATE_KEY_PATH),
    )
    parser.add_argument(
        "--operator-public-key", default=os.environ.get("IND_LOG_OPERATOR_PUBLIC_KEY", "")
    )
    parser.add_argument(
        "--operator-public-key-file",
        default=os.environ.get("IND_LOG_OPERATOR_PUBLIC_KEY_FILE", DEFAULT_PUBLIC_KEY_PATH),
    )
    parser.add_argument(
        "--page-size",
        type=int,
        default=int(os.environ.get("IND_HASH_LOG_EXPORT_PAGE_SIZE", DEFAULT_PAGE_SIZE)),
    )
    parser.add_argument(
        "--poll-seconds",
        type=int,
        default=int(os.environ.get("IND_HASH_LOG_EXPORT_POLL_SECONDS", DEFAULT_POLL_SECONDS)),
    )
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()

    operator_private_key = args.operator_private_key or read_key_file(
        args.operator_private_key_file, "private_key"
    )
    operator_public_key = args.operator_public_key or read_key_file(
        args.operator_public_key_file, "public_key"
    )
    if not operator_private_key or not operator_public_key:
        print(
            "ERROR: operator private and public keys are required to sign hash-log archive manifests",
            file=sys.stderr,
        )
        raise SystemExit(2)

    source = OperatorEntrySource(args.operator_url, timeout=args.timeout)
    archive = StaticHashLogArchive(args.archive_dir, operator_private_key, operator_public_key)
    if args.once:
        exported = export_once(source, archive, args.state_file, page_size=args.page_size)
        print(f"exported {exported} transfer-hash log entrie(s)")
        return
    export_loop(
        source, archive, args.state_file, page_size=args.page_size, poll_seconds=args.poll_seconds
    )


if __name__ == "__main__":
    main()
