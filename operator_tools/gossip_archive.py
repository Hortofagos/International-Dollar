#!/usr/bin/env python3
"""Export, audit, and replay full public IND gossip messages."""

import argparse
import json
import os
import sys
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from ind import settings as ind_settings
from ind import token as ind_token
from tools import testnet_peers


GOSSIP_ARCHIVE_MANIFEST_TYPE = "ind.public_gossip_archive_manifest.v1"
GOSSIP_ARCHIVE_SIGNATURE_DOMAIN = "IND_PUBLIC_GOSSIP_ARCHIVE_MANIFEST_V1"
SEGMENT_HASH_ALGORITHM = "sha3_256"
SIGNATURE_ALGORITHM = "ECDSA_SECP256K1_SHA3_256_BASE85"
DEFAULT_ARCHIVE_DIR = "operator_tools/gossip-archive"
DEFAULT_SEGMENT_SIZE = 1000


class GossipArchiveError(RuntimeError):
    """Raised when gossip archive export or audit fails."""


def canonical_json(data):
    return ind_token.canonical_json(data)


def canonical_bytes(data):
    return canonical_json(data).encode("utf-8")


def atomic_write_text(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8", newline="\n")
    tmp.replace(path)


def read_key_file(path, field):
    path = Path(path)
    if not path.exists():
        return ""
    text = path.read_text(encoding="utf-8").strip()
    if path.suffix.lower() == ".json":
        try:
            return str(json.loads(text).get(field, "")).strip()
        except json.JSONDecodeError:
            return ""
    return text


def segment_hash(data):
    return ind_token.sha3_hex(data)


def manifest_signature_payload(manifest):
    unsigned = dict(manifest)
    unsigned.pop("signature", None)
    return unsigned


def sign_manifest(manifest, private_key):
    if not private_key:
        raise GossipArchiveError("archive signing private key is required")
    signed = dict(manifest)
    signed["signature"] = ind_token.b85_sign_domain(
        private_key,
        GOSSIP_ARCHIVE_SIGNATURE_DOMAIN,
        manifest_signature_payload(signed),
    )
    return signed


def verify_manifest_signature(manifest, expected_public_key=None):
    required = {
        "type",
        "version",
        "archive_id",
        "network",
        "message_count",
        "first_message_index",
        "last_message_index",
        "segment_hash_algorithm",
        "signature_algorithm",
        "signing_public_key",
        "segments",
        "manifest_timestamp",
        "signature",
    }
    if not isinstance(manifest, dict) or not required.issubset(manifest):
        raise GossipArchiveError("malformed gossip archive manifest")
    if manifest["type"] != GOSSIP_ARCHIVE_MANIFEST_TYPE or int(manifest["version"]) != 1:
        raise GossipArchiveError("unsupported gossip archive manifest version")
    if manifest["segment_hash_algorithm"] != SEGMENT_HASH_ALGORITHM:
        raise GossipArchiveError("unsupported gossip archive segment hash algorithm")
    if manifest["signature_algorithm"] != SIGNATURE_ALGORITHM:
        raise GossipArchiveError("unsupported gossip archive signature algorithm")
    public_key = str(manifest["signing_public_key"]).strip()
    if expected_public_key and public_key != str(expected_public_key).strip():
        raise GossipArchiveError("gossip archive was signed by an unexpected key")
    if not ind_token.b85_verify_domain(
        public_key,
        manifest["signature"],
        GOSSIP_ARCHIVE_SIGNATURE_DOMAIN,
        manifest_signature_payload(manifest),
    ):
        raise GossipArchiveError("invalid gossip archive manifest signature")
    return True


def archive_id_for(network, message_count, segments):
    return ind_token.sha3_hex(
        canonical_bytes(
            {
                "network": network,
                "message_count": int(message_count),
                "segments": segments,
                "segment_hash_algorithm": SEGMENT_HASH_ALGORITHM,
            }
        )
    )


def _message_bill(message):
    if message.get("type") in {ind_token.TRANSFER_ANNOUNCEMENT_V2_TYPE, ind_token.RECEIPT_ANNOUNCEMENT_V2_TYPE}:
        return message.get("bill")
    if message.get("type") in {ind_token.TRANSFER_ANNOUNCEMENT_TYPE, ind_token.RECEIPT_ANNOUNCEMENT_TYPE}:
        return message.get("token")
    return None


def _expanded_store_messages(store, conn):
    rows = conn.execute(
        """
        SELECT message_hash, message_type, message_json, first_seen
        FROM messages
        ORDER BY first_seen ASC, message_hash ASC
        """
    ).fetchall()
    for row in rows:
        message = store._expand_stored_message(conn, row["message_json"])
        if not message:
            continue
        yield {
            "message_hash": row["message_hash"],
            "message_type": row["message_type"],
            "first_seen": int(row["first_seen"]),
            "message": message,
        }


def _conflict_messages(conn):
    rows = conn.execute(
        """
        SELECT proof_hash, proof_json, detected_at
        FROM conflicts
        ORDER BY detected_at ASC, proof_hash ASC
        """
    ).fetchall()
    for row in rows:
        message = json.loads(row["proof_json"])
        yield {
            "message_hash": row["proof_hash"],
            "message_type": ind_token.CONFLICT_PROOF_TYPE,
            "first_seen": int(row["detected_at"]),
            "message": message,
        }


def iter_public_messages(db_path=None, network=None):
    store = ind_token.INDLocalStore(db_path=db_path)
    network = network or ind_settings.network_name()
    seen = set()
    with store._connect() as conn:
        raw_entries = list(_expanded_store_messages(store, conn)) + list(_conflict_messages(conn))
    raw_entries.sort(key=lambda item: (int(item["first_seen"]), str(item["message_hash"])))
    message_index = 0
    for item in raw_entries:
        message_hash = str(item["message_hash"])
        if message_hash in seen:
            continue
        seen.add(message_hash)
        yield {
            "message_index": message_index,
            "message_hash": message_hash,
            "message_type": str(item["message_type"]),
            "first_seen": int(item["first_seen"]),
            "network": str(network),
            "message": item["message"],
        }
        message_index += 1


def write_segments(entries, archive_dir, segment_size):
    archive_dir = Path(archive_dir)
    messages_dir = archive_dir / "messages"
    messages_dir.mkdir(parents=True, exist_ok=True)
    for old_file in messages_dir.glob("messages_*.jsonl"):
        old_file.unlink()
    segments = []
    entries = list(entries)
    for offset in range(0, len(entries), int(segment_size)):
        chunk = entries[offset : offset + int(segment_size)]
        if not chunk:
            continue
        first = int(chunk[0]["message_index"])
        last = int(chunk[-1]["message_index"])
        relative_path = f"messages/messages_{first:012d}_{last:012d}.jsonl"
        text = "".join(canonical_json(entry) + "\n" for entry in chunk)
        data = text.encode("utf-8")
        atomic_write_text(archive_dir / relative_path, text)
        segments.append(
            {
                "path": relative_path,
                "first_message_index": first,
                "last_message_index": last,
                "message_count": len(chunk),
                "first_seen": int(chunk[0]["first_seen"]),
                "last_seen": int(chunk[-1]["first_seen"]),
                "segment_hash": segment_hash(data),
                "byte_length": len(data),
            }
        )
    return segments


def export_archive(
    archive_dir,
    *,
    db_path=None,
    network=None,
    private_key=None,
    public_key=None,
    segment_size=DEFAULT_SEGMENT_SIZE,
    manifest_timestamp=None,
):
    network = network or ind_settings.network_name()
    entries = list(iter_public_messages(db_path=db_path, network=network))
    segments = write_segments(entries, archive_dir, segment_size)
    message_count = len(entries)
    manifest = {
        "type": GOSSIP_ARCHIVE_MANIFEST_TYPE,
        "version": 1,
        "archive_id": "",
        "network": network,
        "message_count": message_count,
        "first_message_index": 0 if entries else None,
        "last_message_index": int(entries[-1]["message_index"]) if entries else None,
        "segment_hash_algorithm": SEGMENT_HASH_ALGORITHM,
        "signature_algorithm": SIGNATURE_ALGORITHM,
        "signing_public_key": str(public_key or "").strip(),
        "segments": segments,
        "manifest_timestamp": int(manifest_timestamp or time.time()),
    }
    manifest["archive_id"] = archive_id_for(network, message_count, segments)
    manifest = sign_manifest(manifest, private_key)
    verify_manifest_signature(manifest, expected_public_key=public_key)
    atomic_write_text(Path(archive_dir) / "manifest.json", canonical_json(manifest) + "\n")
    return manifest


def _segment_entries_from_bytes(data):
    entries = []
    for raw_line in data.decode("utf-8").splitlines():
        line = raw_line.strip()
        if line:
            entries.append(json.loads(line))
    return entries


def audit_archive(archive_dir, *, manifest_path=None, expected_public_key=None):
    archive_dir = Path(archive_dir)
    manifest_path = Path(manifest_path) if manifest_path else archive_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    verify_manifest_signature(manifest, expected_public_key=expected_public_key)
    expected = 0
    total = 0
    for segment in manifest["segments"]:
        path = archive_dir / segment["path"]
        data = path.read_bytes()
        if len(data) != int(segment["byte_length"]):
            raise GossipArchiveError(f"segment byte length mismatch: {segment['path']}")
        if segment_hash(data) != segment["segment_hash"]:
            raise GossipArchiveError(f"segment hash mismatch: {segment['path']}")
        entries = _segment_entries_from_bytes(data)
        if len(entries) != int(segment["message_count"]):
            raise GossipArchiveError(f"segment message count mismatch: {segment['path']}")
        if entries:
            first = int(entries[0]["message_index"])
            last = int(entries[-1]["message_index"])
            if first != expected:
                raise GossipArchiveError("gossip archive segments are not contiguous")
            if first != int(segment["first_message_index"]) or last != int(segment["last_message_index"]):
                raise GossipArchiveError(f"segment index range mismatch: {segment['path']}")
            expected = last + 1
            total += len(entries)
    if total != int(manifest["message_count"]):
        raise GossipArchiveError("gossip archive manifest message_count does not match segments")
    expected_archive_id = archive_id_for(manifest["network"], manifest["message_count"], manifest["segments"])
    if manifest["archive_id"] != expected_archive_id:
        raise GossipArchiveError("gossip archive_id does not match segments")
    return {"ok": True, "message_count": total, "segment_count": len(manifest["segments"]), "archive_id": manifest["archive_id"]}


def _entry_refs(entry):
    refs = set()
    message = entry.get("message", {})
    bill = _message_bill(message)
    if isinstance(bill, dict):
        try:
            state = ind_token.verify_token(bill)
            refs.update({state.display_id, state.token_id})
        except Exception:
            refs.add(str(bill.get("token_id", "")))
    if message.get("type") == ind_token.CONFLICT_PROOF_TYPE:
        refs.add(str(message.get("token_id", "")))
    return {item for item in refs if item}


def replay_archive(
    archive_dir,
    peers,
    *,
    start_index=None,
    end_index=None,
    refs=None,
    manifest_path=None,
    expected_public_key=None,
):
    audit_archive(archive_dir, manifest_path=manifest_path, expected_public_key=expected_public_key)
    archive_dir = Path(archive_dir)
    manifest = json.loads((Path(manifest_path) if manifest_path else archive_dir / "manifest.json").read_text(encoding="utf-8"))
    refs = {str(ref).strip() for ref in refs or [] if str(ref).strip()}
    results = []
    for segment in manifest["segments"]:
        entries = _segment_entries_from_bytes((archive_dir / segment["path"]).read_bytes())
        for entry in entries:
            index = int(entry["message_index"])
            if start_index is not None and index < int(start_index):
                continue
            if end_index is not None and index > int(end_index):
                continue
            if refs and not (_entry_refs(entry) & refs):
                continue
            peer_results = testnet_peers.broadcast_message_to_peers(entry["message"], peers)
            results.append({"message_index": index, "message_hash": entry["message_hash"], "peers": peer_results})
    return {"ok": True, "replayed_count": len(results), "results": results}


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Export, audit, and replay public IND gossip archives")
    sub = parser.add_subparsers(dest="command", required=True)

    export = sub.add_parser("export")
    export.add_argument("--db-path", default=None)
    export.add_argument("--archive-dir", default=DEFAULT_ARCHIVE_DIR)
    export.add_argument("--network", default="")
    export.add_argument("--segment-size", type=int, default=DEFAULT_SEGMENT_SIZE)
    export.add_argument("--signing-private-key-file", required=True)
    export.add_argument("--signing-public-key-file", required=True)

    audit = sub.add_parser("audit")
    audit.add_argument("--archive-dir", default=DEFAULT_ARCHIVE_DIR)
    audit.add_argument("--manifest-path", default="")
    audit.add_argument("--expected-public-key-file", default="")

    replay = sub.add_parser("replay")
    replay.add_argument("--archive-dir", default=DEFAULT_ARCHIVE_DIR)
    replay.add_argument("--manifest-path", default="")
    replay.add_argument("--expected-public-key-file", default="")
    replay.add_argument("--peer", action="append", help="seed/node to replay to; repeatable and comma-separated")
    replay.add_argument("--start-index", type=int)
    replay.add_argument("--end-index", type=int)
    replay.add_argument("--ref", action="append", default=[])
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    try:
        if args.command == "export":
            manifest = export_archive(
                args.archive_dir,
                db_path=args.db_path,
                network=args.network or None,
                private_key=read_key_file(args.signing_private_key_file, "private_key"),
                public_key=read_key_file(args.signing_public_key_file, "public_key"),
                segment_size=args.segment_size,
            )
            print(canonical_json({"ok": True, "manifest": manifest}))
            return 0
        if args.command == "audit":
            expected = read_key_file(args.expected_public_key_file, "public_key") if args.expected_public_key_file else None
            print(canonical_json(audit_archive(args.archive_dir, manifest_path=args.manifest_path or None, expected_public_key=expected)))
            return 0
        if args.command == "replay":
            expected = read_key_file(args.expected_public_key_file, "public_key") if args.expected_public_key_file else None
            print(
                canonical_json(
                    replay_archive(
                        args.archive_dir,
                        testnet_peers.parse_peer_args(args.peer),
                        start_index=args.start_index,
                        end_index=args.end_index,
                        refs=args.ref,
                        manifest_path=args.manifest_path or None,
                        expected_public_key=expected,
                    )
                )
            )
            return 0
    except Exception as exc:  # noqa: BLE001 - archive CLI should return machine-readable failure.
        print(canonical_json({"ok": False, "error": str(exc)}), file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
