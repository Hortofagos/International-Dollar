#!/usr/bin/env python3
"""Compare public-testnet bill status across configured seed nodes."""

import argparse
import ipaddress
import json
import os
import socket
import sys
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from tools import testnet_peers
from tools import testnet_report
from ind import sender_node


STALE_STATUSES = {
    "",
    "n",
    "no_response",
    "too_many_refs",
    "malformed_response",
} | sender_node.REQUEST_FAILURE_STATUSES


def _dedupe(items):
    seen = set()
    result = []
    for item in items:
        value = str(item).strip()
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _extract_refs(data):
    refs = []
    if isinstance(data, str):
        return [line.strip() for line in data.replace(",", "\n").splitlines() if line.strip()]
    if isinstance(data, list):
        for item in data:
            refs.extend(_extract_refs(item))
    elif isinstance(data, dict):
        for key in ("ref", "display_id", "token_id", "bill_id"):
            value = data.get(key)
            if isinstance(value, str) and value.strip():
                refs.append(value.strip())
        for value in data.values():
            if isinstance(value, (dict, list)):
                refs.extend(_extract_refs(value))
    return refs


def refs_from_file(path):
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = text
    return _dedupe(_extract_refs(data))


def record_signature(record):
    status = str(record.get("status", ""))
    sequence = None if record.get("sequence") is None else int(record.get("sequence"))
    if status == "conflict":
        return ("", None, status)
    return (
        str(record.get("owner_address", "")),
        sequence,
        status,
    )


def _exception_records(refs, exc):
    return [
        {
            "ref": ref,
            "display_id": ref,
            "owner_address": "",
            "sequence": None,
            "status": "no_response",
            "error": str(exc),
        }
        for ref in refs
    ]


def _records_are_stale(records):
    return bool(records) and any(str(record.get("status", "")) in STALE_STATUSES for record in records)


def _peer_is_ip_literal(peer):
    value = str(peer).strip().strip("[]")
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _resolved_alternate_peers(peer):
    peer = str(peer).strip()
    if not peer or _peer_is_ip_literal(peer):
        return []
    alternates = []
    seen = {peer}
    try:
        records = socket.getaddrinfo(peer, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    except OSError:
        return []
    for record in records:
        sockaddr = record[4]
        if not sockaddr:
            continue
        address = str(sockaddr[0]).strip()
        if not address or address in seen:
            continue
        seen.add(address)
        alternates.append(address)
    return alternates


def _query_peer_status_with_path_fallback(refs, peer, *, status_timeout_seconds=60):
    attempts = []
    try:
        records = testnet_report.query_peer_status(refs, peer=peer, timeout_seconds=status_timeout_seconds)
    except Exception as exc:  # noqa: BLE001 - monitor should convert probe failures to JSON.
        records = _exception_records(refs, exc)
    attempts.append({"peer": peer, "stale": _records_are_stale(records)})
    if not _records_are_stale(records):
        return records, {"queried_peer": peer, "path_status": "ok", "attempts": attempts}

    for alternate in _resolved_alternate_peers(peer):
        try:
            alternate_records = testnet_report.query_peer_status(
                refs,
                peer=alternate,
                timeout_seconds=status_timeout_seconds,
            )
        except Exception as exc:  # noqa: BLE001 - monitor should keep checking alternate paths.
            alternate_records = _exception_records(refs, exc)
        attempts.append({"peer": alternate, "stale": _records_are_stale(alternate_records)})
        if not _records_are_stale(alternate_records):
            return (
                alternate_records,
                {
                    "queried_peer": alternate,
                    "path_status": "alternate_path_ok",
                    "attempts": attempts,
                },
            )
    return records, {"queried_peer": peer, "path_status": "stale", "attempts": attempts}


def build_report(peers, refs, *, finality_buffer_seconds=0, status_timeout_seconds=60, queried_at=None):
    peers = testnet_peers.parse_peer_args(peers)
    refs = _dedupe(refs)
    queried_at = int(time.time() if queried_at is None else queried_at)
    per_peer = []
    mismatches = []
    stale_peers = []
    records_by_ref = {ref: {} for ref in refs}

    for peer in peers:
        records, path = _query_peer_status_with_path_fallback(
            refs,
            peer,
            status_timeout_seconds=status_timeout_seconds,
        )
        per_peer.append({"peer": peer, "queried_peer": path["queried_peer"], "path": path, "records": records})
        if any(str(record.get("status", "")) in STALE_STATUSES for record in records):
            stale_peers.append(peer)
        for record in records:
            records_by_ref.setdefault(record.get("ref") or record.get("display_id"), {})[peer] = record

    for ref, peer_records in records_by_ref.items():
        signatures = {}
        for peer, record in peer_records.items():
            signatures.setdefault(record_signature(record), []).append(peer)
        if len(signatures) > 1:
            mismatches.append(
                {
                    "ref": ref,
                    "records": {peer: peer_records[peer] for peer in sorted(peer_records)},
                }
            )
        missing = [peer for peer in peers if peer not in peer_records]
        if missing:
            mismatches.append({"ref": ref, "missing_peers": missing})

    ok = bool(peers and refs) and not mismatches and not stale_peers
    return {
        "type": "ind.testnet_convergence_status.v1",
        "version": 1,
        "network": "testnet",
        "queried_at": queried_at,
        "finality_buffer_seconds": int(finality_buffer_seconds),
        "status_timeout_seconds": float(status_timeout_seconds),
        "ok": bool(ok),
        "peers": peers,
        "refs": refs,
        "per_peer": per_peer,
        "mismatches": mismatches,
        "stale_peers": sorted(set(stale_peers)),
    }


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Compare IND testnet bill status across seeds")
    parser.add_argument("--peer", action="append", help="seed/node to query; repeatable and comma-separated")
    parser.add_argument("--ref", action="append", dest="refs", help="display ID or bill ID to compare; repeatable")
    parser.add_argument("--ref-file", action="append", default=[], help="JSON/text file containing canary refs")
    parser.add_argument("--canary-ref-file", action="append", default=[], help="alias for --ref-file")
    parser.add_argument("--finality-buffer-seconds", type=int, default=60)
    parser.add_argument(
        "--status-timeout-seconds",
        type=float,
        default=60,
        help="per-route status request timeout; defaults to the 60s settlement window",
    )
    parser.add_argument("--json", action="store_true", help="print JSON output")
    parser.add_argument("--strict", action="store_true", help="return nonzero when convergence is not ok")
    return parser.parse_args(argv)


def main(argv=None):
    os.environ.setdefault("IND_NETWORK", "testnet")
    args = parse_args(argv)
    refs = list(args.refs or [])
    for path in [*args.ref_file, *args.canary_ref_file]:
        refs.extend(refs_from_file(path))
    report = build_report(
        args.peer,
        refs,
        finality_buffer_seconds=args.finality_buffer_seconds,
        status_timeout_seconds=args.status_timeout_seconds,
    )
    print(json.dumps(report, sort_keys=True, indent=2, ensure_ascii=True))
    if args.strict and not report["ok"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
