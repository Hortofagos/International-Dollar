#!/usr/bin/env python3
"""Run bounded adversarial gossip probes against public-testnet seed nodes."""

import argparse
import copy
import json
import os
import sys
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import ind_token
from ind import sender_node
from tools import testnet_peers
from tools import testnet_report


DEFAULT_VALID_MESSAGE = ROOT_DIR / "files" / "testnet" / "local_clean_receipt_1x2.local.json"
DEFAULT_REFS = ("1x0", "1x1", "1x2")
STALE_STATUSES = {
    "",
    "n",
    "no_response",
    "too_many_refs",
    "malformed_response",
} | sender_node.REQUEST_FAILURE_STATUSES


def read_valid_message(path):
    """Read and validate one known-good gossip message for replay/idempotence tests."""

    text = Path(path).read_text(encoding="utf-8")
    return ind_token.unpack_wire_message(text)


def _mutate_first_signature(value):
    if isinstance(value, dict):
        for key in sorted(value):
            if key == "signature" and isinstance(value[key], str) and value[key]:
                value[key] = value[key][:-1] + ("0" if value[key][-1] != "0" else "1")
                return True
            if _mutate_first_signature(value[key]):
                return True
    if isinstance(value, list):
        for item in value:
            if _mutate_first_signature(item):
                return True
    return False


def invalid_probe_payloads(valid_message=None, *, nonce=None):
    """Build invalid payloads that exercise decode, strict JSON, schema, and signature paths."""

    nonce = int(time.time() if nonce is None else nonce)
    probes = [
        {
            "name": "duplicate_json_key",
            "raw": '{"type":"ind.transfer_announcement.v1","type":"shadow"}',
        },
        {
            "name": "floating_point_json",
            "raw": '{"type":"ind.transfer_announcement.v1","version":1.25}',
        },
    ]
    if valid_message is not None:
        extra_field = copy.deepcopy(valid_message)
        extra_field["probe_nonce"] = nonce
        probes.append(
            {
                "name": "fresh_unknown_field",
                "raw": ind_token.pack_wire_message(extra_field),
            }
        )
        bad_signature = copy.deepcopy(valid_message)
        if _mutate_first_signature(bad_signature):
            probes.append(
                {
                    "name": "fresh_bad_signature",
                    "raw": ind_token.pack_wire_message(bad_signature),
                }
            )
    return probes


def _send_gossip(peer, raw):
    started = time.time()
    response = sender_node.connect("b", raw, [peer])
    return {
        "peer": peer,
        "response": response,
        "elapsed_seconds": round(time.time() - started, 3),
    }


def build_report(peers, refs, *, valid_message_path=DEFAULT_VALID_MESSAGE, valid_replays=6, nonce=None):
    """Run the adversarial probe and return a machine-readable report."""

    peers = testnet_peers.parse_peer_args(peers)
    refs = [str(ref).strip() for ref in refs if str(ref).strip()]
    with testnet_report.testnet_network():
        valid_message = None
        valid_raw = ""
        valid_error = ""
        try:
            valid_message = read_valid_message(valid_message_path)
            valid_raw = ind_token.pack_wire_message(valid_message)
        except Exception as exc:  # noqa: BLE001 - surfaced in JSON for operators.
            valid_error = str(exc)

        invalid_probes = invalid_probe_payloads(valid_message, nonce=nonce)
        peer_reports = []
        for peer in peers:
            invalid_results = []
            for probe in invalid_probes:
                sent = _send_gossip(peer, probe["raw"])
                sent["name"] = probe["name"]
                sent["ok"] = sent["response"] == "invalid"
                invalid_results.append(sent)

            replay_results = []
            if valid_raw and int(valid_replays) > 0:
                for attempt in range(int(valid_replays)):
                    sent = _send_gossip(peer, valid_raw)
                    sent["attempt"] = attempt + 1
                    sent["ok"] = sent["response"] == "ok"
                    replay_results.append(sent)

            status_records = testnet_report.query_peer_status(refs, peer=peer) if refs else []
            status_ok = all(str(record.get("status", "")) not in STALE_STATUSES for record in status_records)
            peer_ok = (
                bool(invalid_results)
                and all(item["ok"] for item in invalid_results)
                and (not valid_raw or all(item["ok"] for item in replay_results))
                and status_ok
            )
            peer_reports.append(
                {
                    "peer": peer,
                    "ok": bool(peer_ok),
                    "invalid_probes": invalid_results,
                    "valid_replays": replay_results,
                    "statuses": status_records,
                }
            )

    ok = bool(peers) and all(item["ok"] for item in peer_reports) and not valid_error
    return {
        "type": "ind.testnet_adversarial_probe.v1",
        "version": 1,
        "network": "testnet",
        "ok": bool(ok),
        "valid_message_path": str(valid_message_path),
        "valid_message_error": valid_error,
        "invalid_probe_count_per_peer": len(invalid_probe_payloads(valid_message, nonce=nonce)),
        "valid_replay_count_per_peer": int(valid_replays) if valid_raw else 0,
        "peers": peers,
        "refs": refs,
        "peer_reports": peer_reports,
    }


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Run bounded IND public-testnet adversarial probes.")
    parser.add_argument("--peer", action="append", help="seed/node to probe; repeatable and comma-separated")
    parser.add_argument("--ref", action="append", dest="refs", help="display ID or bill ID to check afterward")
    parser.add_argument("--valid-message", default=str(DEFAULT_VALID_MESSAGE), help="known-good gossip JSON to replay")
    parser.add_argument("--valid-replays", type=int, default=6, help="valid replay attempts per peer")
    parser.add_argument("--json", action="store_true", help="print machine-readable JSON")
    parser.add_argument("--strict", action="store_true", help="return nonzero when the probe is not ok")
    return parser.parse_args(argv)


def main(argv=None):
    os.environ.setdefault("IND_NETWORK", "testnet")
    args = parse_args(argv)
    report = build_report(
        args.peer,
        args.refs or list(DEFAULT_REFS),
        valid_message_path=args.valid_message,
        valid_replays=args.valid_replays,
    )
    if args.json:
        print(json.dumps(report, sort_keys=True, indent=2, ensure_ascii=True))
    else:
        print(f"IND testnet adversarial probe: {'ok' if report['ok'] else 'not ok'}")
        for peer_report in report["peer_reports"]:
            print(f"{peer_report['peer']}\t{'ok' if peer_report['ok'] else 'not ok'}")
    if args.strict and not report["ok"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
