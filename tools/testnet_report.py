#!/usr/bin/env python3
# Report public-testnet bill status from a remote node without reading wallet keys.

import argparse
import contextlib
import json
import os
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from ind import token as ind_token
from ind import sender_node

DEFAULT_REFS = ("1x1", "1x2", "1x3")
DEFAULT_PEER = "testnet-seed.international-dollar.com"
DEFAULT_STATUS_REQUEST_TIMEOUT_SECONDS = 60
DEFAULT_STATUS_REQUEST_BUDGET_SECONDS = 75


@contextlib.contextmanager
def testnet_network():
    previous = os.environ.get("IND_NETWORK")
    os.environ["IND_NETWORK"] = "testnet"
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop("IND_NETWORK", None)
        else:
            os.environ["IND_NETWORK"] = previous


# Parse the node status endpoint's compact line protocol.
def parse_status_response(raw):
    lines = [line.strip() for line in str(raw or "").splitlines() if line.strip()]
    records = []
    index = 0
    while index < len(lines):
        ref = lines[index]
        if index + 2 < len(lines) and lines[index + 1] == "x" and lines[index + 2] == "invalid":
            records.append(
                {
                    "ref": ref,
                    "display_id": ref,
                    "owner_address": "",
                    "sequence": None,
                    "status": "invalid",
                }
            )
            index += 3
            continue
        if index + 3 >= len(lines):
            records.append(
                {
                    "ref": ref,
                    "display_id": ref,
                    "owner_address": "",
                    "sequence": None,
                    "status": "malformed_response",
                }
            )
            break
        sequence = lines[index + 2]
        try:
            sequence_value = int(sequence)
        except ValueError:
            sequence_value = None
        status = lines[index + 3]
        owner_address = lines[index + 1]
        if status == "conflict":
            owner_address = ""
        records.append(
            {
                "ref": ref,
                "display_id": lines[index],
                "owner_address": owner_address,
                "sequence": sequence_value,
                "status": status,
            }
        )
        index += 4
    return records


# Query one node's public status endpoint for display IDs or bill IDs.
def query_peer_status(
    refs,
    peer=DEFAULT_PEER,
    *,
    timeout_seconds=DEFAULT_STATUS_REQUEST_TIMEOUT_SECONDS,
    max_duration_seconds=DEFAULT_STATUS_REQUEST_BUDGET_SECONDS,
):
    refs = [str(ref).strip() for ref in refs if str(ref).strip()]
    if not refs:
        return []
    timeout_seconds = max(1.0, float(timeout_seconds))
    max_duration_seconds = max(timeout_seconds, float(max_duration_seconds))
    with testnet_network():
        raw = sender_node.connect(
            "c",
            "\n".join(refs),
            [peer],
            timeout=timeout_seconds,
            max_duration_seconds=max_duration_seconds,
        )
    stale_statuses = {"", "n", "too_many_refs"} | sender_node.REQUEST_FAILURE_STATUSES
    if raw in stale_statuses:
        return [
            {
                "ref": ref,
                "display_id": ref,
                "owner_address": "",
                "sequence": None,
                "status": raw or "no_response",
            }
            for ref in refs
        ]
    return parse_status_response(raw)


# Read local testnet store status without touching any wallet files.
def local_status(refs, finalize=True):
    with testnet_network():
        store = ind_token.INDLocalStore()
        if finalize:
            store.finalize_pending()
        records = []
        for ref in refs:
            record = store.status_record_for_ref(ref)
            if record:
                records.append(record)
            else:
                records.append(
                    {
                        "ref": ref,
                        "display_id": ref,
                        "owner_address": "",
                        "sequence": None,
                        "status": "unknown",
                    }
                )
    return records


def parse_args():
    parser = argparse.ArgumentParser(description="Report IND public-testnet bill statuses.")
    parser.add_argument(
        "--peer",
        default=DEFAULT_PEER,
        help="remote node or DNS seed to query for status",
    )
    parser.add_argument(
        "--ref",
        dest="refs",
        action="append",
        help="bill display ID or protocol bill ID to check; repeatable",
    )
    parser.add_argument(
        "--local",
        action="store_true",
        help="read the local testnet store instead of the remote status endpoint",
    )
    parser.add_argument(
        "--no-finalize-local",
        action="store_true",
        help="when using --local, do not finalize pending records first",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print machine-readable JSON instead of a compact table",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=DEFAULT_STATUS_REQUEST_TIMEOUT_SECONDS,
        help="per-route status request timeout; defaults to the 60s testnet settlement window",
    )
    return parser.parse_args()


def main():
    os.environ.setdefault("IND_NETWORK", "testnet")
    args = parse_args()
    refs = args.refs or list(DEFAULT_REFS)
    records = (
        local_status(refs, finalize=not args.no_finalize_local)
        if args.local
        else query_peer_status(refs, peer=args.peer, timeout_seconds=args.timeout_seconds)
    )
    payload = {
        "network": "testnet",
        "source": "local" if args.local else args.peer,
        "records": records,
    }
    if args.json:
        print(json.dumps(payload, sort_keys=True, indent=2))
        return
    print(f"IND testnet status from {payload['source']}")
    print("ref\tstatus\tsequence\towner")
    for record in records:
        sequence = "" if record["sequence"] is None else str(record["sequence"])
        print(
            "\t".join(
                [
                    record["display_id"],
                    record["status"],
                    sequence,
                    record["owner_address"],
                ]
            )
        )


if __name__ == "__main__":
    main()
