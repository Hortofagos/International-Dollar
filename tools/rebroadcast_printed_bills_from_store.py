"""Rebroadcast locally verified printed-bill transfers and confirm remote status.

This is an operational recovery helper for the case where transfer announcement
files were handed to a peer socket but the remote node did not persist them.
It rebuilds announcements from local sequence-2 BillV3 rows and only counts a
bill complete after a status query reports the expected owner at sequence >= 2.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

os.environ.setdefault("IND_NETWORK", "mainnet")
os.environ.setdefault("IND_NODE_PORT", "8888")

from ind import protocol as ind_token  # noqa: E402
from ind import protocol_v3, sender_node, wallet_services  # noqa: E402


def emit(event: str, **data) -> None:
    payload = {"event": event, "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
    payload.update(data)
    print(json.dumps(payload, sort_keys=True), flush=True)


def load_local_sequence2(db_path: Path, prefix: str, first: int, last: int):
    con = sqlite3.connect(str(db_path))
    try:
        rows = con.execute(
            """
            SELECT display_id, bill_blob, proof_bundle_hash, owner_address
            FROM bills_v3
            WHERE display_id LIKE ?
              AND CAST(substr(display_id, ?) AS INTEGER) BETWEEN ? AND ?
              AND sequence = 2
            ORDER BY CAST(substr(display_id, ?) AS INTEGER)
            """,
            (prefix + "%", len(prefix) + 1, first, last, len(prefix) + 1),
        ).fetchall()
    finally:
        con.close()
    return {
        row[0]: {
            "bill_blob": row[1],
            "proof_bundle_hash": row[2],
            "owner_address": row[3],
        }
        for row in rows
    }


def status_records(display_id: str, peers: list[str]):
    result = sender_node.connect_result("c", display_id, peers, max_duration_seconds=20)
    return result, sender_node._parse_status_response(result.response)


def is_confirmed(display_id: str, expected_owner: str, peers: list[str]) -> bool:
    _result, records = status_records(display_id, peers)
    return any(
        record.get("display_id") == display_id
        and record.get("owner_address") == expected_owner
        and int(record.get("sequence") or 0) >= 2
        for record in records
    )


def make_announcement(store, display_id: str, item: dict) -> bytes:
    bill = protocol_v3.decode_bill(item["bill_blob"])
    proof_hash = item["proof_bundle_hash"] or bill.get("proof_bundle_ref", {}).get(
        "proof_bundle_hash"
    )
    proof_bundle = store.get_proof_bundle_v3(proof_hash)
    archive_segments = wallet_services._archive_segments_for_proof_bundle(store, proof_bundle)
    announcement = protocol_v3.create_transfer_announcement(
        bill,
        proof_bundle=proof_bundle,
        archive_segments=archive_segments,
    )
    protocol_v3.verify_transfer_announcement(
        announcement,
        proof_bundle_resolver=store.proof_bundle_resolver_v3,
        transparency_verifier=getattr(store, "transparency_verifier", None),
        archive_segment_resolver=store.archive_segment_resolver_v3,
    )
    return ind_token.pack_wire_message(announcement)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--first", type=int, required=True)
    parser.add_argument("--last", type=int, required=True)
    parser.add_argument("--prefix", default="100000x")
    parser.add_argument("--db", default="ind_gossip.db")
    parser.add_argument(
        "--peer",
        action="append",
        dest="peers",
        default=[],
        help="Mainnet peer to use; may be repeated.",
    )
    parser.add_argument("--max-broadcast-attempts", type=int, default=5)
    parser.add_argument("--poll-attempts", type=int, default=10)
    parser.add_argument("--poll-delay-seconds", type=float, default=2.0)
    parser.add_argument("--retry-delay-seconds", type=float, default=5.0)
    parser.add_argument("--batch-size", type=int, default=1)
    return parser.parse_args()


def run_batch_mode(args, peers, store, items, expected_total: int) -> int:
    confirmed_ids: set[str] = set()
    skipped = 0
    rebroadcasted = 0
    failed: list[str] = []
    numbers = list(range(args.first, args.last + 1))
    batch_size = max(1, int(args.batch_size))

    for batch_start in range(0, len(numbers), batch_size):
        batch_numbers = numbers[batch_start : batch_start + batch_size]
        batch_ids = [args.prefix + str(number) for number in batch_numbers]
        pending = []

        for display_id in batch_ids:
            item = items[display_id]
            expected_owner = item["owner_address"]
            if is_confirmed(display_id, expected_owner, peers):
                confirmed_ids.add(display_id)
                skipped += 1
            else:
                pending.append(display_id)

        for attempt in range(1, max(1, args.max_broadcast_attempts) + 1):
            if not pending:
                break
            for display_id in list(pending):
                raw = make_announcement(store, display_id, items[display_id])
                result = sender_node._broadcast_gossip_to_peer_quorum(
                    raw,
                    peers,
                    min_peer_acks=1,
                    fanout=1,
                    timeout=12,
                    bill_budget_seconds=25,
                )
                if result.status == sender_node.REQUEST_OK:
                    rebroadcasted += 1

            poll_pending = set(pending)
            for _poll in range(1, max(1, args.poll_attempts) + 1):
                newly_confirmed = []
                for display_id in list(poll_pending):
                    expected_owner = items[display_id]["owner_address"]
                    if is_confirmed(display_id, expected_owner, peers):
                        newly_confirmed.append(display_id)
                for display_id in newly_confirmed:
                    confirmed_ids.add(display_id)
                    poll_pending.discard(display_id)
                if not poll_pending:
                    break
                time.sleep(max(0.1, args.poll_delay_seconds))

            pending = [display_id for display_id in pending if display_id not in confirmed_ids]
            if pending and attempt < max(1, args.max_broadcast_attempts):
                time.sleep(max(0.1, args.retry_delay_seconds))

        for display_id in pending:
            if display_id not in failed:
                failed.append(display_id)
                emit("bill_failed", current=display_id, batch_start=batch_ids[0])

        emit(
            "progress",
            batch_start=batch_ids[0],
            batch_end=batch_ids[-1],
            confirmed=len(confirmed_ids),
            skipped=skipped,
            rebroadcasted=rebroadcasted,
            failed=len(failed),
        )

    emit(
        "complete",
        confirmed=len(confirmed_ids),
        skipped=skipped,
        rebroadcasted=rebroadcasted,
        failed=len(failed),
        failed_sample=failed[:20],
    )
    return 0 if len(confirmed_ids) == expected_total and not failed else 1


def main() -> int:
    args = parse_args()
    peers = args.peers or [
        "2a01:4f8:c015:da76::1",
        "167.233.115.216",
        "seed.international-dollar.com",
    ]
    db_path = Path(args.db)
    store = sender_node.wallet_sync_store()
    items = load_local_sequence2(db_path, args.prefix, args.first, args.last)
    expected_total = args.last - args.first + 1
    emit("start", local_sequence2=len(items), expected_total=expected_total, peers=peers)
    if len(items) != expected_total:
        missing = [
            args.prefix + str(number)
            for number in range(args.first, args.last + 1)
            if args.prefix + str(number) not in items
        ]
        emit("missing_local_sequence2", count=len(missing), sample=missing[:10])
        return 2

    if int(args.batch_size) > 1:
        return run_batch_mode(args, peers, store, items, expected_total)

    confirmed = 0
    skipped = 0
    rebroadcasted = 0
    failed: list[str] = []

    for index, number in enumerate(range(args.first, args.last + 1), start=1):
        display_id = args.prefix + str(number)
        item = items[display_id]
        expected_owner = item["owner_address"]

        if is_confirmed(display_id, expected_owner, peers):
            confirmed += 1
            skipped += 1
            if confirmed % 10 == 0 or confirmed == expected_total:
                emit(
                    "progress",
                    index=index,
                    confirmed=confirmed,
                    skipped=skipped,
                    rebroadcasted=rebroadcasted,
                    failed=len(failed),
                    current=display_id,
                    action="skip_confirmed",
                )
            continue

        raw = make_announcement(store, display_id, item)
        bill_done = False
        last_status = ""
        last_route = ""
        for _attempt in range(1, max(1, args.max_broadcast_attempts) + 1):
            result = sender_node._broadcast_gossip_to_peer_quorum(
                raw,
                peers,
                min_peer_acks=1,
                fanout=1,
                timeout=12,
                bill_budget_seconds=25,
            )
            last_status = result.status
            last_route = result.route or ""
            if result.status == sender_node.REQUEST_OK:
                rebroadcasted += 1
            for _poll in range(1, max(1, args.poll_attempts) + 1):
                time.sleep(max(0.1, args.poll_delay_seconds))
                if is_confirmed(display_id, expected_owner, peers):
                    confirmed += 1
                    bill_done = True
                    break
            if bill_done:
                break
            time.sleep(max(0.1, args.retry_delay_seconds))

        if not bill_done:
            failed.append(display_id)
            emit(
                "bill_failed",
                index=index,
                current=display_id,
                last_status=last_status,
                last_route=last_route,
            )
        if confirmed % 10 == 0 or failed or index == expected_total:
            emit(
                "progress",
                index=index,
                confirmed=confirmed,
                skipped=skipped,
                rebroadcasted=rebroadcasted,
                failed=len(failed),
                current=display_id,
            )

    emit(
        "complete",
        confirmed=confirmed,
        skipped=skipped,
        rebroadcasted=rebroadcasted,
        failed=len(failed),
        failed_sample=failed[:20],
    )
    return 0 if confirmed == expected_total and not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
