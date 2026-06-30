#!/usr/bin/env python3
"""Exercise native V3 wallet transfers across the public testnet seeds."""

import argparse
import json
import os
import shutil
import sys
import tempfile
import time
import traceback
from hashlib import sha3_256
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

os.environ["IND_NETWORK"] = "testnet"
os.environ["IND_NODE_PORT"] = "18888"
os.environ.setdefault("IND_REQUIRE_TRANSPARENCY_LOG", "0")
os.environ.setdefault("IND_SUBMIT_TO_TRANSPARENCY_LOG", "0")

from ind import archive_segment_v3
from ind import keys_v3
from ind import proof_bundle_v3
from ind import protocol_v3
from ind import runtime as runtime_json
from ind import sender_node
from ind import spend_map_v3
from ind import token as ind_token
from ind import transparency_server as log_server
from ind import wallet_services
from ind.store import INDLocalStore
from tools import testnet_peers, testnet_report


DEFAULT_PEERS = testnet_peers.parse_peer_args(None)
ACCEPTED_FINAL_STATUSES = {"settled", "verified"}
TRANSFER_BROADCAST_TIMEOUT_SECONDS = 60.0


def _now():
    return int(time.time())


def _sha3_text(text):
    return sha3_256(str(text).encode("ascii")).hexdigest()


def _operator_keypair(label):
    seed = sha3_256(f"v3-public-e2e:{label}".encode("ascii")).digest()
    _address, private_key, public_key = keys_v3.generate_keypair(seed)
    return private_key, public_key


def _wallet_lines(wallet):
    address, private_key, public_key = wallet
    return [address, private_key, public_key]


def _wallet_report(wallet):
    return {"address": wallet[0]}


def _safe_path(path):
    return str(Path(path))


def _message_hash(message):
    return ind_token.message_hash(message)


def _latest_bill_row(store, token_id):
    with store._connect() as conn:
        row = conn.execute(
            """
            SELECT bill_hash, token_id, display_id, owner_address, sequence,
                   checkpoint_hash, proof_bundle_hash, first_seen, updated_at, status
            FROM bills_v3
            WHERE token_id = ?
            ORDER BY sequence DESC, LENGTH(bill_blob) ASC, updated_at DESC
            LIMIT 1
            """,
            (str(token_id),),
        ).fetchone()
    if not row:
        return None
    result = dict(row)
    result["sequence"] = int(result["sequence"])
    result["first_seen"] = int(result["first_seen"])
    result["updated_at"] = int(result["updated_at"])
    return result


def _status_snapshot(store, token_id, display_id, expected_owner=None):
    row = _latest_bill_row(store, token_id)
    status_record = store.status_record_for_ref(display_id) or {}
    confidence = {}
    if row:
        confidence = store.bill_v3_confidence(
            token_id,
            expected_owner=expected_owner or row["owner_address"],
            min_settled_seconds=0,
        )
    return {
        "row": row,
        "status_record": status_record,
        "confidence": confidence,
    }


def _verify_bill_snapshot(store, bill, proof_bundle, trusted_operator_public_key):
    state = protocol_v3.verify_bill(
        bill,
        proof_bundle=proof_bundle,
        proof_bundle_resolver=store.proof_bundle_resolver_v3,
        trusted_operator_public_key=trusted_operator_public_key,
        archive_segment_resolver=store.archive_segment_resolver_v3,
    )
    parsed = protocol_v3.parse_display_id(state.display_id)
    source = proof_bundle.get("source_evidence") if isinstance(proof_bundle, dict) else {}
    segment_hash = str(source.get("archive_segment_hash") or "")
    return {
        "verified": True,
        "display_id": state.display_id,
        "display_value": int(parsed["value"]),
        "display_serial": int(parsed["serial"]),
        "token_id": state.token_id,
        "owner_address": state.owner_address,
        "sequence": int(state.sequence),
        "proof_bundle_hash": bill["proof_bundle_ref"]["proof_bundle_hash"],
        "proof_bundle_resolves": store.get_proof_bundle_v3(
            bill["proof_bundle_ref"]["proof_bundle_hash"]
        )
        is not None,
        "archive_segment_hash": segment_hash,
        "archive_segment_resolves": bool(segment_hash and store.get_archive_segment_v3(segment_hash)),
    }


def _broadcast_message(
    message,
    peers,
    label,
    *,
    timeout=12.0,
    delay_seconds=0.25,
    retry_limit=4,
):
    raw = ind_token.pack_wire_message(message)
    message_hash = _message_hash(message)
    results = []
    for peer in peers:
        started = time.time()
        attempts = []
        retry_count = max(1, int(retry_limit))
        for attempt_index in range(retry_count):
            result = sender_node.connect_result(
                "b",
                raw,
                [peer],
                timeout=timeout,
                max_duration_seconds=max(timeout + 4.0, 6.0),
            )
            attempts.extend(result.attempts)
            if result.status == sender_node.REQUEST_OK:
                break
            retry_after = max(
                [float(result.retry_after_seconds or 0.0)]
                + [float(item.get("retry_after_seconds") or 0.0) for item in result.attempts]
            )
            if (
                result.status != sender_node.REQUEST_RATE_LIMITED
                or attempt_index >= retry_count - 1
            ):
                break
            time.sleep(max(1.0, retry_after + 0.5, float(delay_seconds or 0.0)))
        results.append(
            {
                "peer": peer,
                "route": result.route,
                "status": result.status,
                "response": result.response,
                "ok": result.status == sender_node.REQUEST_OK,
                "elapsed_seconds": round(time.time() - started, 3),
                "attempts": attempts,
                "retry_attempts": attempt_index + 1,
                "error": result.error,
            }
        )
        if delay_seconds:
            time.sleep(float(delay_seconds))
    return {
        "label": label,
        "message_type": message.get("type", ""),
        "message_hash": message_hash,
        "peer_results": results,
        "all_ok": all(item["ok"] for item in results),
    }


def _query_public_status(peers, refs, *, timeout_seconds=20):
    status = {}
    for peer in peers:
        try:
            status[peer] = testnet_report.query_peer_status(
                refs,
                peer=peer,
                timeout_seconds=timeout_seconds,
                max_duration_seconds=max(timeout_seconds + 5, 10),
            )
        except Exception as exc:  # noqa: BLE001 - report probe errors as data.
            status[peer] = [
                {
                    "ref": ref,
                    "display_id": ref,
                    "owner_address": "",
                    "sequence": None,
                    "status": "probe_error",
                    "error": str(exc),
                }
                for ref in refs
            ]
    return status


def _decode_message_bill(message):
    if message.get("type") == protocol_v3.TRANSFER_ANNOUNCEMENT_TYPE:
        bill, _bundle, _segments = protocol_v3.decode_transfer_announcement(message)
        return bill
    return None


def _message_matches_transfer(message, token_id, sequence):
    if message.get("type") != protocol_v3.TRANSFER_ANNOUNCEMENT_TYPE:
        return False
    try:
        bill = _decode_message_bill(message)
        return (
            bill
            and bill.get("token_id") == token_id
            and bill.get("recent_transfers")
            and int(bill["recent_transfers"][-1]["sequence"]) == int(sequence)
        )
    except Exception:
        return False


def _record_matches_bill(record, token_id, sequence):
    if not isinstance(record, dict):
        return False
    try:
        if record.get("token_id") == token_id and int(record.get("sequence", -1)) == int(sequence):
            return True
        bill = record.get("bill")
        if not isinstance(bill, dict) or bill.get("token_id") != token_id:
            return False
        checkpoint = bill.get("checkpoint_core") or {}
        if int(checkpoint.get("sequence", -1)) == int(sequence):
            return True
        recent = bill.get("recent_transfers") or []
        return bool(recent) and int(recent[-1].get("sequence", -1)) == int(sequence)
    except Exception:
        return False


def _fetch_wallet_message_report(address, token_id, sequence, peers):
    per_peer = []
    for peer in peers:
        messages, reports = sender_node.fetch_wallet_messages(
            address, peers=[peer], return_report=True
        )
        records = [
            record
            for report in reports
            for record in (report.get("records") or [])
            if isinstance(record, dict)
        ]
        has_transfer = any(
            _message_matches_transfer(message, token_id, sequence) for message in messages
        )
        has_record = any(
            _record_matches_bill(record, token_id, sequence) for record in records
        )
        per_peer.append(
            {
                "peer": peer,
                "reports": reports,
                "message_count": len(messages),
                "record_count": len(records),
                "message_types": sorted(
                    {str(message.get("type", "")) for message in messages if isinstance(message, dict)}
                ),
                "has_transfer": has_transfer,
                "has_record": has_record,
                "has_bill": has_transfer or has_record,
            }
        )
    return {
        "address": address,
        "token_id": token_id,
        "sequence": int(sequence),
        "per_peer": per_peer,
        "all_peers_have_transfer": all(item["has_transfer"] for item in per_peer),
        "all_peers_have_record": all(item["has_record"] for item in per_peer),
        "all_peers_have_bill": all(item["has_bill"] for item in per_peer),
    }


def _wait_for_wallet_messages(address, token_id, sequence, peers, timeout_seconds=20, interval=2):
    deadline = time.monotonic() + max(0, float(timeout_seconds))
    last = None
    while True:
        last = _fetch_wallet_message_report(address, token_id, sequence, peers)
        if last["all_peers_have_bill"]:
            last["wait_ok"] = True
            return last
        if time.monotonic() >= deadline:
            last["wait_ok"] = False
            return last
        time.sleep(float(interval))


def _cleanup_new_transaction_files(before_files):
    before = {Path(path) for path in before_files}
    after = {Path(path) for path in runtime_json.transaction_files()}
    created = sorted(after - before)
    removed = []
    for path in created:
        try:
            path.unlink()
            removed.append(path.name)
        except OSError:
            pass
    return {"created": [path.name for path in created], "removed": removed}


def _drain_new_transaction_messages(before_files):
    before = {Path(path) for path in before_files}
    after = {Path(path) for path in runtime_json.transaction_files()}
    created = sorted(after - before)
    messages = []
    removed = []
    for path in created:
        try:
            messages.append(runtime_json.read_transaction_message(path))
        finally:
            try:
                path.unlink()
                removed.append(path.name)
            except OSError:
                pass
    return {
        "created": [path.name for path in created],
        "removed": removed,
        "messages": messages,
    }


def _build_initial_bill(store, owner_wallet, *, run_id, label, display_id, value=1):
    operator_private, operator_public = _operator_keypair(f"{run_id}:{label}")
    with tempfile.TemporaryDirectory(prefix=f"ind-v3-e2e-{label}-") as temp_dir:
        log = log_server.TransparencyLog(
            str(Path(temp_dir) / "operator.sqlite3"),
            operator_private,
            operator_public,
        )
        issued_at = max(1, _now() - 30)
        genesis_hash = _sha3_text(f"{run_id}:{label}:genesis")
        token_id = _sha3_text(f"{run_id}:{label}:token")
        parsed = protocol_v3.parse_display_id(display_id)
        issuer = wallet_services.generate_wallet_v3(
            sha3_256(f"{run_id}:{label}:issuer".encode("ascii")).digest()
        )
        owner_address = owner_wallet[0]
        genesis_ref = {
            "type": protocol_v3.GENESIS_REF_TYPE,
            "version": protocol_v3.VERSION,
            "network_id": int(protocol_v3.DEFAULT_NETWORK_ID),
            "genesis_hash": genesis_hash,
            "manifest_hash": None,
            "issuer_key_id": None,
            "issue_index": int(parsed["serial"]),
            "issued_at": issued_at,
        }
        base_state = {
            "sequence": 0,
            "owner_address": issuer[0],
            "last_transfer_hash": genesis_hash,
            "last_transfer_timestamp": issued_at,
            "last_transfer_day": issued_at // 86400,
            "transfers_in_last_day": 0,
            "display_id": display_id,
            "value": int(value),
        }
        first_transfer = protocol_v3.create_transfer_from_state(
            token_id,
            base_state,
            issuer[1],
            issuer[2],
            owner_address,
            metadata={"source": "v3-public-wallet-e2e", "phase": "initial-funding"},
            timestamp=issued_at + 5,
            network_id=protocol_v3.DEFAULT_NETWORK_ID,
        )
        archive_segment = archive_segment_v3.make_archive_segment(
            token_id,
            genesis_ref,
            base_state,
            [first_transfer],
            network_id=protocol_v3.DEFAULT_NETWORK_ID,
        )
        checkpoint_core = archive_segment_v3.verify_archive_segment(archive_segment)
        transfer_hash = protocol_v3.transfer_hash(first_transfer)
        transfer_append = log.append_entry_hash(
            transfer_hash,
            submitted_at=issued_at + 8,
            transfer=first_transfer,
        )
        claim = protocol_v3.spend_claim_for_transfer(
            first_transfer,
            log.log_id,
            transfer_append["leaf_index"],
            issued_at + 8,
        )
        with log._connect() as conn:
            log._record_spend_claim(
                conn,
                claim,
                transfer_hash,
                transfer_append["leaf_index"],
                issued_at + 8,
            )
        checkpoint_append = log.append_entry_hash(
            checkpoint_core["checkpoint_hash"],
            submitted_at=issued_at + 9,
            entry_kind="checkpoint",
            entry=checkpoint_core,
        )
        root = log.publish_root(issued_at + 12)
        inclusion = log.inclusion_proof(checkpoint_append["entry_hash"], root["tree_size"])
        with log._connect() as conn:
            claims = log._spend_claim_records(conn, tree_size=root["tree_size"])
        compressed = spend_map_v3.build_compressed_spend_map_proof(
            claims,
            protocol_v3.spend_key_for_transfer(first_transfer),
            root["tree_size"],
            network_id=protocol_v3.DEFAULT_NETWORK_ID,
        )
        source_evidence = proof_bundle_v3.make_archive_segment_evidence(
            archive_segment,
            network_id=protocol_v3.DEFAULT_NETWORK_ID,
            include_segment=False,
        )
        proof_bundle = proof_bundle_v3.make_proof_bundle(
            checkpoint_core,
            root,
            inclusion,
            compressed,
            source_evidence,
            network_id=protocol_v3.DEFAULT_NETWORK_ID,
            created_at=issued_at + 13,
        )

    store.store_archive_segment_v3(archive_segment)
    store.store_proof_bundle_v3(
        proof_bundle,
        trusted_operator_public_key=operator_public,
    )
    bill = protocol_v3.create_bill_from_checkpoint_core(
        genesis_ref,
        checkpoint_core,
        proof_bundle,
        trusted_operator_public_key=operator_public,
        archive_segment_resolver=store.archive_segment_resolver_v3,
    )
    store.store_bill_v3(
        bill,
        proof_bundle=proof_bundle,
        status="settled",
        trusted_operator_public_key=operator_public,
    )
    return {
        "label": label,
        "display_id": display_id,
        "token_id": token_id,
        "operator_public_key": operator_public,
        "operator_log_id": proof_bundle["log_id"],
        "archive_segment": archive_segment,
        "archive_segment_hash": archive_segment["segment_hash"],
        "proof_bundle": proof_bundle,
        "proof_bundle_hash": proof_bundle["proof_bundle_hash"],
        "bill": bill,
        "checkpoint_hash": checkpoint_core["checkpoint_hash"],
        "initial_owner": owner_address,
    }


def _run_receive_sync(store, wallets):
    for wallet in wallets:
        runtime_json.write_decrypted_wallet(
            wallet[0],
            "\n".join([wallet[0], wallet[1], wallet[2]]) + "\n",
        )
    events = []
    summary = sender_node.receive_bills(progress_callback=events.append)
    return {"summary": summary, "events": events[-20:]}


def _run_hop(store, bill_info, wallets, sender_name, recipient_name, peers, index):
    sender_wallet = wallets[sender_name]
    recipient_wallet = wallets[recipient_name]
    token_id = bill_info["token_id"]
    display_id = bill_info["display_id"]
    trusted_key = bill_info["operator_public_key"]
    proof_bundle = store.get_proof_bundle_v3(bill_info["proof_bundle_hash"])
    source_segment = bill_info["archive_segment"]
    current_bill = store.get_bill_v3_by_token_id(token_id)
    pre_state = protocol_v3.verify_bill(
        current_bill,
        proof_bundle=proof_bundle,
        proof_bundle_resolver=store.proof_bundle_resolver_v3,
        trusted_operator_public_key=trusted_key,
        archive_segment_resolver=store.archive_segment_resolver_v3,
    )
    before_transactions = runtime_json.transaction_files()
    spend_state = wallet_services.spend_wallet_bill_v3(
        _wallet_lines(sender_wallet),
        f"{display_id} {int(pre_state.sequence)} {_now()}",
        recipient_wallet[0],
        store=store,
        proof_bundle=proof_bundle,
        trusted_operator_public_key=trusted_key,
        timestamp=max(_now(), int(pre_state.sequence) + int(pre_state.last_transfer_hash[:6], 16) % 2),
    )
    queued_cleanup = _cleanup_new_transaction_files(before_transactions)
    if spend_state is None:
        raise RuntimeError(f"hop {index} spend returned None")
    transferred_bill = store.get_bill_v3_by_token_id(token_id)
    transfer_announcement = protocol_v3.create_transfer_announcement(
        transferred_bill,
        proof_bundle=proof_bundle,
        archive_segments=[source_segment],
    )
    local_transfer_result = store.ingest_message(transfer_announcement)
    after_transfer = _status_snapshot(store, token_id, display_id, recipient_wallet[0])
    transfer_broadcast = _broadcast_message(
        transfer_announcement,
        peers,
        f"hop_{index}_transfer_{sender_name}_to_{recipient_name}",
        timeout=TRANSFER_BROADCAST_TIMEOUT_SECONDS,
    )
    before_claim_transactions = runtime_json.transaction_files()
    claim_result = wallet_services.claim_bill_payload(
        ind_token.pack_wire_message(transfer_announcement),
        _wallet_lines(recipient_wallet),
        recipient_wallet[0],
    )
    claim_queue = _drain_new_transaction_messages(before_claim_transactions)
    after_claim = _status_snapshot(store, token_id, display_id, recipient_wallet[0])
    finalized = store.finalize_pending(buffer_seconds=0)
    after_finalize = _status_snapshot(store, token_id, display_id, recipient_wallet[0])
    final_bill = store.get_bill_v3_by_token_id(token_id)
    verify = _verify_bill_snapshot(store, final_bill, proof_bundle, trusted_key)
    public_status = _query_public_status(peers, [display_id, token_id])
    wallet_messages = _wait_for_wallet_messages(
        recipient_wallet[0],
        token_id,
        int(spend_state.sequence),
        peers,
    )
    return {
        "hop": index,
        "path": f"{sender_name}->{recipient_name}",
        "sender_address": sender_wallet[0],
        "recipient_address": recipient_wallet[0],
        "display_id": display_id,
        "token_id": token_id,
        "sequence": int(spend_state.sequence),
        "owner_after_spend": spend_state.owner_address,
        "queued_transaction_files": queued_cleanup,
        "local_transfer_result": {
            "accepted": bool(local_transfer_result.get("accepted")),
            "status": local_transfer_result.get("status"),
        },
        "status_after_transfer": after_transfer,
        "claim_result": bool(claim_result),
        "claim_queue": {
            "created": claim_queue["created"],
            "removed": claim_queue["removed"],
            "message_types": [
                str(message.get("type", "")) for message in claim_queue["messages"]
                if isinstance(message, dict)
            ],
        },
        "status_after_claim": after_claim,
        "finalized": finalized,
        "status_after_finalize": after_finalize,
        "verify": verify,
        "transfer_message_hash": _message_hash(transfer_announcement),
        "transfer_broadcast": transfer_broadcast,
        "public_status": public_status,
        "wallet_bill_convergence": wallet_messages,
    }


def _run_negative_cases(store, bill_info, wallets, peers, run_id):
    wallet_a = wallets["A"]
    wallet_b = wallets["B"]
    wallet_wrong = wallet_services.generate_wallet_v3(
        sha3_256(f"{run_id}:wrong-wallet".encode("ascii")).digest()
    )
    proof_bundle = store.get_proof_bundle_v3(bill_info["proof_bundle_hash"])
    trusted_key = bill_info["operator_public_key"]
    source_segment = bill_info["archive_segment"]
    base_bill = bill_info["bill"]
    token_id = bill_info["token_id"]

    wrong_spend = {"rejected": False, "error": ""}
    try:
        result = wallet_services.spend_wallet_bill_v3(
            _wallet_lines(wallet_b),
            base_bill,
            wallet_wrong[0],
            store=store,
            proof_bundle=proof_bundle,
            trusted_operator_public_key=trusted_key,
        )
        wrong_spend["rejected"] = result is None
        wrong_spend["result"] = "None" if result is None else "unexpected_state"
    except Exception as exc:  # noqa: BLE001 - rejection by exception is acceptable here.
        wrong_spend["rejected"] = True
        wrong_spend["error"] = str(exc)

    branch_a = protocol_v3.create_transfer(
        base_bill,
        wallet_a[1],
        wallet_a[2],
        wallet_b[0],
        proof_bundle=proof_bundle,
        proof_bundle_resolver=store.proof_bundle_resolver_v3,
        trusted_operator_public_key=trusted_key,
        archive_segment_resolver=store.archive_segment_resolver_v3,
        metadata={"source": "v3-public-wallet-e2e", "negative": "double-spend-a"},
        timestamp=_now() + 1,
    )
    branch_b = protocol_v3.create_transfer(
        base_bill,
        wallet_a[1],
        wallet_a[2],
        wallet_wrong[0],
        proof_bundle=proof_bundle,
        proof_bundle_resolver=store.proof_bundle_resolver_v3,
        trusted_operator_public_key=trusted_key,
        archive_segment_resolver=store.archive_segment_resolver_v3,
        metadata={"source": "v3-public-wallet-e2e", "negative": "double-spend-b"},
        timestamp=_now() + 2,
    )
    ann_a = protocol_v3.create_transfer_announcement(
        branch_a, proof_bundle=proof_bundle, archive_segments=[source_segment]
    )
    ann_b = protocol_v3.create_transfer_announcement(
        branch_b, proof_bundle=proof_bundle, archive_segments=[source_segment]
    )
    first_branch = {}
    second_branch = {}
    try:
        first_branch = store.ingest_message(ann_a)
    except Exception as exc:  # noqa: BLE001
        first_branch = {"accepted": False, "error": str(exc)}
    try:
        second_branch = store.ingest_message(ann_b)
    except Exception as exc:  # noqa: BLE001
        second_branch = {"accepted": False, "error": str(exc)}
    conflict_proof = protocol_v3.create_conflict_proof(
        branch_a,
        branch_b,
        proof_bundle_a=proof_bundle,
        proof_bundle_b=proof_bundle,
        proof_bundle_resolver=store.proof_bundle_resolver_v3,
        trusted_operator_public_key=trusted_key,
        archive_segment_resolver=store.archive_segment_resolver_v3,
    )
    conflict_result = store.ingest_message(conflict_proof)
    branch_a_broadcast = _broadcast_message(
        ann_a,
        peers,
        "negative_double_spend_first_branch",
    )
    branch_b_broadcast = _broadcast_message(
        ann_b,
        peers,
        "negative_double_spend_second_branch",
    )
    conflict_broadcast = _broadcast_message(
        conflict_proof,
        peers,
        "negative_double_spend_conflict_proof",
    )

    clone_path = Path(store.db_path).with_name(Path(store.db_path).stem + "_stale_probe.sqlite3")
    shutil.copyfile(store.db_path, clone_path)
    clone = INDLocalStore(db_path=clone_path, require_transparency=False)
    latest_before = _latest_bill_row(clone, token_id)
    stale_result = {}
    try:
        stale_result = clone.ingest_message(ann_b)
    except Exception as exc:  # noqa: BLE001
        stale_result = {"accepted": False, "error": str(exc)}
    latest_after = _latest_bill_row(clone, token_id)
    stale_no_corrupt = (
        latest_before
        and latest_after
        and latest_before["sequence"] == latest_after["sequence"]
        and latest_before["owner_address"] == latest_after["owner_address"]
        and latest_before["bill_hash"] == latest_after["bill_hash"]
    )

    return {
        "wrong_spend_with_non_owner_wallet": wrong_spend,
        "double_spend": {
            "display_id": bill_info["display_id"],
            "token_id": token_id,
            "branch_a_hash": protocol_v3.transfer_hash(branch_a["recent_transfers"][-1]),
            "branch_b_hash": protocol_v3.transfer_hash(branch_b["recent_transfers"][-1]),
            "first_branch_local": {
                "accepted": bool(first_branch.get("accepted")),
                "status": first_branch.get("status"),
                "error": first_branch.get("error", ""),
            },
            "second_branch_local": {
                "accepted": bool(second_branch.get("accepted")),
                "status": second_branch.get("status"),
                "error": second_branch.get("error", ""),
            },
            "conflict_proof_hash": conflict_proof["proof_hash"],
            "conflict_local": {
                "accepted": bool(conflict_result.get("accepted")),
                "status": conflict_result.get("status"),
                "duplicate_conflict": bool(conflict_result.get("duplicate_conflict")),
            },
            "first_branch_broadcast": branch_a_broadcast,
            "second_branch_broadcast": branch_b_broadcast,
            "conflict_broadcast": conflict_broadcast,
        },
        "stale_branch_clone_probe": {
            "clone_store": _safe_path(clone_path),
            "local_result": {
                "accepted": bool(stale_result.get("accepted")),
                "status": stale_result.get("status"),
                "error": stale_result.get("error", ""),
            },
            "latest_before": latest_before,
            "latest_after": latest_after,
            "did_not_corrupt_latest_tip": bool(stale_no_corrupt),
        },
    }


def _report_ok(report):
    if not report.get("hops"):
        return False
    for hop in report["hops"]:
        if hop["owner_after_spend"] != hop["recipient_address"]:
            return False
        if not hop["verify"].get("verified"):
            return False
        if not hop["transfer_broadcast"].get("all_ok"):
            return False
        final_row = (hop["status_after_finalize"].get("row") or {})
        if final_row.get("status") not in ACCEPTED_FINAL_STATUSES:
            return False
    negatives = report.get("negative_cases") or {}
    if not negatives.get("wrong_spend_with_non_owner_wallet", {}).get("rejected"):
        return False
    conflict = negatives.get("double_spend", {})
    if not conflict.get("conflict_local", {}).get("accepted"):
        return False
    if not conflict.get("conflict_broadcast", {}).get("all_ok"):
        return False
    return bool(negatives.get("stale_branch_clone_probe", {}).get("did_not_corrupt_latest_tip"))


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--peer", action="append", help="seed/node; repeatable and comma-separated")
    parser.add_argument("--hops", type=int, default=3)
    parser.add_argument("--run-id", default=time.strftime("%Y%m%d_%H%M%S"))
    parser.add_argument("--report-path", type=Path)
    parser.add_argument("--keep-store", action="store_true")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    peers = testnet_peers.parse_peer_args(args.peer or DEFAULT_PEERS, default_to_config=False)
    if not peers:
        peers = list(DEFAULT_PEERS)
    run_id = args.run_id
    report_path = args.report_path or (
        ROOT_DIR / "files" / "testnet" / f"{run_id}_v3_public_wallet_e2e.json"
    )
    report_path.parent.mkdir(parents=True, exist_ok=True)
    store_path = report_path.with_suffix(".sqlite3")
    os.environ["IND_STORE_PATH"] = str(store_path)
    runtime_json.ensure_runtime_files()

    wallet_a = wallet_services.generate_wallet_v3(
        sha3_256(f"{run_id}:wallet-a".encode("ascii")).digest()
    )
    wallet_b = wallet_services.generate_wallet_v3(
        sha3_256(f"{run_id}:wallet-b".encode("ascii")).digest()
    )
    wallets = {"A": wallet_a, "B": wallet_b}
    store = INDLocalStore(db_path=store_path, require_transparency=False)
    serial_base = int(time.time())
    main_display_id = protocol_v3.canonical_display_id(1, serial_base)
    negative_display_id = protocol_v3.canonical_display_id(1, serial_base + 1)
    main_bill = _build_initial_bill(
        store,
        wallet_a,
        run_id=run_id,
        label="main",
        display_id=main_display_id,
        value=1,
    )
    negative_bill = _build_initial_bill(
        store,
        wallet_a,
        run_id=run_id,
        label="negative",
        display_id=negative_display_id,
        value=1,
    )

    report = {
        "type": "ind.v3_public_wallet_e2e.v3",
        "run_id": run_id,
        "network": "testnet",
        "node_port": os.environ["IND_NODE_PORT"],
        "commands": [
            "$env:IND_NETWORK='testnet'; $env:IND_NODE_PORT='18888'; .\\.venv\\Scripts\\python.exe tools\\v3_testnet_smoke.py --run-pytest",
            "$env:IND_NETWORK='testnet'; $env:IND_NODE_PORT='18888'; .\\.venv\\Scripts\\python.exe tools\\v3_public_wallet_e2e.py",
        ],
        "peers": peers,
        "store_path": _safe_path(store_path),
        "wallets": {"A": _wallet_report(wallet_a), "B": _wallet_report(wallet_b)},
        "main_bill": {
            key: main_bill[key]
            for key in (
                "display_id",
                "token_id",
                "initial_owner",
                "operator_log_id",
                "operator_public_key",
                "proof_bundle_hash",
                "archive_segment_hash",
                "checkpoint_hash",
            )
        },
        "negative_bill": {
            key: negative_bill[key]
            for key in (
                "display_id",
                "token_id",
                "initial_owner",
                "operator_log_id",
                "operator_public_key",
                "proof_bundle_hash",
                "archive_segment_hash",
                "checkpoint_hash",
            )
        },
        "initial_status": _status_snapshot(
            store, main_bill["token_id"], main_bill["display_id"], wallet_a[0]
        ),
        "hops": [],
        "negative_cases": {},
        "failures": [],
    }

    path = [("A", "B"), ("B", "A"), ("A", "B"), ("B", "A")]
    try:
        for index, (sender_name, recipient_name) in enumerate(path[: max(0, args.hops)], start=1):
            hop = _run_hop(
                store,
                main_bill,
                wallets,
                sender_name,
                recipient_name,
                peers,
                index,
            )
            report["hops"].append(hop)
        report["negative_cases"] = _run_negative_cases(
            store,
            negative_bill,
            wallets,
            peers,
            run_id,
        )
    except Exception as exc:  # noqa: BLE001 - final report should preserve the traceback message.
        report["failures"].append(
            {
                "error": str(exc),
                "type": type(exc).__name__,
                "traceback": traceback.format_exc(),
            }
        )
    finally:
        for wallet in wallets.values():
            runtime_json.clear_decrypted_wallet(wallet[0])

    report["final_status"] = _status_snapshot(
        store, main_bill["token_id"], main_bill["display_id"]
    )
    report["public_final_status"] = _query_public_status(
        peers,
        [main_bill["display_id"], main_bill["token_id"], negative_bill["display_id"]],
        timeout_seconds=30,
    )
    report["ok"] = _report_ok(report) and not report["failures"]
    if not args.keep_store and report["ok"]:
        # Keep the JSON report, but remove the isolated DB when everything passed.
        try:
            Path(store_path).unlink()
            report["store_removed"] = True
        except OSError:
            report["store_removed"] = False
    else:
        report["store_removed"] = False
    report_path.write_text(
        json.dumps(report, sort_keys=True, indent=2, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, sort_keys=True, indent=2, ensure_ascii=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
