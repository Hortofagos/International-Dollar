#!/usr/bin/env python3
"""Deliberately attempt a testnet double spend to test conflict rejection."""

import argparse
import json
import os
import sys
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import ind_token
from ind import address_generation
from ind import sender_node
from tools import testnet_faucet
from tools import testnet_peers
from tools import testnet_report


DEFAULT_FAUCET_PRIVATE_KEY = ROOT_DIR / "files" / "testnet" / "faucet_private_key.local.json"
DEFAULT_FAUCET_PUBLIC_KEY = ROOT_DIR / "files" / "testnet" / "faucet_public_key.local.json"


def _last_transfer_hash(token):
    return ind_token.transfer_hash(token["history"][-1])


def build_double_spend_messages(manifest, index, faucet_private, faucet_public, *, now=None):
    """Create two valid same-state spends plus the portable conflict proof."""

    now = int(time.time() if now is None else now)
    recipient_a, _private_a, _public_a = address_generation.generate_keypair()
    recipient_b, _private_b, _public_b = address_generation.generate_keypair()
    bill = ind_token.make_lazy_genesis_token(
        int(index),
        manifest,
        metadata={"network": "testnet", "source": "testnet-double-spend-drill-v1"},
    )
    branch_a = ind_token.create_transfer(
        bill,
        faucet_private,
        faucet_public,
        recipient_a,
        metadata={"network": "testnet", "source": "testnet-double-spend-drill-v1", "branch": "a"},
        timestamp=now,
    )
    branch_b = ind_token.create_transfer(
        bill,
        faucet_private,
        faucet_public,
        recipient_b,
        metadata={"network": "testnet", "source": "testnet-double-spend-drill-v1", "branch": "b"},
        timestamp=now + 1,
    )
    proof = ind_token.create_conflict_proof(branch_a, branch_b, detected_at=now + 2)
    state = ind_token.verify_token(branch_a)
    return {
        "display_id": state.display_id,
        "token_id": state.token_id,
        "sequence": int(proof["sequence"]),
        "recipient_a": recipient_a,
        "recipient_b": recipient_b,
        "branch_a": branch_a,
        "branch_b": branch_b,
        "announcement_a": ind_token.create_transfer_announcement(branch_a, now=now + 3),
        "announcement_b": ind_token.create_transfer_announcement(branch_b, now=now + 4),
        "proof": proof,
        "branch_a_hash": _last_transfer_hash(branch_a),
        "branch_b_hash": _last_transfer_hash(branch_b),
    }


def _broadcast(peer, message, label):
    raw = ind_token.pack_wire_message(message)
    started = time.time()
    response = sender_node.connect("b", raw, [peer])
    return {
        "label": label,
        "peer": peer,
        "response": response,
        "ok": response == "ok",
        "message_hash": ind_token.message_hash(message),
        "elapsed_seconds": round(time.time() - started, 3),
    }


def evaluate_heal_result(post_heal_statuses, heal_broadcasts):
    conflict_everywhere = all(status == "conflict" for status in post_heal_statuses)
    proofs_accepted = all(
        item["response"] == "ok"
        for item in heal_broadcasts
        if item["label"] == "heal_conflict_proof"
    )
    return {
        "ok": conflict_everywhere and proofs_accepted,
        "conflict_everywhere": conflict_everywhere,
        "proofs_accepted": proofs_accepted,
        "expected_result": "conflict",
    }


def run_drill(
    peers,
    *,
    manifest_path=testnet_faucet.DEFAULT_MANIFEST,
    faucet_private_key_file=DEFAULT_FAUCET_PRIVATE_KEY,
    faucet_public_key_file=DEFAULT_FAUCET_PUBLIC_KEY,
    state_file=testnet_faucet.DEFAULT_STATE_PATH,
    index=None,
    partition_wait_seconds=3,
    heal_wait_seconds=8,
    reserve_index=True,
):
    """Execute the live public-testnet double-spend drill."""

    peers = testnet_peers.parse_peer_args(peers)
    if len(peers) < 2:
        raise SystemExit("double-spend drill requires at least two distinct peers")

    with testnet_report.testnet_network():
        manifest = testnet_faucet.read_json(manifest_path)
        manifest_hash = testnet_faucet.ensure_manifest_trusted_for_process(manifest)
        faucet_private = testnet_faucet.read_key(faucet_private_key_file, "private_key")
        faucet_public = testnet_faucet.read_key(faucet_public_key_file, "public_key")
        faucet_address = ind_token.address_from_public_key(faucet_public)
        owner_addresses = {item["owner_address"] for item in testnet_faucet.manifest_ranges(manifest)}
        if owner_addresses != {faucet_address}:
            raise SystemExit("faucet public key does not match the owner address in every manifest range")

        state = testnet_faucet.read_json(
            state_file,
            default={"next_index": manifest["ranges"][0]["start_index"]},
        )
        issue_index = testnet_faucet.pick_index(manifest, state, explicit_index=index)
        messages = build_double_spend_messages(manifest, issue_index, faucet_private, faucet_public)

        partition_broadcasts = [
            _broadcast(peers[0], messages["announcement_a"], "partition_branch_a"),
            _broadcast(peers[1], messages["announcement_b"], "partition_branch_b"),
        ]
        if partition_wait_seconds:
            time.sleep(max(0, int(partition_wait_seconds)))
        partition_statuses = {
            peer: testnet_report.query_peer_status([messages["display_id"]], peer=peer)
            for peer in peers
        }

        heal_broadcasts = []
        for peer in peers:
            heal_broadcasts.append(_broadcast(peer, messages["announcement_a"], "heal_branch_a"))
            heal_broadcasts.append(_broadcast(peer, messages["announcement_b"], "heal_branch_b"))
            heal_broadcasts.append(_broadcast(peer, messages["proof"], "heal_conflict_proof"))
        if heal_wait_seconds:
            time.sleep(max(0, int(heal_wait_seconds)))
        heal_statuses = {
            peer: testnet_report.query_peer_status([messages["display_id"]], peer=peer)
            for peer in peers
        }

        if reserve_index and index is None:
            state["next_index"] = issue_index + 1
            state["updated_at"] = int(time.time())
            testnet_faucet.write_json(state_file, state)

    post_heal_statuses = [
        records[0].get("status") if records else "missing"
        for records in heal_statuses.values()
    ]
    rejected_heal_branches = [
        item for item in heal_broadcasts
        if item["label"] in {"heal_branch_a", "heal_branch_b"} and item["response"] == "invalid"
    ]
    heal_result = evaluate_heal_result(post_heal_statuses, heal_broadcasts)
    return {
        "type": "ind.testnet_double_spend_drill.v1",
        "version": 1,
        "network": "testnet",
        "ok": bool(heal_result["ok"]),
        "manifest_hash": manifest_hash,
        "index": issue_index,
        "reserved_index": bool(reserve_index and index is None),
        "display_id": messages["display_id"],
        "token_id": messages["token_id"],
        "sequence": messages["sequence"],
        "branch_a_hash": messages["branch_a_hash"],
        "branch_b_hash": messages["branch_b_hash"],
        "proof_hash": messages["proof"]["proof_hash"],
        "recipient_a": messages["recipient_a"],
        "recipient_b": messages["recipient_b"],
        "peers": peers,
        "partition_broadcasts": partition_broadcasts,
        "partition_statuses": partition_statuses,
        "heal_broadcasts": heal_broadcasts,
        "heal_statuses": heal_statuses,
        "rejected_heal_branch_count": len(rejected_heal_branches),
        "conflict_everywhere": bool(heal_result["conflict_everywhere"]),
        "proofs_accepted": bool(heal_result["proofs_accepted"]),
        "expected_result": heal_result["expected_result"],
    }


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Attempt one testnet double spend to verify conflict rejection.")
    parser.add_argument("--peer", action="append", help="seed/node to use; repeatable and comma-separated")
    parser.add_argument("--manifest", default=str(testnet_faucet.DEFAULT_MANIFEST), help="public testnet manifest")
    parser.add_argument(
        "--faucet-private-key-file",
        default=str(DEFAULT_FAUCET_PRIVATE_KEY),
        help="JSON/text file with the faucet private key",
    )
    parser.add_argument(
        "--faucet-public-key-file",
        default=str(DEFAULT_FAUCET_PUBLIC_KEY),
        help="JSON/text file with the faucet public key",
    )
    parser.add_argument("--state-file", default=str(testnet_faucet.DEFAULT_STATE_PATH), help="faucet next-index state")
    parser.add_argument("--index", type=int, help="specific manifest index to test")
    parser.add_argument("--partition-wait-seconds", type=int, default=3)
    parser.add_argument("--heal-wait-seconds", type=int, default=8)
    parser.add_argument("--no-reserve-index", action="store_true", help="do not advance faucet next-index state")
    parser.add_argument("--json", action="store_true", help="print machine-readable JSON")
    parser.add_argument("--strict", action="store_true", help="return nonzero when convergence is not ok")
    return parser.parse_args(argv)


def main(argv=None):
    os.environ.setdefault("IND_NETWORK", "testnet")
    args = parse_args(argv)
    report = run_drill(
        args.peer,
        manifest_path=args.manifest,
        faucet_private_key_file=args.faucet_private_key_file,
        faucet_public_key_file=args.faucet_public_key_file,
        state_file=args.state_file,
        index=args.index,
        partition_wait_seconds=args.partition_wait_seconds,
        heal_wait_seconds=args.heal_wait_seconds,
        reserve_index=not args.no_reserve_index,
    )
    if args.json:
        print(json.dumps(report, sort_keys=True, indent=2, ensure_ascii=True))
    else:
        print(f"IND testnet double-spend drill: {'ok' if report['ok'] else 'not ok'}")
        print(f"{report['display_id']}\t{report['sequence']}\t{report['proof_hash']}")
        for peer, records in report["heal_statuses"].items():
            status = records[0].get("status") if records else "missing"
            print(f"{peer}\t{status}")
    if args.strict and not report["ok"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
