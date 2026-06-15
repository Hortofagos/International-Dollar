#!/usr/bin/env python3
"""Build and optionally broadcast a native V3 double-spend drill."""

import argparse
import json
import sys
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from ind import keys_v3, protocol_v3
from ind import runtime as runtime_json
from ind import sender_node
from ind import token as ind_token
from ind.store import INDLocalStore
from tools import testnet_peers


def _wallet_lines(address):
    path = runtime_json.decrypted_wallet_path(address)
    lines = runtime_json.read_decrypted_wallet_lines(path)
    if len(lines) < 3:
        raise RuntimeError("decrypted V3 wallet must contain address/private/public lines")
    if lines[0].strip() != address:
        raise RuntimeError("decrypted wallet address does not match requested address")
    if not keys_v3.public_key_matches_address(lines[2].strip(), address):
        raise RuntimeError("V3 wallet public key does not match address")
    return [line.strip() for line in lines[:3]]


def _load_bill(store, display_id=None, token_id=None):
    if display_id:
        bill = store.get_bill_v3_by_display_id(display_id)
        if bill:
            return bill
    if token_id:
        bill = store.get_bill_v3_by_token_id(token_id)
        if bill:
            return bill
    raise RuntimeError("stored BillV3 was not found")


def build_double_spend_messages(
    store,
    bill,
    wallet_lines,
    *,
    recipient_a=None,
    recipient_b=None,
    trusted_operator_public_key=None,
    now=None,
):
    """Create two same-state V3 transfers plus portable conflict proof."""

    now = int(time.time() if now is None else now)
    wallet_address, private_key, public_key = [str(item).strip() for item in wallet_lines[:3]]
    keys_v3.validate_address(wallet_address, "wallet V3 address")
    if not keys_v3.public_key_matches_address(public_key, wallet_address):
        raise RuntimeError("wallet public key does not match V3 address")

    proof_bundle = store.get_proof_bundle_v3(bill["proof_bundle_ref"]["proof_bundle_hash"])
    state = protocol_v3.verify_bill(
        bill,
        proof_bundle=proof_bundle,
        proof_bundle_resolver=store.proof_bundle_resolver_v3,
        transparency_verifier=getattr(store, "transparency_verifier", None),
        trusted_operator_public_key=trusted_operator_public_key,
        archive_segment_resolver=store.archive_segment_resolver_v3,
    )
    if state.owner_address != wallet_address:
        raise RuntimeError("wallet does not own the BillV3 tip")

    recipient_a = recipient_a or keys_v3.generate_keypair()[0]
    recipient_b = recipient_b or keys_v3.generate_keypair()[0]
    branch_a = protocol_v3.create_transfer(
        bill,
        private_key,
        public_key,
        recipient_a,
        proof_bundle=proof_bundle,
        proof_bundle_resolver=store.proof_bundle_resolver_v3,
        transparency_verifier=getattr(store, "transparency_verifier", None),
        trusted_operator_public_key=trusted_operator_public_key,
        archive_segment_resolver=store.archive_segment_resolver_v3,
        metadata={"source": "v3-double-spend-drill", "branch": "a"},
        timestamp=now,
    )
    branch_b = protocol_v3.create_transfer(
        bill,
        private_key,
        public_key,
        recipient_b,
        proof_bundle=proof_bundle,
        proof_bundle_resolver=store.proof_bundle_resolver_v3,
        transparency_verifier=getattr(store, "transparency_verifier", None),
        trusted_operator_public_key=trusted_operator_public_key,
        archive_segment_resolver=store.archive_segment_resolver_v3,
        metadata={"source": "v3-double-spend-drill", "branch": "b"},
        timestamp=now + 1,
    )
    proof = protocol_v3.create_conflict_proof(
        branch_a,
        branch_b,
        proof_bundle_a=proof_bundle,
        proof_bundle_b=proof_bundle,
        proof_bundle_resolver=store.proof_bundle_resolver_v3,
        transparency_verifier=getattr(store, "transparency_verifier", None),
        trusted_operator_public_key=trusted_operator_public_key,
        archive_segment_resolver=store.archive_segment_resolver_v3,
        detected_at=now + 2,
    )
    return {
        "type": "ind.testnet_double_spend_drill.v3",
        "version": protocol_v3.VERSION,
        "network_id": int(bill["network_id"]),
        "display_id": state.display_id,
        "token_id": state.token_id,
        "sequence": int(proof["sequence"]),
        "recipient_a": recipient_a,
        "recipient_b": recipient_b,
        "announcement_a": protocol_v3.create_transfer_announcement(
            branch_a,
            proof_bundle=proof_bundle,
            now=now + 3,
        ),
        "announcement_b": protocol_v3.create_transfer_announcement(
            branch_b,
            proof_bundle=proof_bundle,
            now=now + 4,
        ),
        "proof": proof,
        "branch_a_hash": protocol_v3.transfer_hash(branch_a["recent_transfers"][-1]),
        "branch_b_hash": protocol_v3.transfer_hash(branch_b["recent_transfers"][-1]),
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


def run_drill(
    peers,
    *,
    display_id=None,
    token_id=None,
    wallet_address=None,
    trusted_operator_public_key=None,
    store=None,
    dry_run=False,
):
    peers = testnet_peers.parse_peer_args(peers)
    store = store or INDLocalStore()
    bill = _load_bill(store, display_id=display_id, token_id=token_id)
    if wallet_address is None:
        wallet_address = protocol_v3.verify_bill(
            bill,
            proof_bundle_resolver=store.proof_bundle_resolver_v3,
            transparency_verifier=getattr(store, "transparency_verifier", None),
            trusted_operator_public_key=trusted_operator_public_key,
            archive_segment_resolver=store.archive_segment_resolver_v3,
        ).owner_address
    messages = build_double_spend_messages(
        store,
        bill,
        _wallet_lines(wallet_address),
        trusted_operator_public_key=trusted_operator_public_key,
    )
    if dry_run:
        return {**messages, "broadcasts": []}
    if len(peers) < 2:
        raise RuntimeError("V3 double-spend drill requires at least two peers")
    broadcasts = [
        _broadcast(peers[0], messages["announcement_a"], "partition_branch_a"),
        _broadcast(peers[1], messages["announcement_b"], "partition_branch_b"),
    ]
    for peer in peers:
        broadcasts.append(_broadcast(peer, messages["proof"], "heal_conflict_proof"))
    return {**messages, "broadcasts": broadcasts}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--peer", action="append", help="seed/node to use; repeatable")
    parser.add_argument("--display-id", help="stored BillV3 display id")
    parser.add_argument("--token-id", help="stored BillV3 token id")
    parser.add_argument("--wallet-address", help="decrypted wallet address that owns the bill")
    parser.add_argument("--trusted-operator-public-key", help="pinned transparency operator key")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    report = run_drill(
        args.peer or [],
        display_id=args.display_id,
        token_id=args.token_id,
        wallet_address=args.wallet_address,
        trusted_operator_public_key=args.trusted_operator_public_key,
        dry_run=args.dry_run,
    )
    print(json.dumps(report, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
