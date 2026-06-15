# Measure deterministic V1/V2 bill sizes against V3 target shapes.

import argparse
import base64
import json
import os
import sys
from hashlib import sha3_256
from pathlib import Path

import ecdsa

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ind import binary_v3, keys_v3, spend_map_v3
from ind import token as ind_token
from ind import transparency_client as log_client

BASE_TIMESTAMP = 1_700_000_000
DEFAULT_TRANSFER_COUNT = 32


def canonical_size(data):
    if isinstance(data, bytes):
        return len(data)
    return len(ind_token.canonical_json(data).encode("utf-8"))


def deterministic_v1_keypair(label):
    order = ecdsa.SECP256k1.order
    seed = int.from_bytes(sha3_256(f"IND-measurement:{label}".encode("ascii")).digest(), "big")
    secret = ((seed % (order - 1)) + 1).to_bytes(32, "big")
    signing_key = ecdsa.SigningKey.from_string(secret, curve=ecdsa.SECP256k1, hashfunc=sha3_256)
    public_key = signing_key.get_verifying_key().to_string()
    private_text = base64.b85encode(signing_key.to_string()).decode("ascii")
    public_text = base64.b85encode(public_key).decode("ascii")
    return private_text, public_text, ind_token.address_from_public_key(public_text)


def deterministic_v3_keypair(label):
    seed = sha3_256(f"IND-v3-measurement:{label}".encode("ascii")).digest()
    return keys_v3.generate_keypair(seed)


def build_full_bill(transfer_count):
    previous = os.environ.get("IND_ALLOW_UNTRUSTED_GENESIS")
    os.environ["IND_ALLOW_UNTRUSTED_GENESIS"] = "1"
    try:
        issuer_private, issuer_public, _issuer_address = deterministic_v1_keypair("issuer")
        alice_private, alice_public, alice_address = deterministic_v1_keypair("alice")
        bob_private, bob_public, bob_address = deterministic_v1_keypair("bob")
        bill = ind_token.make_genesis_token(
            33,
            alice_address,
            issuer_private,
            issuer_public,
            value=1,
            nonce=ind_token.sha3_hex("v3-measurement-genesis"),
            issued_at=BASE_TIMESTAMP,
        )
        holders = [
            (alice_private, alice_public, alice_address),
            (bob_private, bob_public, bob_address),
        ]
        current = 0
        for index in range(transfer_count):
            sender_private, sender_public, _sender_address = holders[current]
            recipient = holders[1 - current][2]
            bill = ind_token.create_transfer(
                bill,
                sender_private,
                sender_public,
                recipient,
                metadata={"fixture": "v3-measurement", "index": index},
                timestamp=BASE_TIMESTAMP + ((index + 1) * 10_000),
            )
            current = 1 - current
        return bill
    finally:
        if previous is None:
            os.environ.pop("IND_ALLOW_UNTRUSTED_GENESIS", None)
        else:
            os.environ["IND_ALLOW_UNTRUSTED_GENESIS"] = previous


def synthetic_transparency_for_bill(bill):
    last_transfer = bill["history"][-1]
    claim = log_client.spend_claim_for_transfer(
        last_transfer,
        "measurement-log",
        len(bill["history"]) - 1,
        BASE_TIMESTAMP + 500_000,
    )
    spend_root = log_client.spend_map_root([claim])
    root = {
        "type": log_client.LOG_ROOT_TYPE,
        "version": log_client.LOG_VERSION,
        "log_id": "measurement-log",
        "tree_algorithm": log_client.LOG_TREE_ALGORITHM,
        "hash_algorithm": log_client.LOG_HASH_ALGORITHM,
        "signature_algorithm": log_client.LOG_SIGNATURE_ALGORITHM,
        "tree_size": len(bill["history"]),
        "root_hash": ind_token.sha3_hex("measurement-root"),
        "spend_map_algorithm": log_client.LOG_SPEND_MAP_ALGORITHM,
        "spend_map_root": spend_root,
        "spend_map_size": 1,
        "timestamp": BASE_TIMESTAMP + 500_001,
        "operator_public_key": "measurement-operator-public-key",
        "signature": base64.b85encode(b"\x11" * 64).decode("ascii"),
    }
    inclusion_proof = {
        "type": log_client.LOG_INCLUSION_PROOF_TYPE,
        "version": log_client.LOG_VERSION,
        "algorithm": log_client.LOG_TREE_ALGORITHM,
        "entry_hash": ind_token.transfer_hash(last_transfer),
        "leaf_index": len(bill["history"]) - 1,
        "tree_size": len(bill["history"]),
        "audit_path": [
            {
                "side": "left" if index % 2 else "right",
                "hash": sha3_256(f"path:{index}".encode("ascii")).hexdigest(),
            }
            for index in range(6)
        ],
    }
    spend_proof = log_client.build_spend_map_proof(
        [claim],
        log_client.spend_key_for_transfer(last_transfer),
        len(bill["history"]),
    )
    return {
        "type": "ind.checkpoint_transparency.v2",
        "version": ind_token.BILL_VERSION,
        "root": root,
        "inclusion_proof": inclusion_proof,
        "spend_proof": spend_proof,
    }


def compact_bill_with_proof(full_bill, transparency):
    checkpoint = ind_token.create_bill_checkpoint(full_bill, transparency=transparency)
    return ind_token.create_compact_bill(full_bill, checkpoint)


def compact_bill_with_proof_ref(full_bill, transparency):
    root = transparency["root"]
    proof_bundle_blob = ind_token.canonical_json(transparency).encode("utf-8")
    proof_bundle_hash = sha3_256(b"IND-V3-PROOF-BUNDLE-FIXTURE:" + proof_bundle_blob).digest()
    checkpoint = ind_token.create_bill_checkpoint(full_bill)
    compact_core = {
        "magic": "IND3BILL",
        "version": 3,
        "network_id": 1,
        "token_id": full_bill["token_id"],
        "value": full_bill["genesis"]["value"],
        "genesis_ref": {
            "genesis_hash": ind_token.genesis_hash(full_bill["genesis"]),
            "manifest_hash": None,
            "issuer_key_id": sha3_256(
                full_bill["genesis"]["issuer_public_key"].encode("ascii")
            ).hexdigest(),
            "issue_index": full_bill["genesis"]["index"],
            "issued_at": full_bill["genesis"]["issued_at"],
        },
        "checkpoint_core": {
            key: checkpoint[key]
            for key in (
                "sequence",
                "owner_address",
                "value",
                "display_id",
                "last_transfer_hash",
                "last_transfer_timestamp",
                "last_transfer_day",
                "transfers_in_last_day",
                "previous_checkpoint_hash",
                "checkpoint_hash",
            )
        },
        "proof_bundle_ref": {
            "log_id": root["log_id"],
            "signed_root_hash": sha3_256(
                ind_token.canonical_json(root).encode("utf-8")
            ).hexdigest(),
            "tree_size": root["tree_size"],
            "proof_bundle_algorithm": 1,
            "proof_bundle_hash": proof_bundle_hash.hex(),
        },
        "recent_transfers": [],
    }
    return compact_core


def compressed_spend_map_proof_size(v2_spend_proof):
    compressed = spend_map_v3.build_compressed_spend_map_proof(
        v2_spend_proof["spend_claims"],
        v2_spend_proof["spend_key"],
        v2_spend_proof["tree_size"],
    )
    return canonical_size(compressed), len(compressed["non_empty_siblings"])


def sample_bill_v3_binary_size():
    alice_address, _alice_private, alice_public = deterministic_v3_keypair("alice")
    _bob_address, _bob_private, bob_public = deterministic_v3_keypair("bob")
    token_id = sha3_256(b"v3 measurement token").digest()
    genesis_hash = sha3_256(b"v3 measurement genesis").digest()
    issuer_key_id = sha3_256(b"v3 issuer").digest()
    checkpoint_hash = sha3_256(b"v3 checkpoint").digest()
    previous_hash = genesis_hash
    transfer_hash = sha3_256(b"v3 transfer").digest()
    signed_root_hash = sha3_256(b"v3 signed root").digest()
    proof_bundle_hash = sha3_256(b"v3 proof bundle").digest()
    binary = b"".join(
        (
            b"IND3BILL",
            binary_v3.encode_uvarint(3),
            binary_v3.encode_uvarint(1),
            token_id,
            binary_v3.encode_uvarint(1),
            genesis_hash,
            binary_v3.encode_nullable_hash(None),
            binary_v3.encode_nullable_hash(issuer_key_id),
            binary_v3.encode_uvarint(33),
            binary_v3.encode_uvarint(BASE_TIMESTAMP),
            binary_v3.encode_uvarint(1),
            binary_v3.encode_ascii(alice_address, max_length=64),
            binary_v3.encode_uvarint(1),
            sha3_256(b"1x33").digest(),
            transfer_hash,
            binary_v3.encode_uvarint(BASE_TIMESTAMP + 10_000),
            binary_v3.encode_uvarint((BASE_TIMESTAMP + 10_000) // 86400),
            binary_v3.encode_uvarint(1),
            binary_v3.encode_nullable_hash(None),
            checkpoint_hash,
            binary_v3.encode_ascii("measurement-log", max_length=64),
            signed_root_hash,
            binary_v3.encode_uvarint(32),
            binary_v3.encode_uvarint(1),
            proof_bundle_hash,
            binary_v3.encode_uvarint(1),
            binary_v3.encode_uvarint(1),
            binary_v3.encode_uvarint(binary_v3.SIGNATURE_ALGORITHM_ID),
            binary_v3.encode_uvarint(1),
            previous_hash,
            binary_v3.encode_ascii(alice_address, max_length=64),
            binary_v3.encode_uvarint(BASE_TIMESTAMP + 10_000),
            binary_v3.encode_uvarint(0),
            sha3_256(b"metadata").digest(),
            keys_v3.decode_public_key(bob_public),
            b"\x22" * 64,
        )
    )
    return len(binary)


def measure(transfer_count):
    previous = os.environ.get("IND_ALLOW_UNTRUSTED_GENESIS")
    os.environ["IND_ALLOW_UNTRUSTED_GENESIS"] = "1"
    try:
        full_bill = build_full_bill(transfer_count)
        transparency = synthetic_transparency_for_bill(full_bill)
        compact_with_proof = compact_bill_with_proof(full_bill, transparency)
        compact_with_ref = compact_bill_with_proof_ref(full_bill, transparency)
        compressed_size, non_empty_siblings = compressed_spend_map_proof_size(
            transparency["spend_proof"]
        )
        proof_bundle_size = canonical_size(transparency)
        archive_segment = {
            "magic": "IND3ARCH",
            "version": 3,
            "network_id": 1,
            "token_id": full_bill["token_id"],
            "start_sequence": 1,
            "end_sequence": transfer_count,
            "previous_segment_hash": None,
            "checkpoint_hash": compact_with_ref["checkpoint_core"]["checkpoint_hash"],
            "transfers": full_bill["history"],
        }
        return {
            "transfer_count": transfer_count,
            "v1_full_history_bill_bytes": canonical_size(full_bill),
            "current_v2_compact_bill_bytes": canonical_size(compact_with_proof),
            "v2_embedded_transparency_bytes": canonical_size(transparency),
            "v2_spend_map_proof_bytes": canonical_size(transparency["spend_proof"]),
            "v3_bill_v3_binary_estimate_bytes": sample_bill_v3_binary_size(),
            "v3_bill_v3_json_shape_with_proof_ref_bytes": canonical_size(compact_with_ref),
            "v3_proof_bundle_v3_bytes": proof_bundle_size,
            "v3_compressed_spend_map_proof_json_bytes": compressed_size,
            "v3_self_contained_export_bytes": canonical_size(compact_with_ref)
            + proof_bundle_size
            + canonical_size(archive_segment),
            "proof_cache_dedupe_ratio": round(
                canonical_size(compact_with_proof) / max(canonical_size(compact_with_ref), 1), 3
            ),
            "archive_segment_dedupe_ratio": round(
                canonical_size(full_bill) / max(canonical_size(archive_segment), 1), 3
            ),
            "v2_spend_map_audit_path_entries": len(transparency["spend_proof"]["audit_path"]),
            "v3_non_empty_spend_map_siblings": non_empty_siblings,
        }
    finally:
        if previous is None:
            os.environ.pop("IND_ALLOW_UNTRUSTED_GENESIS", None)
        else:
            os.environ["IND_ALLOW_UNTRUSTED_GENESIS"] = previous


def render_markdown(result):
    lines = [
        "# V3 Storage Measurement",
        "",
        f"Transfer count: {result['transfer_count']}",
        "",
        "| Metric | Bytes / value |",
        "| --- | ---: |",
    ]
    for key, value in result.items():
        if key == "transfer_count":
            continue
        lines.append(f"| `{key}` | {value} |")
    lines.append("")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--transfers", type=int, default=DEFAULT_TRANSFER_COUNT)
    parser.add_argument("--json", action="store_true", help="print JSON instead of Markdown")
    parser.add_argument("--output", help="optional file path for the report")
    args = parser.parse_args(argv)
    result = measure(args.transfers)
    text = json.dumps(result, sort_keys=True, indent=2) if args.json else render_markdown(result)
    if args.output:
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)


if __name__ == "__main__":
    main()
