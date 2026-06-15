import base64
import os
from hashlib import sha3_256

import ecdsa
import pytest

from ind import spend_map_v3
from ind import token as ind_token
from ind import transparency_client as log_client

BASE_TIMESTAMP = 1_700_000_000


def test_compressed_spend_map_proof_matches_v2_root_semantics():
    fixture = _spend_map_fixture()
    compressed = spend_map_v3.build_compressed_spend_map_proof(
        fixture["claims"],
        fixture["target_spend_key"],
        fixture["tree_size"],
    )

    full_claims = log_client.verify_spend_map_proof(fixture["full_proof"], fixture["root"])
    compressed_claims = spend_map_v3.verify_compressed_spend_map_proof(compressed, fixture["root"])

    assert compressed["non_empty_sibling_count"] < log_client.SPEND_MAP_KEY_BITS
    assert compressed_claims == full_claims
    assert len(spend_map_v3.expand_compressed_spend_map_proof(compressed)["audit_path"]) == 256


def test_compressed_spend_map_proof_rejects_duplicate_depths():
    fixture = _spend_map_fixture()
    compressed = spend_map_v3.build_compressed_spend_map_proof(
        fixture["claims"],
        fixture["target_spend_key"],
        fixture["tree_size"],
    )
    sibling = _valid_extra_sibling(compressed["spend_key"], 200)
    compressed["non_empty_siblings"] = [sibling, dict(sibling)]
    compressed["non_empty_sibling_count"] = 2

    with pytest.raises(log_client.InclusionProofError, match="duplicate"):
        spend_map_v3.verify_compressed_spend_map_proof(compressed, fixture["root"])


def test_compressed_spend_map_proof_rejects_explicit_empty_sibling():
    fixture = _spend_map_fixture()
    compressed = spend_map_v3.build_compressed_spend_map_proof(
        fixture["claims"],
        fixture["target_spend_key"],
        fixture["tree_size"],
    )
    depth = 200
    sibling = _valid_extra_sibling(compressed["spend_key"], depth)
    sibling["hash"] = log_client._spend_map_empty_hashes()[depth]
    compressed["non_empty_siblings"] = [sibling]
    compressed["non_empty_sibling_count"] = 1

    with pytest.raises(log_client.InclusionProofError, match="empty sibling"):
        spend_map_v3.verify_compressed_spend_map_proof(compressed, fixture["root"])


def test_compressed_spend_map_proof_rejects_side_tampering():
    fixture = _spend_map_fixture()
    compressed = spend_map_v3.build_compressed_spend_map_proof(
        fixture["claims"],
        fixture["target_spend_key"],
        fixture["tree_size"],
    )
    if not compressed["non_empty_siblings"]:
        compressed["non_empty_siblings"] = [_valid_extra_sibling(compressed["spend_key"], 200)]
        compressed["non_empty_sibling_count"] = 1
    compressed["non_empty_siblings"][0]["side"] = (
        "left" if compressed["non_empty_siblings"][0]["side"] == "right" else "right"
    )

    with pytest.raises(log_client.InclusionProofError, match="spend key"):
        spend_map_v3.verify_compressed_spend_map_proof(compressed, fixture["root"])


def test_compressed_spend_map_proof_rejects_claim_tampering():
    fixture = _spend_map_fixture()
    compressed = spend_map_v3.build_compressed_spend_map_proof(
        fixture["claims"],
        fixture["target_spend_key"],
        fixture["tree_size"],
    )
    compressed["spend_claims"][0]["transfer_hash"] = "00" * 32

    with pytest.raises(log_client.InclusionProofError):
        spend_map_v3.verify_compressed_spend_map_proof(compressed, fixture["root"])


def test_compressed_spend_map_proof_rejects_noncanonical_sibling_order():
    fixture = _spend_map_fixture()
    compressed = spend_map_v3.build_compressed_spend_map_proof(
        fixture["claims"],
        fixture["target_spend_key"],
        fixture["tree_size"],
    )
    compressed["non_empty_siblings"] = [
        _valid_extra_sibling(compressed["spend_key"], 100),
        _valid_extra_sibling(compressed["spend_key"], 200),
    ]
    compressed["non_empty_sibling_count"] = 2

    with pytest.raises(log_client.InclusionProofError, match="canonical"):
        spend_map_v3.verify_compressed_spend_map_proof(compressed, fixture["root"])


def test_compressed_spend_map_proof_rejects_network_mismatch():
    fixture = _spend_map_fixture()
    compressed = spend_map_v3.build_compressed_spend_map_proof(
        fixture["claims"],
        fixture["target_spend_key"],
        fixture["tree_size"],
        network_id=2,
    )

    with pytest.raises(log_client.InclusionProofError, match="network id mismatch"):
        spend_map_v3.verify_compressed_spend_map_proof(
            compressed,
            fixture["root"],
            expected_network_id=1,
        )


def _spend_map_fixture():
    previous = os.environ.get("IND_ALLOW_UNTRUSTED_GENESIS")
    os.environ["IND_ALLOW_UNTRUSTED_GENESIS"] = "1"
    try:
        issuer_private, issuer_public, _issuer_address = _keypair("issuer")
        alice_private, alice_public, alice_address = _keypair("alice")
        _bob_private, _bob_public, bob_address = _keypair("bob")
        carol_private, carol_public, carol_address = _keypair("carol")
        operator_private, operator_public, _operator_address = _keypair("operator")

        bill_a = ind_token.make_genesis_token(
            90,
            alice_address,
            issuer_private,
            issuer_public,
            value=1,
            nonce=ind_token.sha3_hex("spend-map-v3-a"),
            issued_at=BASE_TIMESTAMP,
        )
        bill_b = ind_token.make_genesis_token(
            91,
            carol_address,
            issuer_private,
            issuer_public,
            value=1,
            nonce=ind_token.sha3_hex("spend-map-v3-b"),
            issued_at=BASE_TIMESTAMP,
        )
        bill_a = ind_token.create_transfer(
            bill_a,
            alice_private,
            alice_public,
            bob_address,
            timestamp=BASE_TIMESTAMP + 10,
        )
        bill_b = ind_token.create_transfer(
            bill_b,
            carol_private,
            carol_public,
            bob_address,
            timestamp=BASE_TIMESTAMP + 20,
        )
        transfer_a = bill_a["history"][-1]
        transfer_b = bill_b["history"][-1]
        log_id = log_client.log_id_from_public_key(operator_public)
        claims = [
            log_client.spend_claim_for_transfer(transfer_a, log_id, 0, BASE_TIMESTAMP + 30),
            log_client.spend_claim_for_transfer(transfer_b, log_id, 1, BASE_TIMESTAMP + 31),
        ]
        target_spend_key = log_client.spend_key_for_transfer(transfer_a)
        tree_size = 2
        spend_root = log_client.spend_map_root(claims)
        root = log_client.make_signed_root(
            tree_size,
            ind_token.sha3_hex("spend-map-v3-root"),
            BASE_TIMESTAMP + 40,
            operator_private,
            operator_public,
            spend_map_root=spend_root,
            spend_map_size=len(claims),
        )
        full_proof = log_client.build_spend_map_proof(claims, target_spend_key, tree_size)
        return {
            "claims": claims,
            "target_spend_key": target_spend_key,
            "tree_size": tree_size,
            "root": root,
            "full_proof": full_proof,
        }
    finally:
        if previous is None:
            os.environ.pop("IND_ALLOW_UNTRUSTED_GENESIS", None)
        else:
            os.environ["IND_ALLOW_UNTRUSTED_GENESIS"] = previous


def _valid_extra_sibling(spend_key, depth):
    side = spend_map_v3._expected_side_by_depth(spend_key)[depth]
    return {
        "depth": depth,
        "side": side,
        "hash": sha3_256(f"non-empty:{depth}".encode("ascii")).hexdigest(),
    }


def _keypair(label):
    order = ecdsa.SECP256k1.order
    seed = int.from_bytes(sha3_256(f"spend-map-v3:{label}".encode("ascii")).digest(), "big")
    secret = ((seed % (order - 1)) + 1).to_bytes(32, "big")
    signing_key = ecdsa.SigningKey.from_string(secret, curve=ecdsa.SECP256k1, hashfunc=sha3_256)
    public_key = base64.b85encode(signing_key.get_verifying_key().to_string()).decode("ascii")
    private_key = base64.b85encode(signing_key.to_string()).decode("ascii")
    return private_key, public_key, ind_token.address_from_public_key(public_key)
