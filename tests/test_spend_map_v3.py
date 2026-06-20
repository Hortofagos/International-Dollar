from hashlib import sha3_256

import pytest

from ind import keys_v3, protocol_v3, spend_map_v3
from ind import transparency_client as log_client

BASE_TIMESTAMP = 1_700_000_000


def test_compressed_spend_map_proof_matches_sparse_root_semantics():
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
    alice_address, alice_private, alice_public = keys_v3.generate_keypair(b"\x41" * 32)
    bob_address, _bob_private, _bob_public = keys_v3.generate_keypair(b"\x42" * 32)
    carol_address, carol_private, carol_public = keys_v3.generate_keypair(b"\x43" * 32)
    operator_private, operator_public = _operator_keypair("operator")
    state_a = _base_state(alice_address, "1x90", "spend-map-v3-a")
    state_b = _base_state(carol_address, "1x91", "spend-map-v3-b")
    token_a = sha3_256(b"spend-map-v3-token-a").hexdigest()
    token_b = sha3_256(b"spend-map-v3-token-b").hexdigest()
    transfer_a = protocol_v3.create_transfer_from_state(
        token_a,
        state_a,
        alice_private,
        alice_public,
        bob_address,
        timestamp=BASE_TIMESTAMP + 10,
    )
    transfer_b = protocol_v3.create_transfer_from_state(
        token_b,
        state_b,
        carol_private,
        carol_public,
        bob_address,
        timestamp=BASE_TIMESTAMP + 20,
    )
    log_id = log_client.log_id_from_public_key(operator_public)
    claims = [
        protocol_v3.spend_claim_for_transfer(transfer_a, log_id, 0, BASE_TIMESTAMP + 30),
        protocol_v3.spend_claim_for_transfer(transfer_b, log_id, 1, BASE_TIMESTAMP + 31),
    ]
    target_spend_key = protocol_v3.spend_key_for_transfer(transfer_a)
    tree_size = 2
    spend_root = log_client.spend_map_root(claims)
    root = log_client.make_signed_root(
        tree_size,
        sha3_256(b"spend-map-v3-root").hexdigest(),
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


def _valid_extra_sibling(spend_key, depth):
    side = spend_map_v3._expected_side_by_depth(spend_key)[depth]
    return {
        "depth": depth,
        "side": side,
        "hash": sha3_256(f"non-empty:{depth}".encode("ascii")).hexdigest(),
    }


def _base_state(owner_address, display_id, label):
    return {
        "sequence": 0,
        "owner_address": owner_address,
        "last_transfer_hash": sha3_256(label.encode("ascii")).hexdigest(),
        "last_transfer_timestamp": BASE_TIMESTAMP,
        "last_transfer_day": BASE_TIMESTAMP // 86400,
        "transfers_in_last_day": 0,
        "display_id": display_id,
        "value": 1,
    }


def _operator_keypair(label):
    seed = sha3_256(f"spend-map-v3:{label}".encode("ascii")).digest()
    _address, private_key, public_key = keys_v3.generate_keypair(seed)
    return private_key, public_key
