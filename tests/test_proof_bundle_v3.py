import copy
import os

import pytest

from ind import proof_bundle_v3, spend_map_v3

from .test_archive_segment_v3 import native_v3_archive_fixture

os.environ.setdefault("IND_ALLOW_UNTRUSTED_GENESIS", "1")

BASE_TIMESTAMP = 1_700_000_000


def test_proof_bundle_v3_verifies_archive_source_and_transparency_proofs(tmp_path):
    fixture = _proof_bundle_fixture(tmp_path)

    checkpoint = proof_bundle_v3.verify_proof_bundle(
        fixture["bundle"],
        expected_checkpoint_hash=fixture["checkpoint"]["checkpoint_hash"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=fixture["archive_resolver"],
    )

    assert checkpoint["checkpoint_hash"] == fixture["checkpoint"]["checkpoint_hash"]
    assert checkpoint["owner_address"] == fixture["bob_address"]


def test_proof_bundle_v3_requires_trusted_policy(tmp_path):
    fixture = _proof_bundle_fixture(tmp_path)

    with pytest.raises(
        proof_bundle_v3.ProofBundleV3Error,
        match="trusted transparency verifier|pinned operator key",
    ):
        proof_bundle_v3.verify_proof_bundle(fixture["bundle"])


def test_proof_bundle_v3_rejects_inclusion_only_bundle(tmp_path):
    fixture = _proof_bundle_fixture(tmp_path)
    bundle = copy.deepcopy(fixture["bundle"])
    bundle["source_evidence"] = {
        "type": proof_bundle_v3.PROOF_ARCHIVE_SEGMENT_TYPE,
        "version": proof_bundle_v3.PROOF_BUNDLE_VERSION,
        "network_id": spend_map_v3.DEFAULT_NETWORK_ID,
        "source_format": proof_bundle_v3.SOURCE_FORMAT_V3_ARCHIVE_SEGMENT,
        "archive_segment_hash": "00" * 32,
        "source_checkpoint_hash": fixture["checkpoint"]["checkpoint_hash"],
        "previous_proof_bundle_hash": None,
        "archive_segment": fixture["archive_segment"],
    }
    bundle = proof_bundle_v3.finalize_proof_bundle(bundle)

    with pytest.raises(proof_bundle_v3.ProofBundleV3Error, match="archive segment hash"):
        proof_bundle_v3.verify_proof_bundle(
            bundle,
            expected_checkpoint_hash=fixture["checkpoint"]["checkpoint_hash"],
            trusted_operator_public_key=fixture["log_public"],
            archive_segment_resolver=fixture["archive_resolver"],
        )


def test_proof_bundle_v3_rejects_wrong_network(tmp_path):
    fixture = _proof_bundle_fixture(tmp_path, network_id=2)

    with pytest.raises(proof_bundle_v3.ProofBundleV3Error, match="network id mismatch"):
        proof_bundle_v3.verify_proof_bundle(
            fixture["bundle"],
            expected_checkpoint_hash=fixture["checkpoint"]["checkpoint_hash"],
            expected_network_id=1,
            trusted_operator_public_key=fixture["log_public"],
            archive_segment_resolver=fixture["archive_resolver"],
        )


def test_proof_bundle_v3_rejects_tampered_hash_and_ref(tmp_path):
    fixture = _proof_bundle_fixture(tmp_path)
    bundle = copy.deepcopy(fixture["bundle"])
    bundle["checkpoint_hash"] = "00" * 32

    with pytest.raises(proof_bundle_v3.ProofBundleV3Error, match="hash mismatch"):
        proof_bundle_v3.verify_proof_bundle(
            bundle,
            trusted_operator_public_key=fixture["log_public"],
        )

    ref = proof_bundle_v3.proof_bundle_ref(fixture["bundle"])
    ref["proof_bundle_hash"] = "11" * 32
    with pytest.raises(proof_bundle_v3.ProofBundleV3Error, match="reference hash mismatch"):
        proof_bundle_v3.verify_proof_bundle_ref(ref, fixture["bundle"])


def test_proof_bundle_v3_binary_envelope_round_trip(tmp_path):
    fixture = _proof_bundle_fixture(tmp_path)

    encoded = proof_bundle_v3.encode_proof_bundle(fixture["bundle"])
    decoded = proof_bundle_v3.decode_proof_bundle(encoded)

    assert decoded == fixture["bundle"]
    with pytest.raises(proof_bundle_v3.ProofBundleV3Error, match="invalid proof bundle magic"):
        proof_bundle_v3.decode_proof_bundle(b"BAD3PBDL" + encoded[len(b"IND3PBDL") :])


def _proof_bundle_fixture(tmp_path, network_id=spend_map_v3.DEFAULT_NETWORK_ID):
    fixture = native_v3_archive_fixture(tmp_path, network_id=network_id)
    return {
        "bundle": fixture["bundle"],
        "checkpoint": fixture["checkpoint_core"],
        "log_public": fixture["log_public"],
        "bob_address": fixture["bob_address"],
        "genesis_ref": fixture["genesis_ref"],
        "archive_resolver": fixture["archive_resolver"],
        "archive_segment": fixture["archive_segment"],
    }
