import copy

import pytest

from ind import keys_v3, proof_bundle_v3, protocol_v3

from .test_archive_segment_v3 import native_v3_archive_fixture


def _native_bill_fixture(tmp_path):
    fixture = native_v3_archive_fixture(tmp_path)
    bill = protocol_v3.create_bill_from_checkpoint_core(
        fixture["genesis_ref"],
        fixture["checkpoint_core"],
        fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=fixture["archive_resolver"],
    )
    return fixture, bill


def test_protocol_v3_thin_bill_verifies_with_proof_bundle(tmp_path):
    fixture, bill = _native_bill_fixture(tmp_path)

    state = protocol_v3.verify_bill(
        bill,
        proof_bundle=fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=fixture["archive_resolver"],
    )

    assert state.owner_address == fixture["bob_address"]
    assert state.sequence == fixture["checkpoint_core"]["sequence"]
    assert state.last_transfer_hash == fixture["checkpoint_core"]["last_transfer_hash"]


def test_protocol_v3_binary_bill_round_trip(tmp_path):
    fixture, bill = _native_bill_fixture(tmp_path)

    decoded = protocol_v3.decode_bill(protocol_v3.encode_bill(bill))

    assert decoded == bill
    assert protocol_v3.verify_bill(
        decoded,
        proof_bundle=fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=fixture["archive_resolver"],
    )


def test_protocol_v3_requires_available_proof_bundle(tmp_path):
    fixture, bill = _native_bill_fixture(tmp_path)

    with pytest.raises(protocol_v3.ProtocolV3Error, match="proof bundle is required"):
        protocol_v3.verify_bill(
            bill,
            trusted_operator_public_key=fixture["log_public"],
            archive_segment_resolver=fixture["archive_resolver"],
        )


def test_protocol_v3_rejects_proof_bundle_ref_mismatch(tmp_path):
    fixture, bill = _native_bill_fixture(tmp_path)
    bill["proof_bundle_ref"] = copy.deepcopy(bill["proof_bundle_ref"])
    bill["proof_bundle_ref"]["proof_bundle_hash"] = "22" * 32

    with pytest.raises(proof_bundle_v3.ProofBundleV3Error, match="reference hash mismatch"):
        protocol_v3.verify_bill(
            bill,
            proof_bundle=fixture["bundle"],
            trusted_operator_public_key=fixture["log_public"],
            archive_segment_resolver=fixture["archive_resolver"],
        )


def test_protocol_v3_rejects_inclusion_only_bundle(tmp_path):
    fixture, bill = _native_bill_fixture(tmp_path)
    bad_bundle = copy.deepcopy(fixture["bundle"])
    bad_bundle["source_evidence"] = {
        "type": proof_bundle_v3.PROOF_ARCHIVE_SEGMENT_TYPE,
        "version": proof_bundle_v3.PROOF_BUNDLE_VERSION,
        "network_id": proof_bundle_v3.DEFAULT_NETWORK_ID,
        "source_format": proof_bundle_v3.SOURCE_FORMAT_V3_ARCHIVE_SEGMENT,
        "archive_segment_hash": "00" * 32,
        "source_checkpoint_hash": fixture["checkpoint_core"]["checkpoint_hash"],
        "previous_proof_bundle_hash": None,
        "archive_segment": fixture["archive_segment"],
    }
    bad_bundle = proof_bundle_v3.finalize_proof_bundle(bad_bundle)
    bill["proof_bundle_ref"] = proof_bundle_v3.proof_bundle_ref(bad_bundle)

    with pytest.raises(proof_bundle_v3.ProofBundleV3Error, match="archive segment hash"):
        protocol_v3.verify_bill(
            bill,
            proof_bundle=bad_bundle,
            trusted_operator_public_key=fixture["log_public"],
            archive_segment_resolver=fixture["archive_resolver"],
        )


def test_protocol_v3_appends_and_verifies_native_recent_transfer(tmp_path):
    fixture = native_v3_archive_fixture(tmp_path)
    bill = protocol_v3.create_bill_from_checkpoint_core(
        fixture["genesis_ref"],
        fixture["checkpoint_core"],
        fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=fixture["archive_resolver"],
    )

    next_bill = protocol_v3.create_transfer(
        bill,
        fixture["bob_private"],
        fixture["bob_public"],
        fixture["carol_address"],
        proof_bundle=fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=fixture["archive_resolver"],
        timestamp=1_700_000_050,
    )
    state = protocol_v3.verify_bill(
        next_bill,
        proof_bundle=fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=fixture["archive_resolver"],
    )

    assert state.sequence == fixture["checkpoint_core"]["sequence"] + 1
    assert state.owner_address == fixture["carol_address"]


def test_protocol_v3_rejects_wrong_native_recent_sender(tmp_path):
    fixture = native_v3_archive_fixture(tmp_path)
    bill = protocol_v3.create_bill_from_checkpoint_core(
        fixture["genesis_ref"],
        fixture["checkpoint_core"],
        fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=fixture["archive_resolver"],
    )

    with pytest.raises(protocol_v3.ProtocolV3Error, match="sender key"):
        protocol_v3.create_transfer(
            bill,
            fixture["carol_private"],
            fixture["carol_public"],
            fixture["carol_address"],
            proof_bundle=fixture["bundle"],
            trusted_operator_public_key=fixture["log_public"],
            archive_segment_resolver=fixture["archive_resolver"],
            timestamp=1_700_000_050,
        )


def test_protocol_v3_creates_and_verifies_native_receipt(tmp_path):
    fixture = native_v3_archive_fixture(tmp_path)
    bill = protocol_v3.create_bill_from_checkpoint_core(
        fixture["genesis_ref"],
        fixture["checkpoint_core"],
        fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=fixture["archive_resolver"],
    )
    next_bill = protocol_v3.create_transfer(
        bill,
        fixture["bob_private"],
        fixture["bob_public"],
        fixture["carol_address"],
        proof_bundle=fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=fixture["archive_resolver"],
        timestamp=1_700_000_050,
    )

    receipt = protocol_v3.create_receipt(
        next_bill,
        fixture["carol_private"],
        fixture["carol_public"],
        proof_bundle=fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=fixture["archive_resolver"],
        timestamp=1_700_000_060,
    )
    state = protocol_v3.verify_receipt(
        next_bill,
        receipt,
        proof_bundle=fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=fixture["archive_resolver"],
    )

    assert state.owner_address == fixture["carol_address"]
    assert receipt["network_id"] == protocol_v3.DEFAULT_NETWORK_ID


def test_protocol_v3_rejects_wrong_receipt_signer(tmp_path):
    fixture = native_v3_archive_fixture(tmp_path)
    bill = protocol_v3.create_bill_from_checkpoint_core(
        fixture["genesis_ref"],
        fixture["checkpoint_core"],
        fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=fixture["archive_resolver"],
    )

    with pytest.raises(protocol_v3.ProtocolV3Error, match="bill recipient"):
        protocol_v3.create_receipt(
            bill,
            fixture["carol_private"],
            fixture["carol_public"],
            proof_bundle=fixture["bundle"],
            trusted_operator_public_key=fixture["log_public"],
            archive_segment_resolver=fixture["archive_resolver"],
        )


def test_protocol_v3_creates_and_verifies_conflict_proof(tmp_path):
    fixture = native_v3_archive_fixture(tmp_path)
    dave_address, _dave_private, _dave_public = keys_v3.generate_keypair(b"\x24" * 32)
    bill = protocol_v3.create_bill_from_checkpoint_core(
        fixture["genesis_ref"],
        fixture["checkpoint_core"],
        fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=fixture["archive_resolver"],
    )
    branch_a = protocol_v3.create_transfer(
        bill,
        fixture["bob_private"],
        fixture["bob_public"],
        fixture["carol_address"],
        proof_bundle=fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=fixture["archive_resolver"],
        timestamp=1_700_000_050,
    )
    branch_b = protocol_v3.create_transfer(
        bill,
        fixture["bob_private"],
        fixture["bob_public"],
        dave_address,
        proof_bundle=fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=fixture["archive_resolver"],
        timestamp=1_700_000_051,
    )

    proof = protocol_v3.create_conflict_proof(
        branch_a,
        branch_b,
        proof_bundle_a=fixture["bundle"],
        proof_bundle_b=fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=fixture["archive_resolver"],
        detected_at=1_700_000_070,
    )

    assert protocol_v3.verify_conflict_proof(proof)
    assert proof["spend_key"] == protocol_v3.spend_key_for_transfer(proof["transfer_a"])


def test_protocol_v3_rejects_tampered_conflict_proof(tmp_path):
    fixture = native_v3_archive_fixture(tmp_path)
    dave_address, _dave_private, _dave_public = keys_v3.generate_keypair(b"\x24" * 32)
    bill = protocol_v3.create_bill_from_checkpoint_core(
        fixture["genesis_ref"],
        fixture["checkpoint_core"],
        fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=fixture["archive_resolver"],
    )
    branch_a = protocol_v3.create_transfer(
        bill,
        fixture["bob_private"],
        fixture["bob_public"],
        fixture["carol_address"],
        proof_bundle=fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=fixture["archive_resolver"],
        timestamp=1_700_000_050,
    )
    branch_b = protocol_v3.create_transfer(
        bill,
        fixture["bob_private"],
        fixture["bob_public"],
        dave_address,
        proof_bundle=fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=fixture["archive_resolver"],
        timestamp=1_700_000_051,
    )
    proof = protocol_v3.create_conflict_proof(
        branch_a,
        branch_b,
        proof_bundle_a=fixture["bundle"],
        proof_bundle_b=fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=fixture["archive_resolver"],
    )
    proof["transfer_b"] = copy.deepcopy(proof["transfer_b"])
    proof["transfer_b"]["signature"] = "00" * 64

    with pytest.raises(protocol_v3.ProtocolV3Error, match="signature|fields|hash"):
        protocol_v3.verify_conflict_proof(proof)


def test_protocol_v3_rejects_conflict_proof_with_negative_transfer_timestamp(tmp_path):
    fixture = native_v3_archive_fixture(tmp_path)
    dave_address, _dave_private, _dave_public = keys_v3.generate_keypair(b"\x24" * 32)
    bill = protocol_v3.create_bill_from_checkpoint_core(
        fixture["genesis_ref"],
        fixture["checkpoint_core"],
        fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=fixture["archive_resolver"],
    )
    branch_a = protocol_v3.create_transfer(
        bill,
        fixture["bob_private"],
        fixture["bob_public"],
        fixture["carol_address"],
        proof_bundle=fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=fixture["archive_resolver"],
        timestamp=1_700_000_050,
    )
    branch_b = protocol_v3.create_transfer(
        bill,
        fixture["bob_private"],
        fixture["bob_public"],
        dave_address,
        proof_bundle=fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=fixture["archive_resolver"],
        timestamp=1_700_000_051,
    )
    proof = protocol_v3.create_conflict_proof(
        branch_a,
        branch_b,
        proof_bundle_a=fixture["bundle"],
        proof_bundle_b=fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=fixture["archive_resolver"],
    )
    proof["transfer_b"] = copy.deepcopy(proof["transfer_b"])
    proof["transfer_b"]["timestamp"] = -1
    proof["transfer_b"]["signature"] = keys_v3.sign(
        fixture["bob_private"],
        protocol_v3._transfer_signing_preimage(proof["transfer_b"]),
    ).hex()

    with pytest.raises(protocol_v3.ProtocolV3Error, match="timestamp"):
        protocol_v3.verify_conflict_proof(proof)


def test_protocol_v3_rejects_conflict_proof_with_far_future_transfer_timestamp(tmp_path):
    fixture = native_v3_archive_fixture(tmp_path)
    dave_address, _dave_private, _dave_public = keys_v3.generate_keypair(b"\x24" * 32)
    bill = protocol_v3.create_bill_from_checkpoint_core(
        fixture["genesis_ref"],
        fixture["checkpoint_core"],
        fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=fixture["archive_resolver"],
    )
    branch_a = protocol_v3.create_transfer(
        bill,
        fixture["bob_private"],
        fixture["bob_public"],
        fixture["carol_address"],
        proof_bundle=fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=fixture["archive_resolver"],
        timestamp=1_700_000_050,
    )
    branch_b = protocol_v3.create_transfer(
        bill,
        fixture["bob_private"],
        fixture["bob_public"],
        dave_address,
        proof_bundle=fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=fixture["archive_resolver"],
        timestamp=1_700_000_051,
    )
    proof = protocol_v3.create_conflict_proof(
        branch_a,
        branch_b,
        proof_bundle_a=fixture["bundle"],
        proof_bundle_b=fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=fixture["archive_resolver"],
    )
    proof["transfer_b"] = copy.deepcopy(proof["transfer_b"])
    proof["transfer_b"]["timestamp"] = 9_999_999_999
    proof["transfer_b"]["signature"] = keys_v3.sign(
        fixture["bob_private"],
        protocol_v3._transfer_signing_preimage(proof["transfer_b"]),
    ).hex()

    with pytest.raises(protocol_v3.ProtocolV3Error, match="future"):
        protocol_v3.verify_conflict_proof(proof)
