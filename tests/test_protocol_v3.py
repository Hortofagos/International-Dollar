import copy

import pytest

from ind import binary_v3, keys_v3, proof_bundle_v3, protocol_v3
from ind import token as ind_token

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


def _v3_state(address, *, value=5, display_id="5x1"):
    return {
        "sequence": 1,
        "owner_address": address,
        "last_transfer_hash": "11" * 32,
        "last_transfer_timestamp": 1_700_000_000,
        "last_transfer_day": 1_700_000_000 // 86400,
        "transfers_in_last_day": 1,
        "display_id": display_id,
        "value": value,
    }


def test_protocol_rejects_unsupported_bill_denominations():
    with pytest.raises(ind_token.ValidationError, match="allowed IND denomination"):
        ind_token.validate_bill_value(3, "bill value")

    assert ind_token.validate_bill_value(5, "bill value") == 5


def test_protocol_v3_rejects_unsupported_bill_denominations():
    address, _private_key, _public_key = keys_v3.generate_keypair(b"\x31" * 32)

    with pytest.raises(protocol_v3.ProtocolV3Error, match="allowed IND denomination"):
        protocol_v3.checkpoint_core_from_state(
            "token-id",
            "00" * 32,
            _v3_state(address, value=3, display_id="3x1"),
        )


def test_protocol_v3_requires_display_id_value_prefix_to_match_value():
    address, _private_key, _public_key = keys_v3.generate_keypair(b"\x32" * 32)

    with pytest.raises(protocol_v3.ProtocolV3Error, match="value prefix"):
        protocol_v3.checkpoint_core_from_state(
            "token-id",
            "00" * 32,
            _v3_state(address, value=5, display_id="10x1"),
        )


@pytest.mark.parametrize(
    "display_id",
    [
        "2xcofixi16",
        "1x0341108e1",
        "20x0017272",
        "20x",
        "20xx1727",
        "20x-1",
        "02x12",
        "3x232",
        "7x21",
        "1x0",
        "1x6000000001",
        "10x4500000001",
        "100000x100000001",
    ],
)
def test_protocol_v3_rejects_noncanonical_display_ids(display_id):
    with pytest.raises(protocol_v3.ProtocolV3Error, match="display id|denomination"):
        protocol_v3.parse_display_id(display_id, "display id")


@pytest.mark.parametrize(
    "display_id",
    [
        "1x1",
        "1x6000000000",
        "2x42",
        "10x4500000000",
        "20x1727272",
        "100x999999",
        "100000x100000000",
    ],
)
def test_protocol_v3_accepts_canonical_display_ids(display_id):
    parsed = protocol_v3.parse_display_id(display_id)

    assert display_id == protocol_v3.canonical_display_id(parsed["value"], parsed["serial"])


@pytest.mark.parametrize(
    ("value", "issue_index"),
    [
        (1, 0),
        (1, 6_000_000_001),
        (10, 4_500_000_001),
        (100000, 100_000_001),
    ],
)
def test_protocol_v3_rejects_canonical_display_ids_outside_serial_range(value, issue_index):
    with pytest.raises(protocol_v3.ProtocolV3Error, match="range"):
        protocol_v3.canonical_display_id(value, issue_index)


def test_protocol_v3_requires_display_id_serial_to_match_genesis_issue_index(tmp_path):
    fixture = native_v3_archive_fixture(tmp_path, display_id="20x1727272")
    bad_genesis_ref = copy.deepcopy(fixture["genesis_ref"])
    bad_genesis_ref["issue_index"] = 1727273

    with pytest.raises(protocol_v3.ProtocolV3Error, match="issue index"):
        protocol_v3.create_bill_from_checkpoint_core(
            bad_genesis_ref,
            fixture["checkpoint_core"],
            fixture["bundle"],
            trusted_operator_public_key=fixture["log_public"],
            archive_segment_resolver=fixture["archive_resolver"],
        )


def test_protocol_v3_rejects_zero_genesis_issue_index(tmp_path):
    fixture = native_v3_archive_fixture(tmp_path, display_id="1x1")
    bad_genesis_ref = copy.deepcopy(fixture["genesis_ref"])
    bad_genesis_ref["issue_index"] = 0

    with pytest.raises(protocol_v3.ProtocolV3Error, match="issue index"):
        protocol_v3.create_bill_from_checkpoint_core(
            bad_genesis_ref,
            fixture["checkpoint_core"],
            fixture["bundle"],
            trusted_operator_public_key=fixture["log_public"],
            archive_segment_resolver=fixture["archive_resolver"],
        )


def test_protocol_v3_rejects_display_id_serial_above_denomination_cap_in_state():
    address, _private_key, _public_key = keys_v3.generate_keypair(b"\x33" * 32)

    with pytest.raises(protocol_v3.ProtocolV3Error, match="range"):
        protocol_v3.verify_transfer_sequence_from_state(
            "00" * 32,
            _v3_state(address, value=10, display_id="10x4500000001"),
            [],
        )


def test_protocol_v3_rejects_non_v3_owner_addresses_in_checkpoint_state(tmp_path):
    _fixture, bill = _native_bill_fixture(tmp_path)
    bill["checkpoint_core"] = copy.deepcopy(bill["checkpoint_core"])
    bill["checkpoint_core"]["owner_address"] = "not-a-v3-address"

    with pytest.raises(protocol_v3.ProtocolV3Error, match="owner address"):
        protocol_v3.validate_bill_display_id(bill)


def test_protocol_v3_rejects_non_v3_owner_addresses_in_base_state():
    with pytest.raises(protocol_v3.ProtocolV3Error, match="owner address"):
        protocol_v3.verify_transfer_sequence_from_state(
            "00" * 32,
            _v3_state("not-a-v3-address"),
            [],
        )


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


def test_protocol_v3_rejects_legacy_json_binary_envelope():
    legacy_json_envelope = b"".join(
        (
            protocol_v3.BILL_MAGIC,
            binary_v3.encode_uvarint(protocol_v3.VERSION),
            binary_v3.encode_uvarint(protocol_v3.DEFAULT_NETWORK_ID),
            binary_v3.encode_bytes(b"{}"),
        )
    )

    with pytest.raises(protocol_v3.ProtocolV3Error):
        protocol_v3.decode_bill(legacy_json_envelope)


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


@pytest.mark.parametrize(
    ("api_name", "args"),
    [
        ("encode_receipt", ({},)),
        ("decode_receipt", (b"",)),
        ("receipt_hash", ({},)),
        ("verify_receipt_signature", ({},)),
        ("create_receipt", ({}, "", "")),
        ("verify_receipt", ({}, {})),
        ("create_receipt_announcement", ({}, "", "")),
        ("verify_receipt_announcement", ({},)),
    ],
)
def test_protocol_v3_receipt_api_is_disabled(api_name, args):
    with pytest.raises(protocol_v3.ProtocolV3Error, match="ReceiptV3 is not an active protocol"):
        getattr(protocol_v3, api_name)(*args)


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

    with pytest.raises(protocol_v3.ProtocolV3Error, match="timestamp"):
        protocol_v3._transfer_signing_preimage(proof["transfer_b"])


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

    with pytest.raises(protocol_v3.ProtocolV3Error, match="future"):
        protocol_v3._transfer_signing_preimage(proof["transfer_b"])
