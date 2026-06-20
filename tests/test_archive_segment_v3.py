import copy
import os
from hashlib import sha3_256

import pytest

from ind import archive_segment_v3, keys_v3, proof_bundle_v3, protocol_v3, spend_map_v3
from ind import transparency_server as log_server

os.environ.setdefault("IND_ALLOW_UNTRUSTED_GENESIS", "1")

BASE_TIMESTAMP = 1_700_000_000


def test_archive_segment_v3_verifies_native_transfer_chain(tmp_path):
    fixture = native_v3_archive_fixture(tmp_path)

    checkpoint = archive_segment_v3.verify_archive_segment(fixture["archive_segment"])

    assert checkpoint["checkpoint_hash"] == fixture["checkpoint_core"]["checkpoint_hash"]
    assert checkpoint["owner_address"] == fixture["bob_address"]


def test_archive_segment_v3_rejects_tampering(tmp_path):
    fixture = native_v3_archive_fixture(tmp_path)
    segment = copy.deepcopy(fixture["archive_segment"])
    segment["transfers"][0]["recipient_address"] = fixture["alice_address"]

    with pytest.raises(archive_segment_v3.ArchiveSegmentV3Error, match="hash mismatch"):
        archive_segment_v3.verify_archive_segment(segment)

    segment = copy.deepcopy(fixture["archive_segment"])
    segment["segment_hash"] = "00" * 32
    with pytest.raises(archive_segment_v3.ArchiveSegmentV3Error, match="hash mismatch"):
        archive_segment_v3.verify_archive_segment(segment)


def test_proof_bundle_v3_verifies_archive_segment_by_resolver(tmp_path):
    fixture = native_v3_archive_fixture(tmp_path)

    checkpoint = proof_bundle_v3.verify_proof_bundle(
        fixture["bundle"],
        expected_checkpoint_hash=fixture["checkpoint_core"]["checkpoint_hash"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=fixture["archive_resolver"],
    )

    assert checkpoint["checkpoint_hash"] == fixture["checkpoint_core"]["checkpoint_hash"]


def test_proof_bundle_v3_requires_archive_segment_resolver(tmp_path):
    fixture = native_v3_archive_fixture(tmp_path)

    with pytest.raises(proof_bundle_v3.ProofBundleV3Error, match="archive segment resolver"):
        proof_bundle_v3.verify_proof_bundle(
            fixture["bundle"],
            expected_checkpoint_hash=fixture["checkpoint_core"]["checkpoint_hash"],
            trusted_operator_public_key=fixture["log_public"],
        )


def test_archive_segment_v3_recursively_resolves_previous_segments(tmp_path):
    fixture = native_v3_archive_fixture(tmp_path)
    second_transfer = protocol_v3.create_transfer_from_state(
        fixture["token_id"],
        protocol_v3._initial_state_from_checkpoint_core(fixture["checkpoint_core"]),
        fixture["bob_private"],
        fixture["bob_public"],
        fixture["carol_address"],
        timestamp=BASE_TIMESTAMP + 50,
    )
    second_segment = archive_segment_v3.make_archive_segment(
        fixture["token_id"],
        fixture["genesis_ref"],
        protocol_v3._initial_state_from_checkpoint_core(fixture["checkpoint_core"]),
        [second_transfer],
        previous_segment_hash=fixture["archive_segment"]["segment_hash"],
        previous_checkpoint_hash=fixture["checkpoint_core"]["checkpoint_hash"],
    )
    segments = {
        fixture["archive_segment"]["segment_hash"]: fixture["archive_segment"],
        second_segment["segment_hash"]: second_segment,
    }

    with pytest.raises(
        archive_segment_v3.ArchiveSegmentV3Error,
        match="previous archive segment resolver",
    ):
        archive_segment_v3.verify_archive_segment(second_segment)

    checkpoint = archive_segment_v3.verify_archive_segment(
        second_segment,
        previous_segment_resolver=lambda segment_hash: segments[segment_hash],
    )

    assert checkpoint["previous_checkpoint_hash"] == fixture["checkpoint_core"]["checkpoint_hash"]
    assert checkpoint["owner_address"] == fixture["carol_address"]


def test_proof_bundle_v3_recursively_verifies_previous_checkpoint_bundle(tmp_path):
    fixture = native_v3_archive_fixture(tmp_path)
    second_transfer = protocol_v3.create_transfer_from_state(
        fixture["token_id"],
        protocol_v3._initial_state_from_checkpoint_core(fixture["checkpoint_core"]),
        fixture["bob_private"],
        fixture["bob_public"],
        fixture["carol_address"],
        timestamp=BASE_TIMESTAMP + 50,
    )
    second_segment = archive_segment_v3.make_archive_segment(
        fixture["token_id"],
        fixture["genesis_ref"],
        protocol_v3._initial_state_from_checkpoint_core(fixture["checkpoint_core"]),
        [second_transfer],
        previous_segment_hash=fixture["archive_segment"]["segment_hash"],
        previous_checkpoint_hash=fixture["checkpoint_core"]["checkpoint_hash"],
    )
    segments = {
        fixture["archive_segment"]["segment_hash"]: fixture["archive_segment"],
        second_segment["segment_hash"]: second_segment,
    }

    def archive_resolver(segment_hash):
        return segments[segment_hash]

    second_checkpoint = archive_segment_v3.verify_archive_segment(
        second_segment,
        previous_segment_resolver=archive_resolver,
    )
    second_bundle = _append_native_checkpoint_bundle(
        fixture,
        second_segment,
        second_transfer,
        second_checkpoint,
        BASE_TIMESTAMP + 60,
        previous_proof_bundle_hash=fixture["bundle"]["proof_bundle_hash"],
        archive_resolver=archive_resolver,
    )
    bundles = {
        fixture["bundle"]["proof_bundle_hash"]: fixture["bundle"],
        second_bundle["proof_bundle_hash"]: second_bundle,
    }

    with pytest.raises(proof_bundle_v3.ProofBundleV3Error, match="previous proof bundle resolver"):
        proof_bundle_v3.verify_proof_bundle(
            second_bundle,
            expected_checkpoint_hash=second_checkpoint["checkpoint_hash"],
            trusted_operator_public_key=fixture["log_public"],
            archive_segment_resolver=archive_resolver,
        )

    checkpoint = proof_bundle_v3.verify_proof_bundle(
        second_bundle,
        expected_checkpoint_hash=second_checkpoint["checkpoint_hash"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=archive_resolver,
        proof_bundle_resolver=lambda proof_hash: bundles[proof_hash],
    )

    assert checkpoint["checkpoint_hash"] == second_checkpoint["checkpoint_hash"]


def native_v3_archive_fixture(
    tmp_path,
    network_id=spend_map_v3.DEFAULT_NETWORK_ID,
    operator_label="native-log",
    token_label="native-v3-token",
    genesis_label="native-v3-genesis",
    display_id="1x1",
):
    log_private, log_public, _log_address = _operator_keypair(operator_label)
    log = log_server.TransparencyLog(str(tmp_path / f"{operator_label}.db"), log_private, log_public)
    alice_address, alice_private, alice_public = keys_v3.generate_keypair(b"\x21" * 32)
    bob_address, bob_private, bob_public = keys_v3.generate_keypair(b"\x22" * 32)
    carol_address, carol_private, carol_public = keys_v3.generate_keypair(b"\x23" * 32)
    genesis_hash = sha3_256(str(genesis_label).encode("ascii")).hexdigest()
    token_id = sha3_256(str(token_label).encode("ascii")).hexdigest()
    parsed_display = protocol_v3.parse_display_id(display_id, "fixture display id")
    genesis_ref = {
        "type": protocol_v3.GENESIS_REF_TYPE,
        "version": protocol_v3.VERSION,
        "network_id": int(network_id),
        "genesis_hash": genesis_hash,
        "manifest_hash": None,
        "issuer_key_id": None,
        "issue_index": int(parsed_display["serial"]),
        "issued_at": BASE_TIMESTAMP,
    }
    base_state = {
        "sequence": 0,
        "owner_address": alice_address,
        "last_transfer_hash": genesis_hash,
        "last_transfer_timestamp": BASE_TIMESTAMP,
        "last_transfer_day": BASE_TIMESTAMP // 86400,
        "transfers_in_last_day": 0,
        "display_id": display_id,
        "value": int(parsed_display["value"]),
    }
    first_transfer = protocol_v3.create_transfer_from_state(
        token_id,
        base_state,
        alice_private,
        alice_public,
        bob_address,
        timestamp=BASE_TIMESTAMP + 10,
        network_id=network_id,
    )
    archive_segment = archive_segment_v3.make_archive_segment(
        token_id,
        genesis_ref,
        base_state,
        [first_transfer],
        network_id=network_id,
    )
    checkpoint_core = archive_segment_v3.verify_archive_segment(
        archive_segment,
        expected_network_id=network_id,
    )
    transfer_hash = protocol_v3.transfer_hash(first_transfer)
    transfer_append = log.append_entry_hash(
        transfer_hash,
        submitted_at=BASE_TIMESTAMP + 20,
        transfer=first_transfer,
    )
    claim = protocol_v3.spend_claim_for_transfer(
        first_transfer,
        log.log_id,
        transfer_append["leaf_index"],
        BASE_TIMESTAMP + 20,
    )
    with log._connect() as conn:
        log._record_spend_claim(
            conn,
            claim,
            transfer_hash,
            transfer_append["leaf_index"],
            BASE_TIMESTAMP + 20,
        )
    checkpoint_append = log.append_entry_hash(
        checkpoint_core["checkpoint_hash"],
        submitted_at=BASE_TIMESTAMP + 21,
        entry_kind="checkpoint",
        entry=checkpoint_core,
    )
    root = log.publish_root(BASE_TIMESTAMP + 40)
    inclusion = log.inclusion_proof(checkpoint_append["entry_hash"], root["tree_size"])
    with log._connect() as conn:
        claims = log._spend_claim_records(conn, tree_size=root["tree_size"])
    compressed = spend_map_v3.build_compressed_spend_map_proof(
        claims,
        protocol_v3.spend_key_for_transfer(first_transfer),
        root["tree_size"],
        network_id=network_id,
    )
    source_evidence = proof_bundle_v3.make_archive_segment_evidence(
        archive_segment,
        network_id=network_id,
        include_segment=False,
    )
    bundle = proof_bundle_v3.make_proof_bundle(
        checkpoint_core,
        root,
        inclusion,
        compressed,
        source_evidence,
        network_id=network_id,
        created_at=BASE_TIMESTAMP + 41,
    )
    segments = {archive_segment["segment_hash"]: archive_segment}
    return {
        "log": log,
        "archive_segment": archive_segment,
        "archive_resolver": lambda segment_hash: segments[segment_hash],
        "bundle": bundle,
        "checkpoint_core": checkpoint_core,
        "genesis_ref": genesis_ref,
        "log_public": log_public,
        "token_id": token_id,
        "first_transfer": first_transfer,
        "alice_address": alice_address,
        "bob_address": bob_address,
        "bob_private": bob_private,
        "bob_public": bob_public,
        "carol_address": carol_address,
        "carol_private": carol_private,
        "carol_public": carol_public,
    }


def _append_native_checkpoint_bundle(
    fixture,
    archive_segment,
    transfer,
    checkpoint,
    submitted_at,
    previous_proof_bundle_hash=None,
    archive_resolver=None,
):
    log = fixture["log"]
    transfer_hash = protocol_v3.transfer_hash(transfer)
    transfer_append = log.append_entry_hash(
        transfer_hash,
        submitted_at=submitted_at,
        transfer=transfer,
    )
    claim = protocol_v3.spend_claim_for_transfer(
        transfer,
        log.log_id,
        transfer_append["leaf_index"],
        submitted_at,
    )
    with log._connect() as conn:
        log._record_spend_claim(
            conn,
            claim,
            transfer_hash,
            transfer_append["leaf_index"],
            submitted_at,
        )
    checkpoint_append = log.append_entry_hash(
        checkpoint["checkpoint_hash"],
        submitted_at=submitted_at + 1,
        entry_kind="checkpoint",
        entry=checkpoint,
    )
    root = log.publish_root(submitted_at + 20)
    inclusion = log.inclusion_proof(checkpoint_append["entry_hash"], root["tree_size"])
    with log._connect() as conn:
        claims = log._spend_claim_records(conn, tree_size=root["tree_size"])
    compressed = spend_map_v3.build_compressed_spend_map_proof(
        claims,
        protocol_v3.spend_key_for_transfer(transfer),
        root["tree_size"],
        network_id=archive_segment["network_id"],
    )
    source_evidence = proof_bundle_v3.make_archive_segment_evidence(
        archive_segment,
        network_id=archive_segment["network_id"],
        include_segment=False,
        previous_proof_bundle_hash=previous_proof_bundle_hash,
        previous_segment_resolver=archive_resolver,
    )
    return proof_bundle_v3.make_proof_bundle(
        checkpoint,
        root,
        inclusion,
        compressed,
        source_evidence,
        network_id=archive_segment["network_id"],
        created_at=submitted_at + 21,
    )


def _operator_keypair(label):
    seed = sha3_256(f"archive-segment-v3:{label}".encode("ascii")).digest()
    address, private_key, public_key = keys_v3.generate_keypair(seed)
    return private_key, public_key, address
