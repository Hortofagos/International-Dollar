from ind import protocol_v3, wallet_services
from ind.store import INDLocalStore

from .test_archive_segment_v3 import native_v3_archive_fixture


def test_store_v3_persists_archive_bundle_and_bill(tmp_path):
    fixture = native_v3_archive_fixture(tmp_path)
    store = INDLocalStore(db_path=tmp_path / "wallet-v3.db", require_transparency=False)

    segment_hash = store.store_archive_segment_v3(fixture["archive_segment"])
    store.store_proof_bundle_v3(
        fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
    )
    bill = protocol_v3.create_bill_from_checkpoint_core(
        fixture["genesis_ref"],
        fixture["checkpoint_core"],
        fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=store.archive_segment_resolver_v3,
    )
    bill_hash = store.store_bill_v3(
        bill,
        status="settled",
        trusted_operator_public_key=fixture["log_public"],
    )

    assert store.get_archive_segment_v3(segment_hash) == fixture["archive_segment"]
    assert store.get_proof_bundle_v3(fixture["bundle"]["proof_bundle_hash"]) == fixture["bundle"]
    assert store.get_bill_v3(bill_hash) == bill
    assert store.get_bill_v3_by_token_id(fixture["token_id"]) == bill
    assert store.get_bill_v3_by_display_id("1xnative-v3") == bill

    state = protocol_v3.verify_bill(
        store.get_bill_v3(bill_hash),
        proof_bundle_resolver=store.proof_bundle_resolver_v3,
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=store.archive_segment_resolver_v3,
    )
    assert state.owner_address == fixture["bob_address"]


def test_store_v3_persists_receipts_and_conflict_proofs(tmp_path):
    fixture = native_v3_archive_fixture(tmp_path)
    store = INDLocalStore(db_path=tmp_path / "wallet-v3.db", require_transparency=False)
    store.store_archive_segment_v3(fixture["archive_segment"])
    store.store_proof_bundle_v3(
        fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
    )
    bill = protocol_v3.create_bill_from_checkpoint_core(
        fixture["genesis_ref"],
        fixture["checkpoint_core"],
        fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=store.archive_segment_resolver_v3,
    )
    transferred = protocol_v3.create_transfer(
        bill,
        fixture["bob_private"],
        fixture["bob_public"],
        fixture["carol_address"],
        proof_bundle_resolver=store.proof_bundle_resolver_v3,
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=store.archive_segment_resolver_v3,
        timestamp=1_700_000_050,
    )
    receipt = protocol_v3.create_receipt(
        transferred,
        fixture["carol_private"],
        fixture["carol_public"],
        proof_bundle_resolver=store.proof_bundle_resolver_v3,
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=store.archive_segment_resolver_v3,
        timestamp=1_700_000_060,
    )

    receipt_hash = store.store_receipt_v3(
        transferred,
        receipt,
        trusted_operator_public_key=fixture["log_public"],
    )

    conflict = protocol_v3.create_conflict_proof_from_transfers(
        transferred["recent_transfers"][0],
        protocol_v3.create_transfer(
            bill,
            fixture["bob_private"],
            fixture["bob_public"],
            fixture["alice_address"],
            proof_bundle_resolver=store.proof_bundle_resolver_v3,
            trusted_operator_public_key=fixture["log_public"],
            archive_segment_resolver=store.archive_segment_resolver_v3,
            timestamp=1_700_000_051,
        )["recent_transfers"][0],
    )
    conflict_hash = store.store_conflict_proof_v3(conflict)

    assert receipt_hash == protocol_v3.receipt_hash(receipt)
    assert conflict_hash == conflict["proof_hash"]


def test_wallet_services_v3_spends_stored_bill(tmp_path):
    fixture = native_v3_archive_fixture(tmp_path)
    store = INDLocalStore(db_path=tmp_path / "wallet-v3.db", require_transparency=False)
    store.store_archive_segment_v3(fixture["archive_segment"])
    store.store_proof_bundle_v3(
        fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
    )
    bill = protocol_v3.create_bill_from_checkpoint_core(
        fixture["genesis_ref"],
        fixture["checkpoint_core"],
        fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=store.archive_segment_resolver_v3,
    )
    store.store_bill_v3(
        bill,
        status="settled",
        trusted_operator_public_key=fixture["log_public"],
    )
    wallet_lines = [fixture["bob_address"], fixture["bob_private"], fixture["bob_public"]]

    state = wallet_services.spend_wallet_bill_v3(
        wallet_lines,
        "1xnative-v3 wallet",
        fixture["carol_address"],
        store=store,
        trusted_operator_public_key=fixture["log_public"],
        timestamp=1_700_000_050,
    )

    assert state.owner_address == fixture["carol_address"]
    assert store.get_bill_v3_by_token_id(fixture["token_id"])["recent_transfers"]
