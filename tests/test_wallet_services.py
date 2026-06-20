import pytest

from ind import keys_v3
from ind import protocol as ind_token
from ind import protocol_v3
from ind import runtime as runtime_json
from ind import wallet_services
from ind.store import INDLocalStore

from .test_archive_segment_v3 import native_v3_archive_fixture


def test_wallet_display_label_keeps_invalid_ids_unmodified():
    assert wallet_services.wallet_display_label("1x0341108e1") == "1x0341108e1"
    assert wallet_services.wallet_display_label("2xcofixi16") == "2xcofixi16"


def test_wallet_display_label_keeps_canonical_and_named_ids():
    assert wallet_services.wallet_display_label("5x0") == "5x0"
    assert wallet_services.wallet_display_label("-5x0") == "-5x0"
    assert wallet_services.wallet_display_label("1xnative-v3") == "1xnative-v3"


def test_wallet_display_value_reads_denomination_prefix():
    assert wallet_services.wallet_display_value("100x0341108e4") == 0
    assert wallet_services.wallet_display_value("5x2") == 5
    assert wallet_services.wallet_display_value("-20x3") == 20
    assert wallet_services.wallet_display_value("not-a-bill") == 0


def test_wallet_owned_line_value_ignores_sent_rows():
    assert wallet_services.wallet_owned_line_value("100x0341108e4 2 1781546789") == 0
    assert wallet_services.wallet_owned_line_value("-100x0341108e4 3 1781546900") == 0


def test_filter_locally_sent_records_excludes_wallet_marked_sent_bills():
    records = [
        {"display_id": "1x1"},
        {"display_id": "1x2"},
        {"display_id": "2x3"},
    ]
    wallet_lines = [
        "x324sq85mgDVTGK4oHXw2b2LHh4YFriSx\n",
        "private\n",
        "public\n",
        "1x1 1 1781546789\n",
        "-1x2 2 1781546900\n",
    ]

    assert wallet_services.wallet_sent_display_ids(wallet_lines) == {"1x2"}
    assert wallet_services.filter_locally_sent_records(records, wallet_lines) == [
        {"display_id": "1x1"},
        {"display_id": "2x3"},
    ]


def test_wallet_record_queries_are_unlimited_by_default():
    address, _private_key, _public_key = keys_v3.generate_keypair(b"wallet-record-limit-test-0000001")
    calls = []

    class Store:
        def bill_v3_records_for_owner(self, owner_address, statuses=None, limit="unexpected"):
            calls.append((owner_address, statuses, limit))
            return []

    store = Store()

    assert wallet_services.spendable_wallet_records(address, store=store) == []
    assert wallet_services.pending_wallet_records(address, store=store) == []
    assert calls == [
        (address, ("settled", "verified"), None),
        (address, ("pending",), None),
    ]


def test_validate_recipient_address_accepts_generated_v3_address():
    address = "x324sq85mgDVTGK4oHXw2b2LHh4YFriSx"

    assert wallet_services.validate_recipient_address(f" {address}\n") == address


def test_validate_recipient_address_rejects_non_v3_address():
    with pytest.raises(ind_token.ValidationError, match="invalid recipient address"):
        wallet_services.validate_recipient_address("not-a-v3-address")


def test_claim_bill_payload_v3_uses_embedded_proof_context(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("IND_NETWORK", "testnet")
    monkeypatch.setenv("IND_NODE_PORT", "18888")
    monkeypatch.setenv("IND_STORE_PATH", str(tmp_path / "wallet.sqlite3"))
    fixture = native_v3_archive_fixture(tmp_path / "fixture")
    bill = protocol_v3.create_bill_from_checkpoint_core(
        fixture["genesis_ref"],
        fixture["checkpoint_core"],
        fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=fixture["archive_resolver"],
    )
    transferred = protocol_v3.create_transfer(
        bill,
        fixture["bob_private"],
        fixture["bob_public"],
        fixture["carol_address"],
        proof_bundle=fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=fixture["archive_resolver"],
        timestamp=1_700_000_050,
    )
    announcement = protocol_v3.create_transfer_announcement(
        transferred,
        proof_bundle=fixture["bundle"],
        archive_segments=[fixture["archive_segment"]],
    )

    assert wallet_services.claim_bill_payload(
        ind_token.pack_wire_message(announcement),
        [fixture["carol_address"], fixture["carol_private"], fixture["carol_public"]],
        fixture["carol_address"],
    )
    assert list(runtime_json.transaction_files()) == []
    store = INDLocalStore(db_path=tmp_path / "wallet.sqlite3", require_transparency=False)
    record = store.status_record_for_ref(fixture["token_id"])
    assert record["owner_address"] == fixture["carol_address"]
    assert record["status"] == "verified"


def test_spend_wallet_bill_v3_uses_stored_embedded_proof_context(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("IND_NETWORK", "testnet")
    monkeypatch.setenv("IND_NODE_PORT", "18888")
    store = INDLocalStore(db_path=tmp_path / "wallet.sqlite3", require_transparency=False)
    fixture = native_v3_archive_fixture(tmp_path / "fixture")
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
        archive_segment_resolver=fixture["archive_resolver"],
    )
    store.store_bill_v3(
        bill,
        proof_bundle=fixture["bundle"],
        status="verified",
        trusted_operator_public_key=fixture["log_public"],
    )

    state = wallet_services.spend_wallet_bill_v3(
        [fixture["bob_address"], fixture["bob_private"], fixture["bob_public"]],
        bill,
        fixture["carol_address"],
        store=store,
        timestamp=int(fixture["first_transfer"]["timestamp"]) + 40,
    )

    assert state.owner_address == fixture["carol_address"]
    queued = [runtime_json.read_transaction_message(path) for path in runtime_json.transaction_files()]
    assert [message["type"] for message in queued] == [protocol_v3.TRANSFER_ANNOUNCEMENT_TYPE]
    assert queued[0]["archive_segments"]
    decoded = protocol_v3.verify_transfer_announcement(
        queued[0],
        trusted_operator_public_key=fixture["log_public"],
    )
    assert decoded["state"].owner_address == fixture["carol_address"]
