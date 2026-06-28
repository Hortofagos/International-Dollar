import pytest

from ind import keys_v3
from ind import protocol as ind_token
from ind import protocol_v3
from ind import runtime as runtime_json
from ind import transparency_client as log_client
from ind import wallet_services
from ind.store import INDLocalStore

from .test_archive_segment_v3 import native_v3_archive_fixture


def _verifier_for_fixture(fixture, label):
    operator = log_client.LocalTransparencyOperator(fixture["log"])
    mirror = log_client.StaticRootMirror(
        [fixture["bundle"]["signed_root"]],
        identity_id=("wallet-services-mirror", label),
    )
    return log_client.TransparencyVerifier(
        operator,
        [mirror],
        operator_public_key=fixture["log_public"],
        min_mirrors=1,
        allow_unsafe_single_mirror=True,
        max_root_lag_seconds=60,
        max_current_root_age_seconds=1_000_000_000,
        observed_root_store=log_client.InMemoryObservedRootStore(),
        run_startup_check=False,
    )


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


def test_latest_bill_transfer_timestamp_reads_encoded_v3_bill_record(tmp_path):
    fixture = native_v3_archive_fixture(tmp_path / "fixture")
    bill = protocol_v3.create_bill_from_checkpoint_core(
        fixture["genesis_ref"],
        fixture["checkpoint_core"],
        fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=fixture["archive_resolver"],
    )
    transfer_timestamp = int(fixture["first_transfer"]["timestamp"]) + 40
    transferred = protocol_v3.create_transfer(
        bill,
        fixture["bob_private"],
        fixture["bob_public"],
        fixture["carol_address"],
        proof_bundle=fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=fixture["archive_resolver"],
        timestamp=transfer_timestamp,
    )
    record = {
        "bill_blob": protocol_v3.encode_bill(transferred),
        "updated_at": transfer_timestamp + 600,
    }

    assert wallet_services.latest_bill_transfer_timestamp(record=record) == transfer_timestamp


def test_latest_bill_transfer_timestamp_reads_compact_checkpoint_timestamp():
    assert (
        wallet_services.latest_bill_transfer_timestamp(
            bill={
                "recent_transfers": [],
                "checkpoint_core": {"last_transfer_timestamp": 1_700_000_123},
            },
            fallback=1_700_000_999,
        )
        == 1_700_000_123
    )


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


def test_filter_locally_sent_records_keeps_newer_returned_bill_sequence():
    records = [
        {"display_id": "2x23", "sequence": 3},
        {"display_id": "2x23", "sequence": 4},
        {"display_id": "2x24", "sequence": 4},
    ]
    wallet_lines = [
        "x324sq85mgDVTGK4oHXw2b2LHh4YFriSx\n",
        "private\n",
        "public\n",
        "-2x23 3 1781546900\n",
    ]

    assert wallet_services.filter_locally_sent_records(records, wallet_lines) == [
        {"display_id": "2x23", "sequence": 4},
        {"display_id": "2x24", "sequence": 4},
    ]


def test_wallet_balance_counts_uses_lightweight_records_and_wallet_lines():
    address, _private_key, _public_key = keys_v3.generate_keypair(b"\x42" * 32)

    class Store:
        def bill_v3_count_records_for_owner(self, owner_address, statuses=None):
            assert owner_address == address
            assert statuses == ("settled", "verified", "pending")
            return [
                {"display_id": "5x3", "sequence": 1, "status": "settled"},
                {"display_id": "5x3", "sequence": 2, "status": "settled"},
                {"display_id": "2x4", "sequence": 1, "status": "pending"},
                {"display_id": "100x0341108e4", "sequence": 1, "status": "settled"},
            ]

    counts = wallet_services.wallet_balance_counts(
        address,
        store=Store(),
        wallet_lines=[
            address + "\n",
            "private\n",
            "public\n",
            "-5x3 1 1781546900\n",
            "1x9 1 1781547000\n",
        ],
        bill_values=(1, 2, 5),
    )

    assert counts["bill_counts"] == {1: 1, 2: 0, 5: 1}
    assert counts["pending_bill_counts"] == {1: 0, 2: 1, 5: 0}
    assert counts["balance"] == 6


def test_wallet_balance_counts_treats_verified_as_pending_when_quorum_requires_settled():
    address, _private_key, _public_key = keys_v3.generate_keypair(b"\x45" * 32)

    class Store:
        def spendable_bill_v3_statuses(self):
            return ("settled",)

        def bill_v3_count_records_for_owner(self, owner_address, statuses=None):
            assert owner_address == address
            assert statuses == ("settled", "verified", "pending")
            return [
                {"display_id": "5x3", "sequence": 1, "status": "settled"},
                {"display_id": "2x4", "sequence": 1, "status": "verified"},
            ]

    counts = wallet_services.wallet_balance_counts(
        address,
        store=Store(),
        bill_values=(2, 5),
    )

    assert counts["bill_counts"] == {2: 0, 5: 1}
    assert counts["pending_bill_counts"] == {2: 1, 5: 0}
    assert counts["balance"] == 5


def test_spendable_wallet_metadata_records_use_lightweight_query_and_filter_sent():
    address, _private_key, _public_key = keys_v3.generate_keypair(b"\x43" * 32)

    class Store:
        def bill_v3_metadata_records_for_owner(self, owner_address, statuses=None, limit=None):
            assert owner_address == address
            assert statuses == ("settled", "verified")
            assert limit == 20
            return [
                {"display_id": "5x3", "sequence": 1, "status": "settled"},
                {"display_id": "5x3", "sequence": 2, "status": "settled"},
                {"display_id": "2x4", "sequence": 1, "status": "verified"},
            ]

        def bill_v3_records_for_owner(self, *_args, **_kwargs):
            raise AssertionError("print metadata path must not load bill blobs")

    records = wallet_services.spendable_wallet_metadata_records(
        address,
        store=Store(),
        wallet_lines=[
            address + "\n",
            "private\n",
            "public\n",
            "-5x3 1 1781546900\n",
        ],
        limit=20,
    )

    assert records == [
        {"display_id": "5x3", "sequence": 2, "status": "settled"},
        {"display_id": "2x4", "sequence": 1, "status": "verified"},
    ]


def test_spendable_wallet_metadata_records_passes_offset_when_requested():
    address, _private_key, _public_key = keys_v3.generate_keypair(b"\x44" * 32)

    class Store:
        def bill_v3_metadata_records_for_owner(
            self,
            owner_address,
            statuses=None,
            limit=None,
            offset=0,
        ):
            assert owner_address == address
            assert statuses == ("settled", "verified")
            assert limit == 10
            assert offset == 20
            return [{"display_id": "1x21", "sequence": 1, "status": "settled"}]

    records = wallet_services.spendable_wallet_metadata_records(
        address,
        store=Store(),
        wallet_lines=[address + "\n", "private\n", "public\n"],
        limit=10,
        offset=20,
    )

    assert records == [{"display_id": "1x21", "sequence": 1, "status": "settled"}]


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


def test_spendable_wallet_display_ids_uses_targeted_store_lookup():
    address, _private_key, _public_key = keys_v3.generate_keypair(
        b"wallet-targeted-spendable-lookup"
    )
    calls = []

    class Store:
        def spendable_bill_v3_display_ids(self, owner_address, display_ids):
            calls.append((owner_address, list(display_ids)))
            return {"20x1", "50x2"}

        def bill_v3_records_for_owner(self, *args, **kwargs):
            raise AssertionError("full spendable wallet scan should not be used")

    assert wallet_services.spendable_wallet_display_ids(
        address,
        ["20x1", "50x2", "100x3"],
        store=Store(),
    ) == {"20x1", "50x2"}
    assert calls == [(address, ["20x1", "50x2", "100x3"])]


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


def test_claim_bill_payload_spends_paper_wallet_to_active_wallet(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("IND_NETWORK", "testnet")
    monkeypatch.setenv("IND_NODE_PORT", "18888")
    monkeypatch.setenv("IND_STORE_PATH", str(tmp_path / "wallet.sqlite3"))
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
    paper_address, paper_private, paper_public = keys_v3.generate_keypair(b"\x24" * 32)
    paper_bill = protocol_v3.create_transfer(
        bill,
        fixture["bob_private"],
        fixture["bob_public"],
        paper_address,
        proof_bundle=fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=fixture["archive_resolver"],
        timestamp=1_700_000_050,
    )
    paper_state = protocol_v3.verify_bill(
        paper_bill,
        proof_bundle=fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=fixture["archive_resolver"],
    )
    store.store_bill_v3(
        paper_bill,
        proof_bundle=fixture["bundle"],
        status="verified",
        trusted_operator_public_key=fixture["log_public"],
    )
    paper_payload = "\n".join(
        [
            paper_state.display_id,
            paper_private,
            paper_public,
            str(paper_state.sequence),
        ]
    )

    assert wallet_services.claim_bill_payload(
        paper_payload,
        [fixture["carol_address"], fixture["carol_private"], fixture["carol_public"]],
        fixture["carol_address"],
    )
    queued = [runtime_json.read_transaction_message(path) for path in runtime_json.transaction_files()]
    assert [message["type"] for message in queued] == [protocol_v3.TRANSFER_ANNOUNCEMENT_TYPE]
    decoded = protocol_v3.verify_transfer_announcement(
        queued[0],
        trusted_operator_public_key=fixture["log_public"],
    )
    assert decoded["state"].owner_address == fixture["carol_address"]
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


def test_spend_wallet_bill_v3_passes_store_transparency_verifier(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("IND_NETWORK", "testnet")
    monkeypatch.setenv("IND_NODE_PORT", "18888")
    fixture = native_v3_archive_fixture(tmp_path / "fixture")
    verifier = _verifier_for_fixture(fixture, "spend")
    store = INDLocalStore(
        db_path=tmp_path / "wallet.sqlite3",
        require_transparency=True,
        transparency_verifier=verifier,
    )
    store.store_archive_segment_v3(fixture["archive_segment"])
    store.store_proof_bundle_v3(fixture["bundle"])
    bill = protocol_v3.create_bill_from_checkpoint_core(
        fixture["genesis_ref"],
        fixture["checkpoint_core"],
        fixture["bundle"],
        transparency_verifier=verifier,
        archive_segment_resolver=fixture["archive_resolver"],
    )
    store.store_bill_v3(
        bill,
        proof_bundle=fixture["bundle"],
        status="verified",
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


def _store_fixture_bill(store, fixture):
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
    return bill


def test_spend_wallet_bills_batch_parallel_queues_in_order(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("IND_NETWORK", "testnet")
    monkeypatch.setenv("IND_NODE_PORT", "18888")
    store = INDLocalStore(db_path=tmp_path / "wallet.sqlite3", require_transparency=False)
    first = native_v3_archive_fixture(
        tmp_path / "first",
        token_label="batch-token-first",
        genesis_label="batch-genesis-first",
        display_id="1x1",
    )
    second = native_v3_archive_fixture(
        tmp_path / "second",
        token_label="batch-token-second",
        genesis_label="batch-genesis-second",
        display_id="2x2",
    )
    _store_fixture_bill(store, first)
    _store_fixture_bill(store, second)
    wallet_lines = [first["bob_address"], first["bob_private"], first["bob_public"]]

    results = wallet_services.spend_wallet_bills_batch(
        wallet_lines,
        ["1x1 wallet", "2x2 wallet"],
        first["carol_address"],
        store=store,
        workers=2,
    )

    assert [result["error"] for result in results] == [None, None]
    assert [result["state"].display_id for result in results] == ["1x1", "2x2"]
    queued = [runtime_json.read_transaction_message(path) for path in runtime_json.transaction_files()]
    assert len(queued) == 2
    decoded = [
        protocol_v3.verify_transfer_announcement(
            message,
            trusted_operator_public_key=first["log_public"],
        )
        for message in queued
    ]
    assert [item["state"].display_id for item in decoded] == ["1x1", "2x2"]
    assert [item["state"].owner_address for item in decoded] == [
        first["carol_address"],
        first["carol_address"],
    ]


def test_spend_wallet_bills_batch_rejects_duplicate_display_id(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("IND_NETWORK", "testnet")
    monkeypatch.setenv("IND_NODE_PORT", "18888")
    store = INDLocalStore(db_path=tmp_path / "wallet.sqlite3", require_transparency=False)
    fixture = native_v3_archive_fixture(tmp_path / "fixture", display_id="1x1")
    _store_fixture_bill(store, fixture)
    wallet_lines = [fixture["bob_address"], fixture["bob_private"], fixture["bob_public"]]

    results = wallet_services.spend_wallet_bills_batch(
        wallet_lines,
        ["1x1 wallet", "1x1 duplicate"],
        fixture["carol_address"],
        store=store,
        workers=2,
    )

    assert results[0]["error"] is None
    assert results[1]["state"] is None
    assert "duplicate bill selected" in str(results[1]["error"])
    assert len(runtime_json.transaction_files()) == 1


def test_commit_prepared_wallet_spend_rejects_changed_tip(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("IND_NETWORK", "testnet")
    monkeypatch.setenv("IND_NODE_PORT", "18888")
    store = INDLocalStore(db_path=tmp_path / "wallet.sqlite3", require_transparency=False)
    fixture = native_v3_archive_fixture(tmp_path / "fixture", display_id="1x1")
    bill = _store_fixture_bill(store, fixture)
    wallet_lines = [fixture["bob_address"], fixture["bob_private"], fixture["bob_public"]]

    prepared = wallet_services.prepare_spend_wallet_bill_v3(
        wallet_lines,
        bill,
        fixture["carol_address"],
        store=store,
        trusted_operator_public_key=fixture["log_public"],
        timestamp=int(fixture["first_transfer"]["timestamp"]) + 40,
    )
    competing = protocol_v3.create_transfer(
        bill,
        fixture["bob_private"],
        fixture["bob_public"],
        fixture["alice_address"],
        proof_bundle=fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=store.archive_segment_resolver_v3,
        timestamp=int(fixture["first_transfer"]["timestamp"]) + 41,
    )
    store.store_bill_v3(
        competing,
        proof_bundle=fixture["bundle"],
        status="verified",
        trusted_operator_public_key=fixture["log_public"],
    )

    with pytest.raises(ind_token.ValidationError, match="tip changed|sequence changed"):
        wallet_services.commit_prepared_wallet_spend_v3(prepared, store=store)

    assert runtime_json.transaction_files() == []
