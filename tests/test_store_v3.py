import copy
import json
import sqlite3
import time
import urllib.error

import pytest

from ind import (
    keys_v3,
    protocol_v3,
    store as store_module,
    transparency_client as log_client,
    wallet_services,
)
from ind.store import INDLocalStore

from .test_archive_segment_v3 import BASE_TIMESTAMP, native_v3_archive_fixture


def _v3_verifier_for_fixture(fixture, label):
    operator = log_client.LocalTransparencyOperator(fixture["log"])
    mirror = log_client.StaticRootMirror(
        [fixture["bundle"]["signed_root"]],
        identity_id=("test-v3-mirror", label),
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


def _live_v3_operator_and_verifier(fixture, label):
    operator = log_client.LocalTransparencyOperator(fixture["log"])

    class LocalMirror:
        identity_id = ("test-live-v3-mirror", label)

        def root_at(self, timestamp):
            return operator.root_at(timestamp)

        def latest_root(self):
            return operator.latest_root()

    verifier = log_client.TransparencyVerifier(
        operator,
        [LocalMirror()],
        operator_public_key=fixture["log_public"],
        min_mirrors=1,
        allow_unsafe_single_mirror=True,
        max_root_lag_seconds=1_000_000_000,
        max_current_root_age_seconds=1_000_000_000,
        observed_root_store=log_client.InMemoryObservedRootStore(),
        run_startup_check=False,
    )
    return operator, verifier


def test_optional_root_gossip_ignores_unavailable_environment_verifier(tmp_path, monkeypatch):
    monkeypatch.setattr(store_module, "_configured_transparency_submitter", lambda: None)

    def fail_environment_verifier():
        raise ValueError("production settings are incomplete")

    monkeypatch.setattr(store_module, "_environment_transparency_verifier", fail_environment_verifier)

    store = INDLocalStore(db_path=tmp_path / "wallet-v3.db", require_transparency=False)

    assert store.transparency_verifier is None


def _pending_v3_fixture(tmp_path):
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
        timestamp=BASE_TIMESTAMP + 50,
    )
    store.store_bill_v3(
        transferred,
        proof_bundle=fixture["bundle"],
        status="pending",
        trusted_operator_public_key=fixture["log_public"],
    )
    return fixture, store, transferred


def _mark_transfer_log_proven(store, transferred, proof_bundle, operator_public_key=None):
    transfer = transferred["recent_transfers"][-1]
    if operator_public_key is not None:
        proof_bundle = copy.deepcopy(proof_bundle)
        proof_bundle["signed_root"]["operator_public_key"] = operator_public_key
        proof_bundle["log_id"] = log_client.log_id_from_public_key(operator_public_key)
        proof_bundle["signed_root"]["log_id"] = proof_bundle["log_id"]
    with store._connect() as conn:
        store._record_v3_transfer_log_status_conn(
            conn,
            transfer,
            proof_bundle=proof_bundle,
            status="log_proven",
            response={
                "entry_hash": protocol_v3.transfer_hash(transfer),
                "leaf_index": 0,
                "tree_size": 1,
            },
        )


def _late_conflict_proof_for_transferred(fixture, store, transferred):
    bill = protocol_v3.create_bill_from_checkpoint_core(
        fixture["genesis_ref"],
        fixture["checkpoint_core"],
        fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=store.archive_segment_resolver_v3,
    )
    sibling = protocol_v3.create_transfer(
        bill,
        fixture["bob_private"],
        fixture["bob_public"],
        fixture["alice_address"],
        proof_bundle_resolver=store.proof_bundle_resolver_v3,
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=store.archive_segment_resolver_v3,
        timestamp=BASE_TIMESTAMP + 51,
    )
    return protocol_v3.create_conflict_proof(
        transferred,
        sibling,
        proof_bundle_resolver=store.proof_bundle_resolver_v3,
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=store.archive_segment_resolver_v3,
    )


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
    assert store.get_bill_v3_by_display_id("1x1") == bill

    state = protocol_v3.verify_bill(
        store.get_bill_v3(bill_hash),
        proof_bundle_resolver=store.proof_bundle_resolver_v3,
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=store.archive_segment_resolver_v3,
    )
    assert state.owner_address == fixture["bob_address"]


def test_bill_tips_v3_cache_is_rebuildable(tmp_path):
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
        timestamp=BASE_TIMESTAMP + 50,
    )
    bill_hash = store.store_bill_v3(
        transferred,
        proof_bundle=fixture["bundle"],
        status="verified",
        trusted_operator_public_key=fixture["log_public"],
    )
    transfer = transferred["recent_transfers"][-1]
    expected_spend_key = protocol_v3.spend_key_for_transfer(transfer)
    expected_transfer_hash = protocol_v3.transfer_hash(transfer)

    with store._connect() as conn:
        row = conn.execute(
            "SELECT spend_key, tip_transfer_hash FROM bill_tips_v3 WHERE bill_hash = ?",
            (bill_hash,),
        ).fetchone()
        conn.execute("DELETE FROM bill_tips_v3")

    assert row["spend_key"] == expected_spend_key
    assert row["tip_transfer_hash"] == expected_transfer_hash

    result = store.repair_bill_tips_v3()

    with store._connect() as conn:
        rebuilt = conn.execute(
            """
            SELECT spend_key, tip_transfer_hash, owner_address, sequence
            FROM bill_tips_v3
            WHERE bill_hash = ?
            """,
            (bill_hash,),
        ).fetchone()

    assert result == {"rebuilt": 1, "skipped": 0}
    assert rebuilt["spend_key"] == expected_spend_key
    assert rebuilt["tip_transfer_hash"] == expected_transfer_hash
    assert rebuilt["owner_address"] == fixture["carol_address"]
    assert rebuilt["sequence"] == int(transfer["sequence"])
    assert store.get_bill_v3(bill_hash) == transferred


def test_discard_unsettled_bill_v3_restores_previous_spendable_tip(tmp_path):
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
    original_hash = store.store_bill_v3(
        bill,
        proof_bundle=fixture["bundle"],
        status="settled",
        trusted_operator_public_key=fixture["log_public"],
    )
    transferred = protocol_v3.create_transfer(
        bill,
        fixture["bob_private"],
        fixture["bob_public"],
        fixture["carol_address"],
        proof_bundle_resolver=store.proof_bundle_resolver_v3,
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=store.archive_segment_resolver_v3,
        timestamp=BASE_TIMESTAMP + 50,
    )
    transferred_hash = store.store_bill_v3(
        transferred,
        proof_bundle=fixture["bundle"],
        status="verified",
        trusted_operator_public_key=fixture["log_public"],
    )
    transferred_state = protocol_v3.verify_bill(
        transferred,
        proof_bundle=fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=store.archive_segment_resolver_v3,
    )

    assert (
        store.get_spendable_bill_v3_by_display_id(
            transferred_state.display_id,
            fixture["bob_address"],
        )
        is None
    )
    assert not store.discard_unsettled_bill_v3(
        original_hash,
        display_id=transferred_state.display_id,
        owner_address=fixture["bob_address"],
        sequence=transferred_state.sequence - 1,
    )
    assert store.discard_unsettled_bill_v3(
        transferred_hash,
        display_id=transferred_state.display_id,
        owner_address=fixture["carol_address"],
        sequence=transferred_state.sequence,
    )
    restored = store.get_spendable_bill_v3_by_display_id(
        transferred_state.display_id,
        fixture["bob_address"],
    )
    assert restored is not None
    assert protocol_v3.bill_hash(restored).hex() == original_hash


def test_store_v3_does_not_downgrade_settled_bill_status(tmp_path):
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
    store.store_bill_v3(
        bill,
        status="pending",
        trusted_operator_public_key=fixture["log_public"],
    )

    records = store.bill_v3_records_for_owner(fixture["bob_address"], statuses=("settled",))
    assert [record["display_id"] for record in records] == ["1x1"]
    records = store.bill_v3_records_for_owner(
        fixture["bob_address"], statuses=("settled",), limit=None
    )
    assert [record["display_id"] for record in records] == ["1x1"]


def test_store_v3_filters_unsupported_wallet_denominations(tmp_path):
    fixture = native_v3_archive_fixture(tmp_path)
    store = INDLocalStore(db_path=tmp_path / "wallet-v3.db", require_transparency=False)
    bill = protocol_v3.create_bill_from_checkpoint_core(
        fixture["genesis_ref"],
        fixture["checkpoint_core"],
        fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=fixture["archive_resolver"],
    )
    with store._connect() as conn:
        conn.execute(
            """
            INSERT INTO bills_v3(
                bill_hash, token_id, display_id, owner_address, sequence,
                checkpoint_hash, proof_bundle_hash, bill_blob,
                first_seen, updated_at, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "bad-bill",
                "bad-token",
                "3xbad",
                fixture["bob_address"],
                1,
                bill["checkpoint_core"]["checkpoint_hash"],
                None,
                protocol_v3.encode_bill(bill),
                1,
                1,
                "settled",
            ),
        )

    assert store.bill_v3_records_for_owner(fixture["bob_address"], statuses=("settled",)) == []


def test_store_v3_count_records_do_not_decode_bill_blobs(tmp_path, monkeypatch):
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
        archive_segment_resolver=fixture["archive_resolver"],
    )
    store.store_bill_v3(
        bill,
        status="settled",
        trusted_operator_public_key=fixture["log_public"],
    )

    def fail_decode(_data):
        raise AssertionError("count query must not decode bill blobs")

    monkeypatch.setattr(protocol_v3, "decode_bill", fail_decode)

    records = store.bill_v3_count_records_for_owner(
        fixture["bob_address"],
        statuses=("settled",),
    )

    assert len(records) == 1
    assert records[0]["display_id"] == "1x1"
    assert "bill_blob" not in records[0]


def test_store_v3_metadata_records_do_not_decode_bill_blobs(tmp_path, monkeypatch):
    monkeypatch.setenv("IND_LOG_ROOT_GOSSIP", "0")
    store = INDLocalStore(db_path=tmp_path / "wallet-v3.db", require_transparency=False)
    owner_address, _private_key, _public_key = keys_v3.generate_keypair(b"\x44" * 32)
    with store._connect() as conn:
        for index, display_id in enumerate(("1x1", "2x2"), start=1):
            conn.execute(
                """
                INSERT INTO bills_v3(
                    bill_hash, token_id, display_id, owner_address, sequence,
                    checkpoint_hash, proof_bundle_hash, bill_blob,
                    first_seen, updated_at, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    f"metadata-bill-{index}",
                    f"metadata-token-{index}",
                    display_id,
                    owner_address,
                    index,
                    f"metadata-checkpoint-{index}",
                    None,
                    b"not-a-decodable-bill",
                    index,
                    10 + index,
                    "settled",
                ),
            )

    def fail_decode(_data):
        raise AssertionError("metadata query must not decode bill blobs")

    monkeypatch.setattr(protocol_v3, "decode_bill", fail_decode)

    records = store.bill_v3_metadata_records_for_owner(
        owner_address,
        statuses=("settled",),
        limit=1,
    )

    assert len(records) == 1
    assert records[0]["display_id"] == "2x2"
    assert records[0]["sequence"] == 2
    assert "bill_blob" not in records[0]


def _insert_wallet_sync_bill_row(
    store,
    owner_address,
    *,
    display_id,
    sequence=1,
    updated_at=1,
    status="settled",
    token_id=None,
):
    token_id = token_id or f"sync-token-{display_id}-{sequence}"
    with store._connect() as conn:
        conn.execute(
            """
            INSERT INTO bills_v3(
                bill_hash, token_id, display_id, owner_address, sequence,
                checkpoint_hash, proof_bundle_hash, bill_blob,
                first_seen, updated_at, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                f"sync-bill-{display_id}-{sequence}",
                token_id,
                display_id,
                owner_address,
                sequence,
                f"sync-checkpoint-{display_id}-{sequence}",
                None,
                b"not-used-by-this-test",
                updated_at,
                updated_at,
                status,
            ),
        )


def test_wallet_known_display_ranges_are_compact_and_blob_free(tmp_path, monkeypatch):
    store = INDLocalStore(db_path=tmp_path / "wallet-v3.db", require_transparency=False)
    owner_address, _private_key, _public_key = keys_v3.generate_keypair(b"\x45" * 32)
    for display_id, sequence, updated_at in (
        ("20x100", 1, 100),
        ("20x101", 1, 101),
        ("20x102", 1, 102),
        ("20x104", 1, 104),
        ("20x105", 2, 105),
    ):
        _insert_wallet_sync_bill_row(
            store,
            owner_address,
            display_id=display_id,
            sequence=sequence,
            updated_at=updated_at,
        )

    def fail_decode(_data):
        raise AssertionError("range inventory must not decode bill blobs")

    monkeypatch.setattr(protocol_v3, "decode_bill", fail_decode)

    ranges = store.wallet_known_display_ranges(
        owner_address,
        statuses=("settled",),
        max_ranges=10,
        max_bytes=4096,
    )
    capped = store.wallet_known_display_ranges(
        owner_address,
        statuses=("settled",),
        max_ranges=1,
        max_bytes=4096,
    )

    assert ranges == [[20, 100, 102, 1], [20, 104, 104, 1], [20, 105, 105, 2]]
    assert capped == [[20, 100, 102, 1]]


def test_bill_v3_metadata_records_for_owner_supports_offset(tmp_path, monkeypatch):
    store = INDLocalStore(db_path=tmp_path / "wallet-v3.db", require_transparency=False)
    owner_address, _private_key, _public_key = keys_v3.generate_keypair(b"\x47" * 32)
    for index, display_id in enumerate(("1x1", "1x2", "1x3"), start=1):
        _insert_wallet_sync_bill_row(
            store,
            owner_address,
            display_id=display_id,
            updated_at=100 + index,
        )

    def fail_decode(_data):
        raise AssertionError("paged metadata query must not decode bill blobs")

    monkeypatch.setattr(protocol_v3, "decode_bill", fail_decode)

    records = store.bill_v3_metadata_records_for_owner(
        owner_address,
        statuses=("settled",),
        limit=1,
        offset=1,
    )

    assert [record["display_id"] for record in records] == ["1x2"]
    assert "bill_blob" not in records[0]


def test_wallet_bill_sync_response_skips_known_display_ranges_before_blob_decode(
    tmp_path,
    monkeypatch,
):
    store = INDLocalStore(db_path=tmp_path / "wallet-v3.db", require_transparency=False)
    owner_address, _private_key, _public_key = keys_v3.generate_keypair(b"\x46" * 32)
    _insert_wallet_sync_bill_row(store, owner_address, display_id="20x100", updated_at=300)
    _insert_wallet_sync_bill_row(store, owner_address, display_id="20x101", updated_at=200)
    _insert_wallet_sync_bill_row(store, owner_address, display_id="20x102", updated_at=100)
    decoded_candidates = []
    branch_checks = []

    def allow_candidate(record):
        decoded_candidates.append(record["display_id"])
        return True

    def newer_branch_check(_self, _conn, token_id, _sequence):
        branch_checks.append(token_id)
        return False

    monkeypatch.setattr(store_module, "_bill_v3_record_has_allowed_value", allow_candidate)
    monkeypatch.setattr(
        INDLocalStore,
        "_has_materialized_newer_v3_branch_conn",
        newer_branch_check,
    )
    monkeypatch.setattr(
        INDLocalStore,
        "_wallet_sync_record_from_bill_row_v3",
        lambda self, row: {
            "type": "ind.wallet_bill_sync_record.v3",
            "token_id": row["token_id"],
            "display_id": row["display_id"],
            "sequence": int(row["sequence"]),
            "updated_at": int(row["updated_at"]),
        },
    )

    response = store.wallet_bill_sync_response(
        {
            "address": owner_address,
            "direction": "reconcile",
            "known_display_ranges": [[20, 100, 101, 1]],
            "limit": 10,
        }
    )

    assert [record["display_id"] for record in response["records"]] == ["20x102"]
    assert decoded_candidates == ["20x102"]
    assert branch_checks == ["sync-token-20x102-1"]


def test_wallet_bill_sync_response_skips_large_known_ranges_before_branch_lookup(
    tmp_path,
    monkeypatch,
):
    store = INDLocalStore(db_path=tmp_path / "wallet-v3.db", require_transparency=False)
    owner_address, _private_key, _public_key = keys_v3.generate_keypair(b"\x48" * 32)
    for serial in range(1, 301):
        _insert_wallet_sync_bill_row(
            store,
            owner_address,
            display_id=f"20x{serial}",
            updated_at=1_000 + serial,
        )
    _insert_wallet_sync_bill_row(store, owner_address, display_id="20x301", updated_at=1)
    _insert_wallet_sync_bill_row(store, owner_address, display_id="20x302", updated_at=2)
    decoded_candidates = []
    branch_checks = []

    def allow_candidate(record):
        decoded_candidates.append(record["display_id"])
        return True

    def newer_branch_check(_self, _conn, token_id, _sequence):
        branch_checks.append(token_id)
        return False

    monkeypatch.setattr(store_module, "_bill_v3_record_has_allowed_value", allow_candidate)
    monkeypatch.setattr(
        INDLocalStore,
        "_has_materialized_newer_v3_branch_conn",
        newer_branch_check,
    )
    monkeypatch.setattr(
        INDLocalStore,
        "_wallet_sync_record_from_bill_row_v3",
        lambda self, row: {
            "type": "ind.wallet_bill_sync_record.v3",
            "token_id": row["token_id"],
            "display_id": row["display_id"],
            "sequence": int(row["sequence"]),
            "updated_at": int(row["updated_at"]),
        },
    )

    response = store.wallet_bill_sync_response(
        {
            "address": owner_address,
            "direction": "reconcile",
            "known_display_ranges": [[20, 1, 300, 1]],
            "limit": 10,
        }
    )

    assert [record["display_id"] for record in response["records"]] == ["20x302", "20x301"]
    assert decoded_candidates == ["20x302", "20x301"]
    assert branch_checks == ["sync-token-20x302-1", "sync-token-20x301-1"]


def test_wallet_bill_sync_response_does_not_skip_newer_sequence_in_known_range(
    tmp_path,
    monkeypatch,
):
    store = INDLocalStore(db_path=tmp_path / "wallet-v3.db", require_transparency=False)
    owner_address, _private_key, _public_key = keys_v3.generate_keypair(b"\x47" * 32)
    _insert_wallet_sync_bill_row(
        store,
        owner_address,
        display_id="20x100",
        sequence=2,
        updated_at=100,
    )

    monkeypatch.setattr(store_module, "_bill_v3_record_has_allowed_value", lambda _record: True)
    monkeypatch.setattr(
        INDLocalStore,
        "_wallet_sync_record_from_bill_row_v3",
        lambda self, row: {
            "type": "ind.wallet_bill_sync_record.v3",
            "token_id": row["token_id"],
            "display_id": row["display_id"],
            "sequence": int(row["sequence"]),
            "updated_at": int(row["updated_at"]),
        },
    )

    response = store.wallet_bill_sync_response(
        {
            "address": owner_address,
            "direction": "reconcile",
            "known_display_ranges": [[20, 100, 100, 1]],
            "limit": 10,
        }
    )

    assert [(record["display_id"], record["sequence"]) for record in response["records"]] == [
        ("20x100", 2)
    ]


def test_invalid_bills_v3_are_cleaned_from_cache_rows(tmp_path):
    fixture = native_v3_archive_fixture(tmp_path)
    store = INDLocalStore(db_path=tmp_path / "wallet-v3.db", require_transparency=False)
    bill = protocol_v3.create_bill_from_checkpoint_core(
        fixture["genesis_ref"],
        fixture["checkpoint_core"],
        fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=fixture["archive_resolver"],
    )
    bad_bill = copy.deepcopy(bill)
    bad_bill["checkpoint_core"]["display_id"] = "1x0341108e1"
    bad_bill["checkpoint_core"]["display_id_hash"] = protocol_v3._display_id_hash("1x0341108e1")
    bad_blob = b"not-a-v3-bill"
    with store._connect() as conn:
        conn.execute(
            """
            INSERT INTO bills_v3(
                bill_hash, token_id, display_id, owner_address, sequence,
                checkpoint_hash, proof_bundle_hash, bill_blob,
                first_seen, updated_at, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "bad-bill",
                bad_bill["token_id"],
                "1x0341108e1",
                fixture["bob_address"],
                1,
                bad_bill["checkpoint_core"]["checkpoint_hash"],
                bad_bill["proof_bundle_ref"]["proof_bundle_hash"],
                bad_blob,
                1,
                1,
                "settled",
            ),
        )
        conn.execute(
            """
            INSERT INTO messages(
                message_hash, message_type, token_id, recipient_address, message_json, first_seen
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                "bad-message",
                protocol_v3.TRANSFER_ANNOUNCEMENT_TYPE,
                bad_bill["token_id"],
                fixture["bob_address"],
                "{}",
                1,
            ),
        )

    assert store.status_record_for_ref("1x0341108e1")["status"] == "invalid"
    dry_run = store.cleanup_invalid_bills_v3(dry_run=True)
    applied = store.cleanup_invalid_bills_v3(dry_run=False)

    assert dry_run["invalid"] == 1
    assert dry_run["deleted"] == 0
    assert applied["deleted"] == 1
    assert applied["deleted_messages"] == 1
    assert store.status_record_for_ref("1x0341108e1") is None


def test_status_record_for_ref_reports_v3_bill(tmp_path):
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

    by_display = store.status_record_for_ref("1x1")
    by_token = store.status_record_for_ref(fixture["token_id"])

    assert by_display["display_id"] == "1x1"
    assert by_display["owner_address"] == fixture["bob_address"]
    assert by_display["sequence"] == fixture["checkpoint_core"]["sequence"]
    assert by_display["status"] == "strong_local"
    assert by_token["display_id"] == "1x1"


def test_status_record_for_ref_reports_verified_v3_checkpoint_without_transfer_row(tmp_path):
    fixture = native_v3_archive_fixture(tmp_path)
    store = INDLocalStore(db_path=tmp_path / "wallet-v3.db", require_transparency=False)

    store.store_archive_segment_v3(fixture["archive_segment"])
    store.store_proof_bundle_v3(
        fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
    )

    by_display = store.status_record_for_ref("1x1")
    by_token = store.status_record_for_ref(fixture["token_id"])

    assert by_display["status"] == "verified_checkpoint"
    assert by_display["owner_address"] == fixture["bob_address"]
    assert by_display["sequence"] == fixture["checkpoint_core"]["sequence"]
    assert by_token["status"] == "verified_checkpoint"


def test_status_record_for_checkpoint_ref_rejects_v3_conflict_without_bill_row(tmp_path):
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
    branch_a = protocol_v3.create_transfer(
        bill,
        fixture["bob_private"],
        fixture["bob_public"],
        fixture["carol_address"],
        proof_bundle_resolver=store.proof_bundle_resolver_v3,
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=store.archive_segment_resolver_v3,
        timestamp=BASE_TIMESTAMP + 50,
    )
    branch_b = protocol_v3.create_transfer(
        bill,
        fixture["bob_private"],
        fixture["bob_public"],
        fixture["alice_address"],
        proof_bundle_resolver=store.proof_bundle_resolver_v3,
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=store.archive_segment_resolver_v3,
        timestamp=BASE_TIMESTAMP + 51,
    )
    proof = protocol_v3.create_conflict_proof(
        branch_a,
        branch_b,
        proof_bundle_resolver=store.proof_bundle_resolver_v3,
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=store.archive_segment_resolver_v3,
    )
    with pytest.raises(store_module.ValidationError, match="unanchored V3 conflict proof"):
        store.store_conflict_proof_v3(proof)

    by_display = store.status_record_for_ref("1x1")
    by_token = store.status_record_for_ref(fixture["token_id"])

    for record in (by_display, by_token):
        assert record["display_id"] == "1x1"
        assert record["token_id"] == fixture["token_id"]
        assert record["status"] == "verified_checkpoint"
        assert "conflict_proof_hash" not in record


def test_store_v3_rejects_unanchored_conflict_proof_attack_shape(tmp_path):
    fixture = native_v3_archive_fixture(tmp_path)
    store = INDLocalStore(db_path=tmp_path / "wallet-v3.db", require_transparency=False)
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
        timestamp=BASE_TIMESTAMP + 50,
    )
    branch_b = protocol_v3.create_transfer(
        bill,
        fixture["bob_private"],
        fixture["bob_public"],
        fixture["alice_address"],
        proof_bundle=fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=fixture["archive_resolver"],
        timestamp=BASE_TIMESTAMP + 51,
    )
    proof = protocol_v3.create_conflict_proof(
        branch_a,
        branch_b,
        proof_bundle_a=fixture["bundle"],
        proof_bundle_b=fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=fixture["archive_resolver"],
    )

    with pytest.raises(store_module.ValidationError, match="unanchored V3 conflict proof"):
        store.ingest_message(proof)

    assert store.status_record_for_ref(fixture["token_id"]) is None


def test_store_v3_rejects_conflict_proof_for_unknown_same_token_state(tmp_path):
    fixture = native_v3_archive_fixture(tmp_path)
    store = INDLocalStore(db_path=tmp_path / "wallet-v3.db", require_transparency=False)
    store.store_archive_segment_v3(fixture["archive_segment"])
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
    fake_owner, fake_private, fake_public = keys_v3.generate_keypair(
        b"fake-conflict-owner".ljust(32, b"\0")
    )
    recipient_a, _private_a, _public_a = keys_v3.generate_keypair(
        b"fake-conflict-a".ljust(32, b"\0")
    )
    recipient_b, _private_b, _public_b = keys_v3.generate_keypair(
        b"fake-conflict-b".ljust(32, b"\0")
    )
    fake_state = {
        "sequence": 0,
        "owner_address": fake_owner,
        "last_transfer_hash": "88" * 32,
        "last_transfer_timestamp": BASE_TIMESTAMP,
        "last_transfer_day": BASE_TIMESTAMP // 86400,
        "transfers_in_last_day": 0,
        "display_id": fixture["checkpoint_core"]["display_id"],
        "value": int(fixture["checkpoint_core"]["value"]),
    }
    transfer_a = protocol_v3.create_transfer_from_state(
        fixture["token_id"],
        fake_state,
        fake_private,
        fake_public,
        recipient_a,
        timestamp=BASE_TIMESTAMP + 1,
    )
    transfer_b = protocol_v3.create_transfer_from_state(
        fixture["token_id"],
        fake_state,
        fake_private,
        fake_public,
        recipient_b,
        timestamp=BASE_TIMESTAMP + 2,
    )
    proof = protocol_v3.create_conflict_proof_from_transfers(
        transfer_a,
        transfer_b,
        detected_at=BASE_TIMESTAMP + 3,
    )

    with pytest.raises(store_module.ValidationError, match="unanchored V3 conflict proof"):
        store.ingest_message(proof)

    record = store.status_record_for_ref(fixture["token_id"])
    assert record["status"] == "verified"
    assert "conflict_proof_hash" not in record


def test_v3_finality_requires_log_proof_when_requested(tmp_path):
    fixture, store, _transferred = _pending_v3_fixture(tmp_path)

    finalized = store.finalize_pending(
        now=2_000_000_000,
        buffer_seconds=0,
        require_v3_log_proof=True,
        settlement_reconciler=lambda _candidate: {"decision": "settle"},
    )

    assert finalized == []
    assert store.status_record_for_ref(fixture["token_id"])["status"] == "pending"


def test_v3_finality_backs_off_stale_transfer_log_proof_http_400(tmp_path):
    fixture, store, transferred = _pending_v3_fixture(tmp_path)
    transfer = transferred["recent_transfers"][-1]
    operator_key = "operator-key"
    log_id = log_client.log_id_from_public_key(operator_key)

    class FailingVerifier:
        operator_public_key = operator_key

        def __init__(self):
            self.calls = 0

        def current_mirrored_root(self):
            self.calls += 1
            raise urllib.error.HTTPError(
                "http://operator.invalid/v3/proof",
                400,
                "Bad Request",
                hdrs=None,
                fp=None,
            )

    verifier = FailingVerifier()
    store.transparency_verifier = verifier
    with store._connect() as conn:
        store._record_v3_transfer_log_status_conn(
            conn,
            transfer,
            operator_identity={"log_id": log_id, "operator_public_key": operator_key},
            status=store_module.V3_LOG_PENDING_STATUS,
            response={
                "entry_hash": protocol_v3.transfer_hash(transfer),
                "leaf_index": 0,
                "tree_size": 1,
            },
        )

    finalized = store.finalize_pending(
        now=2_000_000_000,
        buffer_seconds=0,
        require_v3_log_proof=True,
        settlement_reconciler=lambda _candidate: {"decision": "settle"},
    )
    retried = store.finalize_pending(
        now=2_000_000_001,
        buffer_seconds=0,
        require_v3_log_proof=True,
        settlement_reconciler=lambda _candidate: {"decision": "settle"},
    )

    assert finalized == []
    assert retried == []
    assert verifier.calls == 1
    with store._connect() as conn:
        row = conn.execute("SELECT * FROM transfer_log_retry_v3").fetchone()
    assert row["transfer_hash"] == protocol_v3.transfer_hash(transfer)
    assert row["log_id"] == log_id
    assert row["attempts"] == 1
    assert row["terminal"] == 0


def test_v3_log_proof_http_400_retry_can_be_marked_terminal(tmp_path):
    fixture, store, transferred = _pending_v3_fixture(tmp_path)
    transfer_hash_value = protocol_v3.transfer_hash(transferred["recent_transfers"][-1])
    log_id = log_client.log_id_from_public_key("operator-key")
    exc = urllib.error.HTTPError(
        "http://operator.invalid/v3/proof",
        400,
        "Bad Request",
        hdrs=None,
        fp=None,
    )

    for attempt in range(store_module.V3_LOG_PROOF_STALE_HTTP_400_ATTEMPTS):
        retry = store._record_v3_log_proof_retry_failure(
            transfer_hash_value,
            log_id,
            exc,
            now=1_700_000_000 + attempt,
        )

    assert retry["terminal"] is True
    assert not store._v3_log_proof_retry_due(
        transfer_hash_value,
        log_id,
        now=1_800_000_000,
    )


def test_v3_finality_waits_for_peer_quorum_decision(tmp_path):
    fixture, store, transferred = _pending_v3_fixture(tmp_path)
    _mark_transfer_log_proven(store, transferred, fixture["bundle"])

    finalized = store.finalize_pending(
        now=2_000_000_000,
        buffer_seconds=0,
        require_v3_log_proof=True,
        settlement_reconciler=lambda _candidate: {
            "decision": "await",
            "reason": "awaiting_peer_quorum",
        },
    )

    assert finalized == []
    assert store.status_record_for_ref(fixture["token_id"])["status"] == "pending"


def test_v3_quorum_mode_does_not_finalize_without_reconciler(tmp_path):
    fixture, store, transferred = _pending_v3_fixture(tmp_path)
    store.settlement_quorum_enabled = True
    _mark_transfer_log_proven(store, transferred, fixture["bundle"])

    finalized = store.finalize_pending(
        now=2_000_000_000,
        buffer_seconds=0,
    )

    assert finalized == []
    assert store.status_record_for_ref(fixture["token_id"])["status"] == "pending"


def test_v3_finality_settles_after_log_proof_and_peer_quorum(tmp_path):
    fixture, store, transferred = _pending_v3_fixture(tmp_path)
    _mark_transfer_log_proven(store, transferred, fixture["bundle"])

    finalized = store.finalize_pending(
        now=2_000_000_000,
        buffer_seconds=0,
        require_v3_log_proof=True,
        settlement_reconciler=lambda _candidate: {"decision": "settle"},
    )

    assert finalized == [fixture["token_id"]]
    assert (
        store.status_record_for_ref(
            fixture["token_id"],
            min_settled_seconds=-(10**12),
        )["status"]
        == "strong_local"
    )


def test_late_conflict_proof_after_settlement_does_not_downgrade_v3_bill(tmp_path):
    fixture, store, transferred = _pending_v3_fixture(tmp_path)
    _mark_transfer_log_proven(store, transferred, fixture["bundle"])
    finalized = store.finalize_pending(
        now=int(time.time()),
        buffer_seconds=0,
        require_v3_log_proof=True,
        settlement_reconciler=lambda _candidate: {"decision": "settle"},
    )
    assert finalized == [fixture["token_id"]]

    proof = _late_conflict_proof_for_transferred(fixture, store, transferred)
    store.store_conflict_proof_v3(proof)

    confidence = store.bill_v3_confidence(
        fixture["token_id"],
        expected_owner=fixture["carol_address"],
        min_settled_seconds=0,
    )
    record = store.status_record_for_ref(fixture["token_id"], min_settled_seconds=0)

    assert confidence["accepted"] is True
    assert confidence["level"] == "strong_local"
    assert record["status"] == "strong_local"
    assert record["owner_address"] == fixture["carol_address"]
    assert wallet_services.bill_is_spendable_v3(
        store,
        transferred,
        fixture["carol_address"],
        trusted_operator_public_key=fixture["log_public"],
    )
    assert store.conflict_messages() == []
    with store._connect() as conn:
        row = conn.execute(
            "SELECT 1 FROM conflicts_v3 WHERE proof_hash = ?",
            (proof["proof_hash"],),
        ).fetchone()
    assert row is None

    response = store.peer_settlement_response_v3(
        {
            "type": "ind.peer_settlement_query.v3",
            "network_id": protocol_v3.DEFAULT_NETWORK_ID,
            "token_id": fixture["token_id"],
            "display_id": fixture["checkpoint_core"]["display_id"],
        }
    )
    assert response["status"] == "strong_local"
    assert response["conflict"] is False
    assert response["conflict_proof_hash"] == ""
    assert response["messages"] == []


def test_pending_conflict_proof_vetoes_v3_settlement(tmp_path):
    fixture, store, transferred = _pending_v3_fixture(tmp_path)
    _mark_transfer_log_proven(store, transferred, fixture["bundle"])
    proof = _late_conflict_proof_for_transferred(fixture, store, transferred)

    result = store.ingest_message(proof)
    finalized = store.finalize_pending(
        now=int(time.time()),
        buffer_seconds=0,
        require_v3_log_proof=True,
        settlement_reconciler=lambda _candidate: {"decision": "settle"},
    )
    record = store.status_record_for_ref(fixture["token_id"], min_settled_seconds=0)

    assert result["status"] == "conflict"
    assert finalized == []
    assert record["status"] == "conflict"
    assert store.conflict_messages()[0]["proof_hash"] == proof["proof_hash"]


def test_late_conflicting_transfer_after_settlement_is_ignored(tmp_path):
    fixture, store, transferred = _pending_v3_fixture(tmp_path)
    _mark_transfer_log_proven(store, transferred, fixture["bundle"])
    finalized = store.finalize_pending(
        now=int(time.time()),
        buffer_seconds=0,
        require_v3_log_proof=True,
        settlement_reconciler=lambda _candidate: {"decision": "settle"},
    )
    assert finalized == [fixture["token_id"]]

    base_bill = protocol_v3.create_bill_from_checkpoint_core(
        fixture["genesis_ref"],
        fixture["checkpoint_core"],
        fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=store.archive_segment_resolver_v3,
    )
    sibling = protocol_v3.create_transfer(
        base_bill,
        fixture["bob_private"],
        fixture["bob_public"],
        fixture["alice_address"],
        proof_bundle_resolver=store.proof_bundle_resolver_v3,
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=store.archive_segment_resolver_v3,
        timestamp=BASE_TIMESTAMP + 51,
    )
    announcement = protocol_v3.create_transfer_announcement(
        sibling,
        proof_bundle=fixture["bundle"],
        archive_segments=[fixture["archive_segment"]],
        now=BASE_TIMESTAMP + 52,
    )

    result = store.ingest_message(announcement)
    record = store.status_record_for_ref(fixture["token_id"], min_settled_seconds=0)

    assert result["status"] == "ignored_conflict"
    assert "conflict_proof" not in result
    assert record["status"] == "strong_local"
    assert record["owner_address"] == fixture["carol_address"]
    assert store.conflict_messages() == []
    with store._connect() as conn:
        conflict_rows = conn.execute(
            "SELECT COUNT(*) AS count_value FROM conflicts_v3 WHERE token_id = ?",
            (fixture["token_id"],),
        ).fetchone()
        sibling_rows = conn.execute(
            """
            SELECT COUNT(*) AS count_value
            FROM bills_v3
            WHERE token_id = ? AND owner_address = ?
            """,
            (fixture["token_id"], fixture["alice_address"]),
        ).fetchone()
    assert int(conflict_rows["count_value"]) == 0
    assert int(sibling_rows["count_value"]) == 0
    assert wallet_services.bill_is_spendable_v3(
        store,
        transferred,
        fixture["carol_address"],
        trusted_operator_public_key=fixture["log_public"],
    )
    assert not wallet_services.bill_is_spendable_v3(
        store,
        sibling,
        fixture["alice_address"],
        trusted_operator_public_key=fixture["log_public"],
    )


def test_late_conflict_proof_after_settlement_is_not_persisted(tmp_path):
    fixture, store, transferred = _pending_v3_fixture(tmp_path)
    _mark_transfer_log_proven(store, transferred, fixture["bundle"])
    finalized = store.finalize_pending(
        now=int(time.time()),
        buffer_seconds=0,
        require_v3_log_proof=True,
        settlement_reconciler=lambda _candidate: {"decision": "settle"},
    )
    assert finalized == [fixture["token_id"]]
    with store._connect() as conn:
        conn.execute(
            "UPDATE bills_v3 SET updated_at = ? WHERE token_id = ? AND status = 'settled'",
            (1, fixture["token_id"]),
        )

    proof = _late_conflict_proof_for_transferred(fixture, store, transferred)
    proof_hash = store.store_conflict_proof_v3(proof)

    assert proof_hash == proof["proof_hash"]
    assert store.conflict_messages() == []
    with store._connect() as conn:
        row = conn.execute(
            "SELECT 1 FROM conflicts_v3 WHERE proof_hash = ?",
            (proof["proof_hash"],),
        ).fetchone()
    assert row is None
    assert (
        store.status_record_for_ref(fixture["token_id"], min_settled_seconds=0)["status"]
        == "strong_local"
    )


def test_v3_finality_requires_operator_witness_quorum(tmp_path):
    fixture, store, transferred = _pending_v3_fixture(tmp_path)

    class Operator:
        def __init__(self, public_key):
            self.operator_public_key = public_key

    store.transparency_submitter = log_client.MultiTransparencySubmitter(
        [Operator("operator-a-key"), Operator("operator-b-key")]
    )
    _mark_transfer_log_proven(store, transferred, fixture["bundle"], "operator-a-key")

    finalized = store.finalize_pending(
        now=2_000_000_000,
        buffer_seconds=0,
        require_v3_log_proof=True,
        settlement_reconciler=lambda _candidate: {"decision": "settle"},
    )

    assert finalized == []
    _mark_transfer_log_proven(store, transferred, fixture["bundle"], "operator-b-key")
    finalized = store.finalize_pending(
        now=2_000_000_001,
        buffer_seconds=0,
        require_v3_log_proof=True,
        settlement_reconciler=lambda _candidate: {"decision": "settle"},
    )

    assert finalized == [fixture["token_id"]]


def test_strict_v3_finality_allows_threshold_below_operator_count_when_within_fanout(
    tmp_path, monkeypatch
):
    class Operator:
        def __init__(self, public_key):
            self.operator_public_key = public_key

    submitter = log_client.MultiTransparencySubmitter(
        [Operator("operator-a-key"), Operator("operator-b-key")]
    )

    monkeypatch.setenv("IND_OPERATOR_FINALITY_MIN_PROOFS", "1")
    store = INDLocalStore(
        db_path=tmp_path / "wallet-v3.db",
        require_transparency=True,
        transparency_submitter=submitter,
        transparency_verifier=object(),
    )

    assert store._operator_finality_required_proofs_v3() == 1


def test_strict_v3_finality_rejects_threshold_above_append_fanout(tmp_path, monkeypatch):
    class Operator:
        def __init__(self, public_key):
            self.operator_public_key = public_key

    submitter = log_client.MultiTransparencySubmitter(
        [Operator("operator-a-key"), Operator("operator-b-key")],
        append_fanout=1,
    )

    monkeypatch.setenv("IND_OPERATOR_FINALITY_MIN_PROOFS", "2")
    with pytest.raises(Exception, match="must not exceed"):
        INDLocalStore(
            db_path=tmp_path / "wallet-v3.db",
            require_transparency=True,
            transparency_submitter=submitter,
            transparency_verifier=object(),
        )


def test_strict_v3_finality_zero_threshold_tracks_append_operator_count(tmp_path, monkeypatch):
    class Operator:
        def __init__(self, public_key):
            self.operator_public_key = public_key

    submitter = log_client.MultiTransparencySubmitter(
        [
            Operator("operator-a-key"),
            Operator("operator-b-key"),
            Operator("operator-c-key"),
        ]
    )

    monkeypatch.setenv("IND_OPERATOR_FINALITY_MIN_PROOFS", "0")
    store = INDLocalStore(
        db_path=tmp_path / "wallet-v3.db",
        require_transparency=True,
        transparency_submitter=submitter,
        transparency_verifier=object(),
    )

    assert store._operator_finality_required_proofs_v3() == 2


def test_strict_v3_finality_majority_threshold_for_even_operator_count(tmp_path, monkeypatch):
    class Operator:
        def __init__(self, public_key):
            self.operator_public_key = public_key

    submitter = log_client.MultiTransparencySubmitter(
        [
            Operator("operator-a-key"),
            Operator("operator-b-key"),
            Operator("operator-c-key"),
            Operator("operator-d-key"),
        ]
    )

    monkeypatch.setenv("IND_OPERATOR_FINALITY_MIN_PROOFS", "0")
    store = INDLocalStore(
        db_path=tmp_path / "wallet-v3.db",
        require_transparency=True,
        transparency_submitter=submitter,
        transparency_verifier=object(),
    )

    assert store._operator_finality_required_proofs_v3() == 3


def test_v3_transfer_log_status_does_not_downgrade_proven(tmp_path):
    fixture, store, transferred = _pending_v3_fixture(tmp_path)
    transfer = transferred["recent_transfers"][-1]
    transfer_hash_value = protocol_v3.transfer_hash(transfer)
    _mark_transfer_log_proven(store, transferred, fixture["bundle"])

    with store._connect() as conn:
        store._record_v3_transfer_log_status_conn(
            conn,
            transfer,
            proof_bundle=fixture["bundle"],
            status="log_pending",
            response={
                "entry_hash": transfer_hash_value,
                "leaf_index": 9,
                "tree_size": 10,
            },
        )

    rows = store._v3_transfer_log_statuses(transfer_hash_value)
    assert len(rows) == 1
    assert rows[0]["status"] == "log_proven"
    assert rows[0]["leaf_index"] == 0


def test_v3_transfer_log_status_does_not_downgrade_pending_to_unlogged(tmp_path):
    fixture, store, transferred = _pending_v3_fixture(tmp_path)
    transfer = transferred["recent_transfers"][-1]
    transfer_hash_value = protocol_v3.transfer_hash(transfer)

    with store._connect() as conn:
        store._record_v3_transfer_log_status_conn(
            conn,
            transfer,
            proof_bundle=fixture["bundle"],
            status="log_pending",
            response={
                "entry_hash": transfer_hash_value,
                "leaf_index": 2,
                "tree_size": 3,
            },
        )
        store._record_v3_transfer_log_status_conn(
            conn,
            transfer,
            proof_bundle=fixture["bundle"],
            status="unlogged",
            response={},
            error="temporary operator failure",
        )

    rows = store._v3_transfer_log_statuses(transfer_hash_value)
    assert len(rows) == 1
    assert rows[0]["status"] == "log_pending"
    assert rows[0]["leaf_index"] == 2
    assert rows[0]["error"] == ""


def test_v3_transfer_log_status_upgrades_pending_to_proven(tmp_path):
    fixture, store, transferred = _pending_v3_fixture(tmp_path)
    transfer = transferred["recent_transfers"][-1]
    transfer_hash_value = protocol_v3.transfer_hash(transfer)

    with store._connect() as conn:
        store._record_v3_transfer_log_status_conn(
            conn,
            transfer,
            proof_bundle=fixture["bundle"],
            status="log_pending",
            response={
                "entry_hash": transfer_hash_value,
                "leaf_index": 2,
                "tree_size": 3,
            },
        )
        store._record_v3_transfer_log_status_conn(
            conn,
            transfer,
            proof_bundle=fixture["bundle"],
            status="log_proven",
            response={
                "entry_hash": transfer_hash_value,
                "leaf_index": 2,
                "tree_size": 3,
            },
        )

    rows = store._v3_transfer_log_statuses(transfer_hash_value)
    assert len(rows) == 1
    assert rows[0]["status"] == "log_proven"


def test_v3_finality_freezes_divergent_operator_witnesses(tmp_path, monkeypatch):
    monkeypatch.setenv("IND_OPERATOR_FINALITY_MIN_PROOFS", "1")
    fixture, store, transferred = _pending_v3_fixture(tmp_path)
    store.operator_finality_min_proofs = 1
    transfer = transferred["recent_transfers"][-1]
    divergent = copy.deepcopy(transfer)
    divergent["recipient_address"] = fixture["bob_address"]

    _mark_transfer_log_proven(store, transferred, fixture["bundle"], "operator-a-key")
    with store._connect() as conn:
        store._record_v3_transfer_log_status_conn(
            conn,
            divergent,
            operator_identity={
                "log_id": log_client.log_id_from_public_key("operator-b-key"),
                "operator_public_key": "operator-b-key",
            },
            status="log_proven",
            response={
                "entry_hash": protocol_v3.transfer_hash(divergent),
                "leaf_index": 1,
                "tree_size": 2,
            },
        )

    finalized = store.finalize_pending(
        now=2_000_000_000,
        buffer_seconds=0,
        require_v3_log_proof=True,
        settlement_reconciler=lambda _candidate: {"decision": "settle"},
    )

    assert finalized == []
    assert store.status_record_for_ref(fixture["token_id"])["status"] == "pending"


def test_transfer_log_status_v3_migrates_to_operator_rows(tmp_path):
    db_path = tmp_path / "wallet-v3.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute("""
            CREATE TABLE transfer_log_status_v3 (
                transfer_hash TEXT PRIMARY KEY,
                token_id TEXT NOT NULL,
                spend_key TEXT NOT NULL,
                log_id TEXT,
                operator_public_key TEXT,
                status TEXT NOT NULL,
                entry_hash TEXT,
                leaf_index INTEGER,
                tree_size INTEGER,
                error TEXT,
                updated_at INTEGER NOT NULL
            )
            """)
        conn.execute(
            """
            INSERT INTO transfer_log_status_v3(
                transfer_hash, token_id, spend_key, log_id, operator_public_key,
                status, entry_hash, leaf_index, tree_size, error, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "a" * 64,
                "token-a",
                "b" * 64,
                "",
                "operator-key",
                "log_proven",
                "a" * 64,
                0,
                1,
                "",
                1,
            ),
        )
        conn.execute("PRAGMA user_version=6")

    store = INDLocalStore(db_path=db_path, require_transparency=False)

    with store._connect() as conn:
        pk_columns = store._table_primary_key_columns(conn, "transfer_log_status_v3")
        row = conn.execute("SELECT * FROM transfer_log_status_v3").fetchone()
    assert pk_columns == ["transfer_hash", "log_id"]
    assert row["log_id"] == log_client.log_id_from_public_key("operator-key")


def test_store_migrates_legacy_receiptless_statuses_to_verified(tmp_path):
    db_path = tmp_path / "wallet-v3.db"
    INDLocalStore(db_path=db_path, require_transparency=False)
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO tokens(
                token_id, display_id, payload, owner_address, last_transfer_hash, sequence,
                value, status, first_seen, updated_at, finalized_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "token-a",
                "1x1",
                "{}",
                "xowner",
                "transfer-a",
                1,
                1,
                "unreceipted",
                1,
                1,
                None,
            ),
        )
        conn.execute(
            """
            INSERT INTO transfers(
                transfer_hash, token_id, previous_hash, sequence, sender_address,
                recipient_address, transfer_json, token_payload, status, first_seen, finalized_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "transfer-a",
                "token-a",
                "previous-a",
                1,
                "xsender",
                "xowner",
                "{}",
                "{}",
                "unreceipted",
                1,
                None,
            ),
        )
        conn.execute(
            """
            INSERT INTO bills_v3(
                bill_hash, token_id, display_id, owner_address, sequence,
                checkpoint_hash, proof_bundle_hash, bill_blob, first_seen, updated_at, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "bill-a",
                "token-a",
                "1x1",
                "xowner",
                1,
                "checkpoint-a",
                None,
                b"not-a-bill",
                1,
                1,
                "unreceipted",
            ),
        )
        conn.execute("PRAGMA user_version=7")

    store = INDLocalStore(db_path=db_path, require_transparency=False)

    with store._connect() as conn:
        token_status = conn.execute("SELECT status FROM tokens").fetchone()[0]
        transfer_status = conn.execute("SELECT status FROM transfers").fetchone()[0]
        bill_status = conn.execute("SELECT status FROM bills_v3").fetchone()[0]
    assert (token_status, transfer_status, bill_status) == (
        "verified",
        "verified",
        "verified",
    )


def test_store_migration_removes_receipt_storage(tmp_path):
    db_path = tmp_path / "wallet-v3.db"
    INDLocalStore(db_path=db_path, require_transparency=False)
    with sqlite3.connect(db_path) as conn:
        conn.execute("""
            CREATE TABLE receipts_v3 (
                receipt_hash TEXT PRIMARY KEY,
                token_id TEXT NOT NULL,
                transfer_hash TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                recipient_address TEXT NOT NULL,
                receipt_json TEXT NOT NULL,
                first_seen INTEGER NOT NULL
            )
            """)
        conn.execute(
            """
            INSERT INTO receipts_v3(
                receipt_hash, token_id, transfer_hash, sequence,
                recipient_address, receipt_json, first_seen
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            ("receipt-a", "token-a", "transfer-a", 1, "xowner", "{}", 1),
        )
        conn.execute(
            """
            INSERT INTO messages(
                message_hash, message_type, token_id, recipient_address, message_json, first_seen
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                "receipt-message",
                "ind.receipt_announcement.v3",
                "token-a",
                "xowner",
                "{}",
                1,
            ),
        )
        conn.execute("PRAGMA user_version=8")

    store = INDLocalStore(db_path=db_path, require_transparency=False)

    with store._connect() as conn:
        receipt_table = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'receipts_v3'"
        ).fetchone()
        receipt_message = conn.execute(
            "SELECT 1 FROM messages WHERE message_type = 'ind.receipt_announcement.v3'"
        ).fetchone()
    assert receipt_table is None
    assert receipt_message is None


def test_store_v3_dev_local_proof_ingests_embedded_transfer_without_verifier(tmp_path):
    fixture = native_v3_archive_fixture(tmp_path)
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
        now=1_700_000_055,
    )
    store = INDLocalStore(db_path=tmp_path / "wallet-v3.db", require_transparency=False)

    result = store.ingest_message(announcement)

    assert result["status"] == "verified"
    assert store.bill_v3_records_for_owner(fixture["carol_address"], statuses=("verified",))


def test_wallet_bill_sync_records_import_without_receipts(tmp_path):
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
        now=1_700_000_055,
    )
    node_store = INDLocalStore(db_path=tmp_path / "node.db", require_transparency=False)
    client_store = INDLocalStore(db_path=tmp_path / "client.db", require_transparency=False)
    node_store.ingest_message(announcement)

    response = node_store.wallet_bill_sync_response(
        {"address": fixture["carol_address"], "known_tokens": {}, "limit": 10}
    )

    assert response["type"] == "ind.wallet_bill_sync_response.v3"
    assert len(response["records"]) == 1
    result = client_store.ingest_wallet_bill_sync_record(response["records"][0])
    assert result["status"] == "verified"
    assert (
        client_store.status_record_for_ref(fixture["token_id"])["owner_address"]
        == fixture["carol_address"]
    )

    followup = node_store.wallet_bill_sync_response(
        client_store.wallet_delta_sync_request(fixture["carol_address"])
    )
    assert followup["records"] == []


def test_wallet_bill_sync_response_pages_with_backfill_cursor(tmp_path, monkeypatch):
    monkeypatch.setenv("IND_LOG_ROOT_GOSSIP", "0")
    store = INDLocalStore(db_path=tmp_path / "wallet-v3.db", require_transparency=False)
    owner_address, _private_key, _public_key = keys_v3.generate_keypair(b"\x46" * 32)
    with store._connect() as conn:
        for index, updated_at in enumerate((300, 200, 100), start=1):
            conn.execute(
                """
                INSERT INTO bills_v3(
                    bill_hash, token_id, display_id, owner_address, sequence,
                    checkpoint_hash, proof_bundle_hash, bill_blob,
                    first_seen, updated_at, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    f"sync-page-bill-{index}",
                    f"sync-page-token-{index}",
                    f"1x{index}",
                    owner_address,
                    1,
                    f"sync-page-checkpoint-{index}",
                    None,
                    b"not-used-by-this-test",
                    updated_at,
                    updated_at,
                    "settled",
                ),
            )

    monkeypatch.setattr(store_module, "_bill_v3_record_has_allowed_value", lambda _record: True)
    monkeypatch.setattr(
        INDLocalStore,
        "_wallet_sync_record_from_bill_row_v3",
        lambda self, row: {
            "type": "ind.wallet_bill_sync_record.v3",
            "token_id": row["token_id"],
            "display_id": row["display_id"],
            "sequence": int(row["sequence"]),
            "updated_at": int(row["updated_at"]),
        },
    )

    first = store.wallet_bill_sync_response(
        {"address": owner_address, "direction": "backfill", "limit": 2}
    )
    second = store.wallet_bill_sync_response(
        {
            "address": owner_address,
            "direction": "backfill",
            "limit": 2,
            "cursor": first["next_cursor"],
        }
    )

    assert [record["display_id"] for record in first["records"]] == ["1x1", "1x2"]
    assert first["has_more"] is True
    assert first["next_cursor"] == {
        "updated_at": 200,
        "sequence": 1,
        "token_id": "sync-page-token-2",
    }
    assert [record["display_id"] for record in second["records"]] == ["1x3"]
    assert second["has_more"] is False
    assert second["next_cursor"] is None


def test_store_v3_rejects_receipt_announcement_gossip(tmp_path):
    fixture = native_v3_archive_fixture(tmp_path)
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
        now=1_700_000_055,
    )
    receipt_announcement = {
        "type": protocol_v3.RECEIPT_ANNOUNCEMENT_TYPE,
        "version": protocol_v3.VERSION,
        "network_id": protocol_v3.DEFAULT_NETWORK_ID,
        "bill": transferred,
        "receipt": {"disabled": True},
        "announced_at": 1_700_000_060,
    }
    store = INDLocalStore(db_path=tmp_path / "wallet-v3.db", require_transparency=False)

    transfer_result = store.ingest_message(announcement)
    with pytest.raises(Exception, match="unsupported gossip message type"):
        store.ingest_message(receipt_announcement)

    assert transfer_result["status"] == "verified"
    assert store.status_record_for_ref(fixture["token_id"])["status"] == "verified"
    assert store.pending_v3_settlement_candidates(now=2_000_000_000, buffer_seconds=0) == []


def test_v3_spendable_lookup_blocks_sender_after_verified_newer_branch(tmp_path):
    fixture = native_v3_archive_fixture(tmp_path)
    store = INDLocalStore(db_path=tmp_path / "wallet-v3.db", require_transparency=False)
    store.store_archive_segment_v3(fixture["archive_segment"])
    bill = protocol_v3.create_bill_from_checkpoint_core(
        fixture["genesis_ref"],
        fixture["checkpoint_core"],
        fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=store.archive_segment_resolver_v3,
    )
    store.store_bill_v3(
        bill,
        proof_bundle=fixture["bundle"],
        status="settled",
        trusted_operator_public_key=fixture["log_public"],
    )
    transferred = protocol_v3.create_transfer(
        bill,
        fixture["bob_private"],
        fixture["bob_public"],
        fixture["carol_address"],
        proof_bundle=fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=store.archive_segment_resolver_v3,
        timestamp=BASE_TIMESTAMP + 50,
    )
    store.store_bill_v3(
        transferred,
        proof_bundle=fixture["bundle"],
        status="verified",
        trusted_operator_public_key=fixture["log_public"],
    )

    assert (
        store.get_spendable_bill_v3_by_display_id(
            fixture["checkpoint_core"]["display_id"],
            fixture["bob_address"],
        )
        is None
    )
    assert (
        store.bill_v3_records_for_owner(
            fixture["bob_address"],
            statuses=("settled", "verified"),
        )
        == []
    )


def test_store_v3_ingest_keeps_only_referenced_archive_sidecars(tmp_path):
    fixture = native_v3_archive_fixture(tmp_path / "referenced")
    unrelated = native_v3_archive_fixture(
        tmp_path / "unrelated",
        operator_label="native-log-unrelated",
        token_label="native-v3-token-unrelated",
        genesis_label="native-v3-genesis-unrelated",
        display_id="1x102",
    )
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
        timestamp=BASE_TIMESTAMP + 50,
    )
    announcement = protocol_v3.create_transfer_announcement(
        transferred,
        proof_bundle=fixture["bundle"],
        archive_segments=[fixture["archive_segment"], unrelated["archive_segment"]],
        now=BASE_TIMESTAMP + 55,
    )
    store = INDLocalStore(db_path=tmp_path / "wallet-v3.db", require_transparency=False)

    result = store.ingest_message(announcement)

    assert result["status"] == "verified"
    assert store.get_archive_segment_v3(fixture["archive_segment"]["segment_hash"]) is not None
    assert store.get_archive_segment_v3(unrelated["archive_segment"]["segment_hash"]) is None


def test_store_v3_native_transfer_ingest_calls_submitter(tmp_path):
    fixture = native_v3_archive_fixture(tmp_path)
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
        now=1_700_000_055,
    )
    calls = []

    class Submitter:
        def submit_transfer_announcement(self, message):
            calls.append(message)
            transfer = protocol_v3.decode_transfer_announcement(message)[0]["recent_transfers"][-1]
            return {
                "accepted": True,
                "entry_hash": protocol_v3.transfer_hash(transfer),
                "leaf_index": 0,
                "tree_size": 1,
                "spend_key": protocol_v3.spend_key_for_transfer(transfer),
            }

    store = INDLocalStore(
        db_path=tmp_path / "wallet-v3.db",
        require_transparency=False,
        transparency_verifier=_v3_verifier_for_fixture(fixture, "submitter"),
        transparency_submitter=Submitter(),
        transparency_submission_verify_timeout_seconds=0,
    )

    result = store.ingest_message(announcement)

    assert result["status"] == "verified"
    assert calls == [announcement]


def test_store_v3_compacts_verified_native_bill_after_interval(tmp_path):
    fixture = native_v3_archive_fixture(tmp_path)
    operator, verifier = _live_v3_operator_and_verifier(fixture, "compact")
    store = INDLocalStore(
        db_path=tmp_path / "wallet-v3.db",
        require_transparency=False,
        transparency_verifier=verifier,
        transparency_submitter=operator,
        checkpoint_interval_transfers=1,
        transparency_submission_verify_timeout_seconds=0,
    )
    store.store_archive_segment_v3(fixture["archive_segment"])
    store.store_proof_bundle_v3(
        fixture["bundle"],
        transparency_verifier=verifier,
    )
    bill = protocol_v3.create_bill_from_checkpoint_core(
        fixture["genesis_ref"],
        fixture["checkpoint_core"],
        fixture["bundle"],
        transparency_verifier=verifier,
        archive_segment_resolver=store.archive_segment_resolver_v3,
    )
    transferred = protocol_v3.create_transfer(
        bill,
        fixture["bob_private"],
        fixture["bob_public"],
        fixture["carol_address"],
        proof_bundle_resolver=store.proof_bundle_resolver_v3,
        transparency_verifier=verifier,
        archive_segment_resolver=store.archive_segment_resolver_v3,
        timestamp=BASE_TIMESTAMP + 50,
    )
    store.ingest_message(
        protocol_v3.create_transfer_announcement(
            transferred,
            proof_bundle=fixture["bundle"],
            archive_segments=[fixture["archive_segment"]],
            now=BASE_TIMESTAMP + 55,
        )
    )
    finalized = store.finalize_pending(now=2_000_000_000, buffer_seconds=0)
    compact = store.get_bill_v3_by_token_id(fixture["token_id"])
    compact_bundle = store.get_proof_bundle_v3(compact["proof_bundle_ref"]["proof_bundle_hash"])

    assert finalized == []
    assert compact["recent_transfers"] == []
    assert compact["checkpoint_core"]["sequence"] == 2
    assert (
        compact["checkpoint_core"]["previous_checkpoint_hash"]
        == fixture["checkpoint_core"]["checkpoint_hash"]
    )
    assert compact_bundle["source_evidence"]["archive_segment"] is None
    assert store.get_compact_bill(fixture["token_id"]) == compact
    state = protocol_v3.verify_bill(
        compact,
        proof_bundle_resolver=store.proof_bundle_resolver_v3,
        transparency_verifier=verifier,
        archive_segment_resolver=store.archive_segment_resolver_v3,
    )
    assert state.owner_address == fixture["carol_address"]


def test_operator_spend_map_persists_incremental_node_cache(tmp_path):
    fixture = native_v3_archive_fixture(tmp_path)

    with fixture["log"]._connect() as conn:
        node_count = conn.execute(
            "SELECT COUNT(*) AS count_value FROM spend_map_nodes_v3"
        ).fetchone()["count_value"]
        cached_claim_count = conn.execute(
            "SELECT COUNT(*) AS count_value FROM spend_map_claims_v3"
        ).fetchone()["count_value"]
        rebuilt_claims = fixture["log"]._spend_claim_records(
            conn,
            tree_size=fixture["bundle"]["signed_root"]["tree_size"],
        )

    proof = fixture["log"].spend_map_proof(
        protocol_v3.spend_key_for_transfer(fixture["first_transfer"]),
        fixture["bundle"]["signed_root"]["tree_size"],
    )
    canonical = log_client.build_spend_map_proof(
        rebuilt_claims,
        protocol_v3.spend_key_for_transfer(fixture["first_transfer"]),
        fixture["bundle"]["signed_root"]["tree_size"],
    )
    claims = log_client.verify_spend_map_proof(proof, fixture["bundle"]["signed_root"])

    assert node_count > 0
    assert cached_claim_count == 1
    assert proof == canonical
    assert claims[0]["transfer_hash"] == protocol_v3.transfer_hash(fixture["first_transfer"])


def test_store_v3_recent_messages_preserve_native_transfer_envelope(tmp_path):
    fixture = native_v3_archive_fixture(tmp_path)
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
        now=1_700_000_055,
    )
    store = INDLocalStore(db_path=tmp_path / "wallet-v3.db", require_transparency=False)

    store.ingest_message(announcement)
    [stored] = store.recent_messages(limit=1)
    replay_store = INDLocalStore(
        db_path=tmp_path / "wallet-v3-replay.db", require_transparency=False
    )
    replay = replay_store.ingest_message(stored)

    assert stored["payload_encoding"] == protocol_v3.V3_PAYLOAD_ENCODING
    assert stored["proof_bundle"] is not None
    assert stored["archive_segments"]
    assert replay["accepted"]


def test_conflict_messages_are_v3_only(tmp_path):
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
        proof_bundle=fixture["bundle"],
        status="verified",
        trusted_operator_public_key=fixture["log_public"],
    )
    branch_a = protocol_v3.create_transfer(
        bill,
        fixture["bob_private"],
        fixture["bob_public"],
        fixture["carol_address"],
        proof_bundle_resolver=store.proof_bundle_resolver_v3,
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=store.archive_segment_resolver_v3,
        timestamp=1_700_000_050,
    )
    branch_b = protocol_v3.create_transfer(
        bill,
        fixture["bob_private"],
        fixture["bob_public"],
        fixture["alice_address"],
        proof_bundle_resolver=store.proof_bundle_resolver_v3,
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=store.archive_segment_resolver_v3,
        timestamp=1_700_000_051,
    )
    proof = protocol_v3.create_conflict_proof_from_transfers(
        branch_a["recent_transfers"][0],
        branch_b["recent_transfers"][0],
    )
    store.store_conflict_proof_v3(proof)
    with store._connect() as conn:
        conn.execute(
            """
            INSERT INTO conflicts(
                proof_hash, conflict_key, token_id, previous_hash, proof_json, detected_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            ("legacy-proof", "legacy-key", "legacy-token", "legacy-prev", "{}", 1),
        )

    messages = store.conflict_messages(limit=10)

    assert [message["type"] for message in messages] == [protocol_v3.CONFLICT_PROOF_TYPE]
    assert messages[0]["proof_hash"] == proof["proof_hash"]


def test_store_v3_conflict_dominates_branch_status_and_confidence(tmp_path):
    fixture = native_v3_archive_fixture(tmp_path)
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
        timestamp=BASE_TIMESTAMP + 50,
    )
    branch_b = protocol_v3.create_transfer(
        bill,
        fixture["bob_private"],
        fixture["bob_public"],
        fixture["alice_address"],
        proof_bundle=fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=fixture["archive_resolver"],
        timestamp=BASE_TIMESTAMP + 51,
    )
    announcement_a = protocol_v3.create_transfer_announcement(
        branch_a,
        proof_bundle=fixture["bundle"],
        archive_segments=[fixture["archive_segment"]],
        now=BASE_TIMESTAMP + 55,
    )
    announcement_b = protocol_v3.create_transfer_announcement(
        branch_b,
        proof_bundle=fixture["bundle"],
        archive_segments=[fixture["archive_segment"]],
        now=BASE_TIMESTAMP + 56,
    )
    submitter_calls = []

    class Submitter:
        def submit_transfer_announcement(self, message):
            submitter_calls.append(message)
            return {"accepted": False}

    store = INDLocalStore(
        db_path=tmp_path / "wallet-v3.db",
        require_transparency=False,
        transparency_submitter=Submitter(),
    )

    first = store.ingest_message(announcement_a)
    second = store.ingest_message(announcement_b)

    assert first["status"] == "verified"
    assert second["status"] == "conflict"
    assert second["conflict_proof"]["type"] == protocol_v3.CONFLICT_PROOF_TYPE
    assert len(submitter_calls) == 1

    expected_sequence = int(branch_a["recent_transfers"][-1]["sequence"])
    by_display = store.status_record_for_ref("1x1")
    by_token = store.status_record_for_ref(fixture["token_id"])
    confidence = store.bill_v3_confidence(
        fixture["token_id"],
        expected_owner=fixture["carol_address"],
        min_settled_seconds=0,
    )

    for record in (by_display, by_token):
        assert record["status"] == "conflict"
        assert record["owner_address"] == ""
        assert record["sequence"] == expected_sequence
        assert set(record["conflicting_owner_addresses"]) == {
            fixture["alice_address"],
            fixture["carol_address"],
        }
    assert by_display["display_id"] == "1x1"
    assert by_token["display_id"] == "1x1"
    assert confidence["accepted"] is False
    assert confidence["level"] == "conflict"


def test_store_v3_accepts_configured_second_operator(tmp_path):
    fixture_a = native_v3_archive_fixture(
        tmp_path / "operator-a",
        operator_label="native-log-a",
        token_label="native-v3-token-a",
        genesis_label="native-v3-genesis-a",
        display_id="1x101",
    )
    fixture_b = native_v3_archive_fixture(
        tmp_path / "operator-b",
        operator_label="native-log-b",
        token_label="native-v3-token-b",
        genesis_label="native-v3-genesis-b",
        display_id="1x102",
    )
    verifier = log_client.MultiTransparencyVerifier(
        [
            _v3_verifier_for_fixture(fixture_a, "operator-a"),
            _v3_verifier_for_fixture(fixture_b, "operator-b"),
        ]
    )
    store = INDLocalStore(
        db_path=tmp_path / "wallet-v3.db",
        require_transparency=False,
        transparency_verifier=verifier,
    )
    store.store_archive_segment_v3(fixture_b["archive_segment"])

    checkpoint = store.store_proof_bundle_v3(
        fixture_b["bundle"],
        transparency_verifier=verifier,
    )

    assert checkpoint["checkpoint_hash"] == fixture_b["checkpoint_core"]["checkpoint_hash"]


def test_store_v3_rejects_unconfigured_operator(tmp_path):
    fixture_a = native_v3_archive_fixture(
        tmp_path / "operator-a",
        operator_label="native-log-a",
        token_label="native-v3-token-a",
        genesis_label="native-v3-genesis-a",
        display_id="1x101",
    )
    fixture_b = native_v3_archive_fixture(
        tmp_path / "operator-b",
        operator_label="native-log-b",
        token_label="native-v3-token-b",
        genesis_label="native-v3-genesis-b",
        display_id="1x102",
    )
    verifier = log_client.MultiTransparencyVerifier(
        [_v3_verifier_for_fixture(fixture_a, "operator-a")]
    )
    store = INDLocalStore(
        db_path=tmp_path / "wallet-v3.db",
        require_transparency=False,
        transparency_verifier=verifier,
    )
    store.store_archive_segment_v3(fixture_b["archive_segment"])

    with pytest.raises(log_client.RootVerificationError, match="untrusted transparency operator"):
        store.store_proof_bundle_v3(fixture_b["bundle"], transparency_verifier=verifier)


def test_submitter_from_environment_ignores_verify_only_operator(monkeypatch):
    monkeypatch.setattr(log_client, "_settings_module", lambda: None)
    monkeypatch.setenv(
        "IND_LOG_OPERATORS",
        json.dumps(
            [
                {
                    "url": "http://127.0.0.1:8890",
                    "public_key": "local-key",
                    "mirrors": ["files/local-mirror"],
                },
                {
                    "public_key": "remote-key",
                    "mirrors": ["https://example.invalid/transparency"],
                    "proof_archives": ["https://example.invalid/transparency/archive"],
                },
            ]
        ),
    )
    monkeypatch.delenv("IND_LOG_OPERATOR_URL", raising=False)

    submitter = log_client.submitter_from_environment()

    assert isinstance(submitter, log_client.HTTPTransparencyOperator)
    assert submitter.http.base_url == "http://127.0.0.1:8890"


def test_multi_submitter_uses_authoritative_operator_key():
    calls = []

    class Operator:
        def __init__(self, label, public_key):
            self.label = label
            self.operator_public_key = public_key

        def status(self):
            return {"state": "active"}

        def submit_transfer_announcement(self, announcement):
            calls.append((self.label, announcement))
            return {"accepted": True, "operator": self.label}

    submitter = log_client.MultiTransparencySubmitter(
        [
            Operator("primary", "primary-key"),
            Operator("iotb", "iotb-key"),
        ]
    )

    result = submitter.submit_transfer_announcement_for_operator(
        {"type": "transfer"},
        operator_public_key="iotb-key",
    )

    assert result == {"accepted": True, "operator": "iotb"}
    assert calls == [("iotb", {"type": "transfer"})]
    with pytest.raises(log_client.TransparencyLogError, match="no matching active"):
        submitter.submit_transfer_announcement_for_operator(
            {"type": "transfer"},
            operator_public_key="missing-key",
        )


def test_multi_submitter_fans_out_to_all_append_operators():
    calls = []

    class Operator:
        def __init__(self, label, public_key, error=None):
            self.label = label
            self.operator_public_key = public_key
            self.error = error

        def status(self):
            return {"state": "active"}

        def submit_transfer_announcement(self, announcement):
            calls.append((self.label, announcement))
            if self.error:
                raise log_client.TransparencyLogError(self.error)
            return {
                "accepted": True,
                "entry_hash": "a" * 64,
                "leaf_index": 0,
                "tree_size": 1,
                "spend_key": "b" * 64,
            }

    submitter = log_client.MultiTransparencySubmitter(
        [
            Operator("primary", "primary-key"),
            Operator("iotb", "iotb-key", error="offline"),
        ]
    )

    results = submitter.submit_transfer_announcement_to_all({"type": "transfer"})

    assert calls == [("primary", {"type": "transfer"}), ("iotb", {"type": "transfer"})]
    assert [item["log_id"] for item in results] == [
        log_client.log_id_from_public_key("primary-key"),
        log_client.log_id_from_public_key("iotb-key"),
    ]
    assert results[0]["accepted"] is True
    assert results[1]["accepted"] is False
    assert results[1]["error"] == "offline"


def test_multi_submitter_caps_fanout_and_keeps_core_domains():
    calls = []

    class Operator:
        def __init__(self, label, public_key, url):
            self.label = label
            self.operator_public_key = public_key
            self.url = url

        def status(self):
            return {"state": "active"}

        def submit_transfer_announcement(self, announcement):
            calls.append(self.label)
            return {
                "accepted": True,
                "entry_hash": "a" * 64,
                "leaf_index": 0,
                "tree_size": 1,
                "spend_key": "b" * 64,
            }

    operators = [
        Operator("other-1", "other-1-key", "https://one.example.test/operator-api"),
        Operator(
            "ind",
            "ind-key",
            "https://testnet-seed.international-dollar.com/operator-api",
        ),
        Operator("other-2", "other-2-key", "https://two.example.test/operator-api"),
        Operator(
            "iotb",
            "iotb-key",
            "https://testnet-seed.internetofthebots.com/operator-api",
        ),
        Operator("other-3", "other-3-key", "https://three.example.test/operator-api"),
        Operator("other-4", "other-4-key", "https://four.example.test/operator-api"),
        Operator("other-5", "other-5-key", "https://five.example.test/operator-api"),
    ]
    submitter = log_client.MultiTransparencySubmitter(operators, append_fanout=5)

    results = submitter.submit_transfer_announcement_to_all({"type": "transfer", "nonce": "a"})

    assert len(results) == 5
    assert len(calls) == 5
    assert "ind" in calls
    assert "iotb" in calls


def test_operator_transparency_url_is_static_root_mirror():
    mirror = log_client._coerce_mirror("https://example.invalid/operator-transparency")

    assert isinstance(mirror, log_client.HTTPStaticRootMirror)


def test_invalid_conflicts_v3_are_cleaned_and_not_rewarned(tmp_path):
    store = INDLocalStore(db_path=tmp_path / "wallet-v3.db", require_transparency=False)
    with store._connect() as conn:
        conn.execute(
            """
            INSERT INTO conflicts_v3(
                proof_hash, conflict_key, token_id, previous_hash, proof_json, detected_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            ("bad-proof", "bad-key", "bad-token", "bad-prev", "{}", 1),
        )

    dry_run = store.cleanup_invalid_conflicts_v3(dry_run=True)
    applied = store.cleanup_invalid_conflicts_v3(dry_run=False)

    assert dry_run["invalid"] == 1
    assert dry_run["deleted"] == 0
    assert applied["deleted"] == 1
    with store._connect() as conn:
        remaining = conn.execute(
            "SELECT COUNT(*) AS count_value FROM conflicts_v3 WHERE proof_hash = ?",
            ("bad-proof",),
        ).fetchone()["count_value"]
    assert remaining == 0

    with store._connect() as conn:
        conn.execute(
            """
            INSERT INTO conflicts_v3(
                proof_hash, conflict_key, token_id, previous_hash, proof_json, detected_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            ("bad-proof-2", "bad-key-2", "bad-token", "bad-prev", "{}", 1),
        )

    assert store.conflict_messages(limit=10) == []
    assert store.conflict_messages(limit=10) == []


def test_store_v3_persists_conflict_proofs(tmp_path):
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
        proof_bundle=fixture["bundle"],
        status="verified",
        trusted_operator_public_key=fixture["log_public"],
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

    assert conflict_hash == conflict["proof_hash"]


def test_wallet_services_v3_spends_stored_bill(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("IND_NETWORK", "testnet")
    monkeypatch.setenv("IND_NODE_PORT", "18888")
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
        "1x1 wallet",
        fixture["carol_address"],
        store=store,
        trusted_operator_public_key=fixture["log_public"],
        timestamp=1_700_000_050,
    )

    assert state.owner_address == fixture["carol_address"]
    assert store.get_bill_v3_by_token_id(fixture["token_id"])["recent_transfers"]
