import os
import json
from types import SimpleNamespace
from unittest import mock

from ind import keys_v3
from ind import sender_node
from ind import token as ind_token


def test_wallet_sync_store_falls_back_for_unconfigured_development_transparency():
    fallback_store = object()

    with mock.patch.dict(os.environ, {"IND_REQUIRE_TRANSPARENCY_LOG": ""}, clear=False):
        with mock.patch.object(
            sender_node.ind_settings,
            "load_security_settings",
            return_value={"security_profile": "development"},
        ):
            with mock.patch.object(sender_node.ind_settings, "production_mode", return_value=False):
                with mock.patch.object(
                    sender_node.ind_token,
                    "INDLocalStore",
                    return_value=fallback_store,
                ) as store_ctor:
                    assert sender_node.wallet_sync_store() is fallback_store

    assert store_ctor.call_args_list == [mock.call(require_transparency=False)]


def test_wallet_sync_store_keeps_explicit_strict_transparency_failure():
    error = ind_token.ValidationError(sender_node.MISSING_TRANSPARENCY_VERIFIER)

    with mock.patch.dict(os.environ, {"IND_REQUIRE_TRANSPARENCY_LOG": "1"}, clear=False):
        with mock.patch.object(sender_node.ind_token, "INDLocalStore", side_effect=error):
            try:
                sender_node.wallet_sync_store()
            except ind_token.ValidationError as exc:
                assert sender_node.MISSING_TRANSPARENCY_VERIFIER in str(exc)
            else:
                raise AssertionError("wallet_sync_store should keep explicit strict failure")


def test_wallet_sync_store_passes_explicit_db_path_to_fallback_store():
    fallback_store = object()

    with mock.patch.dict(os.environ, {"IND_REQUIRE_TRANSPARENCY_LOG": ""}, clear=False):
        with mock.patch.object(
            sender_node.ind_settings,
            "load_security_settings",
            return_value={"security_profile": "development"},
        ):
            with mock.patch.object(sender_node.ind_settings, "production_mode", return_value=False):
                with mock.patch.object(
                    sender_node.ind_token,
                    "INDLocalStore",
                    return_value=fallback_store,
                ) as store_ctor:
                    assert sender_node.wallet_sync_store(db_path="ind_gossip_testnet.db") is fallback_store

    assert store_ctor.call_args_list == [mock.call(
        require_transparency=False,
        db_path="ind_gossip_testnet.db",
    )]


def test_receive_bills_reports_incremental_progress():
    class FakeStore:
        def __init__(self):
            self.ingested = []
            self.records = []

        def ingest_message(self, message):
            self.ingested.append(message)
            return {"accepted": True, "status": "stored"}

        def ingest_wallet_bill_sync_record(self, record):
            self.records.append(record)
            return {"accepted": True, "status": "verified", "state": "bill-hash-only"}

        def finalize_pending(self, buffer_seconds=0):
            return []

        def token_records_for_owner(self, _address, settled_only=True):
            return []

    store = FakeStore()
    wallet_path = SimpleNamespace(name="wallet_decrypted_test")
    events = []
    peer_reports = [
        {
            "peer": "peer-a",
            "status": sender_node.REQUEST_OK,
            "messages": [{"type": "remote"}],
            "records": [
                {
                    "type": "ind.wallet_bill_sync_record.v3",
                    "display_id": "1x1",
                    "sequence": 1,
                }
            ],
            "direction": "reconcile",
            "has_more": True,
            "next_cursor": {"updated_at": 100, "sequence": 1, "token_id": "token-a"},
        },
        {"peer": "peer-b", "status": sender_node.REQUEST_TIMEOUT, "messages": []},
    ]

    with (
        mock.patch.object(sender_node, "ensure_runtime_files"),
        mock.patch.object(sender_node, "wallet_sync_store", return_value=store),
        mock.patch.object(
            sender_node.runtime_json,
            "iter_decrypted_wallet_files",
            return_value=[wallet_path],
        ),
        mock.patch.object(
            sender_node.runtime_json,
            "read_decrypted_wallet_lines",
            return_value=["wallet-address\n", "private\n", "public\n"],
        ),
        mock.patch.object(sender_node.runtime_json, "wallet_bill_lines", return_value=[]),
        mock.patch.object(sender_node, "iter_wallet_message_reports", return_value=peer_reports),
        mock.patch.object(sender_node.ind_settings, "finality_buffer_seconds", return_value=0),
    ):
        summary = sender_node.receive_bills(progress_callback=events.append)

    event_names = [event["event"] for event in events]
    assert summary["processed_messages"] == 1
    assert summary["processed_records"] == 1
    assert summary["fetched_messages"] == 1
    assert summary["fetched_records"] == 1
    assert summary["fetched_unique_records"] == 1
    assert summary["fetched_duplicate_records"] == 0
    assert summary["peer_timeouts"] == 1
    assert event_names.index("peer_report") < event_names.index("complete")
    assert "message_accepted" in event_names
    assert "record_accepted" in event_names
    record_event = next(event for event in events if event["event"] == "record_accepted")
    assert record_event["display_id"] == "1x1"
    assert record_event["sequence"] == 1
    peer_event = next(event for event in events if event["event"] == "peer_report")
    assert peer_event["direction"] == "reconcile"
    assert peer_event["has_more"] is True
    assert peer_event["next_cursor"] is True


def test_receive_bills_counts_duplicate_peer_records_separately():
    class FakeStore:
        def ingest_wallet_bill_sync_record(self, record):
            return {
                "accepted": True,
                "status": "verified",
                "state": SimpleNamespace(
                    display_id=record["display_id"],
                    sequence=record["sequence"],
                ),
            }

        def finalize_pending(self, buffer_seconds=0):
            return []

        def token_records_for_owner(self, _address, settled_only=True):
            return []

    store = FakeStore()
    wallet_path = SimpleNamespace(name="wallet_decrypted_test")
    record = {
        "type": "ind.wallet_bill_sync_record.v3",
        "token_id": "token-a",
        "display_id": "1x1",
        "sequence": 1,
    }
    peer_reports = [
        {"peer": "peer-a", "status": sender_node.REQUEST_OK, "records": [record]},
        {"peer": "peer-b", "status": sender_node.REQUEST_OK, "records": [dict(record)]},
    ]

    with (
        mock.patch.object(sender_node, "ensure_runtime_files"),
        mock.patch.object(sender_node, "wallet_sync_store", return_value=store),
        mock.patch.object(
            sender_node.runtime_json,
            "iter_decrypted_wallet_files",
            return_value=[wallet_path],
        ),
        mock.patch.object(
            sender_node.runtime_json,
            "read_decrypted_wallet_lines",
            return_value=["wallet-address\n", "private\n", "public\n"],
        ),
        mock.patch.object(sender_node.runtime_json, "wallet_bill_lines", return_value=[]),
        mock.patch.object(sender_node, "iter_wallet_message_reports", return_value=peer_reports),
        mock.patch.object(sender_node.ind_settings, "finality_buffer_seconds", return_value=0),
    ):
        events = []
        summary = sender_node.receive_bills(progress_callback=events.append)

    assert summary["fetched_records"] == 2
    assert summary["fetched_unique_records"] == 1
    assert summary["fetched_duplicate_records"] == 1
    assert summary["checked_records"] == 2
    assert summary["processed_records"] == 1
    assert summary["skipped_known_records"] == 1
    checked_events = [event for event in events if event["event"] == "records_checked"]
    assert checked_events
    assert checked_events[-1]["summary"]["checked_records"] == 2
    assert checked_events[-1]["summary"]["skipped_known_records"] == 1


def test_receive_bills_repeats_delta_batches_until_short_response():
    class FakeStore:
        def __init__(self):
            self.records = []

        def wallet_delta_sync_request(self, address, token_limit=5000, response_limit=100):
            return {
                "type": "ind.wallet_bill_sync_request.v3",
                "version": 2,
                "address": address,
                "known_tokens": {
                    record["token_id"]: record["sequence"]
                    for record in self.records
                },
                "limit": response_limit,
            }

        def ingest_wallet_bill_sync_record(self, record):
            self.records.append(record)
            return {
                "accepted": True,
                "status": "verified",
                "state": SimpleNamespace(
                    display_id=record["display_id"],
                    sequence=record["sequence"],
                ),
            }

        def finalize_pending(self, buffer_seconds=0):
            return []

        def token_records_for_owner(self, _address, settled_only=True):
            return []

    def batch(start, count):
        return [
            {
                "type": "ind.wallet_bill_sync_record.v3",
                "token_id": f"token-{index}",
                "display_id": f"1x{index}",
                "sequence": 1,
            }
            for index in range(start, start + count)
        ]

    def iter_reports(_address, sync_request=None, peers=None):
        known_count = len((sync_request or {}).get("known_tokens") or {})
        if known_count == 0:
            records = batch(0, 100)
        elif known_count == 100:
            records = batch(100, 25)
        else:
            records = []
        return [
            {
                "peer": "peer-a",
                "status": sender_node.REQUEST_OK,
                "records": records,
                "messages": [],
                "delta": True,
            }
        ]

    store = FakeStore()
    wallet_path = SimpleNamespace(name="wallet_decrypted_test")

    with (
        mock.patch.object(sender_node, "ensure_runtime_files"),
        mock.patch.object(sender_node, "wallet_sync_store", return_value=store),
        mock.patch.object(
            sender_node.runtime_json,
            "iter_decrypted_wallet_files",
            return_value=[wallet_path],
        ),
        mock.patch.object(
            sender_node.runtime_json,
            "read_decrypted_wallet_lines",
            return_value=["wallet-address\n", "private\n", "public\n"],
        ),
        mock.patch.object(sender_node.runtime_json, "wallet_bill_lines", return_value=[]),
        mock.patch.object(sender_node, "iter_wallet_message_reports", side_effect=iter_reports),
        mock.patch.object(sender_node.ind_settings, "finality_buffer_seconds", return_value=0),
    ):
        summary = sender_node.receive_bills()

    assert summary["status"] == "complete"
    assert summary["sync_rounds"] == 2
    assert summary["processed_records"] == 125
    assert summary["fetched_unique_records"] == 125


def test_receive_bills_pages_backfill_without_known_token_payload():
    class FakeStore:
        def __init__(self):
            self.records = []
            self.requests = []

        def wallet_delta_sync_request(
            self,
            address,
            token_limit=0,
            response_limit=100,
            direction="backfill",
            page_cursor=None,
        ):
            request = {
                "type": "ind.wallet_bill_sync_request.v3",
                "version": 3,
                "address": address,
                "direction": direction,
                "limit": response_limit,
            }
            if page_cursor:
                request["cursor"] = dict(page_cursor)
            self.requests.append(request)
            return request

        def ingest_wallet_bill_sync_record(self, record):
            self.records.append(record)
            return {
                "accepted": True,
                "status": "verified",
                "state": SimpleNamespace(
                    display_id=record["display_id"],
                    sequence=record["sequence"],
                ),
            }

        def finalize_pending(self, buffer_seconds=0):
            return []

        def token_records_for_owner(self, _address, settled_only=True):
            return []

    def batch(start, count):
        return [
            {
                "type": "ind.wallet_bill_sync_record.v3",
                "token_id": f"token-{index}",
                "display_id": f"1x{index}",
                "sequence": 1,
            }
            for index in range(start, start + count)
        ]

    def iter_reports(_address, sync_request=None, peers=None):
        assert "known_tokens" not in (sync_request or {})
        cursor = (sync_request or {}).get("cursor") or {}
        if not cursor:
            records = batch(0, 100)
            has_more = True
            next_cursor = {"updated_at": 100, "sequence": 1, "token_id": "token-99"}
        elif cursor.get("token_id") == "token-99":
            records = batch(100, 25)
            has_more = False
            next_cursor = None
        else:
            records = []
            has_more = False
            next_cursor = None
        return [
            {
                "peer": "peer-a",
                "status": sender_node.REQUEST_OK,
                "records": records,
                "messages": [],
                "delta": True,
                "has_more": has_more,
                "next_cursor": next_cursor,
            }
        ]

    store = FakeStore()
    wallet_path = SimpleNamespace(name="wallet_decrypted_test")

    with (
        mock.patch.object(sender_node, "ensure_runtime_files"),
        mock.patch.object(sender_node, "wallet_sync_store", return_value=store),
        mock.patch.object(
            sender_node.runtime_json,
            "iter_decrypted_wallet_files",
            return_value=[wallet_path],
        ),
        mock.patch.object(
            sender_node.runtime_json,
            "read_decrypted_wallet_lines",
            return_value=["wallet-address\n", "private\n", "public\n"],
        ),
        mock.patch.object(sender_node.runtime_json, "wallet_bill_lines", return_value=[]),
        mock.patch.object(sender_node, "iter_wallet_message_reports", side_effect=iter_reports),
        mock.patch.object(sender_node.ind_settings, "finality_buffer_seconds", return_value=0),
    ):
        summary = sender_node.receive_bills()

    assert summary["status"] == "complete"
    assert summary["sync_rounds"] == 2
    assert summary["processed_records"] == 125
    assert all("known_tokens" not in request for request in store.requests)
    assert store.requests[0]["direction"] == "reconcile"
    assert store.requests[1]["cursor"]["token_id"] == "token-99"


def test_receive_bills_sends_wallet_file_known_display_ranges():
    class FakeStore:
        def spendable_bill_v3_display_ids(self, _address, display_ids):
            return set(display_ids)

        def wallet_delta_sync_request(
            self,
            address,
            token_limit=0,
            response_limit=100,
            direction="backfill",
            page_cursor=None,
        ):
            request = {
                "type": "ind.wallet_bill_sync_request.v3",
                "version": 3,
                "address": address,
                "direction": direction,
                "limit": response_limit,
            }
            if page_cursor:
                request["cursor"] = dict(page_cursor)
            return request

        def finalize_pending(self, buffer_seconds=0):
            return []

        def bill_v3_records_for_owner(self, _address, statuses=None, limit=None):
            return []

        def token_records_for_owner(self, _address, settled_only=True):
            return []

    address, _private_key, _public_key = keys_v3.generate_keypair(b"\x70" * 32)
    wallet_lines = [
        f"{address}\n",
        "private\n",
        "public\n",
        *[f"20x{index} 1 1700000{index:03d}\n" for index in range(1, 301)],
    ]
    captured_requests = []

    def iter_reports(_address, sync_request=None, peers=None):
        captured_requests.append(sync_request)
        return [
            {
                "peer": "peer-a",
                "status": sender_node.REQUEST_OK,
                "records": [],
                "messages": [],
                "delta": True,
            }
        ]

    wallet_path = SimpleNamespace(name="wallet_decrypted_test")

    with (
        mock.patch.object(sender_node, "ensure_runtime_files"),
        mock.patch.object(sender_node, "wallet_sync_store", return_value=FakeStore()),
        mock.patch.object(
            sender_node.runtime_json,
            "iter_decrypted_wallet_files",
            return_value=[wallet_path],
        ),
        mock.patch.object(
            sender_node.runtime_json,
            "read_decrypted_wallet_lines",
            return_value=wallet_lines,
        ),
        mock.patch.object(sender_node, "iter_wallet_message_reports", side_effect=iter_reports),
        mock.patch.object(sender_node.ind_settings, "finality_buffer_seconds", return_value=0),
    ):
        summary = sender_node.receive_bills()

    assert summary["status"] == "complete"
    assert summary["fetched_records"] == 0
    assert summary["checked_records"] == 0
    assert captured_requests[0]["known_display_ranges"] == [[20, 1, 300, 1]]


def test_wallet_sync_request_keeps_wallet_lines_recoverable_without_local_store_record():
    class FakeStore:
        def spendable_bill_v3_display_ids(self, _address, _display_ids):
            return set()

        def wallet_delta_sync_request(
            self,
            address,
            token_limit=0,
            response_limit=100,
            direction="backfill",
            page_cursor=None,
        ):
            return {
                "type": "ind.wallet_bill_sync_request.v3",
                "version": 3,
                "address": address,
                "direction": direction,
                "limit": response_limit,
            }

    address, _private_key, _public_key = keys_v3.generate_keypair(b"\x71" * 32)
    request = sender_node._wallet_sync_request_for_address(
        FakeStore(),
        address,
        direction="reconcile",
        wallet_lines=[
            f"{address}\n",
            "private\n",
            "public\n",
            "20x1 1 1700000001\n",
        ],
    )

    assert "known_display_ranges" not in request


def test_receive_bills_stops_between_records_when_cancelled():
    class FakeStore:
        def __init__(self):
            self.records = []

        def wallet_delta_sync_request(self, address, token_limit=5000, response_limit=100):
            return {
                "type": "ind.wallet_bill_sync_request.v3",
                "version": 2,
                "address": address,
                "known_tokens": {},
                "limit": response_limit,
            }

        def ingest_wallet_bill_sync_record(self, record):
            self.records.append(record)
            return {
                "accepted": True,
                "status": "verified",
                "state": SimpleNamespace(
                    display_id=record["display_id"],
                    sequence=record["sequence"],
                ),
            }

        def finalize_pending(self, buffer_seconds=0):
            return []

        def token_records_for_owner(self, _address, settled_only=True):
            return []

    records = [
        {
            "type": "ind.wallet_bill_sync_record.v3",
            "token_id": f"token-{index}",
            "display_id": f"1x{index}",
            "sequence": 1,
        }
        for index in range(100)
    ]
    store = FakeStore()
    wallet_path = SimpleNamespace(name="wallet_decrypted_test")
    events = []

    with (
        mock.patch.object(sender_node, "ensure_runtime_files"),
        mock.patch.object(sender_node, "wallet_sync_store", return_value=store),
        mock.patch.object(
            sender_node.runtime_json,
            "iter_decrypted_wallet_files",
            return_value=[wallet_path],
        ),
        mock.patch.object(
            sender_node.runtime_json,
            "read_decrypted_wallet_lines",
            return_value=["wallet-address\n", "private\n", "public\n"],
        ),
        mock.patch.object(sender_node.runtime_json, "wallet_bill_lines", return_value=[]),
        mock.patch.object(
            sender_node,
            "iter_wallet_message_reports",
            return_value=[
                {
                    "peer": "peer-a",
                    "status": sender_node.REQUEST_OK,
                    "records": records,
                    "messages": [],
                    "delta": True,
                }
            ],
        ),
        mock.patch.object(sender_node.ind_settings, "finality_buffer_seconds", return_value=0),
    ):
        summary = sender_node.receive_bills(
            progress_callback=events.append,
            stop_requested=lambda: len(store.records) >= 67,
        )

    assert summary["status"] == "cancelled"
    assert summary["processed_records"] == 67
    assert len(store.records) == 67
    assert events[-1]["event"] == "cancelled"


def test_receive_bills_batches_wallet_added_progress():
    class FakeStore:
        def finalize_pending(self, buffer_seconds=0):
            return []

        def token_records_for_owner(self, _address, settled_only=True):
            return [
                {"display_id": "1x1", "sequence": 1},
                {"display_id": "2x2", "sequence": 1},
                {"display_id": "5x3", "sequence": 1},
            ]

    store = FakeStore()
    wallet_path = SimpleNamespace(name="wallet_decrypted_test")
    events = []
    writes = []

    with (
        mock.patch.object(sender_node, "ensure_runtime_files"),
        mock.patch.object(sender_node, "wallet_sync_store", return_value=store),
        mock.patch.object(
            sender_node.runtime_json,
            "iter_decrypted_wallet_files",
            return_value=[wallet_path],
        ),
        mock.patch.object(
            sender_node.runtime_json,
            "read_decrypted_wallet_lines",
            return_value=["wallet-address\n", "private\n", "public\n"],
        ),
        mock.patch.object(sender_node.runtime_json, "wallet_bill_lines", return_value=[]),
        mock.patch.object(sender_node, "iter_wallet_message_reports", return_value=[]),
        mock.patch.object(sender_node.ind_settings, "finality_buffer_seconds", return_value=0),
        mock.patch.object(
            sender_node.wallet_services,
            "latest_bill_transfer_timestamp",
            return_value=1_700_000_123,
        ),
        mock.patch.object(
            sender_node.runtime_json,
            "write_decrypted_wallet_lines",
            side_effect=lambda _path, lines: writes.append(list(lines)),
        ),
    ):
        summary = sender_node.receive_bills(progress_callback=events.append)

    added_events = [event for event in events if event["event"] == "bills_added"]
    assert len(added_events) == 1
    assert added_events[0]["count"] == 3
    assert summary["wallet_bills_added"] == 3
    assert [event["event"] for event in events].count("bill_added") == 0
    assert len(writes) == 1
    assert writes[0][3:] == [
        "1x1 1 1700000123\n",
        "2x2 1 1700000123\n",
        "5x3 1 1700000123\n",
    ]


def test_receive_bills_adds_v3_wallet_records_without_default_limit():
    address, _private_key, _public_key = keys_v3.generate_keypair(b"\x45" * 32)

    class FakeStore:
        def __init__(self):
            self.metadata_calls = []

        def finalize_pending(self, buffer_seconds=0):
            return []

        def token_records_for_owner(self, _address, settled_only=True):
            raise AssertionError("V3 wallet sync should use BillV3 metadata")

        def bill_v3_metadata_records_for_owner(self, owner_address, statuses=None, limit=None):
            self.metadata_calls.append((owner_address, statuses, limit))
            if statuses == ("pending",):
                return []
            assert owner_address == address
            assert statuses == ("settled", "verified")
            assert limit is None
            return [
                {"display_id": "1x1", "sequence": 1, "updated_at": 1_700_000_101},
                {"display_id": "2x2", "sequence": 1, "updated_at": 1_700_000_102},
                {"display_id": "5x3", "sequence": 1, "updated_at": 1_700_000_103},
            ]

        def get_bill_v3_by_display_id_sequence(self, _display_id, _sequence):
            return None

    store = FakeStore()
    wallet_path = SimpleNamespace(name="wallet_decrypted_test")
    writes = []

    with (
        mock.patch.object(sender_node, "ensure_runtime_files"),
        mock.patch.object(sender_node, "wallet_sync_store", return_value=store),
        mock.patch.object(
            sender_node.runtime_json,
            "iter_decrypted_wallet_files",
            return_value=[wallet_path],
        ),
        mock.patch.object(
            sender_node.runtime_json,
            "read_decrypted_wallet_lines",
            return_value=[address + "\n", "private\n", "public\n"],
        ),
        mock.patch.object(sender_node.runtime_json, "wallet_bill_lines", return_value=[]),
        mock.patch.object(sender_node, "iter_wallet_message_reports", return_value=[]),
        mock.patch.object(sender_node.ind_settings, "finality_buffer_seconds", return_value=0),
        mock.patch.object(
            sender_node.wallet_services,
            "latest_bill_transfer_timestamp",
            side_effect=lambda record=None, bill=None, fallback=None: int(fallback),
        ),
        mock.patch.object(
            sender_node.runtime_json,
            "write_decrypted_wallet_lines",
            side_effect=lambda _path, lines: writes.append(list(lines)),
        ),
    ):
        summary = sender_node.receive_bills()

    assert summary["wallet_bills_added"] == 3
    assert writes[0][3:] == [
        "1x1 1 1700000101\n",
        "2x2 1 1700000102\n",
        "5x3 1 1700000103\n",
    ]
    assert (address, ("settled", "verified"), None) in store.metadata_calls


def test_wallet_bill_sync_request_falls_back_to_legacy_recipient_lookup():
    results = [
        sender_node.PeerRequestResult(status=sender_node.REQUEST_INVALID, response="n"),
        sender_node.PeerRequestResult(
            status=sender_node.REQUEST_OK,
            response=json.dumps([{"type": "legacy-message"}]),
            peer="peer-a",
            route="peer-a",
        ),
    ]

    with mock.patch.object(sender_node, "connect_result", side_effect=results) as connect:
        report = sender_node._fetch_wallet_messages_from_peer(
            "peer-a",
            "wallet-address",
            sync_request={
                "type": "ind.wallet_bill_sync_request.v3",
                "version": 2,
                "address": "wallet-address",
                "known_tokens": {"token-a": 4},
                "limit": 100,
            },
        )

    assert [call.args[0] for call in connect.call_args_list] == ["R", "r"]
    assert report["messages"] == [{"type": "legacy-message"}]
    assert report["records"] == []
    assert report["delta"] is False


def test_wallet_bill_sync_request_uses_record_response_without_legacy_fallback():
    result = sender_node.PeerRequestResult(
        status=sender_node.REQUEST_OK,
        response='{"type":"ind.wallet_bill_sync_response.v3","version":1,"records":[{"type":"record"}]}',
        peer="peer-a",
        route="peer-a",
    )

    with mock.patch.object(sender_node, "connect_result", return_value=result) as connect:
        report = sender_node._fetch_wallet_messages_from_peer(
            "peer-a",
            "wallet-address",
            sync_request={
                "type": "ind.wallet_bill_sync_request.v3",
                "version": 2,
                "address": "wallet-address",
                "known_tokens": {},
                "limit": 100,
            },
        )

    assert [call.args[0] for call in connect.call_args_list] == ["R"]
    assert report["messages"] == []
    assert report["records"] == [{"type": "record"}]
    assert report["delta"] is True


def test_wallet_bill_sync_reconcile_request_uses_reconcile_timing():
    reconcile_result = sender_node.PeerRequestResult(
        status=sender_node.REQUEST_OK,
        response=(
            '{"type":"ind.wallet_bill_sync_response.v3","version":2,'
            '"direction":"reconcile","records":[]}'
        ),
        peer="peer-a",
        route="peer-a",
    )
    newer_result = sender_node.PeerRequestResult(
        status=sender_node.REQUEST_OK,
        response=(
            '{"type":"ind.wallet_bill_sync_response.v3","version":2,'
            '"direction":"newer","records":[]}'
        ),
        peer="peer-a",
        route="peer-a",
    )

    with mock.patch.object(
        sender_node,
        "connect_result",
        side_effect=[reconcile_result, newer_result],
    ) as connect:
        reconcile_report = sender_node._fetch_wallet_messages_from_peer(
            "peer-a",
            "wallet-address",
            sync_request={
                "type": "ind.wallet_bill_sync_request.v3",
                "version": 3,
                "address": "wallet-address",
                "direction": "reconcile",
                "known_display_ranges": [[20, 1, 100, 1]],
                "limit": 100,
            },
        )
        newer_report = sender_node._fetch_wallet_messages_from_peer(
            "peer-a",
            "wallet-address",
            sync_request={
                "type": "ind.wallet_bill_sync_request.v3",
                "version": 3,
                "address": "wallet-address",
                "direction": "newer",
                "limit": 100,
            },
        )

    reconcile_kwargs = connect.call_args_list[0].kwargs
    newer_kwargs = connect.call_args_list[1].kwargs
    assert reconcile_kwargs["timeout"] == sender_node.WALLET_SYNC_RECONCILE_REQUEST_TIMEOUT_SECONDS
    assert (
        reconcile_kwargs["max_duration_seconds"]
        == sender_node.WALLET_SYNC_RECONCILE_REQUEST_BUDGET_SECONDS
    )
    assert newer_kwargs["timeout"] == sender_node.WALLET_SYNC_REQUEST_TIMEOUT_SECONDS
    assert newer_kwargs["max_duration_seconds"] == sender_node.WALLET_SYNC_REQUEST_BUDGET_SECONDS
    assert reconcile_report["direction"] == "reconcile"
    assert newer_report["direction"] == "newer"


def test_outbound_gossip_pacer_uses_sliding_peer_window():
    now = [100.0]
    pacer = sender_node.OutboundGossipPacer(
        limit=2,
        window_seconds=5,
        now_func=lambda: now[0],
    )

    assert pacer.available("peer-a")
    pacer.record("peer-a")
    pacer.record("peer-a")

    assert not pacer.available("peer-a")
    assert pacer.wait_seconds(["peer-a"]) == 5

    now[0] = 104.5
    assert not pacer.available("peer-a")
    assert pacer.wait_seconds(["peer-a"]) == 0.5

    now[0] = 105.1
    assert pacer.available("peer-a")


def test_default_wallet_pacer_allows_regular_multibill_burst():
    pacer = sender_node.OutboundGossipPacer(now_func=lambda: 100.0)

    for _ in range(29):
        assert pacer.available("peer-a")
        pacer.record("peer-a")


def test_explicit_retry_after_response_is_rate_limited():
    assert sender_node._response_status("rate_limited:12") == sender_node.REQUEST_RATE_LIMITED
    assert sender_node._retry_after_from_response("rate_limited:12") == 12


def test_queued_gossip_retry_keeps_trying_after_rate_limit(tmp_path):
    transaction_path = tmp_path / "transaction_1.json"
    transaction_path.write_text("{}", encoding="utf-8")
    rate_limited = sender_node.PeerRequestResult(
        status=sender_node.REQUEST_RATE_LIMITED,
        response=sender_node.REQUEST_RATE_LIMITED,
        peer="peer-a",
        route="peer-a",
        attempts=(
            {
                "peer": "peer-a",
                "route": "peer-a",
                "status": sender_node.REQUEST_RATE_LIMITED,
            },
        ),
        retry_after_seconds=0.2,
    )
    accepted = sender_node.PeerRequestResult(
        status=sender_node.REQUEST_OK,
        response="ok",
        peer="peer-a",
        route="peer-a",
        attempts=(
            {
                "peer": "peer-a",
                "route": "peer-a",
                "status": sender_node.REQUEST_OK,
            },
        ),
    )

    with (
        mock.patch.object(sender_node.time, "sleep") as sleep,
        mock.patch.object(
            sender_node,
            "_broadcast_gossip_fire_and_forget",
            side_effect=[rate_limited, accepted],
        ) as broadcast,
    ):
        assert sender_node._run_queued_gossip_retry(
            transaction_path,
            "raw",
            ["peer-a"],
            initial_delay_seconds=0,
        )

    assert not transaction_path.exists()
    assert broadcast.call_count == 2
    sleep.assert_called_once_with(0.2)


def test_send_queued_bills_paced_removes_successful_transaction(tmp_path):
    transaction_path = tmp_path / "transaction_1.json"
    transaction_path.write_text("{}", encoding="utf-8")
    events = []

    class FakeStore:
        def ingest_message(self, _message):
            return {"accepted": True}

    result = sender_node.PeerRequestResult(
        status=sender_node.REQUEST_OK,
        response="",
        peer="peer-a",
        route="peer-a",
        attempts=(
            {
                "peer": "peer-a",
                "route": "peer-a",
                "status": sender_node.REQUEST_OK,
            },
        ),
        acked_peers=("peer-a",),
    )

    with (
        mock.patch.object(sender_node, "ensure_runtime_files"),
        mock.patch.object(sender_node, "_queued_send_peers", return_value=["peer-a"]),
        mock.patch.object(sender_node, "wallet_sync_store", return_value=FakeStore()),
        mock.patch.object(
            sender_node.runtime_json,
            "transaction_files",
            side_effect=lambda: [transaction_path] if transaction_path.exists() else [],
        ),
        mock.patch.object(
            sender_node.runtime_json,
            "read_transaction_message",
            return_value={"type": "queued"},
        ),
        mock.patch.object(sender_node.ind_token, "pack_wire_message", return_value="raw"),
        mock.patch.object(
            sender_node,
            "_broadcast_gossip_fire_and_forget",
            return_value=result,
        ) as dispatch,
        mock.patch.object(sender_node, "connect_result") as connect,
    ):
        summary = sender_node.send_queued_bills_paced(progress_callback=events.append)

    assert not transaction_path.exists()
    assert summary["status"] == "complete"
    assert summary["sent"] == 1
    assert [event["event"] for event in events] == ["preparing", "sending", "complete"]
    dispatch.assert_called_once()
    connect.assert_not_called()


def test_outbound_bill_pacer_limits_bill_rate():
    now = [100.0]
    sleeps = []

    def sleep(delay):
        sleeps.append(delay)
        now[0] += delay

    pacer = sender_node.OutboundBillPacer(
        max_bills_per_second=5,
        now_func=lambda: now[0],
        sleep_func=sleep,
    )

    assert pacer.wait()
    assert pacer.wait()
    assert pacer.wait()
    assert len(sleeps) == 2
    assert all(abs(delay - 0.2) < 0.000001 for delay in sleeps)


def test_send_queued_bills_paced_handles_regular_29_bill_send(tmp_path):
    transaction_paths = [tmp_path / f"transaction_{index}.json" for index in range(29)]
    for transaction_path in transaction_paths:
        transaction_path.write_text("{}", encoding="utf-8")

    class FakeStore:
        def ingest_message(self, _message):
            return {"accepted": True}

    def transaction_files():
        return [transaction_path for transaction_path in transaction_paths if transaction_path.exists()]

    def fake_dispatch(_raw, peers, **_kwargs):
        peer = peers[0]
        return sender_node.PeerRequestResult(
            status=sender_node.REQUEST_OK,
            response="",
            peer=peer,
            route=peer,
            attempts=(
                {
                    "peer": peer,
                    "route": peer,
                    "status": sender_node.REQUEST_OK,
                },
            ),
            acked_peers=(peer,),
        )

    class NoopBillPacer:
        def wait(self, deadline=None):
            return True

    with (
        mock.patch.object(sender_node, "ensure_runtime_files"),
        mock.patch.object(sender_node, "_queued_send_peers", return_value=["peer-a", "peer-b"]),
        mock.patch.object(sender_node, "wallet_sync_store", return_value=FakeStore()),
        mock.patch.object(
            sender_node.runtime_json,
            "transaction_files",
            side_effect=transaction_files,
        ),
        mock.patch.object(
            sender_node.runtime_json,
            "read_transaction_message",
            return_value={"type": "queued"},
        ),
        mock.patch.object(sender_node.ind_token, "pack_wire_message", return_value="raw"),
        mock.patch.object(
            sender_node,
            "_broadcast_gossip_fire_and_forget",
            side_effect=fake_dispatch,
        ) as dispatch,
        mock.patch.object(sender_node, "connect_result") as connect,
        mock.patch.object(sender_node, "_schedule_queued_gossip_retry", return_value=True) as retry,
        mock.patch.object(sender_node, "OutboundBillPacer", return_value=NoopBillPacer()),
    ):
        summary = sender_node.send_queued_bills_paced()

    assert summary["status"] == "complete"
    assert summary["sent"] == 29
    assert all(not transaction_path.exists() for transaction_path in transaction_paths)
    assert dispatch.call_count == 29
    connect.assert_not_called()
    retry.assert_not_called()


def test_send_queued_bills_paced_stops_after_cancel_request(tmp_path):
    transaction_paths = [tmp_path / "transaction_1.json", tmp_path / "transaction_2.json"]
    for transaction_path in transaction_paths:
        transaction_path.write_text("{}", encoding="utf-8")
    events = []

    class FakeStore:
        def ingest_message(self, _message):
            return {"accepted": True}

    class NoopBillPacer:
        def wait(self, deadline=None):
            return True

    result = sender_node.PeerRequestResult(
        status=sender_node.REQUEST_OK,
        response="",
        peer="peer-a",
        route="peer-a",
        attempts=(
            {
                "peer": "peer-a",
                "route": "peer-a",
                "status": sender_node.REQUEST_OK,
            },
        ),
        acked_peers=("peer-a",),
    )

    def transaction_files():
        return [transaction_path for transaction_path in transaction_paths if transaction_path.exists()]

    def fake_dispatch(*_args, **_kwargs):
        sender_node.request_cancel_queued_bills()
        return result

    with (
        mock.patch.object(sender_node, "ensure_runtime_files"),
        mock.patch.object(sender_node, "_queued_send_peers", return_value=["peer-a"]),
        mock.patch.object(sender_node, "wallet_sync_store", return_value=FakeStore()),
        mock.patch.object(
            sender_node.runtime_json,
            "transaction_files",
            side_effect=transaction_files,
        ),
        mock.patch.object(
            sender_node.runtime_json,
            "read_transaction_message",
            return_value={"type": "queued"},
        ),
        mock.patch.object(sender_node.ind_token, "pack_wire_message", return_value="raw"),
        mock.patch.object(
            sender_node,
            "_broadcast_gossip_fire_and_forget",
            side_effect=fake_dispatch,
        ) as dispatch,
        mock.patch.object(sender_node, "OutboundBillPacer", return_value=NoopBillPacer()),
    ):
        summary = sender_node.send_queued_bills_paced(progress_callback=events.append)

    sender_node.clear_cancel_queued_bills()
    assert summary["status"] == "cancelled"
    assert summary["sent"] == 1
    assert not transaction_paths[0].exists()
    assert transaction_paths[1].exists()
    assert dispatch.call_count == 1
    assert events[-1]["event"] == "cancelled"


def test_send_queued_bills_paced_does_not_wait_for_peer_quorum(tmp_path):
    transaction_path = tmp_path / "transaction_1.json"
    transaction_path.write_text("{}", encoding="utf-8")

    class FakeStore:
        def ingest_message(self, _message):
            return {"accepted": True}

    ok = sender_node.PeerRequestResult(
        status=sender_node.REQUEST_OK,
        response="",
        peer="peer-a",
        route="peer-a",
        attempts=(
            {
                "peer": "peer-a",
                "route": "peer-a",
                "status": sender_node.REQUEST_OK,
            },
        ),
        acked_peers=("peer-a",),
    )

    with (
        mock.patch.object(sender_node, "ensure_runtime_files"),
        mock.patch.object(sender_node, "_queued_send_peers", return_value=["peer-a", "peer-b"]),
        mock.patch.object(sender_node, "wallet_sync_store", return_value=FakeStore()),
        mock.patch.object(
            sender_node.runtime_json,
            "transaction_files",
            side_effect=lambda: [transaction_path] if transaction_path.exists() else [],
        ),
        mock.patch.object(
            sender_node.runtime_json,
            "read_transaction_message",
            return_value={"type": "queued"},
        ),
        mock.patch.object(sender_node.ind_token, "pack_wire_message", return_value="raw"),
        mock.patch.object(
            sender_node,
            "_broadcast_gossip_fire_and_forget",
            return_value=ok,
        ) as dispatch,
        mock.patch.object(sender_node, "connect_result") as connect,
    ):
        summary = sender_node.send_queued_bills_paced()

    assert not transaction_path.exists()
    assert summary["status"] == "complete"
    assert summary["sent"] == 1
    dispatch.assert_called_once()
    connect.assert_not_called()


def test_send_queued_bills_paced_keeps_failed_handoff_queued(tmp_path):
    transaction_path = tmp_path / "transaction_1.json"
    transaction_path.write_text("{}", encoding="utf-8")

    class FakeStore:
        def ingest_message(self, _message):
            return {"accepted": True}

    timeout = sender_node.PeerRequestResult(
        status=sender_node.REQUEST_TIMEOUT,
        peer="peer-b",
        route="peer-b",
        attempts=(
            {
                "peer": "peer-b",
                "route": "peer-b",
                "status": sender_node.REQUEST_TIMEOUT,
            },
        ),
    )

    with (
        mock.patch.object(sender_node, "ensure_runtime_files"),
        mock.patch.object(sender_node, "_queued_send_peers", return_value=["peer-a", "peer-b"]),
        mock.patch.object(sender_node, "wallet_sync_store", return_value=FakeStore()),
        mock.patch.object(
            sender_node.runtime_json,
            "transaction_files",
            return_value=[transaction_path],
        ),
        mock.patch.object(
            sender_node.runtime_json,
            "read_transaction_message",
            return_value={"type": "queued"},
        ),
        mock.patch.object(sender_node.ind_token, "pack_wire_message", return_value="raw"),
        mock.patch.object(
            sender_node,
            "_broadcast_gossip_fire_and_forget",
            return_value=timeout,
        ),
        mock.patch.object(sender_node, "_schedule_queued_gossip_retry", return_value=True) as retry,
    ):
        summary = sender_node.send_queued_bills_paced()

    assert transaction_path.exists()
    assert summary["status"] == "partial"
    assert summary["sent"] == 0
    retry.assert_called_once()


def test_send_queued_bills_paced_keeps_rate_limited_handoff_queued(tmp_path):
    transaction_path = tmp_path / "transaction_1.json"
    transaction_path.write_text("{}", encoding="utf-8")
    events = []

    class FakeStore:
        def ingest_message(self, _message):
            return {"accepted": True}

    result = sender_node.PeerRequestResult(
        status=sender_node.REQUEST_RATE_LIMITED,
        response=sender_node.REQUEST_RATE_LIMITED,
        peer="peer-a",
        route="peer-a",
        attempts=(
            {
                "peer": "peer-a",
                "route": "peer-a",
                "status": sender_node.REQUEST_RATE_LIMITED,
            },
        ),
        retry_after_seconds=10,
    )

    with (
        mock.patch.object(sender_node, "ensure_runtime_files"),
        mock.patch.object(sender_node, "_queued_send_peers", return_value=["peer-a"]),
        mock.patch.object(sender_node, "wallet_sync_store", return_value=FakeStore()),
        mock.patch.object(
            sender_node.runtime_json,
            "transaction_files",
            return_value=[transaction_path],
        ),
        mock.patch.object(
            sender_node.runtime_json,
            "read_transaction_message",
            return_value={"type": "queued"},
        ),
        mock.patch.object(sender_node.ind_token, "pack_wire_message", return_value="raw"),
        mock.patch.object(
            sender_node,
            "_broadcast_gossip_fire_and_forget",
            return_value=result,
        ),
        mock.patch.object(sender_node, "_schedule_queued_gossip_retry", return_value=True) as retry,
    ):
        summary = sender_node.send_queued_bills_paced(
            progress_callback=events.append,
            max_duration_seconds=0.01,
        )

    assert transaction_path.exists()
    assert summary["status"] == "partial"
    assert summary["sent"] == 0
    assert any(event["event"] == "waiting" for event in events)
    assert not any(event["event"] == "rate_limited" for event in events)
    retry.assert_called_once()
