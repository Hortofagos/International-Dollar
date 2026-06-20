import os
import json
from types import SimpleNamespace
from unittest import mock

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
            return {"accepted": True, "status": "verified", "state": SimpleNamespace(display_id="1x1", sequence=1)}

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
            "records": [{"type": "record"}],
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
        summary = sender_node.receive_bills()

    assert summary["fetched_records"] == 2
    assert summary["fetched_unique_records"] == 1
    assert summary["fetched_duplicate_records"] == 1
    assert summary["processed_records"] == 2


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
            "_broadcast_gossip_to_peer_quorum",
            side_effect=[rate_limited, accepted],
        ) as broadcast,
        mock.patch.object(
            sender_node.runtime_json,
            "read_transaction_message",
            return_value={"type": "queued"},
        ),
        mock.patch.object(sender_node, "_remote_status_confirms_gossip", return_value=False),
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
        mock.patch.object(sender_node, "connect_result", return_value=result),
    ):
        summary = sender_node.send_queued_bills_paced(progress_callback=events.append)

    assert not transaction_path.exists()
    assert summary["status"] == "complete"
    assert summary["sent"] == 1
    assert [event["event"] for event in events] == ["preparing", "sending", "complete"]


def test_send_queued_bills_paced_handles_regular_29_bill_send(tmp_path):
    transaction_paths = [tmp_path / f"transaction_{index}.json" for index in range(29)]
    for transaction_path in transaction_paths:
        transaction_path.write_text("{}", encoding="utf-8")

    class FakeStore:
        def ingest_message(self, _message):
            return {"accepted": True}

    def transaction_files():
        return [transaction_path for transaction_path in transaction_paths if transaction_path.exists()]

    def fake_connect(_indicator, _raw, ipnl, **_kwargs):
        peer = ipnl[0]
        return sender_node.PeerRequestResult(
            status=sender_node.REQUEST_OK,
            response="ok",
            peer=peer,
            route=peer,
            attempts=(
                {
                    "peer": peer,
                    "route": peer,
                    "status": sender_node.REQUEST_OK,
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
            side_effect=transaction_files,
        ),
        mock.patch.object(
            sender_node.runtime_json,
            "read_transaction_message",
            return_value={"type": "queued"},
        ),
        mock.patch.object(sender_node.ind_token, "pack_wire_message", return_value="raw"),
        mock.patch.object(sender_node, "connect_result", side_effect=fake_connect) as connect,
        mock.patch.object(sender_node, "_schedule_queued_gossip_retry", return_value=True) as retry,
    ):
        summary = sender_node.send_queued_bills_paced()

    assert summary["status"] == "complete"
    assert summary["sent"] == 29
    assert all(not transaction_path.exists() for transaction_path in transaction_paths)
    assert connect.call_count == 58
    retry.assert_not_called()


def test_send_queued_bills_paced_requires_peer_quorum(tmp_path):
    transaction_path = tmp_path / "transaction_1.json"
    transaction_path.write_text("{}", encoding="utf-8")

    class FakeStore:
        def ingest_message(self, _message):
            return {"accepted": True}

    ok_a = sender_node.PeerRequestResult(
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
    ok_b = sender_node.PeerRequestResult(
        status=sender_node.REQUEST_OK,
        response="ok",
        peer="peer-b",
        route="peer-b",
        attempts=(
            {
                "peer": "peer-b",
                "route": "peer-b",
                "status": sender_node.REQUEST_OK,
            },
        ),
    )

    def fake_connect(_indicator, _raw, ipnl, **_kwargs):
        return ok_a if ipnl == ["peer-a"] else ok_b

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
        mock.patch.object(sender_node, "connect_result", side_effect=fake_connect) as connect,
    ):
        summary = sender_node.send_queued_bills_paced()

    assert not transaction_path.exists()
    assert summary["status"] == "complete"
    assert summary["sent"] == 1
    assert sorted(call.args[2][0] for call in connect.call_args_list) == ["peer-a", "peer-b"]


def test_send_queued_bills_paced_keeps_partial_quorum(tmp_path):
    transaction_path = tmp_path / "transaction_1.json"
    transaction_path.write_text("{}", encoding="utf-8")

    class FakeStore:
        def ingest_message(self, _message):
            return {"accepted": True}

    ok = sender_node.PeerRequestResult(
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

    def fake_connect(_indicator, _raw, ipnl, **_kwargs):
        return ok if ipnl == ["peer-a"] else timeout

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
        mock.patch.object(sender_node, "connect_result", side_effect=fake_connect),
        mock.patch.object(sender_node, "_schedule_queued_gossip_retry", return_value=True) as retry,
    ):
        summary = sender_node.send_queued_bills_paced()

    assert transaction_path.exists()
    assert summary["status"] == "partial"
    assert summary["sent"] == 0
    retry.assert_called_once()


def test_send_queued_bills_paced_keeps_rate_limited_transaction(tmp_path):
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
        mock.patch.object(sender_node, "connect_result", return_value=result),
        mock.patch.object(sender_node, "_schedule_queued_gossip_retry", return_value=True) as retry,
    ):
        summary = sender_node.send_queued_bills_paced(
            progress_callback=events.append,
            max_duration_seconds=0.01,
        )

    assert transaction_path.exists()
    assert summary["status"] == "partial"
    assert summary["sent"] == 0
    assert any(event["event"] == "rate_limited" for event in events)
    retry.assert_called_once()
