import socket
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from ind import node_client
from ind import sender_node
from ind import settings as ind_settings


class NetworkRequestResultTests(unittest.TestCase):
    def setUp(self):
        sender_node.already_tried.clear()
        with sender_node._peer_backoff_lock:
            sender_node._peer_backoff_until.clear()
        with sender_node._queued_gossip_retry_lock:
            sender_node._queued_gossip_retries.clear()

    def test_default_peer_request_timeout_is_interactive(self):
        settings = ind_settings.normalize_security_settings({})

        self.assertEqual(settings["peer_request_timeout_seconds"], 10)
        self.assertEqual(ind_settings.peer_request_timeout_seconds(settings), 10)

    def test_expanded_peer_routes_try_hostname_then_ipv6_then_ipv4_then_next_seed(self):
        records = {
            "seed-a.example": [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 8888)),
                (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:4860:4860::8888", 8888, 0, 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 8888)),
            ],
            "seed-b.example": [
                (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:4700:4700::1111", 8888, 0, 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("9.9.9.9", 8888)),
            ],
        }

        def fake_getaddrinfo(host, *_args, **_kwargs):
            return records.get(host, [])

        with mock.patch.object(sender_node.socket, "getaddrinfo", side_effect=fake_getaddrinfo):
            routes = sender_node.expanded_peer_routes(["seed-a.example", "seed-b.example"])

        self.assertEqual(
            [(item["peer"], item["route"]) for item in routes],
            [
                ("seed-a.example", "seed-a.example"),
                ("seed-a.example", "2001:4860:4860::8888"),
                ("seed-a.example", "8.8.8.8"),
                ("seed-a.example", "1.1.1.1"),
                ("seed-b.example", "seed-b.example"),
                ("seed-b.example", "2606:4700:4700::1111"),
                ("seed-b.example", "9.9.9.9"),
            ],
        )

    def test_connect_result_retries_routes_before_success(self):
        records = {
            "seed-a.example": [
                (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:4860:4860::8888", 8888, 0, 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 8888)),
            ],
            "seed-b.example": [],
        }
        called_routes = []

        def fake_getaddrinfo(host, *_args, **_kwargs):
            return records.get(host, [])

        def fake_request(addr, *_args, **_kwargs):
            called_routes.append(addr[0])
            if addr[0] == "seed-b.example":
                return "ok"
            if addr[0] == "2001:4860:4860::8888":
                raise ConnectionResetError("closed")
            raise socket.timeout("slow")

        with mock.patch.object(sender_node, "ensure_runtime_files"):
            with mock.patch.object(sender_node.socket, "getaddrinfo", side_effect=fake_getaddrinfo):
                with mock.patch.object(sender_node.ind_transport, "request", side_effect=fake_request):
                    result = sender_node.connect_result(
                        "b",
                        "payload",
                        ["seed-a.example", "seed-b.example"],
                        timeout=1,
                        max_duration_seconds=10,
                    )

        self.assertTrue(result.ok)
        self.assertEqual(result.response, "ok")
        self.assertEqual(
            called_routes,
            ["seed-a.example", "2001:4860:4860::8888", "8.8.8.8", "seed-b.example"],
        )
        self.assertEqual([attempt["status"] for attempt in result.attempts[:3]], ["timeout", "connection_closed", "timeout"])

    def test_connect_result_records_rate_limit_backoff_and_uses_next_peer(self):
        def fake_request(addr, *_args, **_kwargs):
            if addr[0] == "seed-a.example":
                return "rate_limited"
            return "ok"

        with mock.patch.object(sender_node, "ensure_runtime_files"):
            with mock.patch.object(sender_node.socket, "getaddrinfo", return_value=[]):
                with mock.patch.object(sender_node, "_rate_limit_backoff_seconds", return_value=12):
                    with mock.patch.object(sender_node.ind_transport, "request", side_effect=fake_request):
                        result = sender_node.connect_result(
                            "b",
                            "payload",
                            ["seed-a.example", "seed-b.example"],
                            timeout=1,
                            max_duration_seconds=10,
                        )

        self.assertTrue(result.ok)
        self.assertEqual(result.attempts[0]["status"], "rate_limited")
        self.assertGreaterEqual(result.retry_after_seconds, 12)
        self.assertGreater(sender_node._peer_backoff_remaining("seed-a.example"), 0)

    def test_explicit_invalid_skips_alternate_routes_for_same_peer(self):
        records = {
            "seed-a.example": [
                (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:4860:4860::8888", 8888, 0, 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 8888)),
            ],
            "seed-b.example": [],
        }
        called_routes = []

        def fake_getaddrinfo(host, *_args, **_kwargs):
            return records.get(host, [])

        def fake_request(addr, *_args, **_kwargs):
            called_routes.append(addr[0])
            if addr[0] == "seed-a.example":
                return "invalid"
            return "ok"

        with mock.patch.object(sender_node, "ensure_runtime_files"):
            with mock.patch.object(sender_node.socket, "getaddrinfo", side_effect=fake_getaddrinfo):
                with mock.patch.object(sender_node.ind_transport, "request", side_effect=fake_request):
                    result = sender_node.connect_result(
                        "b",
                        "malformed",
                        ["seed-a.example", "seed-b.example"],
                        timeout=1,
                        max_duration_seconds=10,
                    )

        self.assertTrue(result.ok)
        self.assertEqual(called_routes, ["seed-a.example", "seed-b.example"])
        self.assertEqual([attempt["status"] for attempt in result.attempts], ["invalid", "ok"])

    def test_single_peer_invalid_is_not_fanned_out_to_resolved_routes(self):
        records = [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:4860:4860::8888", 8888, 0, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 8888)),
        ]
        called_routes = []

        def fake_request(addr, *_args, **_kwargs):
            called_routes.append(addr[0])
            return "invalid"

        with mock.patch.object(sender_node, "ensure_runtime_files"):
            with mock.patch.object(sender_node.socket, "getaddrinfo", return_value=records):
                with mock.patch.object(sender_node.ind_transport, "request", side_effect=fake_request):
                    result = sender_node.connect_result(
                        "b",
                        "malformed",
                        ["seed-a.example"],
                        timeout=1,
                        max_duration_seconds=10,
                    )

        self.assertEqual(result.status, "invalid")
        self.assertEqual(called_routes, ["seed-a.example"])
        self.assertEqual(len(result.attempts), 1)

    def test_connect_returns_failure_status_instead_of_n(self):
        with mock.patch.object(sender_node, "ensure_runtime_files"):
            with mock.patch.object(sender_node.socket, "getaddrinfo", return_value=[]):
                with mock.patch.object(sender_node.ind_transport, "request", side_effect=socket.timeout("slow")):
                    response = sender_node.connect("c", "1x1", ["seed-a.example"])

        self.assertEqual(response, "timeout")

    def test_send_bills_keeps_queued_artifact_for_failed_primary_after_fallback_ok(self):
        transaction_path = Path("transaction_folder/transaction_1.json")
        result = sender_node.PeerRequestResult(
            status=sender_node.REQUEST_OK,
            response="ok",
            peer="seed-b.example",
            route="seed-b.example",
            attempts=(
                {"peer": "seed-a.example", "route": "seed-a.example", "status": "timeout"},
                {"peer": "seed-b.example", "route": "seed-b.example", "status": "ok"},
            ),
        )
        store = mock.Mock()
        store.ingest_message.return_value = {"accepted": True}

        with mock.patch.object(sender_node, "ensure_runtime_files"):
            with mock.patch.object(sender_node, "_peer_files", return_value=[]):
                with mock.patch.object(sender_node, "_with_configured_peers", return_value=["seed-a.example", "seed-b.example"]):
                    with mock.patch.object(sender_node.runtime_json, "transaction_files", return_value=[transaction_path]):
                        with mock.patch.object(sender_node.runtime_json, "read_transaction_message", return_value={"type": "test"}):
                            with mock.patch.object(sender_node.ind_token, "INDLocalStore", return_value=store):
                                with mock.patch.object(sender_node.ind_token, "pack_wire_message", return_value="raw"):
                                    with mock.patch.object(sender_node, "connect_result", return_value=result):
                                        with mock.patch.object(sender_node, "_schedule_queued_gossip_retry") as schedule:
                                            with mock.patch.object(sender_node.os, "remove") as remove:
                                                sender_node.send_bills()

        schedule.assert_called_once()
        remove.assert_not_called()

    def test_send_bills_removes_queued_artifact_when_timeout_reconciles_status(self):
        transaction_path = Path("transaction_folder/transaction_1.json")
        result = sender_node.PeerRequestResult(
            status=sender_node.REQUEST_TIMEOUT,
            attempts=({"peer": "seed-a.example", "route": "seed-a.example", "status": "timeout"},),
        )
        store = mock.Mock()
        store.ingest_message.return_value = {"accepted": True}

        with mock.patch.object(sender_node, "ensure_runtime_files"):
            with mock.patch.object(sender_node, "_peer_files", return_value=[]):
                with mock.patch.object(sender_node, "_with_configured_peers", return_value=["seed-a.example"]):
                    with mock.patch.object(sender_node.runtime_json, "transaction_files", return_value=[transaction_path]):
                        with mock.patch.object(sender_node.runtime_json, "read_transaction_message", return_value={"type": "test"}):
                            with mock.patch.object(sender_node.ind_token, "INDLocalStore", return_value=store):
                                with mock.patch.object(sender_node.ind_token, "pack_wire_message", return_value="raw"):
                                    with mock.patch.object(sender_node, "connect_result", return_value=result):
                                        with mock.patch.object(sender_node, "_remote_status_confirms_gossip", return_value=True):
                                            with mock.patch.object(sender_node, "_schedule_queued_gossip_retry") as schedule:
                                                with mock.patch.object(sender_node.os, "remove") as remove:
                                                    sender_node.send_bills()

        remove.assert_called_once_with(transaction_path)
        schedule.assert_not_called()

    def test_remote_status_reconciliation_confirms_exact_landed_gossip(self):
        message = {
            "type": sender_node.ind_token.TRANSFER_ANNOUNCEMENT_TYPE,
            "token": {"fake": "bill"},
        }
        state = SimpleNamespace(display_id="1x99", owner_address="owner-address", sequence=2)
        result = sender_node.PeerRequestResult(
            status=sender_node.REQUEST_OK,
            response="1x99\nowner-address\n2\npending",
            peer="seed-a.example",
            route="seed-a.example",
        )

        with mock.patch.object(sender_node.ind_token, "verify_token", return_value=state):
            with mock.patch.object(sender_node, "connect_result", return_value=result):
                self.assertTrue(sender_node._remote_status_confirms_gossip(message, ["seed-a.example"], attempts=1))

    def test_remote_status_reconciliation_rejects_conflict_status(self):
        message = {
            "type": sender_node.ind_token.TRANSFER_ANNOUNCEMENT_TYPE,
            "token": {"fake": "bill"},
        }
        state = SimpleNamespace(display_id="1x99", owner_address="owner-address", sequence=2)
        result = sender_node.PeerRequestResult(
            status=sender_node.REQUEST_OK,
            response="1x99\nx\n2\nconflict",
            peer="seed-a.example",
            route="seed-a.example",
        )

        with mock.patch.object(sender_node.ind_token, "verify_token", return_value=state):
            with mock.patch.object(sender_node, "connect_result", return_value=result):
                self.assertFalse(sender_node._remote_status_confirms_gossip(message, ["seed-a.example"], attempts=1))

    def test_server_close_counters_snapshot_reasons(self):
        counters = node_client.ServerCloseCounters()
        with mock.patch.object(node_client, "SERVER_CLOSE_COUNTERS", counters):
            node_client.record_server_close("connection_limit", "8.8.8.8")
            node_client.record_server_close("active_connection_limit", "8.8.8.8")
            node_client.record_server_close("request_rate_limited", "8.8.8.8", "status_lookup")

        self.assertEqual(
            counters.snapshot(),
            {
                "connection_limit": 1,
                "active_connection_limit": 1,
                "request_rate_limited": 1,
            },
        )


if __name__ == "__main__":
    unittest.main()
