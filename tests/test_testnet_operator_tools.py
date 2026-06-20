import unittest
from unittest import mock

from ind import protocol_v3
from ind.store import INDLocalStore
from tools import testnet_adversarial_probe, testnet_report, v3_double_spend_drill

from .test_archive_segment_v3 import native_v3_archive_fixture


class TestnetReportTests(unittest.TestCase):
    def test_parse_status_response_handles_mixed_valid_and_invalid_records(self):
        raw = "\n".join(
            [
                "1x0",
                "x",
                "invalid",
                "1x2",
                "x324sq85mgDVTGK4oHXw2b2LHh4YFriSx",
                "2",
                "strong_local",
            ]
        )

        records = testnet_report.parse_status_response(raw)

        self.assertEqual(records[0]["display_id"], "1x0")
        self.assertEqual(records[0]["status"], "invalid")
        self.assertIsNone(records[0]["sequence"])
        self.assertEqual(records[1]["display_id"], "1x2")
        self.assertEqual(records[1]["sequence"], 2)
        self.assertEqual(records[1]["status"], "strong_local")

    def test_parse_status_response_normalizes_conflict_owner_placeholder(self):
        raw = "\n".join(["1x11", "x", "2", "conflict"])

        records = testnet_report.parse_status_response(raw)

        self.assertEqual(records[0]["display_id"], "1x11")
        self.assertEqual(records[0]["owner_address"], "")
        self.assertEqual(records[0]["sequence"], 2)
        self.assertEqual(records[0]["status"], "conflict")

    def test_query_peer_status_reports_no_response_per_ref(self):
        with mock.patch.object(testnet_report.sender_node, "connect", return_value="n"):
            records = testnet_report.query_peer_status(["1x0", "1x2"], peer="example.invalid")

        self.assertEqual([item["status"] for item in records], ["n", "n"])

    def test_query_peer_status_uses_settlement_window_timeout(self):
        with mock.patch.object(
            testnet_report.sender_node, "connect", return_value="1x2\nowner\n2\nstrong_local"
        ) as connect:
            records = testnet_report.query_peer_status(["1x2"], peer="example.invalid")

        self.assertEqual(records[0]["status"], "strong_local")
        connect.assert_called_once_with(
            "c",
            "1x2",
            ["example.invalid"],
            timeout=60,
            max_duration_seconds=75,
        )

class TestnetAdversarialProbeTests(unittest.TestCase):
    def test_invalid_probe_payloads_include_fresh_valid_message_mutations(self):
        valid = {"type": "ind.test.message", "signature": "abc"}

        probes = testnet_adversarial_probe.invalid_probe_payloads(valid, nonce=123)

        self.assertEqual(
            [item["name"] for item in probes],
            [
                "duplicate_json_key",
                "floating_point_json",
                "fresh_unknown_field",
                "fresh_bad_signature",
            ],
        )
        self.assertIn("indz1:", probes[-1]["raw"])

    def test_build_report_uses_invalid_rejections_and_valid_replays(self):
        valid = {"type": "ind.test.message", "signature": "abc"}

        def fake_connect(_indicator, data, _peers):
            valid_raw = testnet_adversarial_probe.ind_token.pack_wire_message(valid)
            return "ok" if data == valid_raw else "invalid"

        with (
            mock.patch.object(testnet_adversarial_probe, "read_valid_message", return_value=valid),
            mock.patch.object(
                testnet_adversarial_probe.sender_node, "connect", side_effect=fake_connect
            ),
            mock.patch.object(
                testnet_adversarial_probe.testnet_report,
                "query_peer_status",
                return_value=[
                    {
                        "ref": "1x2",
                        "display_id": "1x2",
                        "owner_address": "owner",
                        "sequence": 2,
                        "status": "strong_local",
                    }
                ],
            ),
        ):
            report = testnet_adversarial_probe.build_report(
                ["seed-a"],
                ["1x2"],
                valid_message_path="unused.json",
                valid_replays=2,
                nonce=123,
            )

        self.assertTrue(report["ok"])
        self.assertEqual(report["invalid_probe_count_per_peer"], 4)
        self.assertEqual(report["valid_replay_count_per_peer"], 2)


def test_v3_double_spend_drill_builds_native_conflict(tmp_path):
    fixture = native_v3_archive_fixture(tmp_path)
    store = INDLocalStore(db_path=tmp_path / "v3-drill.db", require_transparency=False)
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

    messages = v3_double_spend_drill.build_double_spend_messages(
        store,
        bill,
        [fixture["bob_address"], fixture["bob_private"], fixture["bob_public"]],
        trusted_operator_public_key=fixture["log_public"],
        now=1_700_000_050,
    )

    assert messages["type"] == "ind.testnet_double_spend_drill.v3"
    assert messages["announcement_a"]["type"] == protocol_v3.TRANSFER_ANNOUNCEMENT_TYPE
    assert messages["announcement_b"]["type"] == protocol_v3.TRANSFER_ANNOUNCEMENT_TYPE
    assert protocol_v3.verify_conflict_proof(messages["proof"])
    assert messages["branch_a_hash"] != messages["branch_b_hash"]


if __name__ == "__main__":
    unittest.main()
