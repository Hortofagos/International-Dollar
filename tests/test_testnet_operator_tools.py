import os
import unittest
from unittest import mock

from tools import testnet_report
from tools import testnet_adversarial_probe
from tools import testnet_double_spend_drill
from tools import testnet_smoke


class TestnetReportTests(unittest.TestCase):
    def test_parse_status_response_handles_mixed_valid_and_invalid_records(self):
        raw = "\n".join(
            [
                "1x0",
                "x",
                "invalid",
                "1x2",
                "x1AWhc6ARhi9RmDwvUexWWAhYh5AK5jhx",
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
        with mock.patch.object(testnet_report.sender_node, "connect", return_value="1x2\nowner\n2\nstrong_local") as connect:
            records = testnet_report.query_peer_status(["1x2"], peer="example.invalid")

        self.assertEqual(records[0]["status"], "strong_local")
        connect.assert_called_once_with(
            "c",
            "1x2",
            ["example.invalid"],
            timeout=60,
            max_duration_seconds=75,
        )


class TestnetSmokeTests(unittest.TestCase):
    def test_temporary_env_restores_previous_values(self):
        with mock.patch.dict(os.environ, {"IND_NETWORK": "mainnet"}, clear=False):
            with testnet_smoke.temporary_env({"IND_NETWORK": "testnet", "IND_STORE_PATH": "test.db"}):
                self.assertEqual(os.environ["IND_NETWORK"], "testnet")
                self.assertEqual(os.environ["IND_STORE_PATH"], "test.db")

            self.assertEqual(os.environ["IND_NETWORK"], "mainnet")
            self.assertNotIn("IND_STORE_PATH", os.environ)

    def test_validate_wallet_lines_rejects_wrong_public_key(self):
        address, _private_key, _public_key = testnet_smoke.address_generation.generate_keypair()
        _other_address, other_private_key, other_public_key = testnet_smoke.address_generation.generate_keypair()

        with self.assertRaisesRegex(testnet_smoke.SmokeError, "public key"):
            testnet_smoke.validate_wallet_lines(
                address,
                [address + "\n", other_private_key + "\n", other_public_key + "\n"],
            )


class TestnetAdversarialProbeTests(unittest.TestCase):
    def test_invalid_probe_payloads_include_fresh_valid_message_mutations(self):
        valid = {"type": "ind.test.message", "signature": "abc"}

        probes = testnet_adversarial_probe.invalid_probe_payloads(valid, nonce=123)

        self.assertEqual([item["name"] for item in probes], [
            "duplicate_json_key",
            "floating_point_json",
            "fresh_unknown_field",
            "fresh_bad_signature",
        ])
        self.assertIn("indz1:", probes[-1]["raw"])

    def test_build_report_uses_invalid_rejections_and_valid_replays(self):
        valid = {"type": "ind.test.message", "signature": "abc"}

        def fake_connect(_indicator, data, _peers):
            valid_raw = testnet_adversarial_probe.ind_token.pack_wire_message(valid)
            return "ok" if data == valid_raw else "invalid"

        with (
            mock.patch.object(testnet_adversarial_probe, "read_valid_message", return_value=valid),
            mock.patch.object(testnet_adversarial_probe.sender_node, "connect", side_effect=fake_connect),
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


class TestnetDoubleSpendDrillTests(unittest.TestCase):
    def test_build_double_spend_messages_creates_verifiable_conflict(self):
        _issuer_address, issuer_private, issuer_public = (
            testnet_double_spend_drill.address_generation.generate_keypair()
        )
        faucet_address, faucet_private, faucet_public = (
            testnet_double_spend_drill.address_generation.generate_keypair()
        )
        manifest = testnet_double_spend_drill.ind_token.make_genesis_manifest(
            testnet_double_spend_drill.ind_token.make_denomination_ranges([(1, 1)], faucet_address, start_index=40),
            issuer_private,
            issuer_public,
            issued_at=1_700_000_000,
        )

        with mock.patch.dict(os.environ, {"IND_ALLOW_UNTRUSTED_GENESIS": "1"}, clear=False):
            messages = testnet_double_spend_drill.build_double_spend_messages(
                manifest,
                40,
                faucet_private,
                faucet_public,
                now=1_700_000_010,
            )

            self.assertEqual(messages["display_id"], "1x40")
            self.assertTrue(testnet_double_spend_drill.ind_token.verify_conflict_proof(messages["proof"]))
            self.assertNotEqual(messages["branch_a_hash"], messages["branch_b_hash"])

    def test_heal_success_predicate_expects_conflict_everywhere(self):
        broadcasts = [
            {"label": "heal_branch_a", "response": "invalid"},
            {"label": "heal_branch_b", "response": "invalid"},
            {"label": "heal_conflict_proof", "response": "ok"},
            {"label": "heal_conflict_proof", "response": "ok"},
        ]

        result = testnet_double_spend_drill.evaluate_heal_result(["conflict", "conflict"], broadcasts)

        self.assertTrue(result["ok"])
        self.assertTrue(result["conflict_everywhere"])
        self.assertTrue(result["proofs_accepted"])
        self.assertEqual(result["expected_result"], "conflict")

        clean_result = testnet_double_spend_drill.evaluate_heal_result(["strong_local", "conflict"], broadcasts)
        self.assertFalse(clean_result["ok"])
        self.assertFalse(clean_result["conflict_everywhere"])

        rejected_proof = list(broadcasts)
        rejected_proof[-1] = {"label": "heal_conflict_proof", "response": "invalid"}
        proof_result = testnet_double_spend_drill.evaluate_heal_result(["conflict", "conflict"], rejected_proof)
        self.assertFalse(proof_result["ok"])
        self.assertFalse(proof_result["proofs_accepted"])


if __name__ == "__main__":
    unittest.main()
