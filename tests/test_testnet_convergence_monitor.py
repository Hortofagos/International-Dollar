import unittest
from unittest import mock

from tools import testnet_convergence_monitor


class TestnetConvergenceMonitorTests(unittest.TestCase):
    def test_matching_seed_status_is_ok(self):
        def fake_query(refs, peer, **_kwargs):
            return [
                {
                    "ref": refs[0],
                    "display_id": refs[0],
                    "owner_address": "owner",
                    "sequence": 3,
                    "status": "strong_local",
                }
            ]

        with mock.patch.object(testnet_convergence_monitor.testnet_report, "query_peer_status", side_effect=fake_query):
            report = testnet_convergence_monitor.build_report(["seed-a", "seed-b"], ["1x5"])

        self.assertTrue(report["ok"])
        self.assertEqual(report["mismatches"], [])

    def test_mismatched_owner_fails(self):
        def fake_query(refs, peer, **_kwargs):
            owner = "owner-a" if peer == "seed-a" else "owner-b"
            return [
                {
                    "ref": refs[0],
                    "display_id": refs[0],
                    "owner_address": owner,
                    "sequence": 3,
                    "status": "strong_local",
                }
            ]

        with mock.patch.object(testnet_convergence_monitor.testnet_report, "query_peer_status", side_effect=fake_query):
            report = testnet_convergence_monitor.build_report(["seed-a", "seed-b"], ["1x5"])

        self.assertFalse(report["ok"])
        self.assertEqual(report["mismatches"][0]["ref"], "1x5")

    def test_conflict_owner_mismatch_is_ok(self):
        def fake_query(refs, peer, **_kwargs):
            owner = "stale-owner-a" if peer == "seed-a" else "stale-owner-b"
            sequence = 1 if peer == "seed-a" else 2
            return [
                {
                    "ref": refs[0],
                    "display_id": refs[0],
                    "owner_address": owner,
                    "sequence": sequence,
                    "status": "conflict",
                }
            ]

        with mock.patch.object(testnet_convergence_monitor.testnet_report, "query_peer_status", side_effect=fake_query):
            report = testnet_convergence_monitor.build_report(["seed-a", "seed-b"], ["1x11"])

        self.assertTrue(report["ok"])
        self.assertEqual(report["mismatches"], [])

    def test_conflict_vs_non_conflict_fails(self):
        def fake_query(refs, peer, **_kwargs):
            status = "conflict" if peer == "seed-a" else "strong_local"
            return [
                {
                    "ref": refs[0],
                    "display_id": refs[0],
                    "owner_address": "",
                    "sequence": 2,
                    "status": status,
                }
            ]

        with mock.patch.object(testnet_convergence_monitor.testnet_report, "query_peer_status", side_effect=fake_query):
            report = testnet_convergence_monitor.build_report(["seed-a", "seed-b"], ["1x11"])

        self.assertFalse(report["ok"])
        self.assertEqual(report["mismatches"][0]["ref"], "1x11")

    def test_stale_peer_fails(self):
        def fake_query(refs, peer, **_kwargs):
            return [
                {
                    "ref": refs[0],
                    "display_id": refs[0],
                    "owner_address": "",
                    "sequence": None,
                    "status": "no_response",
                }
            ]

        with mock.patch.object(testnet_convergence_monitor.testnet_report, "query_peer_status", side_effect=fake_query):
            report = testnet_convergence_monitor.build_report(["seed-a"], ["1x5"])

        self.assertFalse(report["ok"])
        self.assertEqual(report["stale_peers"], ["seed-a"])

    def test_hostname_stale_path_falls_back_to_resolved_address(self):
        calls = []

        def fake_query(refs, peer, **kwargs):
            calls.append((peer, kwargs.get("timeout_seconds")))
            if peer == "seed-a":
                return [
                    {
                        "ref": refs[0],
                        "display_id": refs[0],
                        "owner_address": "",
                        "sequence": None,
                        "status": "n",
                    }
                ]
            return [
                {
                    "ref": refs[0],
                    "display_id": refs[0],
                    "owner_address": "owner",
                    "sequence": 3,
                    "status": "strong_local",
                }
            ]

        addrinfo = [(0, 0, 0, "", ("203.0.113.10", 0))]
        with mock.patch.object(testnet_convergence_monitor.testnet_report, "query_peer_status", side_effect=fake_query):
            with mock.patch.object(testnet_convergence_monitor.socket, "getaddrinfo", return_value=addrinfo):
                report = testnet_convergence_monitor.build_report(["seed-a"], ["1x5"])

        self.assertTrue(report["ok"])
        self.assertEqual(report["stale_peers"], [])
        self.assertEqual(report["per_peer"][0]["peer"], "seed-a")
        self.assertEqual(report["per_peer"][0]["queried_peer"], "203.0.113.10")
        self.assertEqual(report["per_peer"][0]["path"]["path_status"], "alternate_path_ok")
        self.assertEqual(calls, [("seed-a", 60), ("203.0.113.10", 60)])


if __name__ == "__main__":
    unittest.main()
