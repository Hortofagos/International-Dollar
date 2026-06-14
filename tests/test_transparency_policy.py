import unittest

from ind.transparency_policy import TransparencyVerifierPolicy


class TransparencyVerifierPolicyTests(unittest.TestCase):
    def test_policy_coerces_constructor_values(self):
        policy = TransparencyVerifierPolicy.from_values(
            max_root_lag_seconds="120",
            min_mirrors="2",
            allow_unsafe_single_mirror="",
            strict_mode="1",
            consistency_check_interval_seconds="900",
            consistency_max_stale_seconds="3600",
            max_current_root_age_seconds="300",
            current_root_future_skew_seconds="120",
        )

        self.assertEqual(policy.max_root_lag_seconds, 120)
        self.assertEqual(policy.min_mirrors, 2)
        self.assertFalse(policy.allow_unsafe_single_mirror)
        self.assertTrue(policy.strict_mode)
        self.assertEqual(policy.consistency_check_interval_seconds, 900)
        self.assertEqual(policy.consistency_max_stale_seconds, 3600)
        self.assertEqual(policy.max_current_root_age_seconds, 300)
        self.assertEqual(policy.current_root_future_skew_seconds, 120)


if __name__ == "__main__":
    unittest.main()
