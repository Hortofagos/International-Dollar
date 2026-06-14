import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ind import node_services


class NodeServicesTests(unittest.TestCase):
    def test_local_operator_settings_use_localhost_and_mirror_dir(self):
        base_dir = Path("C:/tmp/ind")

        settings, mirror_dir = node_services.local_operator_settings(base_dir)

        self.assertEqual(settings["IND_LOG_OPERATOR_URL"], node_services.LOCAL_OPERATOR_URL)
        self.assertEqual(settings["IND_LOG_HOST"], "127.0.0.1")
        self.assertEqual(settings["IND_LOG_MIN_MIRRORS"], "1")
        self.assertEqual(mirror_dir, str(base_dir / node_services.LOCAL_OPERATOR_MIRROR_DIR))

    def test_operator_environment_restores_previous_values(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with mock.patch.dict(os.environ, {"IND_LOG_OPERATOR_URL": "https://example.invalid"}):
                env, _mirror_dir = node_services.apply_operator_environment(temp_dir)
                self.assertEqual(env["IND_LOG_OPERATOR_URL"], node_services.LOCAL_OPERATOR_URL)
                self.assertEqual(os.environ["IND_LOG_OPERATOR_URL"], node_services.LOCAL_OPERATOR_URL)

                node_services.restore_operator_environment()

                self.assertEqual(os.environ["IND_LOG_OPERATOR_URL"], "https://example.invalid")

    def test_startup_bat_includes_operator_only_when_requested(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            node_script = Path(temp_dir) / "node_client.py"

            client_only = node_services.startup_bat_contents(
                temp_dir,
                node_script,
                include_operator=False,
                python_executable="python",
            )
            with_operator = node_services.startup_bat_contents(
                temp_dir,
                node_script,
                include_operator=True,
                python_executable="python",
            )

            self.assertNotIn("log_server.py", client_only)
            self.assertIn("node_client.py", client_only)
            self.assertIn("log_server.py", with_operator)
            self.assertIn("IND_LOG_UNSAFE_SINGLE_MIRROR=1", with_operator)


if __name__ == "__main__":
    unittest.main()
