import os
import tempfile
import unittest

from ind import runtime as runtime_json


class temporary_cwd:
    def __init__(self, path):
        self.path = path
        self.previous = None

    def __enter__(self):
        self.previous = os.getcwd()
        os.chdir(self.path)

    def __exit__(self, exc_type, exc_value, traceback):
        os.chdir(self.previous)


class RuntimeNodeConfigTests(unittest.TestCase):
    def test_full_operator_defaults_disabled_and_preserves_legacy_callers(self):
        with tempfile.TemporaryDirectory() as temp_dir, temporary_cwd(temp_dir):
            runtime_json.ensure_runtime_files()

            self.assertEqual(runtime_json.read_node_config(), ("FULL NODE", "NO", "NO"))
            self.assertEqual(runtime_json.read_node_operator_enabled(), "NO")

            runtime_json.write_node_config("FULL NODE", "YES", "NO", "YES")

            self.assertEqual(runtime_json.read_node_config(), ("FULL NODE", "YES", "NO"))
            self.assertEqual(runtime_json.read_node_operator_enabled(), "YES")

            runtime_json.write_node_config("FULL NODE", "NO", "YES")

            self.assertEqual(runtime_json.read_node_config(), ("FULL NODE", "NO", "YES"))
            self.assertEqual(runtime_json.read_node_operator_enabled(), "YES")

            runtime_json.write_node_config("FULL NODE", "NO", "NO", "NO")

            self.assertEqual(runtime_json.read_node_operator_enabled(), "NO")


if __name__ == "__main__":
    unittest.main()
