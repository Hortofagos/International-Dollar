import json
import os
import tempfile
import unittest

import runtime_json
import wallet_crypto
import wallet_decryption
import wallet_encryption

STRONG_PASSWORD = "correct horse battery staple 42!"


class temporary_cwd:
    def __init__(self, path):
        self.path = path
        self.previous = None

    def __enter__(self):
        self.previous = os.getcwd()
        os.chdir(self.path)

    def __exit__(self, exc_type, exc_value, traceback):
        os.chdir(self.previous)


class WalletCryptoTests(unittest.TestCase):
    def setUp(self):
        runtime_json.clear_decrypted_wallets()
        wallet_crypto.clear_all_session_mwks()

    def _make_runtime_dirs(self):
        os.makedirs("files", exist_ok=True)
        os.makedirs("wallet_folder", exist_ok=True)

    def test_wallet_password_minimum_is_ten_characters(self):
        wallet_crypto.validate_wallet_password("vivid-lantern-73-RIVER!")

        with self.assertRaisesRegex(wallet_crypto.PasswordPolicyError, "at least 10 characters"):
            wallet_crypto.validate_wallet_password("aB3!xYaaa")

        with self.assertRaisesRegex(wallet_crypto.PasswordPolicyError, "too easy"):
            wallet_crypto.validate_wallet_password("aaaaaaaaaa")

    def test_sign_in_choice_cannot_be_persisted(self):
        with tempfile.TemporaryDirectory() as temp_dir, temporary_cwd(temp_dir):
            self._make_runtime_dirs()
            runtime_json.ensure_runtime_files()

            runtime_json.set_check_signed_in(True)

            self.assertFalse(runtime_json.get_check_signed_in())
            self.assertFalse(runtime_json.read_state()["check_signed_in"])

    def test_plaintext_wallet_cleanup_removes_files_and_unlocked_session(self):
        with tempfile.TemporaryDirectory() as temp_dir, temporary_cwd(temp_dir):
            self._make_runtime_dirs()
            runtime_json.ensure_runtime_files()
            stale_path = runtime_json.decrypted_wallet_path("addr123")
            stale_path.write_text("addr123\nprivate-key\npublic-key\n", encoding="utf-8")
            runtime_json.write_decrypted_wallet("addr456", "addr456\nprivate-key\npublic-key\n")
            wallet_crypto.set_session_mwk("addr456", b"\x01" * wallet_crypto.MWK_BYTES)

            wallet_decryption.clear_plaintext_wallet_files(clear_memory=True)

            self.assertFalse(stale_path.exists())
            self.assertEqual(runtime_json.iter_decrypted_wallet_files(), [])
            self.assertIsNone(wallet_crypto.get_session_mwk("addr456"))

    def test_wallet_encryption_uses_indw3_wrapped_mwk_and_decrypts_in_memory(self):
        with tempfile.TemporaryDirectory() as temp_dir, temporary_cwd(temp_dir):
            self._make_runtime_dirs()
            runtime_json.write_wallet_generation(
                "addr123",
                "private-key",
                "public-key",
                wallet_name=" Main Wallet\nTest ",
                bills=["1x-bill 0 0"],
            )

            wallet_encryption.wallet_encrypt(STRONG_PASSWORD)

            encrypted_path = "wallet_folder/wallet_encrypted_addr123.json"
            with open(encrypted_path, encoding="utf-8") as handle:
                encrypted = json.load(handle)
            self.assertEqual(encrypted["format"], wallet_crypto.FORMAT)
            self.assertEqual(encrypted["wallet_name"], "Main Wallet Test")
            self.assertEqual(encrypted["payload"]["cipher"], "AES-256-GCM")
            self.assertEqual(encrypted["wrappers"][0]["type"], wallet_crypto.PASSWORD_WRAPPER)
            self.assertEqual(encrypted["wrappers"][0]["kdf"], "Argon2id")
            self.assertEqual(encrypted["wrappers"][0]["memory_cost_kib"], 256 * 1024)

            serialized = json.dumps(encrypted)
            self.assertNotIn(STRONG_PASSWORD, serialized)
            self.assertNotIn("private-key", serialized)
            self.assertNotIn("public-key", serialized)

            with open("wallet_folder/wallet_decrypted_stale.json", "w", encoding="utf-8") as handle:
                handle.write("stale secret")

            self.assertTrue(wallet_decryption.wallet_decrypt(STRONG_PASSWORD, "addr123"))

            decrypted_path = "wallet_folder/wallet_decrypted_addr123.json"
            self.assertFalse(os.path.exists("wallet_folder/wallet_decrypted_stale.json"))
            self.assertFalse(os.path.exists(decrypted_path))
            self.assertEqual(
                runtime_json.read_decrypted_wallet_payload(decrypted_path),
                "addr123\nprivate-key\npublic-key\n1x-bill 0 0\n",
            )

    def test_wrong_password_does_not_unlock_indw3_wallet(self):
        with tempfile.TemporaryDirectory() as temp_dir, temporary_cwd(temp_dir):
            self._make_runtime_dirs()
            runtime_json.write_wallet_generation("addr123", "private-key", "public-key")
            wallet_encryption.wallet_encrypt(STRONG_PASSWORD)

            self.assertFalse(wallet_decryption.wallet_decrypt("wrong password", "addr123"))
            self.assertEqual(runtime_json.iter_decrypted_wallet_files(), [])

    def test_wallet_name_is_optional_metadata(self):
        with tempfile.TemporaryDirectory() as temp_dir, temporary_cwd(temp_dir):
            self._make_runtime_dirs()
            runtime_json.write_wallet_generation("addr123", "private-key", "public-key")

            wallet_encryption.wallet_encrypt(STRONG_PASSWORD, wallet_name="")

            encrypted_path = "wallet_folder/wallet_encrypted_addr123.json"
            with open(encrypted_path, encoding="utf-8") as handle:
                encrypted = json.load(handle)
            self.assertNotIn("wallet_name", encrypted)

            self.assertTrue(wallet_decryption.wallet_decrypt(STRONG_PASSWORD, "addr123"))
            decrypted_path = "wallet_folder/wallet_decrypted_addr123.json"
            self.assertEqual(
                runtime_json.read_decrypted_wallet_payload(decrypted_path),
                "addr123\nprivate-key\npublic-key\n",
            )

    def test_non_v3_wallet_payloads_do_not_unlock(self):
        with tempfile.TemporaryDirectory() as temp_dir, temporary_cwd(temp_dir):
            self._make_runtime_dirs()
            wallet_plaintext = "legacyaddr\nprivate-key\npublic-key\nlegacy-password\n"
            with open("wallet_folder/wallet_encrypted_legacyaddr.txt", "wb") as handle:
                handle.write(wallet_plaintext.encode("utf-8"))

            self.assertFalse(wallet_decryption.wallet_decrypt("legacy-password", "legacyaddr"))
            self.assertEqual(runtime_json.iter_decrypted_wallet_files(), [])


if __name__ == "__main__":
    unittest.main()
