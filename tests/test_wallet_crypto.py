import json
import os
import tempfile
import unittest

from cryptography.fernet import Fernet

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

    def test_wallet_encryption_uses_indw2_wrapped_mwk_and_decrypts_in_memory(self):
        with tempfile.TemporaryDirectory() as temp_dir, temporary_cwd(temp_dir):
            self._make_runtime_dirs()
            runtime_json.write_wallet_generation(
                "addr123",
                "private-key",
                "public-key",
                tokens=["1x-token 0 0"],
            )

            wallet_encryption.wallet_encrypt(STRONG_PASSWORD)

            encrypted_path = "wallet_folder/wallet_encrypted_addr123.json"
            with open(encrypted_path, "r", encoding="utf-8") as handle:
                encrypted = json.load(handle)
            self.assertEqual(encrypted["format"], wallet_crypto.FORMAT)
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
                "addr123\nprivate-key\npublic-key\n1x-token 0 0\n",
            )

    def test_wrong_password_does_not_unlock_indw2_wallet(self):
        with tempfile.TemporaryDirectory() as temp_dir, temporary_cwd(temp_dir):
            self._make_runtime_dirs()
            runtime_json.write_wallet_generation("addr123", "private-key", "public-key")
            wallet_encryption.wallet_encrypt(STRONG_PASSWORD)

            self.assertFalse(wallet_decryption.wallet_decrypt("wrong password", "addr123"))
            self.assertEqual(runtime_json.iter_decrypted_wallet_files(), [])

    def test_legacy_wallet_payloads_still_decrypt(self):
        with tempfile.TemporaryDirectory() as temp_dir, temporary_cwd(temp_dir):
            self._make_runtime_dirs()
            wallet_plaintext = "legacyaddr\nprivate-key\npublic-key\nlegacy-password\n"
            key = wallet_decryption._derive_key(
                b"legacy-password",
                wallet_decryption.LEGACY_WALLET_SALT,
            )
            encrypted = Fernet(key).encrypt(wallet_plaintext.encode("utf-8"))
            with open("wallet_folder/wallet_encrypted_legacyaddr.txt", "wb") as handle:
                handle.write(encrypted)

            self.assertTrue(wallet_decryption.wallet_decrypt("legacy-password", "legacyaddr"))
            self.assertEqual(
                runtime_json.read_decrypted_wallet_payload("wallet_folder/wallet_decrypted_legacyaddr.json"),
                wallet_plaintext,
            )


if __name__ == "__main__":
    unittest.main()
