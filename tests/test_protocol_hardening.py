import base64
import copy
import os
import sqlite3
import tempfile
import unittest
from hashlib import sha3_256

import ecdsa
from ecdsa import util as ecdsa_util

import ind_token


def keypair(seed=None):
    if seed is None:
        signing_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1, hashfunc=sha3_256)
    else:
        signing_key = ecdsa.SigningKey.from_string(
            bytes([seed]) * 32,
            curve=ecdsa.SECP256k1,
            hashfunc=sha3_256,
        )
    private_key = base64.b85encode(signing_key.to_string()).decode("utf-8")
    public_key = base64.b85encode(signing_key.get_verifying_key().to_string()).decode("utf-8")
    return private_key, public_key, ind_token.address_from_public_key(public_key)


class temporary_env:
    def __init__(self, **values):
        self.values = values
        self.old = {}

    def __enter__(self):
        for key, value in self.values.items():
            self.old[key] = os.environ.get(key)
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def __exit__(self, exc_type, exc_value, traceback):
        for key, value in self.old.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


class ProtocolHardeningTests(unittest.TestCase):
    def test_unknown_fields_are_rejected_in_protocol_objects(self):
        issuer_private, issuer_public, _issuer_address = keypair()
        alice_private, alice_public, alice_address = keypair()
        _bob_private, _bob_public, bob_address = keypair()
        token = ind_token.make_genesis_token(
            1001,
            alice_address,
            issuer_private,
            issuer_public,
            issued_at=1_700_000_000,
        )
        with temporary_env(IND_ALLOW_UNTRUSTED_GENESIS="1"):
            extra_genesis = copy.deepcopy(token)
            extra_genesis["genesis"]["surprise"] = True
            with self.assertRaisesRegex(ind_token.ValidationError, "unknown field"):
                ind_token.verify_token(extra_genesis, now=1_700_000_001)

            transferred = ind_token.create_transfer(
                token,
                alice_private,
                alice_public,
                bob_address,
                timestamp=1_700_000_010,
            )
            extra_transfer = copy.deepcopy(transferred)
            extra_transfer["history"][0]["extra"] = "ignored no more"
            with self.assertRaisesRegex(ind_token.ValidationError, "unknown field"):
                ind_token.verify_token(extra_transfer, now=1_700_000_011)

            message = ind_token.create_transfer_announcement(transferred, now=1_700_000_011)
            message["extra"] = "nope"
            with tempfile.TemporaryDirectory() as temp_dir:
                store = ind_token.INDLocalStore(temp_dir + "/ind.db")
                with self.assertRaisesRegex(ind_token.ValidationError, "unknown field"):
                    store.ingest_message(message)

    def test_manifest_schema_and_strict_json_numbers_are_rejected(self):
        issuer_private, issuer_public, _issuer_address = keypair()
        _owner_private, _owner_public, owner_address = keypair()
        manifest = ind_token.make_genesis_manifest(
            ind_token.make_denomination_ranges([(1, 10)], owner_address),
            issuer_private,
            issuer_public,
            issued_at=1_700_000_000,
        )

        with temporary_env(IND_ALLOW_UNTRUSTED_GENESIS="1"):
            extra_manifest = copy.deepcopy(manifest)
            extra_manifest["shadow_supply"] = 1
            with self.assertRaisesRegex(ind_token.ValidationError, "unknown field"):
                ind_token.verify_genesis_manifest(extra_manifest, now=1_700_000_001)

            numeric_string = copy.deepcopy(manifest)
            numeric_string["total_token_count"] = "10"
            with self.assertRaisesRegex(ind_token.ValidationError, "must be an integer"):
                ind_token.verify_genesis_manifest(numeric_string, now=1_700_000_001)

        with self.assertRaisesRegex(ind_token.ValidationError, "duplicate JSON object key"):
            ind_token.unpack_wire_message('{"type":"a","type":"b"}')
        with self.assertRaisesRegex(ind_token.ValidationError, "floating-point"):
            ind_token.unpack_wire_message('{"type":"a","value":1.25}')
        with self.assertRaisesRegex(ind_token.ValidationError, "numeric constant"):
            ind_token.unpack_wire_message('{"type":"a","value":NaN}')

    def test_conflict_proof_can_target_non_tip_transfer(self):
        issuer_private, issuer_public, _issuer_address = keypair()
        alice_private, alice_public, alice_address = keypair()
        bob_private, bob_public, bob_address = keypair()
        carol_private, carol_public, carol_address = keypair()
        _dave_private, _dave_public, dave_address = keypair()
        erin_private, erin_public, erin_address = keypair()
        _frank_private, _frank_public, frank_address = keypair()

        with temporary_env(IND_ALLOW_UNTRUSTED_GENESIS="1"):
            token = ind_token.make_genesis_token(
                1002,
                alice_address,
                issuer_private,
                issuer_public,
                issued_at=1_700_000_000,
            )
            base = ind_token.create_transfer(token, alice_private, alice_public, bob_address, timestamp=1_700_000_010)
            branch_a = ind_token.create_transfer(base, bob_private, bob_public, carol_address, timestamp=1_700_000_020)
            branch_a = ind_token.create_transfer(branch_a, carol_private, carol_public, dave_address, timestamp=1_700_000_030)
            branch_b = ind_token.create_transfer(base, bob_private, bob_public, erin_address, timestamp=1_700_000_021)
            branch_b = ind_token.create_transfer(branch_b, erin_private, erin_public, frank_address, timestamp=1_700_000_031)
            with tempfile.TemporaryDirectory() as temp_dir:
                store = ind_token.INDLocalStore(temp_dir + "/ind.db")
                store.ingest_message(ind_token.create_transfer_announcement(branch_a, now=1_700_000_032))
                result = store.ingest_message(ind_token.create_transfer_announcement(branch_b, now=1_700_000_033))

            self.assertEqual(result["status"], "conflict")
            self.assertEqual(result["conflict_proof"]["sequence"], 2)
            self.assertTrue(ind_token.verify_conflict_proof(result["conflict_proof"]))

    def test_protocol_signatures_are_domain_separated_and_low_s(self):
        issuer_private, issuer_public, _issuer_address = keypair()
        alice_private, alice_public, alice_address = keypair()
        _bob_private, _bob_public, bob_address = keypair()
        token = ind_token.make_genesis_token(
            1003,
            alice_address,
            issuer_private,
            issuer_public,
            issued_at=1_700_000_000,
        )
        with temporary_env(IND_ALLOW_UNTRUSTED_GENESIS="1"):
            transferred = ind_token.create_transfer(
                token,
                alice_private,
                alice_public,
                bob_address,
                timestamp=1_700_000_010,
            )

        transfer = transferred["history"][-1]
        unsigned = ind_token._without_signature(transfer)
        self.assertFalse(
            ind_token.b85_verify(alice_public, transfer["signature"], ind_token._canonical_bytes(unsigned))
        )
        self.assertTrue(
            ind_token.b85_verify_domain(
                alice_public,
                transfer["signature"],
                ind_token.TRANSFER_SIGNATURE_DOMAIN,
                unsigned,
            )
        )

        signature = base64.b85decode(transfer["signature"])
        r, s = ecdsa_util.sigdecode_string(signature, ecdsa.SECP256k1.order)
        self.assertLessEqual(s, ecdsa.SECP256k1.order // 2)
        high_s = ecdsa_util.sigencode_string(r, ecdsa.SECP256k1.order - s, ecdsa.SECP256k1.order)
        high_s_b85 = base64.b85encode(high_s).decode("utf-8")
        self.assertFalse(
            ind_token.b85_verify_domain(
                alice_public,
                high_s_b85,
                ind_token.TRANSFER_SIGNATURE_DOMAIN,
                unsigned,
            )
        )

    def test_local_store_records_schema_version(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = temp_dir + "/ind.db"
            ind_token.INDLocalStore(db_path)
            conn = sqlite3.connect(db_path)
            try:
                user_version = conn.execute("PRAGMA user_version").fetchone()[0]
                row = conn.execute("SELECT value FROM ind_schema WHERE key = 'schema_version'").fetchone()
            finally:
                conn.close()
        self.assertEqual(user_version, 1)
        self.assertEqual(row[0], "1")


if __name__ == "__main__":
    unittest.main()
