import base64
import os
import unittest
from hashlib import sha3_256

import ecdsa

import ind_token


def keypair(seed):
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


class ProtocolVectorTests(unittest.TestCase):
    def test_deterministic_core_protocol_vectors(self):
        issuer_private, issuer_public, issuer_address = keypair(1)
        alice_private, alice_public, alice_address = keypair(2)
        bob_private, bob_public, bob_address = keypair(3)
        _carol_private, _carol_public, carol_address = keypair(4)

        self.assertEqual(issuer_address, "x1Cq7FYbYmwTYXWaCobDrjdKPY2UHeVGx")
        self.assertEqual(alice_address, "x18LJzGCCvLYqY35R4N1m1UBdZ19iTY8x")
        self.assertEqual(bob_address, "x1BTted5ZYaR6pA27wNvJV2gEi2mWpXEx")
        self.assertEqual(carol_address, "x16zVHgYgTN1u4SPt7EN3eJDpP4GYufUx")

        with temporary_env(IND_ALLOW_UNTRUSTED_GENESIS="1"):
            token = ind_token.make_genesis_token(
                4242,
                alice_address,
                issuer_private,
                issuer_public,
                value=5,
                nonce="vector-nonce",
                issued_at=1_700_000_000,
            )
            transferred = ind_token.create_transfer(
                token,
                alice_private,
                alice_public,
                bob_address,
                metadata={"memo": "vector"},
                timestamp=1_700_000_010,
            )
            receipt = ind_token.create_receipt_announcement(
                transferred,
                bob_private,
                bob_public,
                now=1_700_000_011,
            )
            conflict = ind_token.create_transfer(
                token,
                alice_private,
                alice_public,
                carol_address,
                metadata={"memo": "conflict"},
                timestamp=1_700_000_011,
            )
            proof = ind_token.create_conflict_proof(
                transferred, conflict, detected_at=1_700_000_012
            )
            announcement = ind_token.create_transfer_announcement(transferred, now=1_700_000_011)

            self.assertEqual(
                token["token_id"],
                "ind1_6b0702a7c8582d134ee9de68a49470bee6bdd85a22f31169df644c9d",
            )
            self.assertEqual(
                ind_token.genesis_hash(token["genesis"]),
                "5b8bf349620d7e3d23092150eb038e631cec1ef929fea3bbeac5211f9ff14ec0",
            )
            self.assertEqual(
                ind_token.transfer_hash(transferred["history"][-1]),
                "5726e47f9b91491f74334cb6c436e0c947adfaf1a8d9fa2544224297d149c360",
            )
            self.assertEqual(
                ind_token.sha3_hex(ind_token._canonical_bytes(receipt["receipt"])),
                "432931a6bcd4c11de20339ad0adae55406725153ed46b242b69727c9fffcc0ec",
            )
            self.assertEqual(
                ind_token.message_hash(announcement),
                "89801c92c13bfd239512adceeb5aaa8fde1e0de57744aa222c6c22b3192d41e7",
            )
            self.assertEqual(
                proof["proof_hash"],
                "8350d4e57044c8760202dddf7f3960400c604816db97954174edceef956543aa",
            )
            self.assertTrue(ind_token.pack_wire_message(announcement).startswith("indz1:"))


if __name__ == "__main__":
    unittest.main()
