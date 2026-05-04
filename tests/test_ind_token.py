import base64
import os
from pathlib import Path
import socket
import sqlite3
import tempfile
import threading
import time
import unittest
import zlib
from hashlib import sha3_256

import ecdsa

import ind_transport
import ind_token
import node_client
import sender_node


os.environ.setdefault("IND_ALLOW_UNTRUSTED_GENESIS", "1")


def keypair():
    signing_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1, hashfunc=sha3_256)
    verify_key = signing_key.get_verifying_key()
    private_key = base64.b85encode(signing_key.to_string()).decode("utf-8")
    public_key = base64.b85encode(verify_key.to_string()).decode("utf-8")
    return private_key, public_key, ind_token.address_from_public_key(public_key)


def append_signed_transfer(token, sender_private, sender_public, recipient_address, timestamp):
    if token["history"]:
        previous_transfer = token["history"][-1]
        previous_hash = ind_token.transfer_hash(previous_transfer)
        sequence = int(previous_transfer["sequence"]) + 1
        sender_address = previous_transfer["recipient_address"]
    else:
        previous_hash = ind_token.genesis_hash(token["genesis"])
        sequence = 1
        sender_address = token["genesis"]["owner_address"]
    transfer_unsigned = {
        "type": ind_token.TRANSFER_TYPE,
        "version": ind_token.TOKEN_VERSION,
        "token_id": token["token_id"],
        "sequence": sequence,
        "previous_hash": previous_hash,
        "sender_address": sender_address,
        "sender_public_key": sender_public,
        "recipient_address": recipient_address,
        "timestamp": int(timestamp),
        "metadata": {},
    }
    transfer_signed = dict(transfer_unsigned)
    transfer_signed["signature"] = ind_token.b85_sign_domain(
        sender_private,
        ind_token.TRANSFER_SIGNATURE_DOMAIN,
        transfer_unsigned,
    )
    token["history"].append(transfer_signed)


class temporary_env:
    def __init__(self, **values):
        self.values = values
        self.previous = {}

    def __enter__(self):
        for key, value in self.values.items():
            self.previous[key] = os.environ.get(key)
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def __exit__(self, exc_type, exc_value, traceback):
        for key, value in self.previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


class INDTokenTests(unittest.TestCase):
    def test_numerology_constants_shape_protocol(self):
        issuer_private, issuer_public, _issuer_address = keypair()
        _alice_private, _alice_public, alice_address = keypair()
        token = ind_token.make_genesis_token(33, alice_address, issuer_private, issuer_public)
        alignment = token["genesis"]["metadata"][ind_token.NUMEROLOGY_METADATA_KEY]

        self.assertEqual(ind_token.TOTAL_SUPPLY, 33_000_000_000)
        self.assertEqual(ind_token.ADDRESS_LENGTH, 33)
        self.assertEqual(len(alice_address), 33)
        self.assertEqual(alignment["master_number"], 33)
        self.assertEqual(alignment["angel_number"], 777)
        self.assertEqual(alignment["money_number"], 8)
        self.assertEqual(alignment["birthday_number"], 9)
        self.assertEqual(alignment["birthday_code"], "09.10.2003")
        self.assertEqual(alignment["address_length"], 33)
        self.assertEqual(len(alignment["seal"]), 33)
        self.assertEqual(ind_token.verify_token(token).owner_address, alice_address)

    def test_finality_buffer_is_at_least_sixty_seconds(self):
        self.assertGreaterEqual(ind_token.FINALITY_BUFFER_SECONDS, 60)

    def test_address_format_has_version_and_checksum(self):
        _private_key, public_key, address = keypair()

        self.assertEqual(len(address), ind_token.ADDRESS_LENGTH)
        self.assertTrue(address.startswith("x1"))
        self.assertTrue(address.endswith("x"))
        self.assertTrue(ind_token.is_current_address(address))
        self.assertEqual(address, ind_token.validate_address(address))

        replacement = "2" if address[-2] != "2" else "3"
        tampered = address[:-2] + replacement + address[-1]
        self.assertFalse(ind_token.is_current_address(tampered))
        with self.assertRaisesRegex(ind_token.ValidationError, "invalid address"):
            ind_token.validate_address(tampered)

    def test_invalid_recipient_address_is_rejected(self):
        issuer_private, issuer_public, _issuer_address = keypair()
        alice_private, alice_public, alice_address = keypair()
        token = ind_token.make_genesis_token(6, alice_address, issuer_private, issuer_public)

        with self.assertRaisesRegex(ind_token.ValidationError, "invalid recipient address"):
            ind_token.create_transfer(token, alice_private, alice_public, "not-an-address")

    def test_legacy_addresses_still_spend_existing_tokens(self):
        issuer_private, issuer_public, _issuer_address = keypair()
        alice_private, alice_public, _alice_address = keypair()
        bob_private, bob_public, _bob_address = keypair()
        alice_legacy = ind_token.legacy_address_from_public_key(alice_public)
        bob_legacy = ind_token.legacy_address_from_public_key(bob_public)
        token = ind_token.make_genesis_token(61, alice_legacy, issuer_private, issuer_public)

        transferred = ind_token.create_transfer(token, alice_private, alice_public, bob_legacy)
        state = ind_token.verify_token(transferred)

        self.assertEqual(transferred["history"][-1]["sender_address"], alice_legacy)
        self.assertEqual(state.owner_address, bob_legacy)
        self.assertEqual(
            ind_token.create_receipt(transferred, bob_private, bob_public)["recipient_address"],
            bob_legacy,
        )

    def test_previous_checked_addresses_still_spend_existing_tokens(self):
        issuer_private, issuer_public, _issuer_address = keypair()
        alice_private, alice_public, _alice_address = keypair()
        bob_private, bob_public, _bob_address = keypair()
        alice_previous = ind_token.previous_address_from_public_key(alice_public)
        bob_previous = ind_token.previous_address_from_public_key(bob_public)
        token = ind_token.make_genesis_token(62, alice_previous, issuer_private, issuer_public)

        self.assertEqual(len(alice_previous), ind_token.PREVIOUS_ADDRESS_LENGTH)
        self.assertTrue(ind_token.is_previous_address(alice_previous))

        transferred = ind_token.create_transfer(token, alice_private, alice_public, bob_previous)
        state = ind_token.verify_token(transferred)

        self.assertEqual(transferred["history"][-1]["sender_address"], alice_previous)
        self.assertEqual(state.owner_address, bob_previous)

    def test_transfer_receipt_finalizes_after_buffer(self):
        issuer_private, issuer_public, _issuer_address = keypair()
        alice_private, alice_public, alice_address = keypair()
        bob_private, bob_public, bob_address = keypair()
        token = ind_token.make_genesis_token(7, alice_address, issuer_private, issuer_public)
        transferred = ind_token.create_transfer(token, alice_private, alice_public, bob_address)
        receipt = ind_token.create_receipt_announcement(transferred, bob_private, bob_public)

        with tempfile.TemporaryDirectory() as temp_dir:
            store = ind_token.INDLocalStore(temp_dir + "/ind_test.db")
            store.ingest_message(ind_token.create_transfer_announcement(transferred))
            store.ingest_message(receipt)
            self.assertEqual(store.get_token_record(transferred["token_id"])["status"], "pending")
            finalized = store.finalize_pending(now=time.time() + ind_token.FINALITY_BUFFER_SECONDS + 1)
            self.assertIn(transferred["token_id"], finalized)
            self.assertEqual(store.get_token_record(transferred["token_id"])["status"], "settled")

    def test_transfer_does_not_finalize_before_buffer(self):
        issuer_private, issuer_public, _issuer_address = keypair()
        alice_private, alice_public, alice_address = keypair()
        bob_private, bob_public, bob_address = keypair()
        token = ind_token.make_genesis_token(8, alice_address, issuer_private, issuer_public)
        transferred = ind_token.create_transfer(token, alice_private, alice_public, bob_address)
        receipt = ind_token.create_receipt_announcement(transferred, bob_private, bob_public)

        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = temp_dir + "/ind_test.db"
            store = ind_token.INDLocalStore(db_path)
            store.ingest_message(ind_token.create_transfer_announcement(transferred))
            store.ingest_message(receipt)
            conn = sqlite3.connect(db_path)
            transfer_first_seen = conn.execute(
                "SELECT first_seen FROM transfers WHERE transfer_hash = ?",
                (ind_token.transfer_hash(transferred["history"][-1]),),
            ).fetchone()[0]
            conn.close()
            finalized = store.finalize_pending(now=transfer_first_seen + ind_token.FINALITY_BUFFER_SECONDS - 1)
            self.assertEqual(finalized, [])
            self.assertEqual(store.get_token_record(transferred["token_id"])["status"], "pending")

    def test_token_confidence_requires_local_settlement(self):
        issuer_private, issuer_public, _issuer_address = keypair()
        alice_private, alice_public, alice_address = keypair()
        bob_private, bob_public, bob_address = keypair()
        token = ind_token.make_genesis_token(801, alice_address, issuer_private, issuer_public)
        transferred = ind_token.create_transfer(token, alice_private, alice_public, bob_address)
        receipt = ind_token.create_receipt_announcement(transferred, bob_private, bob_public)

        with tempfile.TemporaryDirectory() as temp_dir:
            store = ind_token.INDLocalStore(temp_dir + "/ind_test.db")
            store.ingest_message(ind_token.create_transfer_announcement(transferred))
            confidence = store.token_confidence(transferred["token_id"], expected_owner=bob_address)
            self.assertFalse(confidence["accepted"])
            self.assertEqual(confidence["level"], "unreceipted")

            store.ingest_message(receipt)
            confidence = store.token_confidence(transferred["token_id"], expected_owner=bob_address)
            self.assertFalse(confidence["accepted"])
            self.assertEqual(confidence["level"], "pending")

            finalized_at = int(time.time()) + ind_token.FINALITY_BUFFER_SECONDS + 1
            store.finalize_pending(now=finalized_at)
            confidence = store.token_confidence(
                transferred["token_id"],
                expected_owner=bob_address,
                now=finalized_at + ind_token.FINALITY_BUFFER_SECONDS + 1,
            )
            self.assertTrue(confidence["accepted"])
            self.assertEqual(confidence["level"], "strong_local")
            self.assertEqual(confidence["sequence"], 1)

    def test_token_confidence_reports_fresh_settlement_and_wrong_owner(self):
        issuer_private, issuer_public, _issuer_address = keypair()
        alice_private, alice_public, alice_address = keypair()
        bob_private, bob_public, bob_address = keypair()
        _carol_private, _carol_public, carol_address = keypair()
        token = ind_token.make_genesis_token(802, alice_address, issuer_private, issuer_public)
        transferred = ind_token.create_transfer(token, alice_private, alice_public, bob_address)
        receipt = ind_token.create_receipt_announcement(transferred, bob_private, bob_public)

        with tempfile.TemporaryDirectory() as temp_dir:
            store = ind_token.INDLocalStore(temp_dir + "/ind_test.db")
            store.ingest_message(ind_token.create_transfer_announcement(transferred))
            store.ingest_message(receipt)
            finalized_at = int(time.time()) + ind_token.FINALITY_BUFFER_SECONDS + 1
            store.finalize_pending(now=finalized_at)

            confidence = store.token_confidence(transferred["token_id"], expected_owner=bob_address, now=finalized_at)
            self.assertFalse(confidence["accepted"])
            self.assertEqual(confidence["level"], "settled_fresh")

            confidence = store.token_confidence(
                transferred["token_id"],
                expected_owner=carol_address,
                now=finalized_at + ind_token.FINALITY_BUFFER_SECONDS + 1,
            )
            self.assertFalse(confidence["accepted"])
            self.assertEqual(confidence["level"], "wrong_owner")

    def test_token_confidence_conflict_takes_priority(self):
        issuer_private, issuer_public, _issuer_address = keypair()
        alice_private, alice_public, alice_address = keypair()
        _bob_private, _bob_public, bob_address = keypair()
        _carol_private, _carol_public, carol_address = keypair()
        _dave_private, _dave_public, dave_address = keypair()
        token = ind_token.make_genesis_token(803, alice_address, issuer_private, issuer_public)
        transfer_a = ind_token.create_transfer(token, alice_private, alice_public, bob_address)
        transfer_b = ind_token.create_transfer(token, alice_private, alice_public, carol_address)

        with tempfile.TemporaryDirectory() as temp_dir:
            store = ind_token.INDLocalStore(temp_dir + "/ind_test.db")
            store.ingest_message(ind_token.create_transfer_announcement(transfer_a))
            store.ingest_message(ind_token.create_transfer_announcement(transfer_b))
            confidence = store.token_confidence(transfer_a["token_id"], expected_owner=dave_address)
            self.assertFalse(confidence["accepted"])
            self.assertEqual(confidence["level"], "conflict")

    def test_conflicting_transfers_generate_verifiable_proof(self):
        issuer_private, issuer_public, _issuer_address = keypair()
        alice_private, alice_public, alice_address = keypair()
        _bob_private, _bob_public, bob_address = keypair()
        _carol_private, _carol_public, carol_address = keypair()
        token = ind_token.make_genesis_token(9, alice_address, issuer_private, issuer_public)
        transfer_a = ind_token.create_transfer(token, alice_private, alice_public, bob_address)
        transfer_b = ind_token.create_transfer(token, alice_private, alice_public, carol_address)

        with tempfile.TemporaryDirectory() as temp_dir:
            store = ind_token.INDLocalStore(temp_dir + "/ind_test.db")
            store.ingest_message(ind_token.create_transfer_announcement(transfer_a))
            result = store.ingest_message(ind_token.create_transfer_announcement(transfer_b))
            self.assertEqual(result["status"], "conflict")
            self.assertTrue(ind_token.verify_conflict_proof(result["conflict_proof"]))
            self.assertEqual(store.get_token_record(transfer_a["token_id"])["status"], "invalid")

    def test_conflict_detection_after_rebuilt_history(self):
        issuer_private, issuer_public, _issuer_address = keypair()
        alice_private, alice_public, alice_address = keypair()
        bob_private, bob_public, bob_address = keypair()
        _carol_private, _carol_public, carol_address = keypair()
        _dave_private, _dave_public, dave_address = keypair()

        token = ind_token.make_genesis_token(10, alice_address, issuer_private, issuer_public)
        token = ind_token.create_transfer(token, alice_private, alice_public, bob_address)
        transfer_a = ind_token.create_transfer(token, bob_private, bob_public, carol_address)
        transfer_b = ind_token.create_transfer(token, bob_private, bob_public, dave_address)

        with tempfile.TemporaryDirectory() as temp_dir:
            store = ind_token.INDLocalStore(temp_dir + "/ind_test.db")
            store.ingest_message(ind_token.create_transfer_announcement(transfer_a))
            result = store.ingest_message(ind_token.create_transfer_announcement(transfer_b))
            self.assertEqual(result["status"], "conflict")
            self.assertTrue(ind_token.verify_conflict_proof(result["conflict_proof"]))

    def test_store_decomposes_history_and_rebuilds_token(self):
        issuer_private, issuer_public, _issuer_address = keypair()
        alice_private, alice_public, alice_address = keypair()
        bob_private, bob_public, bob_address = keypair()
        carol_private, carol_public, carol_address = keypair()
        dave_private, dave_public, dave_address = keypair()

        token = ind_token.make_genesis_token(11, alice_address, issuer_private, issuer_public)
        token = ind_token.create_transfer(token, alice_private, alice_public, bob_address)
        token = ind_token.create_transfer(token, bob_private, bob_public, carol_address)
        token = ind_token.create_transfer(token, carol_private, carol_public, dave_address)

        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = temp_dir + "/ind_test.db"
            store = ind_token.INDLocalStore(db_path)
            store.ingest_message(ind_token.create_transfer_announcement(token))
            store.ingest_message(ind_token.create_receipt_announcement(token, dave_private, dave_public))

            rebuilt = store.get_token(token["token_id"])
            state = ind_token.verify_token(rebuilt)
            self.assertEqual(state.sequence, 3)
            self.assertEqual(state.owner_address, dave_address)

            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            token_payload = conn.execute("SELECT payload FROM tokens WHERE token_id = ?", (token["token_id"],)).fetchone()["payload"]
            transfer_payloads = conn.execute("SELECT token_payload FROM transfers").fetchall()
            message_payloads = conn.execute("SELECT message_json FROM messages").fetchall()
            conn.close()

            token_ref = ind_token._load_json(token_payload)
            self.assertEqual(token_ref["type"], ind_token.TOKEN_STATE_REF_TYPE)
            self.assertNotIn("history", token_ref)
            for row in transfer_payloads:
                transfer_ref = ind_token._load_json(row["token_payload"])
                self.assertEqual(transfer_ref["type"], ind_token.TOKEN_STATE_REF_TYPE)
                self.assertNotIn("history", transfer_ref)
            for row in message_payloads:
                message_ref = ind_token._load_json(row["message_json"])
                self.assertEqual(message_ref["type"], ind_token.STORED_MESSAGE_REF_TYPE)
                self.assertNotIn("token", message_ref)

    def test_packed_wire_message_round_trips(self):
        issuer_private, issuer_public, _issuer_address = keypair()
        alice_private, alice_public, alice_address = keypair()
        _bob_private, _bob_public, bob_address = keypair()
        token = ind_token.make_genesis_token(12, alice_address, issuer_private, issuer_public)
        transferred = ind_token.create_transfer(token, alice_private, alice_public, bob_address)
        message = ind_token.create_transfer_announcement(transferred)

        packed = ind_token.pack_wire_message(message)
        self.assertTrue(packed.startswith(ind_token.WIRE_PACKED_PREFIX))
        unpacked = ind_token.unpack_wire_message(packed)
        self.assertEqual(unpacked, message)

        with tempfile.TemporaryDirectory() as temp_dir:
            store = ind_token.INDLocalStore(temp_dir + "/ind_test.db")
            result = store.ingest_wire_message(packed)
            self.assertTrue(result["accepted"])

    def test_plain_json_wire_message_still_ingests(self):
        issuer_private, issuer_public, _issuer_address = keypair()
        alice_private, alice_public, alice_address = keypair()
        _bob_private, _bob_public, bob_address = keypair()
        token = ind_token.make_genesis_token(13, alice_address, issuer_private, issuer_public)
        transferred = ind_token.create_transfer(token, alice_private, alice_public, bob_address)
        message = ind_token.create_transfer_announcement(transferred)

        with tempfile.TemporaryDirectory() as temp_dir:
            store = ind_token.INDLocalStore(temp_dir + "/ind_test.db")
            result = store.ingest_wire_message(ind_token.canonical_json(message))
            self.assertTrue(result["accepted"])

    def test_malformed_receipt_is_rejected(self):
        issuer_private, issuer_public, _issuer_address = keypair()
        alice_private, alice_public, alice_address = keypair()
        bob_private, bob_public, bob_address = keypair()
        mallory_private, mallory_public, _mallory_address = keypair()
        token = ind_token.make_genesis_token(14, alice_address, issuer_private, issuer_public)
        transferred = ind_token.create_transfer(token, alice_private, alice_public, bob_address)

        with self.assertRaises(ind_token.ValidationError):
            ind_token.create_receipt_announcement(transferred, mallory_private, mallory_public)

    def test_receipt_timestamp_must_be_sane(self):
        issuer_private, issuer_public, _issuer_address = keypair()
        alice_private, alice_public, alice_address = keypair()
        bob_private, bob_public, bob_address = keypair()
        token = ind_token.make_genesis_token(142, alice_address, issuer_private, issuer_public)
        transferred = ind_token.create_transfer(token, alice_private, alice_public, bob_address)
        tip_timestamp = transferred["history"][-1]["timestamp"]

        with self.assertRaisesRegex(ind_token.ValidationError, "predates transfer"):
            ind_token.create_receipt(
                transferred,
                bob_private,
                bob_public,
                timestamp=tip_timestamp - 1,
            )

        with self.assertRaisesRegex(ind_token.ValidationError, "future"):
            ind_token.create_receipt(
                transferred,
                bob_private,
                bob_public,
                timestamp=int(time.time()) + ind_token.MAX_TRANSFER_FUTURE_SKEW_SECONDS + 60,
            )

    def test_genesis_requires_trusted_key_or_explicit_test_override(self):
        issuer_private, issuer_public, _issuer_address = keypair()
        _alice_private, _alice_public, alice_address = keypair()
        token = ind_token.make_genesis_token(141, alice_address, issuer_private, issuer_public)

        with temporary_env(IND_ALLOW_UNTRUSTED_GENESIS=None, IND_TRUSTED_GENESIS_ISSUER_KEYS=None):
            with self.assertRaisesRegex(ind_token.ValidationError, "no trusted genesis"):
                ind_token.verify_token(token)

        with temporary_env(IND_ALLOW_UNTRUSTED_GENESIS=None, IND_TRUSTED_GENESIS_ISSUER_KEYS=issuer_public):
            self.assertEqual(ind_token.verify_token(token).owner_address, alice_address)

        with temporary_env(IND_ALLOW_UNTRUSTED_GENESIS="1", IND_TRUSTED_GENESIS_ISSUER_KEYS=None):
            self.assertEqual(ind_token.verify_token(token).owner_address, alice_address)

    def test_lazy_genesis_manifest_mints_verifiable_tokens_without_materializing_supply(self):
        issuer_private, issuer_public, _issuer_address = keypair()
        _owner_private, _owner_public, owner_address = keypair()
        ranges = ind_token.make_denomination_ranges(
            [(1, 10_000_000_000), (2, 10_000_000_000), (5, 10_000_000_000)],
            owner_address,
        )
        manifest = ind_token.make_genesis_manifest(
            ranges,
            issuer_private,
            issuer_public,
            issued_at=1_700_000_000,
            metadata={"project": "IND-test"},
        )

        token = ind_token.make_lazy_genesis_token(20_000_000_123, manifest)
        state = ind_token.verify_token(token, now=1_700_000_001)

        self.assertEqual(state.owner_address, owner_address)
        self.assertEqual(state.value, 5)
        self.assertEqual(manifest["total_token_count"], 30_000_000_000)
        self.assertEqual(manifest["metadata"][ind_token.NUMEROLOGY_METADATA_KEY]["angel_number"], 777)
        self.assertLess(len(ind_token.canonical_json(manifest)), 2500)

    def test_lazy_genesis_can_be_trusted_by_manifest_hash(self):
        issuer_private, issuer_public, _issuer_address = keypair()
        _owner_private, _owner_public, owner_address = keypair()
        manifest = ind_token.make_genesis_manifest(
            ind_token.make_denomination_ranges([(1, ind_token.TOTAL_SUPPLY)], owner_address),
            issuer_private,
            issuer_public,
            issued_at=1_700_000_000,
        )
        manifest_hash = ind_token.genesis_manifest_hash(manifest)
        token = ind_token.make_lazy_genesis_token(ind_token.TOTAL_SUPPLY - 1, manifest)

        with temporary_env(
            IND_ALLOW_UNTRUSTED_GENESIS=None,
            IND_TRUSTED_GENESIS_ISSUER_KEYS=None,
            IND_TRUSTED_GENESIS_MANIFEST_HASHES=manifest_hash,
        ):
            self.assertEqual(ind_token.verify_token(token, now=1_700_000_001).owner_address, owner_address)

        with temporary_env(
            IND_ALLOW_UNTRUSTED_GENESIS=None,
            IND_TRUSTED_GENESIS_ISSUER_KEYS=None,
            IND_TRUSTED_GENESIS_MANIFEST_HASHES="badmanifesthash",
        ):
            with self.assertRaisesRegex(ind_token.ValidationError, "manifest hash"):
                ind_token.verify_token(token, now=1_700_000_001)

    def test_lazy_genesis_tampering_is_rejected(self):
        issuer_private, issuer_public, _issuer_address = keypair()
        _owner_private, _owner_public, owner_address = keypair()
        manifest = ind_token.make_genesis_manifest(
            ind_token.make_denomination_ranges([(1, 100)], owner_address),
            issuer_private,
            issuer_public,
            issued_at=1_700_000_000,
        )
        token = ind_token.make_lazy_genesis_token(7, manifest)

        token["genesis"]["value"] = 2

        with self.assertRaisesRegex(ind_token.ValidationError, "commitment"):
            ind_token.verify_token(token, now=1_700_000_001)

    def test_store_deduplicates_lazy_genesis_manifest(self):
        issuer_private, issuer_public, _issuer_address = keypair()
        owner_private, owner_public, owner_address = keypair()
        bob_private, bob_public, bob_address = keypair()
        manifest = ind_token.make_genesis_manifest(
            ind_token.make_denomination_ranges([(1, 100)], owner_address),
            issuer_private,
            issuer_public,
            issued_at=1_700_000_000,
        )
        token_a = ind_token.make_lazy_genesis_token(1, manifest)
        token_b = ind_token.make_lazy_genesis_token(2, manifest)
        token_a = ind_token.create_transfer(token_a, owner_private, owner_public, bob_address, timestamp=1_700_000_001)
        token_b = ind_token.create_transfer(token_b, owner_private, owner_public, bob_address, timestamp=1_700_000_001)

        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = temp_dir + "/ind_test.db"
            store = ind_token.INDLocalStore(db_path)
            store.ingest_message(ind_token.create_transfer_announcement(token_a))
            store.ingest_message(ind_token.create_transfer_announcement(token_b))
            store.ingest_message(ind_token.create_receipt_announcement(token_a, bob_private, bob_public))

            rebuilt = store.get_token(token_a["token_id"])
            self.assertEqual(ind_token.verify_token(rebuilt, now=1_700_000_002).owner_address, bob_address)

            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            manifest_count = conn.execute("SELECT COUNT(*) FROM genesis_manifests").fetchone()[0]
            compact_genesis = ind_token._load_json(
                conn.execute(
                    "SELECT genesis_json FROM token_genesis WHERE token_id = ?",
                    (token_a["token_id"],),
                ).fetchone()["genesis_json"]
            )
            conn.close()

            self.assertEqual(manifest_count, 1)
            self.assertNotIn("manifest", compact_genesis["manifest_ref"])

    def test_daily_transfer_limit_allows_100_rejects_101(self):
        issuer_private, issuer_public, _issuer_address = keypair()
        keys = [keypair(), keypair()]
        base_timestamp = 1_700_000_000
        token = ind_token.make_genesis_token(15, keys[0][2], issuer_private, issuer_public, issued_at=base_timestamp)

        for index in range(ind_token.MAX_TRANSFERS_PER_TOKEN_PER_DAY):
            sender = keys[index % 2]
            recipient = keys[1 - (index % 2)][2]
            append_signed_transfer(token, sender[0], sender[1], recipient, base_timestamp + index)
        self.assertEqual(ind_token.verify_token(token).sequence, ind_token.MAX_TRANSFERS_PER_TOKEN_PER_DAY)

        sender = keys[ind_token.MAX_TRANSFERS_PER_TOKEN_PER_DAY % 2]
        recipient = keys[1 - (ind_token.MAX_TRANSFERS_PER_TOKEN_PER_DAY % 2)][2]
        append_signed_transfer(
            token,
            sender[0],
            sender[1],
            recipient,
            base_timestamp + ind_token.MAX_TRANSFERS_PER_TOKEN_PER_DAY,
        )
        with self.assertRaisesRegex(ind_token.ValidationError, "daily transfer limit"):
            ind_token.verify_token(token)

    def test_next_day_transfer_after_daily_limit_is_valid(self):
        issuer_private, issuer_public, _issuer_address = keypair()
        keys = [keypair(), keypair()]
        base_timestamp = 1_700_000_000
        token = ind_token.make_genesis_token(16, keys[0][2], issuer_private, issuer_public, issued_at=base_timestamp)

        for index in range(ind_token.MAX_TRANSFERS_PER_TOKEN_PER_DAY):
            sender = keys[index % 2]
            recipient = keys[1 - (index % 2)][2]
            append_signed_transfer(token, sender[0], sender[1], recipient, base_timestamp + index)
        sender = keys[ind_token.MAX_TRANSFERS_PER_TOKEN_PER_DAY % 2]
        recipient = keys[1 - (ind_token.MAX_TRANSFERS_PER_TOKEN_PER_DAY % 2)][2]
        next_day = ((base_timestamp // 86400) + 1) * 86400
        append_signed_transfer(token, sender[0], sender[1], recipient, next_day)
        self.assertEqual(ind_token.verify_token(token).sequence, ind_token.MAX_TRANSFERS_PER_TOKEN_PER_DAY + 1)

    def test_non_increasing_transfer_timestamp_is_rejected(self):
        issuer_private, issuer_public, _issuer_address = keypair()
        keys = [keypair(), keypair()]
        base_timestamp = 1_700_000_000
        token = ind_token.make_genesis_token(17, keys[0][2], issuer_private, issuer_public, issued_at=base_timestamp)
        append_signed_transfer(token, keys[0][0], keys[0][1], keys[1][2], base_timestamp)
        append_signed_transfer(token, keys[1][0], keys[1][1], keys[0][2], base_timestamp)

        with self.assertRaisesRegex(ind_token.ValidationError, "strictly increasing"):
            ind_token.verify_token(token)

    def test_far_future_transfer_timestamp_is_rejected(self):
        issuer_private, issuer_public, _issuer_address = keypair()
        alice_private, alice_public, alice_address = keypair()
        _bob_private, _bob_public, bob_address = keypair()
        token = ind_token.make_genesis_token(18, alice_address, issuer_private, issuer_public)
        future_timestamp = int(time.time()) + ind_token.MAX_TRANSFER_FUTURE_SKEW_SECONDS + 60

        with self.assertRaisesRegex(ind_token.ValidationError, "future"):
            ind_token.create_transfer(token, alice_private, alice_public, bob_address, timestamp=future_timestamp)

    def test_transfer_timestamp_before_genesis_is_rejected(self):
        issuer_private, issuer_public, _issuer_address = keypair()
        keys = [keypair(), keypair()]
        issued_at = 1_700_000_100
        token = ind_token.make_genesis_token(19, keys[0][2], issuer_private, issuer_public, issued_at=issued_at)
        append_signed_transfer(token, keys[0][0], keys[0][1], keys[1][2], issued_at - 1)

        with self.assertRaisesRegex(ind_token.ValidationError, "predates genesis"):
            ind_token.verify_token(token)

    def test_large_transfer_metadata_is_rejected(self):
        issuer_private, issuer_public, _issuer_address = keypair()
        alice_private, alice_public, alice_address = keypair()
        _bob_private, _bob_public, bob_address = keypair()
        token = ind_token.make_genesis_token(20, alice_address, issuer_private, issuer_public)
        metadata = {"blob": "x" * (ind_token.MAX_TRANSFER_METADATA_BYTES + 1)}

        with self.assertRaisesRegex(ind_token.ValidationError, "metadata"):
            ind_token.create_transfer(token, alice_private, alice_public, bob_address, metadata=metadata)

    def test_large_genesis_metadata_is_rejected(self):
        issuer_private, issuer_public, _issuer_address = keypair()
        _alice_private, _alice_public, alice_address = keypair()
        metadata = {"blob": "x" * (ind_token.MAX_GENESIS_METADATA_BYTES + 1)}

        with self.assertRaisesRegex(ind_token.ValidationError, "metadata"):
            ind_token.make_genesis_token(21, alice_address, issuer_private, issuer_public, metadata=metadata)

    def test_stale_transfer_announcement_does_not_roll_back_tip(self):
        issuer_private, issuer_public, _issuer_address = keypair()
        alice_private, alice_public, alice_address = keypair()
        bob_private, bob_public, bob_address = keypair()
        _carol_private, _carol_public, carol_address = keypair()
        token = ind_token.make_genesis_token(22, alice_address, issuer_private, issuer_public)
        transfer_1 = ind_token.create_transfer(token, alice_private, alice_public, bob_address)
        transfer_2 = ind_token.create_transfer(transfer_1, bob_private, bob_public, carol_address)

        with tempfile.TemporaryDirectory() as temp_dir:
            store = ind_token.INDLocalStore(temp_dir + "/ind_test.db")
            store.ingest_message(ind_token.create_transfer_announcement(transfer_2))
            state = ind_token.verify_token(store.get_token(transfer_2["token_id"]))
            self.assertEqual(state.sequence, 2)
            self.assertEqual(state.owner_address, carol_address)

            store.ingest_message(ind_token.create_transfer_announcement(transfer_1))
            state = ind_token.verify_token(store.get_token(transfer_2["token_id"]))
            self.assertEqual(state.sequence, 2)
            self.assertEqual(state.owner_address, carol_address)

    def test_packed_wire_decompression_bomb_is_rejected(self):
        raw = b"x" * (ind_token.MAX_WIRE_DECOMPRESSED_BYTES + 1)
        packed = ind_token.WIRE_PACKED_PREFIX + base64.b85encode(zlib.compress(raw, level=9)).decode("utf-8")

        with self.assertRaisesRegex(ind_token.ValidationError, "safety limit"):
            ind_token.unpack_wire_message(packed)

    def test_peer_rate_limiter_blocks_after_limit(self):
        limiter = node_client.PeerRateLimiter(window_seconds=60)
        self.assertTrue(limiter.allow("203.0.113.1", "gossip", 2, now=100))
        self.assertTrue(limiter.allow("203.0.113.1", "gossip", 2, now=101))
        self.assertFalse(limiter.allow("203.0.113.1", "gossip", 2, now=102))
        self.assertTrue(limiter.allow("203.0.113.1", "gossip", 2, now=200))

    def test_peer_tracking_and_seen_sets_are_bounded(self):
        limiter = node_client.PeerRateLimiter(window_seconds=60, max_entries=2)
        self.assertTrue(limiter.allow("203.0.113.1", "gossip", 10, now=100))
        self.assertTrue(limiter.allow("203.0.113.2", "gossip", 10, now=101))
        self.assertTrue(limiter.allow("203.0.113.3", "gossip", 10, now=102))
        self.assertLessEqual(len(limiter.events), 2)

        penalties = node_client.PeerPenaltyBook(max_entries=2)
        penalties.penalize("203.0.113.1", now=100)
        penalties.penalize("203.0.113.2", now=101)
        penalties.penalize("203.0.113.3", now=102)
        self.assertLessEqual(len(penalties.scores), 2)

        seen = node_client.BoundedSeenSet(limit=2)
        self.assertTrue(seen.add("a"))
        self.assertFalse(seen.add("a"))
        self.assertTrue(seen.add("b"))
        self.assertTrue(seen.add("c"))
        self.assertEqual(len(seen), 2)
        self.assertTrue(seen.add("a"))

    def test_gossip_pool_append_is_unique_and_bounded(self):
        pool = []
        self.assertTrue(node_client.append_unique_gossip(pool, "a", limit=2))
        self.assertFalse(node_client.append_unique_gossip(pool, "a", limit=2))
        self.assertTrue(node_client.append_unique_gossip(pool, "b", limit=2))
        self.assertTrue(node_client.append_unique_gossip(pool, "c", limit=2))
        self.assertEqual(pool, ["b", "c"])

    def test_peer_discovery_rejects_non_global_ipv4(self):
        self.assertTrue(sender_node._valid_ipv4("8.8.8.8"))
        self.assertTrue(node_client._valid_ipv4("8.8.4.4"))
        for ip in ("127.0.0.1", "10.0.0.1", "192.168.1.2", "0.0.0.0", "224.0.0.1"):
            self.assertFalse(sender_node._valid_ipv4(ip))
            self.assertFalse(node_client._valid_ipv4(ip))

    def test_ind_transport_round_trips_and_pins_peer_key(self):
        old_private = ind_transport.NOISE_PRIVATE_KEY_PATH
        old_public = ind_transport.NOISE_PUBLIC_KEY_PATH
        old_peers = ind_transport.NOISE_PEER_KEY_DIR
        with tempfile.TemporaryDirectory() as temp_dir:
            ind_transport.NOISE_PRIVATE_KEY_PATH = Path(temp_dir) / "files/noise_private_key.json"
            ind_transport.NOISE_PUBLIC_KEY_PATH = Path(temp_dir) / "files/noise_public_key.json"
            ind_transport.NOISE_PEER_KEY_DIR = Path(temp_dir) / "files/noise_peers"
            client_sock, server_sock = socket.socketpair()
            requests = []

            def server():
                try:
                    first_packet = server_sock.recv(1024)
                    session = ind_transport.server_handshake(server_sock, first_packet)
                    requests.append(session.recv_text(server_sock, 1024))
                    session.send_text(server_sock, "ok", 1024)
                finally:
                    server_sock.close()

            thread = threading.Thread(target=server)
            thread.start()
            try:
                session = ind_transport.client_handshake(client_sock, peer_ip="8.8.8.8")
                session.send_text(client_sock, "bhello", 1024)
                self.assertEqual(session.recv_text(client_sock, 1024), "ok")
                self.assertEqual(requests, ["bhello"])
                with self.assertRaises(ind_transport.PeerKeyMismatch):
                    ind_transport.verify_or_pin_peer_key("8.8.8.8", b"\x01" * 32)
            finally:
                client_sock.close()
                thread.join(timeout=5)
                ind_transport.NOISE_PRIVATE_KEY_PATH = old_private
                ind_transport.NOISE_PUBLIC_KEY_PATH = old_public
                ind_transport.NOISE_PEER_KEY_DIR = old_peers


if __name__ == "__main__":
    unittest.main()
