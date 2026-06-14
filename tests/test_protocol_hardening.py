import base64
import copy
import os
import sqlite3
import tempfile
import unittest
from hashlib import sha3_256
from unittest import mock

import ecdsa
from ecdsa import util as ecdsa_util

import ind_token
from ind import node_client
from ind import protocol as protocol_impl
from ind import settings as ind_settings
from ind import store as ind_store
from ind import transparency_client as log_client


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
                with self.assertRaisesRegex(ind_token.ValidationError, "conflicting transfer rejected"):
                    store.ingest_message(ind_token.create_transfer_announcement(branch_b, now=1_700_000_033))
                messages = store.conflict_messages(limit=10)

            proof = ind_token.create_conflict_proof(branch_a, branch_b, detected_at=1_700_000_034)
            self.assertEqual(proof["sequence"], 2)
            self.assertTrue(ind_token.verify_conflict_proof(proof))
            self.assertEqual(messages, [])

    def test_conflict_proof_ingest_persists_status_and_rebroadcast_evidence(self):
        issuer_private, issuer_public, _issuer_address = keypair()
        faucet_private, faucet_public, faucet_address = keypair()
        _alice_private, _alice_public, alice_address = keypair()
        _bob_private, _bob_public, bob_address = keypair()

        with temporary_env(IND_ALLOW_UNTRUSTED_GENESIS="1"):
            token = ind_token.make_genesis_token(
                1010,
                faucet_address,
                issuer_private,
                issuer_public,
                issued_at=1_700_000_000,
            )
            branch_a = ind_token.create_transfer(
                token,
                faucet_private,
                faucet_public,
                alice_address,
                timestamp=1_700_000_010,
            )
            branch_b = ind_token.create_transfer(
                token,
                faucet_private,
                faucet_public,
                bob_address,
                timestamp=1_700_000_011,
            )
            proof = ind_token.create_conflict_proof(branch_a, branch_b, detected_at=1_700_000_012)
            display_id = ind_token.verify_token(branch_a).display_id
            with tempfile.TemporaryDirectory() as temp_dir:
                db_path = temp_dir + "/ind.db"
                store = ind_token.INDLocalStore(db_path)
                result = store.ingest_message(proof)

                reopened = ind_token.INDLocalStore(db_path)
                status = reopened.status_record_for_ref(display_id)
                messages = reopened.conflict_messages(limit=10)

        self.assertEqual(result["status"], "conflict")
        self.assertIsNone(status)
        self.assertEqual(messages[0]["proof_hash"], proof["proof_hash"])

    def test_conflict_proof_key_ignores_detected_at(self):
        issuer_private, issuer_public, _issuer_address = keypair()
        faucet_private, faucet_public, faucet_address = keypair()
        _alice_private, _alice_public, alice_address = keypair()
        _bob_private, _bob_public, bob_address = keypair()

        with temporary_env(IND_ALLOW_UNTRUSTED_GENESIS="1"):
            token = ind_token.make_genesis_token(
                1012,
                faucet_address,
                issuer_private,
                issuer_public,
                issued_at=1_700_000_000,
            )
            branch_a = ind_token.create_transfer(
                token,
                faucet_private,
                faucet_public,
                alice_address,
                timestamp=1_700_000_010,
            )
            branch_b = ind_token.create_transfer(
                token,
                faucet_private,
                faucet_public,
                bob_address,
                timestamp=1_700_000_011,
            )
            early = ind_token.create_conflict_proof(branch_a, branch_b, detected_at=1_700_000_020)
            late = ind_token.create_conflict_proof(branch_a, branch_b, detected_at=1_700_000_999)

        self.assertNotEqual(early["proof_hash"], late["proof_hash"])
        self.assertEqual(ind_token.conflict_proof_key(early), ind_token.conflict_proof_key(late))

    def test_conflict_proof_ingest_dedupes_detected_at_variants(self):
        issuer_private, issuer_public, _issuer_address = keypair()
        faucet_private, faucet_public, faucet_address = keypair()
        _alice_private, _alice_public, alice_address = keypair()
        _bob_private, _bob_public, bob_address = keypair()

        with temporary_env(IND_ALLOW_UNTRUSTED_GENESIS="1"):
            token = ind_token.make_genesis_token(
                1013,
                faucet_address,
                issuer_private,
                issuer_public,
                issued_at=1_700_000_000,
            )
            branch_a = ind_token.create_transfer(
                token,
                faucet_private,
                faucet_public,
                alice_address,
                timestamp=1_700_000_010,
            )
            branch_b = ind_token.create_transfer(
                token,
                faucet_private,
                faucet_public,
                bob_address,
                timestamp=1_700_000_011,
            )
            proof_a = ind_token.create_conflict_proof(branch_a, branch_b, detected_at=1_700_000_020)
            proof_b = ind_token.create_conflict_proof(branch_a, branch_b, detected_at=1_700_000_999)

            with tempfile.TemporaryDirectory() as temp_dir:
                db_path = temp_dir + "/ind.db"
                store = ind_token.INDLocalStore(db_path)
                first = store.ingest_message(proof_a)
                second = store.ingest_message(proof_b)
                messages = store.conflict_messages(limit=10)
                conn = sqlite3.connect(db_path)
                try:
                    count, distinct_count = conn.execute(
                        "SELECT COUNT(*), COUNT(DISTINCT conflict_key) FROM conflicts"
                    ).fetchone()
                finally:
                    conn.close()

        self.assertTrue(first["accepted"])
        self.assertTrue(second["accepted"])
        self.assertFalse(second["relay"])
        self.assertTrue(second["duplicate_conflict"])
        self.assertNotIn("conflict_proof", second)
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]["proof_hash"], proof_a["proof_hash"])
        self.assertEqual(count, 1)
        self.assertEqual(distinct_count, 1)

    def test_conflict_key_migration_dedupes_legacy_rows(self):
        issuer_private, issuer_public, _issuer_address = keypair()
        faucet_private, faucet_public, faucet_address = keypair()
        _alice_private, _alice_public, alice_address = keypair()
        _bob_private, _bob_public, bob_address = keypair()

        with temporary_env(IND_ALLOW_UNTRUSTED_GENESIS="1"):
            token = ind_token.make_genesis_token(
                1014,
                faucet_address,
                issuer_private,
                issuer_public,
                issued_at=1_700_000_000,
            )
            branch_a = ind_token.create_transfer(
                token,
                faucet_private,
                faucet_public,
                alice_address,
                timestamp=1_700_000_010,
            )
            branch_b = ind_token.create_transfer(
                token,
                faucet_private,
                faucet_public,
                bob_address,
                timestamp=1_700_000_011,
            )
            proof_a = ind_token.create_conflict_proof(branch_a, branch_b, detected_at=1_700_000_020)
            proof_b = ind_token.create_conflict_proof(branch_a, branch_b, detected_at=1_700_000_999)

            with tempfile.TemporaryDirectory() as temp_dir:
                db_path = temp_dir + "/ind.db"
                conn = sqlite3.connect(db_path)
                try:
                    conn.executescript(
                        """
                        CREATE TABLE conflicts (
                            proof_hash TEXT PRIMARY KEY,
                            token_id TEXT NOT NULL,
                            previous_hash TEXT NOT NULL,
                            proof_json TEXT NOT NULL,
                            detected_at INTEGER NOT NULL
                        );
                        PRAGMA user_version=2;
                        """
                    )
                    conn.execute(
                        """
                        INSERT INTO conflicts(proof_hash, token_id, previous_hash, proof_json, detected_at)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            proof_a["proof_hash"],
                            proof_a["token_id"],
                            proof_a["previous_hash"],
                            ind_token._store_json(proof_a),
                            1_700_000_020,
                        ),
                    )
                    conn.execute(
                        """
                        INSERT INTO conflicts(proof_hash, token_id, previous_hash, proof_json, detected_at)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            proof_b["proof_hash"],
                            proof_b["token_id"],
                            proof_b["previous_hash"],
                            ind_token._store_json(proof_b),
                            1_700_000_999,
                        ),
                    )
                    conn.commit()
                finally:
                    conn.close()

                store = ind_token.INDLocalStore(db_path)
                messages = store.conflict_messages(limit=10)
                conn = sqlite3.connect(db_path)
                try:
                    count, distinct_count = conn.execute(
                        "SELECT COUNT(*), COUNT(DISTINCT conflict_key) FROM conflicts"
                    ).fetchone()
                    user_version = conn.execute("PRAGMA user_version").fetchone()[0]
                finally:
                    conn.close()

        self.assertEqual(len(messages), 1)
        self.assertEqual(count, 1)
        self.assertEqual(distinct_count, 1)
        self.assertEqual(user_version, ind_store.STORE_SCHEMA_VERSION)

    def test_conflicting_transfer_skips_transparency_submission(self):
        issuer_private, issuer_public, _issuer_address = keypair()
        faucet_private, faucet_public, faucet_address = keypair()
        _alice_private, _alice_public, alice_address = keypair()
        _bob_private, _bob_public, bob_address = keypair()

        class CountingSubmitter:
            def __init__(self):
                self.calls = []

            def submit_transfer_announcement(self, message):
                self.calls.append(message)
                return {"accepted": False}

        with temporary_env(IND_ALLOW_UNTRUSTED_GENESIS="1", IND_REQUIRE_TRANSPARENCY_LOG="0"):
            token = ind_token.make_genesis_token(
                1015,
                faucet_address,
                issuer_private,
                issuer_public,
                issued_at=1_700_000_000,
            )
            branch_a = ind_token.create_transfer(
                token,
                faucet_private,
                faucet_public,
                alice_address,
                timestamp=1_700_000_010,
            )
            branch_b = ind_token.create_transfer(
                token,
                faucet_private,
                faucet_public,
                bob_address,
                timestamp=1_700_000_011,
            )
            submitter = CountingSubmitter()
            with tempfile.TemporaryDirectory() as temp_dir:
                store = ind_token.INDLocalStore(
                    temp_dir + "/ind.db",
                    transparency_submitter=submitter,
                    require_transparency=False,
                )
                first = store.ingest_message(ind_token.create_transfer_announcement(branch_a, now=1_700_000_012))
                with self.assertRaisesRegex(ind_token.ValidationError, "conflicting transfer rejected"):
                    store.ingest_message(ind_token.create_transfer_announcement(branch_b, now=1_700_000_013))
                messages = store.conflict_messages(limit=10)

        self.assertEqual(first["status"], "unreceipted")
        self.assertEqual(messages, [])
        self.assertEqual(len(submitter.calls), 1)

    def test_invalid_gossip_is_not_marked_seen_before_store_validation(self):
        issuer_private, issuer_public, _issuer_address = keypair()
        alice_private, alice_public, alice_address = keypair()
        _bob_private, _bob_public, bob_address = keypair()

        with temporary_env(IND_ALLOW_UNTRUSTED_GENESIS="1"):
            token = ind_token.make_genesis_token(
                1011,
                alice_address,
                issuer_private,
                issuer_public,
                issued_at=1_700_000_000,
            )
            transferred = ind_token.create_transfer(
                token,
                alice_private,
                alice_public,
                bob_address,
                timestamp=1_700_000_010,
            )
            invalid_message = ind_token.create_transfer_announcement(transferred, now=1_700_000_011)
            invalid_message["unexpected"] = "poison"
            raw = ind_token.pack_wire_message(invalid_message)

            seen = node_client.BoundedSeenSet()
            rate_limiter = node_client.PeerRateLimiter()
            prepared = node_client.prepare_incoming_gossip("203.0.113.10", raw, seen, rate_limiter)

            with tempfile.TemporaryDirectory() as temp_dir:
                store = ind_token.INDLocalStore(temp_dir + "/ind.db")
                with self.assertRaisesRegex(ind_token.ValidationError, "unknown field"):
                    store.ingest_message(prepared["message"])

            self.assertTrue(prepared["accepted"])
            self.assertNotIn(prepared["message_hash"], seen)

    def test_oversized_compressed_gossip_returns_invalid_without_penalty(self):
        old_limit = protocol_impl.MAX_WIRE_COMPRESSED_BYTES
        protocol_impl.MAX_WIRE_COMPRESSED_BYTES = 8
        try:
            peer = "203.0.113.20"
            raw = ind_token.WIRE_PACKED_PREFIX + ("0" * 11)
            penalties = node_client.PeerPenaltyBook(threshold=1)

            response = node_client.handle_incoming_gossip(
                peer,
                raw,
                node_client.BoundedSeenSet(),
                node_client.PeerRateLimiter(),
                object(),
                [],
                penalties,
            )

            self.assertEqual(response, "invalid")
            self.assertTrue(penalties.allow(peer))
        finally:
            protocol_impl.MAX_WIRE_COMPRESSED_BYTES = old_limit

    def test_malformed_gossip_returns_invalid_and_penalizes_peer(self):
        peer = "203.0.113.21"
        penalties = node_client.PeerPenaltyBook(threshold=1)

        response = node_client.handle_incoming_gossip(
            peer,
            "not-json",
            node_client.BoundedSeenSet(),
            node_client.PeerRateLimiter(),
            object(),
            [],
            penalties,
        )

        self.assertEqual(response, "invalid")
        self.assertFalse(penalties.allow(peer))

    def test_valid_compressed_gossip_still_works(self):
        class AcceptingStore:
            def __init__(self):
                self.message = None
                self.peer_id = None

            def ingest_message(self, message, peer_id=None):
                self.message = message
                self.peer_id = peer_id
                return {"accepted": True}

        peer = "203.0.113.22"
        message = {"type": "test_gossip", "value": "ok"}
        raw = ind_token.pack_wire_message(message)
        seen = node_client.BoundedSeenSet()
        gossip_pool = []
        store = AcceptingStore()

        response = node_client.handle_incoming_gossip(
            peer,
            raw,
            seen,
            node_client.PeerRateLimiter(),
            store,
            gossip_pool,
            node_client.PeerPenaltyBook(),
        )

        self.assertEqual(response, "ok")
        self.assertEqual(store.message, message)
        self.assertEqual(store.peer_id, peer)
        self.assertEqual(len(gossip_pool), 1)
        self.assertEqual(ind_token.unpack_wire_message(gossip_pool[0]), message)

    def test_oversized_status_request_still_returns_too_many_refs(self):
        old_limit = node_client.MAX_STATUS_REFS_PER_REQUEST
        node_client.MAX_STATUS_REFS_PER_REQUEST = 2
        try:
            with mock.patch.object(node_client, "_status_lines_for_refs", return_value="ok") as status_lines:
                self.assertEqual(node_client._status_response_for_request("1x1\n1x2"), "ok")
                status_lines.assert_called_once_with(["1x1", "1x2"])
                self.assertEqual(node_client._status_response_for_request("1x1\n1x2\n1x3"), "too_many_refs")
        finally:
            node_client.MAX_STATUS_REFS_PER_REQUEST = old_limit

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
        self.assertEqual(user_version, ind_store.STORE_SCHEMA_VERSION)
        self.assertEqual(row[0], str(ind_store.STORE_SCHEMA_VERSION))

    def test_production_security_profile_requires_strict_trust_pins(self):
        unsafe = ind_settings.default_settings()
        unsafe["security_profile"] = "production"
        with self.assertRaisesRegex(ValueError, "production IND security settings are incomplete"):
            ind_settings.assert_production_security(unsafe)

        _operator_private, operator_public, _operator_address = keypair()
        _issuer_private, issuer_public, _issuer_address = keypair()
        strict = ind_settings.default_settings()
        strict.update(
            {
                "security_profile": "production",
                "require_transparency_log": True,
                "transparency_operator_url": "https://operator.example",
                "transparency_operator_public_key": operator_public,
                "trusted_root_mirrors": ["https://mirror-a.example", "https://mirror-b.example"],
                "transparency_proof_archives": ["https://archive-a.example"],
                "trusted_genesis_issuer_keys": [issuer_public],
            }
        )

        with temporary_env(
            IND_ALLOW_UNTRUSTED_GENESIS=None,
            IND_REQUIRE_TRANSPARENCY_LOG=None,
            IND_SUBMIT_TO_TRANSPARENCY_LOG=None,
        ):
            self.assertTrue(ind_settings.assert_production_security(strict))

        operator_settings = dict(strict)
        operator_settings["security_role"] = "operator"
        with temporary_env(
            IND_ALLOW_UNTRUSTED_GENESIS=None,
            IND_REQUIRE_TRANSPARENCY_LOG=None,
            IND_SUBMIT_TO_TRANSPARENCY_LOG=None,
        ):
            self.assertTrue(ind_settings.assert_production_security(operator_settings))

    def test_transparency_http_base_urls_reject_traversal_shapes(self):
        settings = ind_settings.normalize_security_settings(
            {
                "transparency_operator_url": "https://operator.example/operator/%2e%2e",
                "trusted_root_mirrors": [
                    "https://mirror.example/transparency",
                    "https://mirror.example/transparency/%252e%252e/banner",
                ],
                "transparency_proof_archives": [
                    "https://archive.example/operator-transparency",
                    "https://archive.example/operator-transparency/../banner",
                ],
            }
        )

        self.assertEqual(settings["transparency_operator_url"], "")
        self.assertEqual(settings["trusted_root_mirrors"], ["https://mirror.example/transparency"])
        self.assertEqual(settings["transparency_proof_archives"], ["https://archive.example/operator-transparency"])

        with self.assertRaisesRegex(log_client.TransparencyLogError, "unsafe transparency source URL"):
            log_client.HTTPTransparencyOperator("https://operator.example/operator/%2e%2e")

    def test_security_settings_malformed_json_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            settings_path = os.path.join(temp_dir, "security_settings.json")
            with open(settings_path, "w", encoding="utf-8") as handle:
                handle.write('{"security_profile": "production",')
            with self.assertRaisesRegex(ValueError, "invalid IND security settings JSON"):
                ind_settings.load_security_settings(settings_path)


if __name__ == "__main__":
    unittest.main()
