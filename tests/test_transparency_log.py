import base64
import copy
import functools
import http.server
import os
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from hashlib import sha3_256
from pathlib import Path
from unittest import mock

import ecdsa
import pytest

import ind_token
import log_client
import log_server
from ind import settings as ind_settings
from ind import store as ind_store
from ind import wallet_services

os.environ.setdefault("IND_ALLOW_UNTRUSTED_GENESIS", "1")
pytestmark = pytest.mark.skip(reason="archived V1/V2 bill protocol tests")


def keypair():
    signing_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1, hashfunc=sha3_256)
    verify_key = signing_key.get_verifying_key()
    private_key = base64.b85encode(signing_key.to_string()).decode("utf-8")
    public_key = base64.b85encode(verify_key.to_string()).decode("utf-8")
    return private_key, public_key, ind_token.address_from_public_key(public_key)


def signed_transfer_token(index=9001, timestamp=1_700_000_010):
    issuer_private, issuer_public, _issuer_address = keypair()
    alice_private, alice_public, alice_address = keypair()
    _bob_private, _bob_public, bob_address = keypair()
    token = ind_token.make_genesis_token(
        index,
        alice_address,
        issuer_private,
        issuer_public,
        issued_at=timestamp - 10,
    )
    return ind_token.create_transfer(
        token,
        alice_private,
        alice_public,
        bob_address,
        timestamp=timestamp,
    )


def independent_static_mirrors(root):
    return [
        log_client.StaticRootMirror([root], identity_id="test-root-mirror-a"),
        log_client.StaticRootMirror([root], identity_id="test-root-mirror-b"),
    ]


def in_memory_root_store():
    return log_client.InMemoryObservedRootStore()


class TransparencyLogTests(unittest.TestCase):
    def make_log(self, temp_dir):
        log_private, log_public, _log_address = keypair()
        return (
            log_server.TransparencyLog(temp_dir + "/log.db", log_private, log_public),
            log_private,
            log_public,
        )

    def test_empty_log_can_publish_initial_signed_root(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log, _log_private, log_public = self.make_log(temp_dir)

            root = log.publish_root(1_700_000_001)

            self.assertEqual(root["tree_size"], 0)
            self.assertEqual(root["root_hash"], log_client.LOG_EMPTY_ROOT_HASH)
            self.assertTrue(log_client.verify_signed_root(root, log_public))

    def test_roots_limit_returns_newest_roots_in_chronological_order(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log, _log_private, _log_public = self.make_log(temp_dir)
            published = [log.publish_root(1_700_000_000 + index) for index in range(5)]

            roots = log.roots(limit=2)

            self.assertEqual(
                [root["timestamp"] for root in roots],
                [published[-2]["timestamp"], published[-1]["timestamp"]],
            )

    def test_inclusion_proof_verifies_against_signed_root(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log, _log_private, log_public = self.make_log(temp_dir)
            entry_hash = ind_token.sha3_hex(b"entry")
            log.append_entry_hash(entry_hash)
            root = log.publish_root(1_700_000_060)

            proof = log.inclusion_proof(entry_hash, root["tree_size"])

            self.assertTrue(log_client.verify_inclusion_proof(entry_hash, proof, root, log_public))

    def test_new_signed_roots_use_ct_style_sha3_identifier(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log, _log_private, log_public = self.make_log(temp_dir)
            log.append_entry_hash(ind_token.sha3_hex(b"entry"))
            root = log.publish_root(1_700_000_060)

            self.assertEqual(root["tree_algorithm"], log_client.LOG_TREE_ALGORITHM)
            self.assertEqual(root["tree_algorithm"], "CT_STYLE_SHA3_256_V1")
            self.assertTrue(log_client.verify_signed_root(root, log_public))

    def test_legacy_tree_algorithm_identifier_verifies_only_when_enabled(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log, log_private, log_public = self.make_log(temp_dir)
            log.append_entry_hash(ind_token.sha3_hex(b"entry"))
            root = log.publish_root(1_700_000_060)
            legacy_root = copy.deepcopy(root)
            legacy_root["tree_algorithm"] = log_client.LEGACY_LOG_TREE_ALGORITHM
            legacy_root.pop("signature")
            legacy_root["signature"] = ind_token.b85_sign(
                log_private,
                log_client.root_signature_payload(legacy_root),
            )

            self.assertTrue(log_client.verify_signed_root(legacy_root, log_public))
            with (
                mock.patch.dict(
                    log_client.os.environ, {"IND_LOG_ACCEPT_LEGACY_ALGORITHM_NAMES": "0"}
                ),
                self.assertRaisesRegex(
                    log_client.RootVerificationError, "unsupported transparency tree algorithm"
                ),
            ):
                log_client.verify_signed_root(legacy_root, log_public)

    def test_unknown_tree_algorithm_identifier_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log, log_private, log_public = self.make_log(temp_dir)
            log.append_entry_hash(ind_token.sha3_hex(b"entry"))
            root = log.publish_root(1_700_000_060)
            forged_algorithm_root = copy.deepcopy(root)
            forged_algorithm_root["tree_algorithm"] = "RFC6962_SHA256_V1"
            forged_algorithm_root.pop("signature")
            forged_algorithm_root["signature"] = ind_token.b85_sign(
                log_private,
                log_client.root_signature_payload(forged_algorithm_root),
            )

            with self.assertRaisesRegex(
                log_client.RootVerificationError, "unsupported transparency tree algorithm"
            ):
                log_client.verify_signed_root(forged_algorithm_root, log_public)

    def test_consistency_proof_verifies_append_only_growth(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log, _log_private, log_public = self.make_log(temp_dir)
            log.append_entry_hash(ind_token.sha3_hex(b"first"))
            old_root = log.publish_root(1_700_000_060)
            log.append_entry_hash(ind_token.sha3_hex(b"second"))
            new_root = log.publish_root(1_700_000_120)

            proof = log.consistency_proof(old_root["tree_size"], new_root["tree_size"])

            self.assertTrue(
                log_client.verify_consistency_proof(old_root, new_root, proof, log_public)
            )

    def test_ind_token_validation_accepts_logged_history(self):
        token = signed_transfer_token(index=9002, timestamp=1_700_000_010)
        with tempfile.TemporaryDirectory() as temp_dir:
            log, _log_private, log_public = self.make_log(temp_dir)
            log.append_transfer_announcement(ind_token.create_transfer_announcement(token))
            root = log.publish_root(1_700_000_040)
            verifier = log_client.TransparencyVerifier(
                log_client.LocalTransparencyOperator(log),
                independent_static_mirrors(root),
                operator_public_key=log_public,
                max_root_lag_seconds=60,
                observed_root_store=in_memory_root_store(),
                run_startup_check=False,
            )

            state = ind_token.verify_token(token, transparency_verifier=verifier, now=1_700_000_050)

            self.assertEqual(state.sequence, 1)

    def test_history_verification_uses_root_that_contains_transfer_leaf(self):
        token = signed_transfer_token(index=9020, timestamp=1_700_000_010)
        with tempfile.TemporaryDirectory() as temp_dir:
            log, _log_private, log_public = self.make_log(temp_dir)
            log.append_entry_hash(ind_token.sha3_hex(b"unrelated-before-transfer"))
            early_root = log.publish_root(1_700_000_010)
            log.append_transfer_announcement(ind_token.create_transfer_announcement(token))
            later_root = log.publish_root(1_700_000_040)
            mirrors = [
                log_client.StaticRootMirror(
                    [early_root, later_root], identity_id="test-root-mirror-a"
                ),
                log_client.StaticRootMirror(
                    [early_root, later_root], identity_id="test-root-mirror-b"
                ),
            ]
            verifier = log_client.TransparencyVerifier(
                log_client.LocalTransparencyOperator(log),
                mirrors,
                operator_public_key=log_public,
                max_root_lag_seconds=60,
                observed_root_store=in_memory_root_store(),
                run_startup_check=False,
            )

            state = ind_token.verify_token(token, transparency_verifier=verifier, now=1_700_000_050)

            self.assertEqual(state.sequence, 1)

    def test_spend_key_is_token_state_not_sender_public_key(self):
        token = signed_transfer_token(index=9021, timestamp=1_700_000_010)
        transfer = token["history"][-1]
        mutated = copy.deepcopy(transfer)
        mutated["sender_public_key"] = "different-proof-key"

        self.assertEqual(
            log_client.spend_key_for_transfer(transfer),
            log_client.spend_key_for_transfer(mutated),
        )

    def test_transparency_schemas_reject_extra_fields_and_numeric_strings(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log, log_private, log_public = self.make_log(temp_dir)
            entry_hash = ind_token.sha3_hex(b"entry")
            log.append_entry_hash(entry_hash)
            root = log.publish_root(1_700_000_060)
            proof = log.inclusion_proof(entry_hash, root["tree_size"])

            extra_root = copy.deepcopy(root)
            extra_root["unknown"] = True
            with self.assertRaisesRegex(log_client.RootVerificationError, "unknown field"):
                log_client.verify_signed_root(extra_root, log_public)

            string_tree_size = copy.deepcopy(root)
            string_tree_size["tree_size"] = str(string_tree_size["tree_size"])
            with self.assertRaisesRegex(log_client.RootVerificationError, "integer"):
                log_client.verify_signed_root(string_tree_size, log_public)

            extra_proof = copy.deepcopy(proof)
            extra_proof["unknown"] = True
            with self.assertRaisesRegex(log_client.InclusionProofError, "unknown field"):
                log_client.verify_inclusion_proof(entry_hash, extra_proof, root, log_public)

            string_proof = copy.deepcopy(proof)
            string_proof["tree_size"] = str(string_proof["tree_size"])
            with self.assertRaisesRegex(log_client.InclusionProofError, "integer"):
                log_client.verify_inclusion_proof(entry_hash, string_proof, root, log_public)

            new_private, new_public, _new_address = keypair()
            rotation = log_client.make_key_rotation(
                log_private,
                log_public,
                new_private,
                new_public,
                rotation_timestamp=1_700_000_100,
                effective_from_tree_size=1,
            )
            rotation["rotation_timestamp"] = str(rotation["rotation_timestamp"])
            with self.assertRaisesRegex(log_client.KeyRotationError, "integer"):
                log_client.verify_key_rotation(rotation)

    def test_local_store_can_submit_validated_transfers_to_operator(self):
        token = signed_transfer_token(index=9004, timestamp=1_700_000_010)
        announcement = ind_token.create_transfer_announcement(token)
        entry_hash = ind_token.transfer_hash(token["history"][-1])
        with tempfile.TemporaryDirectory() as temp_dir:
            log, _log_private, _log_public = self.make_log(temp_dir)
            store = ind_token.INDLocalStore(
                temp_dir + "/ind.db",
                transparency_submitter=log_client.LocalTransparencyOperator(log),
            )

            result = store.ingest_message(announcement)

            self.assertTrue(result["accepted"])
            root = log.publish_root(1_700_000_040)
            proof = log.inclusion_proof(entry_hash, root["tree_size"])
            self.assertEqual(proof["entry_hash"], entry_hash)

    def test_operator_rejects_conflicting_sibling_spend_claims(self):
        issuer_private, issuer_public, _issuer_address = keypair()
        alice_private, alice_public, alice_address = keypair()
        _bob_private, _bob_public, bob_address = keypair()
        _carol_private, _carol_public, carol_address = keypair()
        token = ind_token.make_genesis_token(
            9010,
            alice_address,
            issuer_private,
            issuer_public,
            issued_at=1_700_000_000,
        )
        to_bob = ind_token.create_transfer(
            token,
            alice_private,
            alice_public,
            bob_address,
            timestamp=1_700_000_010,
        )
        to_carol = ind_token.create_transfer(
            token,
            alice_private,
            alice_public,
            carol_address,
            timestamp=1_700_000_011,
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            log, _log_private, _log_public = self.make_log(temp_dir)

            first = log.append_transfer_announcement(ind_token.create_transfer_announcement(to_bob))

            self.assertTrue(first["accepted"])
            self.assertFalse(first["duplicate"])
            with self.assertRaisesRegex(log_server.LogServerError, "conflicting spend is rejected"):
                log.append_transfer_announcement(ind_token.create_transfer_announcement(to_carol))
            duplicate = log.append_transfer_announcement(
                ind_token.create_transfer_announcement(to_bob)
            )
            self.assertTrue(duplicate["duplicate"])
            root = log.publish_root(1_700_000_040)
            proof = log.spend_map_proof(first["spend_key"], root["tree_size"])
            self.assertEqual(root["spend_map_size"], 1)
            self.assertEqual(len(proof["spend_claims"]), 1)
            self.assertTrue(
                log_client.verify_spend_map_proof_for_transfer(
                    to_bob["history"][-1],
                    proof,
                    root,
                    operator_public_key=root["operator_public_key"],
                )
            )

    def test_current_spend_key_check_survives_rejected_later_double_spend(self):
        issuer_private, issuer_public, _issuer_address = keypair()
        alice_private, alice_public, alice_address = keypair()
        _bob_private, _bob_public, bob_address = keypair()
        _carol_private, _carol_public, carol_address = keypair()
        token = ind_token.make_genesis_token(
            9025,
            alice_address,
            issuer_private,
            issuer_public,
            issued_at=1_700_000_000,
        )
        to_bob = ind_token.create_transfer(
            token,
            alice_private,
            alice_public,
            bob_address,
            timestamp=1_700_000_010,
        )
        to_carol = ind_token.create_transfer(
            token,
            alice_private,
            alice_public,
            carol_address,
            timestamp=1_700_000_011,
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            log, _log_private, log_public = self.make_log(temp_dir)
            log.append_transfer_announcement(ind_token.create_transfer_announcement(to_bob))
            historical_root = log.publish_root(1_700_000_040)
            with self.assertRaisesRegex(log_server.LogServerError, "conflicting spend is rejected"):
                log.append_transfer_announcement(ind_token.create_transfer_announcement(to_carol))
            current_root = log.publish_root(1_700_000_080)

            class RootMirror:
                def __init__(self, identity_id):
                    self.identity_id = identity_id

                def root_at(self, timestamp):
                    if int(timestamp) <= int(historical_root["timestamp"]):
                        return historical_root
                    return current_root

                def latest_root(self):
                    return current_root

            verifier = log_client.TransparencyVerifier(
                log_client.LocalTransparencyOperator(log),
                [RootMirror("double-spend-mirror-a"), RootMirror("double-spend-mirror-b")],
                operator_public_key=log_public,
                max_root_lag_seconds=60,
                observed_root_store=in_memory_root_store(),
                run_startup_check=False,
            )

            self.assertTrue(verifier.verify_token_history(to_bob))
            self.assertTrue(
                ind_token.verify_token(to_bob, transparency_verifier=verifier, now=1_700_000_090)
            )

    def test_spend_map_proof_verifies_transfer_winner(self):
        token = signed_transfer_token(index=9011, timestamp=1_700_000_010)
        transfer = token["history"][-1]
        with tempfile.TemporaryDirectory() as temp_dir:
            log, _log_private, log_public = self.make_log(temp_dir)
            append_result = log.append_transfer_announcement(
                ind_token.create_transfer_announcement(token)
            )
            root = log.publish_root(1_700_000_040)

            proof = log.spend_map_proof(append_result["spend_key"], root["tree_size"])

            self.assertEqual(root["spend_map_size"], 1)
            self.assertTrue(
                log_client.verify_spend_map_proof_for_transfer(
                    transfer,
                    proof,
                    root,
                    operator_public_key=log_public,
                )
            )
            tampered = copy.deepcopy(proof)
            tampered["spend_claims"][0]["transfer_hash"] = "00" * 32
            with self.assertRaises(log_client.InclusionProofError):
                log_client.verify_spend_map_proof_for_transfer(
                    transfer,
                    tampered,
                    root,
                    operator_public_key=log_public,
                )

    def test_compact_checkpoint_verifies_without_full_history(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log, _log_private, log_public = self.make_log(temp_dir)
            issuer_private, issuer_public, _issuer_address = keypair()
            alice_private, alice_public, alice_address = keypair()
            bob_private, bob_public, bob_address = keypair()
            _carol_private, _carol_public, carol_address = keypair()
            token = ind_token.make_genesis_token(
                9200, alice_address, issuer_private, issuer_public, issued_at=1_700_000_000
            )
            token = ind_token.create_transfer(
                token, alice_private, alice_public, bob_address, timestamp=1_700_000_010
            )
            log.append_transfer_announcement(ind_token.create_transfer_announcement(token))

            checkpoint = ind_token.create_bill_checkpoint(token)
            append_result = log.append_checkpoint_announcement(
                ind_token.create_checkpoint_announcement(checkpoint, bill=token)
            )
            root = log.publish_root(1_700_000_050)
            inclusion = log.inclusion_proof(append_result["checkpoint_hash"], root["tree_size"])
            spend = log.spend_map_proof(
                log_client.spend_key_for_transfer(token["history"][-1]), root["tree_size"]
            )
            checkpoint["transparency"] = {
                "type": "ind.checkpoint_transparency.v2",
                "version": ind_token.BILL_VERSION,
                "root": root,
                "inclusion_proof": inclusion,
                "spend_proof": spend,
            }

            compact = ind_token.create_compact_bill(token, checkpoint)
            with self.assertRaisesRegex(
                ind_token.ValidationError, "trusted transparency verifier|pinned operator key"
            ):
                ind_token.verify_bill(compact)

            with mock.patch.dict(os.environ, {"IND_LOG_OPERATOR_PUBLIC_KEY": log_public}):
                state = ind_token.verify_bill(compact)

                self.assertEqual(state.sequence, 1)
                self.assertEqual(state.owner_address, bob_address)
                self.assertEqual(compact["recent_history"], [])
                next_bill = ind_token.create_transfer_v2(
                    compact,
                    bob_private,
                    bob_public,
                    carol_address,
                    timestamp=1_700_000_020,
                )
                self.assertEqual(
                    ind_token.create_transfer_announcement(next_bill)["type"],
                    ind_token.TRANSFER_ANNOUNCEMENT_V2_TYPE,
                )
                self.assertEqual(
                    ind_token.verify_bill(
                        next_bill, require_recent_transparency=False
                    ).owner_address,
                    carol_address,
                )

    def test_compact_checkpoint_rejects_missing_or_tampered_proof(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log, _log_private, _log_public = self.make_log(temp_dir)
            issuer_private, issuer_public, _issuer_address = keypair()
            alice_private, alice_public, alice_address = keypair()
            _bob_private, _bob_public, bob_address = keypair()
            token = ind_token.make_genesis_token(
                9201, alice_address, issuer_private, issuer_public, issued_at=1_700_000_000
            )
            token = ind_token.create_transfer(
                token, alice_private, alice_public, bob_address, timestamp=1_700_000_010
            )
            checkpoint = ind_token.create_bill_checkpoint(token)
            compact = {
                "type": ind_token.BILL_TYPE,
                "version": ind_token.BILL_VERSION,
                "token_id": token["token_id"],
                "genesis": token["genesis"],
                "checkpoint": checkpoint,
                "recent_history": [],
            }

            with self.assertRaisesRegex(ind_token.ValidationError, "missing transparency"):
                ind_token.verify_bill(compact)

            bad_value = copy.deepcopy(checkpoint)
            bad_value["value"] += 1
            bad_value["checkpoint_hash"] = ind_token.checkpoint_hash(bad_value)
            with self.assertRaisesRegex(ind_token.ValidationError, "checkpoint value mismatch"):
                ind_token.verify_checkpoint_for_genesis(
                    bad_value,
                    token["genesis"],
                    require_transparency=False,
                )

            bad_display = copy.deepcopy(checkpoint)
            bad_display["display_id"] = "bad-display"
            bad_display["checkpoint_hash"] = ind_token.checkpoint_hash(bad_display)
            with self.assertRaisesRegex(
                ind_token.ValidationError, "checkpoint display id mismatch"
            ):
                ind_token.verify_checkpoint_for_genesis(
                    bad_display,
                    token["genesis"],
                    require_transparency=False,
                )

            bad_day = copy.deepcopy(checkpoint)
            bad_day["last_transfer_day"] += 1
            bad_day["checkpoint_hash"] = ind_token.checkpoint_hash(bad_day)
            with self.assertRaisesRegex(
                ind_token.ValidationError, "checkpoint last transfer day mismatch"
            ):
                ind_token.verify_checkpoint_for_genesis(
                    bad_day,
                    token["genesis"],
                    require_transparency=False,
                )

            log.append_transfer_announcement(ind_token.create_transfer_announcement(token))
            with self.assertRaisesRegex(log_server.LogServerError, "requires source bill"):
                log.append_checkpoint_announcement(checkpoint)
            result = log.append_checkpoint_announcement(
                ind_token.create_checkpoint_announcement(checkpoint, bill=token)
            )
            root = log.publish_root(1_700_000_050)
            checkpoint["transparency"] = {
                "type": "ind.checkpoint_transparency.v2",
                "version": ind_token.BILL_VERSION,
                "root": root,
                "inclusion_proof": log.inclusion_proof(
                    result["checkpoint_hash"], root["tree_size"]
                ),
                "spend_proof": log.spend_map_proof(
                    log_client.spend_key_for_transfer(token["history"][-1]), root["tree_size"]
                ),
            }
            tampered = copy.deepcopy(compact)
            tampered["checkpoint"] = copy.deepcopy(checkpoint)
            tampered["checkpoint"]["owner_address"] = alice_address
            with self.assertRaisesRegex(ind_token.ValidationError, "checkpoint hash mismatch"):
                ind_token.verify_bill(tampered)

    def test_compact_checkpoint_rejects_attacker_controlled_embedded_root(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            attacker_log, _attacker_log_private, _attacker_log_public = self.make_log(temp_dir)
            _trusted_log_private, trusted_log_public, _trusted_log_address = keypair()
            issuer_private, issuer_public, _issuer_address = keypair()
            _real_private, _real_public, real_address = keypair()
            attacker_private, attacker_public, attacker_address = keypair()

            bill = ind_token.make_genesis_token(
                9208,
                real_address,
                issuer_private,
                issuer_public,
                issued_at=1_700_000_000,
            )
            genesis = bill["genesis"]
            transfer_unsigned = {
                "type": ind_token.TRANSFER_TYPE,
                "version": ind_token.TOKEN_VERSION,
                "token_id": bill["token_id"],
                "sequence": 1,
                "previous_hash": ind_token.genesis_hash(genesis),
                "sender_address": attacker_address,
                "sender_public_key": attacker_public,
                "recipient_address": attacker_address,
                "timestamp": 1_700_000_010,
                "metadata": {},
            }
            forged_transfer = copy.deepcopy(transfer_unsigned)
            forged_transfer["signature"] = ind_token.b85_sign_domain(
                attacker_private,
                ind_token.TRANSFER_SIGNATURE_DOMAIN,
                transfer_unsigned,
            )
            forged_transfer_hash = ind_token.transfer_hash(forged_transfer)
            checkpoint = {
                "type": ind_token.BILL_CHECKPOINT_TYPE,
                "version": ind_token.BILL_VERSION,
                "token_id": bill["token_id"],
                "genesis_hash": ind_token.genesis_hash(genesis),
                "sequence": 1,
                "owner_address": attacker_address,
                "value": int(genesis["value"]),
                "display_id": ind_token.token_display_id({"genesis": genesis}),
                "last_transfer_hash": forged_transfer_hash,
                "last_transfer_timestamp": int(forged_transfer["timestamp"]),
                "last_transfer_day": int(forged_transfer["timestamp"]) // 86400,
                "transfers_in_last_day": 1,
                "previous_checkpoint_hash": None,
            }
            checkpoint["checkpoint_hash"] = ind_token.checkpoint_hash(checkpoint)

            transfer_append = attacker_log.append_entry_hash(
                forged_transfer_hash,
                submitted_at=1_700_000_020,
                transfer=forged_transfer,
            )
            claim = attacker_log._spend_claim_from_transfer(forged_transfer)
            with attacker_log._connect() as conn:
                attacker_log._record_spend_claim(
                    conn,
                    claim,
                    forged_transfer_hash,
                    transfer_append["leaf_index"],
                    1_700_000_020,
                )
            attacker_log.append_entry_hash(
                checkpoint["checkpoint_hash"],
                submitted_at=1_700_000_021,
                entry_kind="checkpoint",
                entry=checkpoint,
            )
            root = attacker_log.publish_root(1_700_000_030)
            checkpoint["transparency"] = {
                "type": "ind.checkpoint_transparency.v2",
                "version": ind_token.BILL_VERSION,
                "root": root,
                "inclusion_proof": attacker_log.inclusion_proof(
                    checkpoint["checkpoint_hash"],
                    root["tree_size"],
                ),
                "spend_proof": attacker_log.spend_map_proof(
                    log_client.spend_key_for_transfer(forged_transfer),
                    root["tree_size"],
                ),
            }
            forged_compact = {
                "type": ind_token.BILL_TYPE,
                "version": ind_token.BILL_VERSION,
                "token_id": bill["token_id"],
                "genesis": genesis,
                "checkpoint": checkpoint,
                "recent_history": [],
            }

            with mock.patch.dict(os.environ, {"IND_LOG_OPERATOR_PUBLIC_KEY": trusted_log_public}):
                with self.assertRaisesRegex(
                    ind_token.ValidationError, "unexpected operator|checkpoint transparency"
                ):
                    ind_token.verify_bill(forged_compact, now=1_700_000_031)

    def test_store_creates_compact_checkpoint_after_settlement(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log, _log_private, log_public = self.make_log(temp_dir)
            operator = log_client.LocalTransparencyOperator(log)
            mirror = log_client.LocalTransparencyOperator(log)
            mirror.identity_id = ("local-mirror", "checkpoint-test")
            issuer_private, issuer_public, _issuer_address = keypair()
            alice_private, alice_public, alice_address = keypair()
            bob_private, bob_public, bob_address = keypair()
            carol_private, carol_public, carol_address = keypair()
            token = ind_token.make_genesis_token(
                9202, alice_address, issuer_private, issuer_public, issued_at=1_700_000_000
            )
            token = ind_token.create_transfer(
                token, alice_private, alice_public, bob_address, timestamp=1_700_000_010
            )
            transfer_message = ind_token.create_transfer_announcement(token)
            log.append_transfer_announcement(transfer_message)
            log.publish_root(1_700_000_040)
            verifier = log_client.TransparencyVerifier(
                operator,
                [mirror],
                operator_public_key=log_public,
                min_mirrors=1,
                allow_unsafe_single_mirror=True,
                max_root_lag_seconds=60,
                max_current_root_age_seconds=1_000_000_000,
                observed_root_store=in_memory_root_store(),
                run_startup_check=False,
            )
            store = ind_token.INDLocalStore(
                str(Path(temp_dir) / "store.db"),
                transparency_submitter=operator,
                transparency_verifier=verifier,
                transparency_submission_verify_timeout_seconds=0,
                first_checkpoint_after_transfers=1,
                checkpoint_interval_transfers=1,
            )

            store.ingest_message(transfer_message)
            store.ingest_message(
                ind_token.create_receipt_announcement(token, bob_private, bob_public)
            )
            store.finalize_pending(
                now=int(time.time()) + ind_token.FINALITY_BUFFER_SECONDS + 10, buffer_seconds=0
            )
            compact = store.get_compact_bill_by_display_id(ind_token.verify_token(token).display_id)

            self.assertIsNotNone(compact)
            self.assertEqual(compact["type"], ind_token.BILL_TYPE)
            self.assertEqual(compact["recent_history"], [])
            self.assertEqual(
                ind_token.verify_bill(compact, transparency_verifier=verifier).owner_address,
                bob_address,
            )

            next_bill = ind_token.create_transfer_v2(
                compact,
                bob_private,
                bob_public,
                carol_address,
                timestamp=1_700_000_020,
                transparency_verifier=verifier,
            )
            recipient_store = ind_token.INDLocalStore(
                str(Path(temp_dir) / "recipient.db"),
                transparency_submitter=operator,
                transparency_verifier=verifier,
                transparency_submission_verify_timeout_seconds=0,
                first_checkpoint_after_transfers=1,
                checkpoint_interval_transfers=1,
            )
            recipient_store.ingest_message(
                ind_token.create_transfer_announcement(next_bill, transparency_verifier=verifier)
            )
            recipient_store.ingest_message(
                ind_token.create_receipt_announcement(
                    next_bill,
                    carol_private,
                    carol_public,
                    transparency_verifier=verifier,
                )
            )
            recipient_store.finalize_pending(
                now=int(time.time()) + ind_token.FINALITY_BUFFER_SECONDS + 10, buffer_seconds=0
            )
            compact_next = recipient_store.get_compact_bill_by_display_id(
                ind_token.verify_token(token).display_id
            )

            self.assertIsNotNone(compact_next)
            self.assertEqual(compact_next["type"], ind_token.BILL_TYPE)
            self.assertEqual(compact_next["checkpoint"]["sequence"], 2)
            self.assertEqual(compact_next["recent_history"], [])
            self.assertEqual(
                ind_token.verify_bill(compact_next, transparency_verifier=verifier).owner_address,
                carol_address,
            )
            self.assertEqual(
                recipient_store.get_token_by_display_id(ind_token.verify_token(token).display_id)[
                    "type"
                ],
                ind_token.BILL_TYPE,
            )

    def test_store_checkpoint_policy_uses_first_threshold_then_interval(self):
        self.assertEqual(ind_store.DEFAULT_FIRST_CHECKPOINT_AFTER_TRANSFERS, 10)
        self.assertEqual(ind_store.DEFAULT_CHECKPOINT_INTERVAL_TRANSFERS, 10)
        with tempfile.TemporaryDirectory() as temp_dir:
            log, _log_private, log_public = self.make_log(temp_dir)
            operator = log_client.LocalTransparencyOperator(log)
            mirror = log_client.LocalTransparencyOperator(log)
            mirror.identity_id = ("local-mirror", "checkpoint-policy")
            verifier = log_client.TransparencyVerifier(
                operator,
                [mirror],
                operator_public_key=log_public,
                min_mirrors=1,
                allow_unsafe_single_mirror=True,
                max_root_lag_seconds=60,
                max_current_root_age_seconds=1_000_000_000,
                observed_root_store=in_memory_root_store(),
                run_startup_check=False,
            )
            store = ind_token.INDLocalStore(
                str(Path(temp_dir) / "policy.db"),
                transparency_submitter=operator,
                transparency_verifier=verifier,
                transparency_submission_verify_timeout_seconds=0,
                first_checkpoint_after_transfers=3,
                checkpoint_interval_transfers=2,
            )
            issuer_private, issuer_public, _issuer_address = keypair()
            owners = [keypair() for _ in range(6)]
            bill = ind_token.make_genesis_token(
                9203,
                owners[0][2],
                issuer_private,
                issuer_public,
                issued_at=1_700_000_000,
            )

            def settle(next_bill, recipient_private, recipient_public):
                store.ingest_message(
                    ind_token.create_transfer_announcement(
                        next_bill,
                        transparency_verifier=verifier,
                    )
                )
                store.ingest_message(
                    ind_token.create_receipt_announcement(
                        next_bill,
                        recipient_private,
                        recipient_public,
                        transparency_verifier=verifier,
                    )
                )
                store.finalize_pending(
                    now=int(time.time()) + ind_token.FINALITY_BUFFER_SECONDS + 10, buffer_seconds=0
                )

            bill = ind_token.create_transfer(
                bill, owners[0][0], owners[0][1], owners[1][2], timestamp=1_700_000_010
            )
            settle(bill, owners[1][0], owners[1][1])
            self.assertIsNone(
                store.get_compact_bill_by_display_id(ind_token.verify_token(bill).display_id)
            )

            bill = ind_token.create_transfer(
                bill, owners[1][0], owners[1][1], owners[2][2], timestamp=1_700_000_020
            )
            settle(bill, owners[2][0], owners[2][1])
            self.assertIsNone(
                store.get_compact_bill_by_display_id(ind_token.verify_token(bill).display_id)
            )

            bill = ind_token.create_transfer(
                bill, owners[2][0], owners[2][1], owners[3][2], timestamp=1_700_000_030
            )
            settle(bill, owners[3][0], owners[3][1])
            compact = store.get_compact_bill_by_display_id(ind_token.verify_token(bill).display_id)
            self.assertIsNotNone(compact)
            self.assertEqual(compact["checkpoint"]["sequence"], 3)

            bill = ind_token.create_transfer_v2(
                compact,
                owners[3][0],
                owners[3][1],
                owners[4][2],
                timestamp=1_700_000_040,
                transparency_verifier=verifier,
            )
            settle(bill, owners[4][0], owners[4][1])
            compact = store.get_compact_bill_by_display_id(
                ind_token.verify_token(
                    bill,
                    transparency_verifier=verifier,
                    require_recent_transparency=False,
                ).display_id
            )
            self.assertEqual(compact["checkpoint"]["sequence"], 3)

            bill = ind_token.create_transfer_v2(
                compact,
                owners[3][0],
                owners[3][1],
                owners[4][2],
                timestamp=1_700_000_040,
                transparency_verifier=verifier,
            )
            bill = ind_token.create_transfer_v2(
                bill,
                owners[4][0],
                owners[4][1],
                owners[5][2],
                timestamp=1_700_000_050,
                transparency_verifier=verifier,
            )
            settle(bill, owners[5][0], owners[5][1])
            compact = store.get_compact_bill_by_display_id(
                ind_token.verify_token(
                    bill,
                    transparency_verifier=verifier,
                    require_recent_transparency=False,
                ).display_id
            )
            self.assertEqual(compact["checkpoint"]["sequence"], 5)

    def test_manual_wallet_compact_now_forces_checkpoint_before_threshold(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log, _log_private, log_public = self.make_log(temp_dir)
            operator = log_client.LocalTransparencyOperator(log)
            mirror = log_client.LocalTransparencyOperator(log)
            mirror.identity_id = ("local-mirror", "manual-compact")
            verifier = log_client.TransparencyVerifier(
                operator,
                [mirror],
                operator_public_key=log_public,
                min_mirrors=1,
                allow_unsafe_single_mirror=True,
                max_root_lag_seconds=60,
                max_current_root_age_seconds=1_000_000_000,
                observed_root_store=in_memory_root_store(),
                run_startup_check=False,
            )
            store = ind_token.INDLocalStore(
                str(Path(temp_dir) / "manual.db"),
                transparency_submitter=operator,
                transparency_verifier=verifier,
                transparency_submission_verify_timeout_seconds=0,
                first_checkpoint_after_transfers=100,
                checkpoint_interval_transfers=10,
            )
            issuer_private, issuer_public, _issuer_address = keypair()
            alice_private, alice_public, alice_address = keypair()
            bob_private, bob_public, bob_address = keypair()
            bill = ind_token.make_genesis_token(
                9204, alice_address, issuer_private, issuer_public, issued_at=1_700_000_000
            )
            bill = ind_token.create_transfer(
                bill, alice_private, alice_public, bob_address, timestamp=1_700_000_010
            )
            store.ingest_message(ind_token.create_transfer_announcement(bill))
            store.ingest_message(
                ind_token.create_receipt_announcement(bill, bob_private, bob_public)
            )
            store.finalize_pending(now=int(time.time()), buffer_seconds=0)
            display_id = ind_token.verify_token(bill).display_id
            self.assertIsNone(store.get_compact_bill_by_display_id(display_id))

            wallet_lines = [bob_address + "\n", bob_private + "\n", bob_public + "\n"]
            state = wallet_services.compact_wallet_bill(
                wallet_lines, display_id + " 1 0\n", store=store
            )
            compact = store.get_compact_bill_by_display_id(display_id)

            self.assertIsNotNone(state)
            self.assertIsNotNone(compact)
            self.assertEqual(compact["checkpoint"]["sequence"], 1)
            self.assertEqual(
                ind_token.verify_bill(compact, transparency_verifier=verifier).owner_address,
                bob_address,
            )

    def test_high_value_policy_checkpoints_before_first_threshold(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log, _log_private, log_public = self.make_log(temp_dir)
            operator = log_client.LocalTransparencyOperator(log)
            mirror = log_client.LocalTransparencyOperator(log)
            mirror.identity_id = ("local-mirror", "high-value-compact")
            verifier = log_client.TransparencyVerifier(
                operator,
                [mirror],
                operator_public_key=log_public,
                min_mirrors=1,
                allow_unsafe_single_mirror=True,
                max_root_lag_seconds=60,
                max_current_root_age_seconds=1_000_000_000,
                observed_root_store=in_memory_root_store(),
                run_startup_check=False,
            )
            store = ind_token.INDLocalStore(
                str(Path(temp_dir) / "high_value.db"),
                transparency_submitter=operator,
                transparency_verifier=verifier,
                transparency_submission_verify_timeout_seconds=0,
                first_checkpoint_after_transfers=100,
                checkpoint_interval_transfers=10,
                high_value_checkpoint_threshold=5,
            )
            issuer_private, issuer_public, _issuer_address = keypair()
            alice_private, alice_public, alice_address = keypair()
            bob_private, bob_public, bob_address = keypair()
            bill = ind_token.make_genesis_token(
                9205,
                alice_address,
                issuer_private,
                issuer_public,
                value=5,
                issued_at=1_700_000_000,
            )
            bill = ind_token.create_transfer(
                bill, alice_private, alice_public, bob_address, timestamp=1_700_000_010
            )
            store.ingest_message(ind_token.create_transfer_announcement(bill))
            store.ingest_message(
                ind_token.create_receipt_announcement(bill, bob_private, bob_public)
            )
            store.finalize_pending(now=int(time.time()), buffer_seconds=0)
            compact = store.get_compact_bill_by_display_id(ind_token.verify_token(bill).display_id)

            self.assertIsNotNone(compact)
            self.assertEqual(compact["checkpoint"]["sequence"], 1)
            self.assertEqual(
                ind_token.verify_bill(compact, transparency_verifier=verifier).value, 5
            )

    def test_directory_proof_archive_verifies_when_operator_withholds_proofs(self):
        class WithholdingOperator:
            identity_id = ("withholding-operator", "test")

            def latest_root(self):
                raise log_client.TransparencyLogError("operator withheld latest root")

            def inclusion_proof(self, entry_hash, tree_size):
                raise log_client.TransparencyLogError("operator withheld inclusion proof")

            def spend_map_proof(self, spend_key, tree_size):
                raise log_client.TransparencyLogError("operator withheld spend proof")

        token = signed_transfer_token(index=9024, timestamp=1_700_000_010)
        transfer = token["history"][-1]
        with tempfile.TemporaryDirectory() as temp_dir:
            mirror_dir = temp_dir + "/mirror"
            log, _log_private, log_public = self.make_log(temp_dir)
            log.mirror_dirs = [Path(mirror_dir)]
            log.append_transfer_announcement(ind_token.create_transfer_announcement(token))
            root = log.publish_root(1_700_000_040)
            mirror = log_client.DirectoryRootMirror(mirror_dir)
            verifier = log_client.TransparencyVerifier(
                WithholdingOperator(),
                [mirror],
                operator_public_key=log_public,
                max_root_lag_seconds=60,
                min_mirrors=1,
                allow_unsafe_single_mirror=True,
                observed_root_store=in_memory_root_store(),
                proof_archives=[mirror],
                run_startup_check=False,
            )

            self.assertTrue(verifier.verify_transfer(transfer, now=1_700_000_050))
            self.assertTrue(
                log_client.verify_proof_archive(
                    log.proof_archive(root["tree_size"]), root, log_public
                )
            )

    def test_static_http_root_mirror_reads_streamed_website_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            mirror_dir = Path(temp_dir) / "public" / "transparency"
            mirror_dir.mkdir(parents=True)
            log, _log_private, log_public = self.make_log(temp_dir)
            log.append_entry_hash(ind_token.sha3_hex(b"entry"))
            root = log.publish_root(1_700_000_040)
            (mirror_dir / "latest.json").write_text(
                log_client.canonical_json(root) + "\n", encoding="utf-8"
            )
            (mirror_dir / "roots.jsonl").write_text(
                log_client.canonical_json(root) + "\n", encoding="utf-8"
            )

            handler = functools.partial(
                http.server.SimpleHTTPRequestHandler, directory=str(Path(temp_dir) / "public")
            )
            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                mirror = log_client.HTTPStaticRootMirror(
                    f"http://127.0.0.1:{server.server_port}/transparency"
                )

                self.assertEqual(mirror.latest_root()["root_hash"], root["root_hash"])
                self.assertEqual(mirror.root_at(1_700_000_010)["root_hash"], root["root_hash"])
                self.assertTrue(log_client.verify_signed_root(mirror.latest_root(), log_public))
            finally:
                server.shutdown()
                server.server_close()

    def test_operator_http_handler_rejects_traversal_shaped_path(self):
        server = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0), log_server.TransparencyLogHandler
        )
        server.transparency_log = mock.Mock()
        server.root_interval_seconds = 60
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with self.assertRaises(urllib.error.HTTPError) as raised:
                urllib.request.urlopen(
                    f"http://127.0.0.1:{server.server_port}/v1/%2e%2e/root",
                    timeout=5,
                )
            self.assertEqual(raised.exception.code, 400)
        finally:
            server.shutdown()
            server.server_close()

    def test_verifier_environment_propagates_settings_errors(self):
        with (
            mock.patch.object(
                ind_settings,
                "load_security_settings",
                side_effect=ValueError("bad production config"),
            ),
            self.assertRaisesRegex(ValueError, "bad production config"),
        ):
            log_client.verifier_from_environment()

    def test_strict_store_verifies_submission_against_mirrored_root_before_accepting(self):
        token = signed_transfer_token(index=9005, timestamp=1_700_000_010)
        announcement = ind_token.create_transfer_announcement(token)
        with tempfile.TemporaryDirectory() as temp_dir:
            log, _log_private, log_public = self.make_log(temp_dir)

            class PublishingMirror:
                def __init__(self, identity_id):
                    self.identity_id = identity_id

                def root_at(self, timestamp):
                    return log.publish_root(max(int(timestamp), 1_700_000_040))

                def latest_root(self):
                    return log.latest_root() or log.publish_root(1_700_000_040)

            verifier = log_client.TransparencyVerifier(
                log_client.LocalTransparencyOperator(log),
                [
                    PublishingMirror("test-publishing-mirror-a"),
                    PublishingMirror("test-publishing-mirror-b"),
                ],
                operator_public_key=log_public,
                max_root_lag_seconds=60,
                observed_root_store=in_memory_root_store(),
                run_startup_check=False,
            )
            store = ind_token.INDLocalStore(
                temp_dir + "/ind.db",
                transparency_submitter=log_client.LocalTransparencyOperator(log),
                transparency_verifier=verifier,
                require_transparency=True,
                transparency_submission_verify_timeout_seconds=0,
            )

            with mock.patch("log_client.time.time", return_value=1_700_000_050):
                result = store.ingest_message(announcement)

            self.assertTrue(result["accepted"])

    def test_duplicate_submission_response_still_requires_inclusion_verification(self):
        token = signed_transfer_token(index=9006, timestamp=1_700_000_010)
        announcement = ind_token.create_transfer_announcement(token)
        with tempfile.TemporaryDirectory() as temp_dir:
            log, _log_private, log_public = self.make_log(temp_dir)
            log.append_transfer_announcement(announcement)
            root = log.publish_root(1_700_000_040)
            verifier = log_client.TransparencyVerifier(
                log_client.LocalTransparencyOperator(log),
                independent_static_mirrors(root),
                operator_public_key=log_public,
                max_root_lag_seconds=60,
                observed_root_store=in_memory_root_store(),
                run_startup_check=False,
            )
            store = ind_token.INDLocalStore(
                temp_dir + "/ind.db",
                transparency_submitter=log_client.LocalTransparencyOperator(log),
                transparency_verifier=verifier,
                require_transparency=True,
                transparency_submission_verify_timeout_seconds=0,
            )

            with mock.patch("log_client.time.time", return_value=1_700_000_050):
                result = store.ingest_message(announcement)

            self.assertTrue(result["accepted"])

    def test_retroactive_forgery_is_rejected_when_root_is_too_late(self):
        token = signed_transfer_token(index=9003, timestamp=1_700_000_010)
        with tempfile.TemporaryDirectory() as temp_dir:
            log, _log_private, log_public = self.make_log(temp_dir)
            log.append_transfer_announcement(ind_token.create_transfer_announcement(token))
            late_root = log.publish_root(1_700_001_000)
            verifier = log_client.TransparencyVerifier(
                log_client.LocalTransparencyOperator(log),
                independent_static_mirrors(late_root),
                operator_public_key=log_public,
                max_root_lag_seconds=60,
                observed_root_store=in_memory_root_store(),
                run_startup_check=False,
            )

            with self.assertRaisesRegex(ind_token.ValidationError, "transparency log"):
                ind_token.verify_token(token, transparency_verifier=verifier, now=1_700_001_010)

    def test_mirror_disagreement_detection_reports_signed_split_view(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log, log_private, log_public = self.make_log(temp_dir)
            log.append_entry_hash(ind_token.sha3_hex(b"first"))
            root = log.publish_root(1_700_000_060)
            conflicting_root = copy.deepcopy(root)
            conflicting_root["tree_size"] = int(root["tree_size"]) + 1
            conflicting_root["root_hash"] = "11" * 32
            conflicting_root.pop("signature")
            conflicting_root["signature"] = ind_token.b85_sign(
                log_private,
                log_client.root_signature_payload(conflicting_root),
            )

            with self.assertRaises(log_client.MirrorDisagreementError) as caught:
                log_client.detect_mirror_disagreement(
                    [root, conflicting_root], operator_public_key=log_public
                )

            self.assertEqual(caught.exception.evidence["timestamp"], root["timestamp"])

    def test_root_gossip_announcement_verifies_signed_root(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log, _log_private, log_public = self.make_log(temp_dir)
            log.append_entry_hash(ind_token.sha3_hex(b"entry"))
            root = log.publish_root(1_700_000_060)

            message = ind_token.create_transparency_root_announcement(
                root, observed_at=1_700_000_061
            )
            verified_root = ind_token.verify_transparency_root_announcement(
                message, operator_public_key=log_public
            )

            self.assertEqual(verified_root["root_hash"], root["root_hash"])

    def test_equivocation_proof_message_verifies_without_trusting_reporter(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log, log_private, log_public = self.make_log(temp_dir)
            log.append_entry_hash(ind_token.sha3_hex(b"entry"))
            root = log.publish_root(1_700_000_060)
            split_root = copy.deepcopy(root)
            split_root["timestamp"] = int(root["timestamp"]) + 60
            split_root["root_hash"] = "55" * 32
            split_root.pop("signature")
            split_root["signature"] = ind_token.b85_sign(
                log_private,
                log_client.root_signature_payload(split_root),
            )

            proof = ind_token.create_transparency_equivocation_proof(root, split_root)
            verified = ind_token.verify_transparency_equivocation_proof(
                proof, operator_public_key=log_public
            )

            self.assertEqual(verified["collision_type"], "same_tree_size")


if __name__ == "__main__":
    unittest.main()
