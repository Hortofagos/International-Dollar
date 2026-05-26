import base64
import copy
import os
import tempfile
import unittest
from unittest import mock
from hashlib import sha3_256
from pathlib import Path

import ecdsa

import ind_token
import log_client
import log_server
from ind import settings as ind_settings


os.environ.setdefault("IND_ALLOW_UNTRUSTED_GENESIS", "1")


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
        return log_server.TransparencyLog(temp_dir + "/log.db", log_private, log_public), log_private, log_public

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
            with mock.patch.dict(log_client.os.environ, {"IND_LOG_ACCEPT_LEGACY_ALGORITHM_NAMES": "0"}):
                with self.assertRaisesRegex(log_client.RootVerificationError, "unsupported transparency tree algorithm"):
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

            with self.assertRaisesRegex(log_client.RootVerificationError, "unsupported transparency tree algorithm"):
                log_client.verify_signed_root(forged_algorithm_root, log_public)

    def test_consistency_proof_verifies_append_only_growth(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log, _log_private, log_public = self.make_log(temp_dir)
            log.append_entry_hash(ind_token.sha3_hex(b"first"))
            old_root = log.publish_root(1_700_000_060)
            log.append_entry_hash(ind_token.sha3_hex(b"second"))
            new_root = log.publish_root(1_700_000_120)

            proof = log.consistency_proof(old_root["tree_size"], new_root["tree_size"])

            self.assertTrue(log_client.verify_consistency_proof(old_root, new_root, proof, log_public))

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
                log_client.StaticRootMirror([early_root, later_root], identity_id="test-root-mirror-a"),
                log_client.StaticRootMirror([early_root, later_root], identity_id="test-root-mirror-b"),
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

    def test_operator_logs_conflicting_sibling_spend_claims(self):
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
            conflicting = log.append_transfer_announcement(ind_token.create_transfer_announcement(to_carol))
            self.assertTrue(conflicting["accepted"])
            self.assertFalse(conflicting["duplicate"])
            duplicate = log.append_transfer_announcement(ind_token.create_transfer_announcement(to_bob))
            self.assertTrue(duplicate["duplicate"])
            root = log.publish_root(1_700_000_040)
            proof = log.spend_map_proof(first["spend_key"], root["tree_size"])
            self.assertEqual(root["spend_map_size"], 2)
            self.assertEqual(len(proof["spend_claims"]), 2)
            with self.assertRaisesRegex(log_client.InclusionProofError, "conflicting sibling"):
                log_client.verify_spend_map_proof_for_transfer(
                    to_bob["history"][-1],
                    proof,
                    root,
                    operator_public_key=root["operator_public_key"],
                )

    def test_current_spend_key_check_catches_later_double_spend(self):
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
            with self.assertRaisesRegex(ind_token.ValidationError, "conflicting sibling"):
                ind_token.verify_token(to_bob, transparency_verifier=verifier, now=1_700_000_090)

    def test_spend_map_proof_verifies_transfer_winner(self):
        token = signed_transfer_token(index=9011, timestamp=1_700_000_010)
        transfer = token["history"][-1]
        with tempfile.TemporaryDirectory() as temp_dir:
            log, _log_private, log_public = self.make_log(temp_dir)
            append_result = log.append_transfer_announcement(ind_token.create_transfer_announcement(token))
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
            self.assertTrue(log_client.verify_proof_archive(log.proof_archive(root["tree_size"]), root, log_public))

    def test_verifier_environment_propagates_settings_errors(self):
        with mock.patch.object(ind_settings, "load_security_settings", side_effect=ValueError("bad production config")):
            with self.assertRaisesRegex(ValueError, "bad production config"):
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
                [PublishingMirror("test-publishing-mirror-a"), PublishingMirror("test-publishing-mirror-b")],
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
        entry_hash = ind_token.transfer_hash(token["history"][-1])
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
                log_client.detect_mirror_disagreement([root, conflicting_root], operator_public_key=log_public)

            self.assertEqual(caught.exception.evidence["timestamp"], root["timestamp"])

    def test_root_gossip_announcement_verifies_signed_root(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log, _log_private, log_public = self.make_log(temp_dir)
            log.append_entry_hash(ind_token.sha3_hex(b"entry"))
            root = log.publish_root(1_700_000_060)

            message = ind_token.create_transparency_root_announcement(root, observed_at=1_700_000_061)
            verified_root = ind_token.verify_transparency_root_announcement(message, operator_public_key=log_public)

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
            verified = ind_token.verify_transparency_equivocation_proof(proof, operator_public_key=log_public)

            self.assertEqual(verified["collision_type"], "same_tree_size")


if __name__ == "__main__":
    unittest.main()
