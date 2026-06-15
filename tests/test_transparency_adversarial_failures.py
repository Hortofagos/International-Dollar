import base64
import copy
import tempfile
import unittest
import warnings
from hashlib import sha3_256
from pathlib import Path
from unittest import mock

import ecdsa
import pytest

import ind_token
import log_client
import log_server
import node_client
from operator_tools import audit_hash_log, hash_log_exporter

ind_token.os.environ.setdefault("IND_ALLOW_UNTRUSTED_GENESIS", "1")
pytestmark = pytest.mark.skip(reason="archived V1/V2 bill protocol tests")


def keypair():
    signing_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1, hashfunc=sha3_256)
    verify_key = signing_key.get_verifying_key()
    private_key = base64.b85encode(signing_key.to_string()).decode("utf-8")
    public_key = base64.b85encode(verify_key.to_string()).decode("utf-8")
    return private_key, public_key


class AdversarialTransparencyTests(unittest.TestCase):
    def make_log(self, temp_dir):
        private_key, public_key = keypair()
        return (
            log_server.TransparencyLog(str(Path(temp_dir) / "log.db"), private_key, public_key),
            private_key,
            public_key,
        )

    def memory_store(self):
        return log_client.InMemoryObservedRootStore()

    def verifier_for_gossip(self, public_key, store=None):
        class GossipOnlyOperator:
            identity_id = ("custom", "gossip-only-operator")

            def consistency_proof(self, first_tree_size, second_tree_size):
                raise TimeoutError("not used by gossip-only tests")

        return log_client.TransparencyVerifier(
            GossipOnlyOperator(),
            [
                log_client.StaticRootMirror([], identity_id="gossip-mirror-a"),
                log_client.StaticRootMirror([], identity_id="gossip-mirror-b"),
            ],
            operator_public_key=public_key,
            observed_root_store=store or self.memory_store(),
            run_startup_check=False,
        )

    def resign_root(self, root, private_key):
        split_root = copy.deepcopy(root)
        split_root.pop("signature", None)
        split_root["signature"] = ind_token.b85_sign(
            private_key, log_client.root_signature_payload(split_root)
        )
        return split_root

    def signed_transfer_token(self, timestamp=1_700_000_010):
        issuer_private, issuer_public = keypair()
        alice_private, alice_public = keypair()
        bob_private, bob_public = keypair()
        alice_address = ind_token.address_from_public_key(alice_public)
        bob_address = ind_token.address_from_public_key(bob_public)
        token = ind_token.make_genesis_token(
            99001,
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

    def signed_root_for_key(self, log, timestamp, private_key, public_key):
        return log_client.make_signed_root(
            log.tree_size(),
            log.current_root_hash(),
            timestamp,
            private_key,
            public_key,
        )

    def malicious_conflicting_spend_root(self):
        issuer_private, issuer_public = keypair()
        alice_private, alice_public = keypair()
        _bob_private, bob_public = keypair()
        _carol_private, carol_public = keypair()
        operator_private, operator_public = keypair()
        alice_address = ind_token.address_from_public_key(alice_public)
        bob_address = ind_token.address_from_public_key(bob_public)
        carol_address = ind_token.address_from_public_key(carol_public)
        token = ind_token.make_genesis_token(
            99110,
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
        transfer_a = to_bob["history"][-1]
        transfer_b = to_carol["history"][-1]
        log_id = log_client.log_id_from_public_key(operator_public)
        claims = [
            log_client.spend_claim_for_transfer(transfer_a, log_id, 0, 1_700_000_020),
            log_client.spend_claim_for_transfer(transfer_b, log_id, 1, 1_700_000_021),
        ]
        root = log_client.make_signed_root(
            2,
            "11" * 32,
            1_700_000_060,
            operator_private,
            operator_public,
            spend_map_root=log_client.spend_map_root(claims),
            spend_map_size=len(claims),
        )
        proof = log_client.build_spend_map_proof(
            claims,
            log_client.spend_key_for_transfer(transfer_a),
            root["tree_size"],
        )
        return transfer_a, proof, root, operator_public

    def test_single_root_mirror_is_rejected_by_default_policy(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log, _private_key, public_key = self.make_log(temp_dir)
            log.append_entry_hash(ind_token.sha3_hex(b"entry"))
            root = log.publish_root(1_700_000_000)

            with self.assertRaises(log_client.TransparencyLogError):
                log_client.TransparencyVerifier(
                    log_client.LocalTransparencyOperator(log),
                    [log_client.StaticRootMirror([root], identity_id="single-test-mirror")],
                    operator_public_key=public_key,
                )

    def test_operator_origin_cannot_be_used_as_mirror_with_different_path(self):
        with self.assertRaisesRegex(log_client.TransparencyLogError, "same http-origin"):
            log_client.TransparencyVerifier(
                "https://log.example/v1",
                [
                    "https://log.example:443/roots",
                    "https://independent.example/roots",
                ],
            )

    def test_duplicate_mirror_origins_do_not_satisfy_min_mirrors(self):
        with self.assertRaisesRegex(log_client.TransparencyLogError, "share http-origin"):
            log_client.TransparencyVerifier(
                "https://operator.example",
                [
                    "https://mirror.example/roots",
                    "https://mirror.example:443/archive",
                ],
            )

    def test_strict_mode_rejects_unsafe_single_mirror_at_startup(self):
        with mock.patch.dict(
            log_client.os.environ,
            {
                "IND_REQUIRE_TRANSPARENCY_LOG": "1",
                "IND_LOG_UNSAFE_SINGLE_MIRROR": "1",
            },
            clear=False,
        ):
            with self.assertRaisesRegex(
                log_client.TransparencyLogError, "IND_REQUIRE_TRANSPARENCY_LOG=1"
            ):
                log_client.verifier_from_environment(strict_mode=True)

    def test_same_tree_size_equivocation_is_detected_across_timestamps(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log, private_key, public_key = self.make_log(temp_dir)
            log.append_entry_hash(ind_token.sha3_hex(b"entry"))
            root = log.publish_root(1_700_000_000)
            split_root = copy.deepcopy(root)
            split_root["timestamp"] = int(root["timestamp"]) + 60
            split_root["root_hash"] = "22" * 32
            split_root.pop("signature")
            split_root["signature"] = ind_token.b85_sign(
                private_key, log_client.root_signature_payload(split_root)
            )

            with self.assertRaises(log_client.MirrorDisagreementError):
                log_client.detect_mirror_disagreement(
                    [root, split_root], operator_public_key=public_key
                )

    def test_tree_size_equivocation_blacklists_operator(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log, private_key, public_key = self.make_log(temp_dir)
            log.append_entry_hash(ind_token.sha3_hex(b"entry"))
            root = log.publish_root(1_700_000_000)
            split_root = copy.deepcopy(root)
            split_root["timestamp"] = int(root["timestamp"]) + 60
            split_root["root_hash"] = "33" * 32
            split_root = self.resign_root(split_root, private_key)
            store = self.memory_store()
            verifier = self.verifier_for_gossip(public_key, store=store)

            verifier.process_root_announcement(
                log_client.make_root_announcement(root), peer_id="peer-a"
            )
            with self.assertRaises(log_client.MirrorDisagreementError):
                verifier.process_root_announcement(
                    log_client.make_root_announcement(split_root), peer_id="peer-b"
                )

            self.assertEqual(store.status(root["log_id"])["status"], "blacklisted")

    def test_timestamp_equivocation_is_detected_from_peer_roots(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log, private_key, public_key = self.make_log(temp_dir)
            log.append_entry_hash(ind_token.sha3_hex(b"first"))
            root = log.publish_root(1_700_000_000)
            log.append_entry_hash(ind_token.sha3_hex(b"second"))
            split_root = log.publish_root(1_700_000_060)
            split_root["timestamp"] = int(root["timestamp"])
            split_root = self.resign_root(split_root, private_key)
            verifier = self.verifier_for_gossip(public_key)

            verifier.process_root_announcement(
                log_client.make_root_announcement(root), peer_id="peer-a"
            )
            with self.assertRaises(log_client.MirrorDisagreementError):
                verifier.process_root_announcement(
                    log_client.make_root_announcement(split_root), peer_id="peer-b"
                )

    def test_forwarded_equivocation_evidence_blacklists_independently(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log, private_key, public_key = self.make_log(temp_dir)
            log.append_entry_hash(ind_token.sha3_hex(b"entry"))
            root = log.publish_root(1_700_000_000)
            split_root = copy.deepcopy(root)
            split_root["timestamp"] = int(root["timestamp"]) + 60
            split_root["root_hash"] = "44" * 32
            split_root = self.resign_root(split_root, private_key)
            verifier_a = self.verifier_for_gossip(public_key)
            verifier_b_store = self.memory_store()
            verifier_b = self.verifier_for_gossip(public_key, store=verifier_b_store)

            verifier_a.process_root_announcement(
                log_client.make_root_announcement(root), peer_id="peer-a"
            )
            with self.assertRaises(log_client.MirrorDisagreementError):
                verifier_a.process_root_announcement(
                    log_client.make_root_announcement(split_root), peer_id="peer-b"
                )
            evidence = [
                message
                for message in verifier_a.consume_pending_gossip_messages()
                if message["type"] == ind_token.TRANSPARENCY_EQUIVOCATION_PROOF_TYPE
            ][0]

            verifier_b.process_equivocation_proof(evidence, peer_id="peer-a")

            self.assertEqual(verifier_b_store.status(root["log_id"])["status"], "blacklisted")

    def test_forged_equivocation_evidence_is_rejected_and_not_forwarded(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_a, _private_a, public_a = self.make_log(Path(temp_dir) / "a")
            log_b, _private_b, _public_b = self.make_log(Path(temp_dir) / "b")
            log_a.append_entry_hash(ind_token.sha3_hex(b"a"))
            root_a = log_a.publish_root(1_700_000_000)
            log_b.append_entry_hash(ind_token.sha3_hex(b"b"))
            root_b = log_b.publish_root(1_700_000_000)
            forged = {
                "type": ind_token.TRANSPARENCY_EQUIVOCATION_PROOF_TYPE,
                "version": 1,
                "log_id": root_a["log_id"],
                "collision_type": "same_timestamp",
                "root_a": root_a,
                "root_b": root_b,
                "detected_at": 1_700_000_010,
            }
            verifier = self.verifier_for_gossip(public_a)

            with self.assertRaises(log_client.RootVerificationError):
                verifier.process_equivocation_proof(forged, peer_id="peer-a")

            self.assertEqual(verifier.consume_pending_gossip_messages(), [])

    def test_conflicting_spend_root_builds_operator_policy_violation_proof(self):
        transfer, spend_proof, root, operator_public = self.malicious_conflicting_spend_root()

        with self.assertRaises(log_client.OperatorPolicyViolationError) as caught:
            log_client.verify_spend_map_proof_for_transfer(
                transfer,
                spend_proof,
                root,
                operator_public_key=operator_public,
            )

        evidence = caught.exception.evidence
        self.assertEqual(evidence["type"], log_client.LOG_OPERATOR_POLICY_VIOLATION_TYPE)
        self.assertEqual(evidence["violation_type"], "accepted_conflicting_spend")
        verified = log_client.verify_operator_policy_violation_proof(
            evidence,
            operator_public_key=operator_public,
        )
        self.assertEqual(verified["log_id"], root["log_id"])

    def test_conflicting_spend_root_blacklists_operator_and_queues_evidence(self):
        transfer, spend_proof, root, operator_public = self.malicious_conflicting_spend_root()

        class PolicyViolatingOperator:
            identity_id = ("custom", "policy-violating-operator")

            def spend_map_proof(self, _spend_key, _tree_size):
                return spend_proof

        store = self.memory_store()
        verifier = log_client.TransparencyVerifier(
            PolicyViolatingOperator(),
            [
                log_client.StaticRootMirror([root], identity_id="policy-mirror-a"),
                log_client.StaticRootMirror([root], identity_id="policy-mirror-b"),
            ],
            operator_public_key=operator_public,
            observed_root_store=store,
            run_startup_check=False,
        )

        with self.assertRaises(log_client.OperatorPolicyViolationError):
            verifier.verify_transfer_current_spend(transfer, current_root=root)

        status = store.status(root["log_id"])
        self.assertEqual(status["status"], "blacklisted")
        self.assertIn("operator policy violation", status["reason"])
        self.assertIn(status["evidence_id"], store.policy_violations)
        messages = verifier.consume_pending_gossip_messages()
        self.assertEqual(messages[0]["type"], log_client.LOG_OPERATOR_POLICY_VIOLATION_TYPE)

    def test_forwarded_operator_policy_violation_blacklists_independently(self):
        transfer, spend_proof, root, operator_public = self.malicious_conflicting_spend_root()
        try:
            log_client.verify_spend_map_proof_for_transfer(
                transfer,
                spend_proof,
                root,
                operator_public_key=operator_public,
            )
        except log_client.OperatorPolicyViolationError as exc:
            evidence = exc.evidence
        else:
            self.fail("expected operator policy violation")

        store = self.memory_store()
        verifier = self.verifier_for_gossip(operator_public, store=store)
        verifier.process_operator_policy_violation_proof(evidence, peer_id="peer-a")

        self.assertEqual(store.status(root["log_id"])["status"], "blacklisted")

    def test_peer_received_roots_do_not_satisfy_min_mirrors(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log, _private_key, public_key = self.make_log(temp_dir)
            log.append_entry_hash(ind_token.sha3_hex(b"entry"))
            root = log.publish_root(1_700_000_000)
            verifier = self.verifier_for_gossip(public_key)

            verifier.process_root_announcement(
                log_client.make_root_announcement(root), peer_id="peer-a"
            )

            with self.assertRaises(log_client.RootVerificationError):
                verifier.mirrored_root_for_timestamp(1_700_000_000)

    def test_root_gossip_replay_is_deduped_before_rate_limit(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log, _private_key, _public_key = self.make_log(temp_dir)
            log.append_entry_hash(ind_token.sha3_hex(b"entry"))
            root = log.publish_root(1_700_000_000)
            raw = ind_token.pack_wire_message(log_client.make_root_announcement(root))
            seen = node_client.BoundedSeenSet()
            limiter = node_client.PeerRateLimiter()

            first = node_client.prepare_incoming_gossip("203.0.113.10", raw, seen, limiter)
            for _ in range(node_client.MAX_ROOT_GOSSIP_PER_PEER_WINDOW + 5):
                if first.get("accepted"):
                    seen.add(first["message_hash"])
                replay = node_client.prepare_incoming_gossip("203.0.113.10", raw, seen, limiter)

            self.assertTrue(first["accepted"])
            self.assertTrue(replay["duplicate"])
            self.assertEqual(len(limiter.events[("203.0.113.10", "root_gossip")]), 1)

    def test_valid_key_rotation_signed_by_both_keys_is_accepted(self):
        old_private, old_public = keypair()
        new_private, new_public = keypair()
        rotation = log_client.make_key_rotation(
            old_private,
            old_public,
            new_private,
            new_public,
            rotation_timestamp=1_700_000_000,
            effective_from_tree_size=10,
            overlap_until_timestamp=1_700_604_800,
        )
        store = self.memory_store()

        record_hash = store.record_key_rotation(rotation)

        self.assertEqual(store.key_rotation_by_hash(record_hash)["new_public_key"], new_public)

    def test_key_rotation_requires_both_old_and_new_signatures(self):
        old_private, old_public = keypair()
        new_private, new_public = keypair()
        rotation = log_client.make_key_rotation(
            old_private,
            old_public,
            new_private,
            new_public,
            rotation_timestamp=1_700_000_000,
            effective_from_tree_size=10,
        )
        old_only = copy.deepcopy(rotation)
        old_only.pop("signature_by_new_key")
        new_only = copy.deepcopy(rotation)
        new_only.pop("signature_by_old_key")

        with self.assertRaises(log_client.KeyRotationError):
            log_client.verify_key_rotation(old_only)
        with self.assertRaises(log_client.KeyRotationError):
            log_client.verify_key_rotation(new_only)

    def test_forged_key_rotation_wrong_log_id_is_rejected(self):
        old_private, old_public = keypair()
        new_private, new_public = keypair()
        rotation = log_client.make_key_rotation(
            old_private,
            old_public,
            new_private,
            new_public,
            rotation_timestamp=1_700_000_000,
            effective_from_tree_size=10,
        )
        rotation["log_id"] = log_client.log_id_from_public_key(new_public)
        rotation.pop("signature_by_old_key")
        rotation.pop("signature_by_new_key")
        payload = log_client.key_rotation_signature_payload(rotation)
        rotation["signature_by_old_key"] = ind_token.b85_sign(old_private, payload)
        rotation["signature_by_new_key"] = ind_token.b85_sign(new_private, payload)

        with self.assertRaisesRegex(log_client.KeyRotationError, "log id does not match old key"):
            log_client.verify_key_rotation(rotation)

    def test_key_rotation_records_must_be_monotonic_by_effective_tree_size(self):
        old_private, old_public = keypair()
        new_private, new_public = keypair()
        newer_private, newer_public = keypair()
        first = log_client.make_key_rotation(
            old_private,
            old_public,
            new_private,
            new_public,
            rotation_timestamp=1_700_000_000,
            effective_from_tree_size=10,
        )
        replay = log_client.make_key_rotation(
            old_private,
            old_public,
            newer_private,
            newer_public,
            rotation_timestamp=1_700_000_060,
            effective_from_tree_size=10,
        )
        store = self.memory_store()

        store.record_key_rotation(first)
        with self.assertRaisesRegex(log_client.KeyRotationError, "strictly monotonic"):
            store.record_key_rotation(replay)

    def test_new_operator_key_root_is_accepted_during_rotation_overlap(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log, old_private, old_public = self.make_log(temp_dir)
            new_private, new_public = keypair()
            log.append_entry_hash(ind_token.sha3_hex(b"entry"))
            new_root = self.signed_root_for_key(log, 1_700_000_120, new_private, new_public)
            rotation = log_client.make_key_rotation(
                old_private,
                old_public,
                new_private,
                new_public,
                rotation_timestamp=1_700_000_000,
                effective_from_tree_size=1,
                overlap_until_timestamp=1_700_604_800,
            )
            verifier = log_client.TransparencyVerifier(
                log_client.LocalTransparencyOperator(log),
                [
                    log_client.StaticRootMirror([new_root], identity_id="rotation-mirror-a"),
                    log_client.StaticRootMirror([new_root], identity_id="rotation-mirror-b"),
                ],
                operator_public_key=old_public,
                observed_root_store=self.memory_store(),
                run_startup_check=False,
            )
            verifier.observe_key_rotation(rotation)

            self.assertEqual(
                verifier.current_mirrored_root(now=1_700_000_130)["operator_public_key"], new_public
            )

    def test_old_operator_key_root_is_rejected_after_rotation_overlap(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log, old_private, old_public = self.make_log(temp_dir)
            new_private, new_public = keypair()
            log.append_entry_hash(ind_token.sha3_hex(b"entry"))
            old_late_root = self.signed_root_for_key(log, 1_700_000_300, old_private, old_public)
            rotation = log_client.make_key_rotation(
                old_private,
                old_public,
                new_private,
                new_public,
                rotation_timestamp=1_700_000_000,
                effective_from_tree_size=1,
                overlap_until_timestamp=1_700_000_200,
            )
            verifier = log_client.TransparencyVerifier(
                log_client.LocalTransparencyOperator(log),
                [
                    log_client.StaticRootMirror([old_late_root], identity_id="old-key-mirror-a"),
                    log_client.StaticRootMirror([old_late_root], identity_id="old-key-mirror-b"),
                ],
                operator_public_key=old_public,
                observed_root_store=self.memory_store(),
                run_startup_check=False,
            )
            verifier.observe_key_rotation(rotation)

            with self.assertRaisesRegex(
                log_client.RootVerificationError, "old operator key after rotation overlap"
            ):
                verifier.current_mirrored_root(now=1_700_000_310)

    def test_old_historical_root_before_rotation_remains_verifiable(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log, old_private, old_public = self.make_log(temp_dir)
            new_private, new_public = keypair()
            log.append_entry_hash(ind_token.sha3_hex(b"entry"))
            old_root = self.signed_root_for_key(log, 1_700_000_100, old_private, old_public)
            rotation = log_client.make_key_rotation(
                old_private,
                old_public,
                new_private,
                new_public,
                rotation_timestamp=1_700_000_200,
                effective_from_tree_size=2,
                overlap_until_timestamp=1_700_000_300,
            )
            verifier = log_client.TransparencyVerifier(
                log_client.LocalTransparencyOperator(log),
                [
                    log_client.StaticRootMirror([old_root], identity_id="old-history-mirror-a"),
                    log_client.StaticRootMirror([old_root], identity_id="old-history-mirror-b"),
                ],
                operator_public_key=old_public,
                observed_root_store=self.memory_store(),
                run_startup_check=False,
            )
            verifier.observe_key_rotation(rotation)

            self.assertEqual(
                verifier.mirrored_root_for_timestamp(1_700_000_090)["root_hash"],
                old_root["root_hash"],
            )

    def test_key_revocation_references_prior_rotation_and_blacklists_old_key(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log, old_private, old_public = self.make_log(temp_dir)
            new_private, new_public = keypair()
            log.append_entry_hash(ind_token.sha3_hex(b"entry"))
            old_after_revocation = self.signed_root_for_key(
                log, 1_700_000_220, old_private, old_public
            )
            rotation = log_client.make_key_rotation(
                old_private,
                old_public,
                new_private,
                new_public,
                rotation_timestamp=1_700_000_000,
                effective_from_tree_size=1,
                overlap_until_timestamp=1_700_604_800,
            )
            revocation = log_client.make_key_revocation(
                new_private,
                rotation,
                revocation_timestamp=1_700_000_200,
            )
            verifier = log_client.TransparencyVerifier(
                log_client.LocalTransparencyOperator(log),
                [
                    log_client.StaticRootMirror(
                        [old_after_revocation], identity_id="revoked-mirror-a"
                    ),
                    log_client.StaticRootMirror(
                        [old_after_revocation], identity_id="revoked-mirror-b"
                    ),
                ],
                operator_public_key=old_public,
                observed_root_store=self.memory_store(),
                run_startup_check=False,
            )
            verifier.observe_key_rotation(rotation)
            verifier.observe_key_revocation(revocation)

            with self.assertRaisesRegex(log_client.RootVerificationError, "revoked operator key"):
                verifier.current_mirrored_root(now=1_700_000_230)

    def test_key_revocation_without_prior_rotation_is_rejected(self):
        old_private, old_public = keypair()
        new_private, new_public = keypair()
        rotation = log_client.make_key_rotation(
            old_private,
            old_public,
            new_private,
            new_public,
            rotation_timestamp=1_700_000_000,
            effective_from_tree_size=1,
        )
        revocation = log_client.make_key_revocation(
            new_private, rotation, revocation_timestamp=1_700_000_200
        )

        with self.assertRaisesRegex(log_client.KeyRevocationError, "unknown rotation"):
            self.memory_store().record_key_revocation(revocation)

    def test_hash_log_archive_manifest_links_export_to_signed_root(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log, private_key, public_key = self.make_log(temp_dir)
            log.append_entry_hash(ind_token.sha3_hex(b"entry"))
            root = log.publish_root(1_700_000_000)

            class Source:
                def entries(self, start, end, limit):
                    return log.entries(start=start, end=end, limit=limit), log.tree_size()

                def latest_root(self):
                    return root

            archive_dir = Path(temp_dir) / "archive"
            state_file = Path(temp_dir) / "state.json"
            hash_log_exporter.export_once(
                Source(),
                hash_log_exporter.StaticHashLogArchive(archive_dir, private_key, public_key),
                state_file,
                page_size=100,
            )
            manifest = ind_token._load_json(
                (archive_dir / "manifest.json").read_text(encoding="utf-8")
            )

            self.assertEqual(manifest["signed_root_hash"], root["root_hash"])
            self.assertIn("signature", manifest)

    def test_hash_log_archive_manifest_signature_verifies(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log, private_key, public_key = self.make_log(temp_dir)
            log.append_entry_hash(ind_token.sha3_hex(b"entry"))
            root = log.publish_root(1_700_000_000)

            class Source:
                def entries(self, start, end, limit):
                    return log.entries(start=start, end=end, limit=limit), log.tree_size()

                def latest_root(self):
                    return root

            archive_dir = Path(temp_dir) / "archive"
            hash_log_exporter.export_once(
                Source(),
                hash_log_exporter.StaticHashLogArchive(archive_dir, private_key, public_key),
                Path(temp_dir) / "state.json",
                page_size=100,
            )
            manifest_path = archive_dir / "manifest.json"
            manifest = ind_token._load_json(manifest_path.read_text(encoding="utf-8"))

            self.assertTrue(hash_log_exporter.verify_manifest_signature(manifest, public_key))
            result = audit_hash_log.verify_archive(
                manifest_path, archive_base=archive_dir, operator_public_key=public_key
            )

            self.assertTrue(result["archive_valid"])
            self.assertFalse(result["mirror_cross_checked"])
            mirror_dir = Path(temp_dir) / "mirror"
            mirror_dir.mkdir()
            (mirror_dir / "roots.jsonl").write_text(
                log_client.canonical_json(root) + "\n", encoding="utf-8"
            )
            mirrored = audit_hash_log.verify_archive(
                manifest_path,
                archive_base=archive_dir,
                operator_public_key=public_key,
                mirror=mirror_dir,
            )
            self.assertTrue(mirrored["mirror_cross_checked"])

    def test_hash_log_archive_tampered_segment_hash_is_detected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log, private_key, public_key = self.make_log(temp_dir)
            log.append_entry_hash(ind_token.sha3_hex(b"entry"))
            root = log.publish_root(1_700_000_000)

            class Source:
                def entries(self, start, end, limit):
                    return log.entries(start=start, end=end, limit=limit), log.tree_size()

                def latest_root(self):
                    return root

            archive_dir = Path(temp_dir) / "archive"
            hash_log_exporter.export_once(
                Source(),
                hash_log_exporter.StaticHashLogArchive(archive_dir, private_key, public_key),
                Path(temp_dir) / "state.json",
                page_size=100,
            )
            segment = next((archive_dir / "entries").glob("*.jsonl"))
            segment.write_text(
                log_client.canonical_json(
                    {
                        "leaf_index": 0,
                        "entry_hash": ind_token.sha3_hex(b"tampered"),
                        "submitted_at": 1,
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                audit_hash_log.ArchiveAuditVerificationError, "segment hash mismatch"
            ):
                audit_hash_log.verify_archive(
                    archive_dir / "manifest.json",
                    archive_base=archive_dir,
                    operator_public_key=public_key,
                )

    def test_hash_log_archive_top_level_signed_root_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log, private_key, public_key = self.make_log(temp_dir)
            log.append_entry_hash(ind_token.sha3_hex(b"entry"))
            root = log.publish_root(1_700_000_000)

            class Source:
                def entries(self, start, end, limit):
                    return log.entries(start=start, end=end, limit=limit), log.tree_size()

                def latest_root(self):
                    return root

            archive_dir = Path(temp_dir) / "archive"
            manifest_path = archive_dir / "manifest.json"
            hash_log_exporter.export_once(
                Source(),
                hash_log_exporter.StaticHashLogArchive(archive_dir, private_key, public_key),
                Path(temp_dir) / "state.json",
                page_size=100,
            )
            manifest = ind_token._load_json(manifest_path.read_text(encoding="utf-8"))
            manifest["signed_root_hash"] = "00" * 32
            manifest.pop("signature")
            manifest = hash_log_exporter.sign_manifest(manifest, private_key)

            with self.assertRaisesRegex(
                hash_log_exporter.HashLogExportError, "signed_root_hash does not match"
            ):
                hash_log_exporter.verify_manifest_signature(manifest, public_key)

    def test_hash_log_archive_wrong_signed_root_is_detected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log, private_key, public_key = self.make_log(temp_dir)
            log.append_entry_hash(ind_token.sha3_hex(b"first"))
            old_root = log.publish_root(1_700_000_000)
            log.append_entry_hash(ind_token.sha3_hex(b"second"))
            new_root = log.publish_root(1_700_000_060)

            class Source:
                def entries(self, start, end, limit):
                    return log.entries(start=start, end=end, limit=limit), log.tree_size()

                def latest_root(self):
                    return new_root

            archive_dir = Path(temp_dir) / "archive"
            manifest_path = archive_dir / "manifest.json"
            hash_log_exporter.export_once(
                Source(),
                hash_log_exporter.StaticHashLogArchive(archive_dir, private_key, public_key),
                Path(temp_dir) / "state.json",
                page_size=100,
            )
            manifest = ind_token._load_json(manifest_path.read_text(encoding="utf-8"))
            manifest["signed_root"] = old_root
            manifest["signed_root_tree_size"] = old_root["tree_size"]
            manifest["signed_root_hash"] = old_root["root_hash"]
            manifest["signed_root_timestamp"] = old_root["timestamp"]
            manifest["archived_entry_count"] = old_root["tree_size"]
            manifest["archive_id"] = hash_log_exporter.archive_id_for(
                manifest["log_id"],
                manifest["signed_root_tree_size"],
                manifest["signed_root_hash"],
                manifest["segments"],
                manifest["segment_hash_algorithm"],
            )
            manifest.pop("signature")
            manifest = hash_log_exporter.sign_manifest(manifest, private_key)
            manifest_path.write_text(log_client.canonical_json(manifest) + "\n", encoding="utf-8")

            with self.assertRaisesRegex(audit_hash_log.ArchiveAuditVerificationError, "tree_size"):
                audit_hash_log.verify_archive(
                    manifest_path, archive_base=archive_dir, operator_public_key=public_key
                )

    def test_hash_log_archive_entries_must_produce_claimed_root(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log, private_key, public_key = self.make_log(temp_dir)
            log.append_entry_hash(ind_token.sha3_hex(b"entry"))
            root = log.publish_root(1_700_000_000)

            class Source:
                def entries(self, start, end, limit):
                    return log.entries(start=start, end=end, limit=limit), log.tree_size()

                def latest_root(self):
                    return root

            archive_dir = Path(temp_dir) / "archive"
            manifest_path = archive_dir / "manifest.json"
            hash_log_exporter.export_once(
                Source(),
                hash_log_exporter.StaticHashLogArchive(archive_dir, private_key, public_key),
                Path(temp_dir) / "state.json",
                page_size=100,
            )
            segment = next((archive_dir / "entries").glob("*.jsonl"))
            tampered = (
                log_client.canonical_json(
                    {
                        "leaf_index": 0,
                        "entry_hash": ind_token.sha3_hex(b"other-entry"),
                        "submitted_at": 1,
                    }
                )
                + "\n"
            ).encode("utf-8")
            segment.write_bytes(tampered)
            manifest = ind_token._load_json(manifest_path.read_text(encoding="utf-8"))
            manifest["segments"][0]["segment_hash"] = hash_log_exporter.segment_hash(tampered)
            manifest["segments"][0]["byte_length"] = len(tampered)
            manifest["archive_id"] = hash_log_exporter.archive_id_for(
                manifest["log_id"],
                manifest["signed_root_tree_size"],
                manifest["signed_root_hash"],
                manifest["segments"],
                manifest["segment_hash_algorithm"],
            )
            manifest.pop("signature")
            manifest = hash_log_exporter.sign_manifest(manifest, private_key)
            manifest_path.write_text(log_client.canonical_json(manifest) + "\n", encoding="utf-8")

            with self.assertRaisesRegex(
                audit_hash_log.ArchiveAuditVerificationError, "do not produce"
            ):
                audit_hash_log.verify_archive(
                    manifest_path, archive_base=archive_dir, operator_public_key=public_key
                )

    def test_hash_log_archive_forged_manifest_signature_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log, private_key, public_key = self.make_log(temp_dir)
            attacker_private, _attacker_public = keypair()
            log.append_entry_hash(ind_token.sha3_hex(b"entry"))
            root = log.publish_root(1_700_000_000)

            class Source:
                def entries(self, start, end, limit):
                    return log.entries(start=start, end=end, limit=limit), log.tree_size()

                def latest_root(self):
                    return root

            archive_dir = Path(temp_dir) / "archive"
            manifest_path = archive_dir / "manifest.json"
            hash_log_exporter.export_once(
                Source(),
                hash_log_exporter.StaticHashLogArchive(archive_dir, private_key, public_key),
                Path(temp_dir) / "state.json",
                page_size=100,
            )
            manifest = ind_token._load_json(manifest_path.read_text(encoding="utf-8"))
            manifest.pop("signature")
            manifest = hash_log_exporter.sign_manifest(manifest, attacker_private)
            manifest_path.write_text(log_client.canonical_json(manifest) + "\n", encoding="utf-8")

            with self.assertRaisesRegex(
                audit_hash_log.ArchiveAuditVerificationError, "invalid archive manifest signature"
            ):
                audit_hash_log.verify_archive(
                    manifest_path, archive_base=archive_dir, operator_public_key=public_key
                )

    def test_replayed_old_root_is_rejected_for_current_verification(self):
        token = self.signed_transfer_token(timestamp=1_700_000_010)
        entry_hash = ind_token.transfer_hash(token["history"][-1])
        with tempfile.TemporaryDirectory() as temp_dir:
            log, _private_key, public_key = self.make_log(temp_dir)
            log.append_entry_hash(entry_hash)
            stale_root = log.publish_root(1_700_000_040)
            verifier = log_client.TransparencyVerifier(
                log_client.LocalTransparencyOperator(log),
                [
                    log_client.StaticRootMirror([stale_root], identity_id="stale-mirror-a"),
                    log_client.StaticRootMirror([stale_root], identity_id="stale-mirror-b"),
                ],
                operator_public_key=public_key,
                max_root_lag_seconds=60,
                observed_root_store=self.memory_store(),
                run_startup_check=False,
            )

            with self.assertRaises(ind_token.ValidationError):
                ind_token.verify_token(token, transparency_verifier=verifier, now=1_800_000_000)

    def test_old_root_can_be_used_for_historical_only_verification(self):
        token = self.signed_transfer_token(timestamp=1_700_000_010)
        with tempfile.TemporaryDirectory() as temp_dir:
            log, _private_key, public_key = self.make_log(temp_dir)
            log.append_transfer_announcement(ind_token.create_transfer_announcement(token))
            historical_root = log.publish_root(1_700_000_040)
            verifier = log_client.TransparencyVerifier(
                log_client.LocalTransparencyOperator(log),
                [
                    log_client.StaticRootMirror([historical_root], identity_id="history-mirror-a"),
                    log_client.StaticRootMirror([historical_root], identity_id="history-mirror-b"),
                ],
                operator_public_key=public_key,
                max_root_lag_seconds=60,
                observed_root_store=self.memory_store(),
                run_startup_check=False,
            )

            state = ind_token.verify_token(
                token,
                transparency_verifier=verifier,
                now=1_800_000_000,
                require_current_root=False,
            )

            self.assertEqual(state.sequence, 1)

    def test_current_root_with_smaller_tree_than_observed_is_rejected_without_blacklist(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log, _private_key, public_key = self.make_log(temp_dir)
            log.append_entry_hash(ind_token.sha3_hex(b"first"))
            old_root = log.publish_root(1_700_000_000)
            log.append_entry_hash(ind_token.sha3_hex(b"second"))
            new_root = log.publish_root(1_700_000_060)
            store = self.memory_store()
            verifier = log_client.TransparencyVerifier(
                log_client.LocalTransparencyOperator(log),
                [
                    log_client.StaticRootMirror([old_root], identity_id="replay-mirror-a"),
                    log_client.StaticRootMirror([old_root], identity_id="replay-mirror-b"),
                ],
                operator_public_key=public_key,
                observed_root_store=store,
                run_startup_check=False,
            )
            verifier.observe_root(new_root, ("custom", "baseline"))

            with self.assertRaisesRegex(log_client.RootVerificationError, "replayed an older tree"):
                verifier.current_mirrored_root(now=1_700_000_080)

            self.assertEqual(store.status(old_root["log_id"])["status"], "active")

    def test_operator_signed_current_rollback_blacklists_with_evidence(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log, private_key, public_key = self.make_log(temp_dir)
            log.append_entry_hash(ind_token.sha3_hex(b"first"))
            old_root = log.publish_root(1_700_000_000)
            log.append_entry_hash(ind_token.sha3_hex(b"second"))
            new_root = log.publish_root(1_700_000_060)
            rollback_root = log_client.make_signed_root(
                old_root["tree_size"],
                old_root["root_hash"],
                1_700_000_120,
                private_key,
                public_key,
            )
            store = self.memory_store()
            verifier = log_client.TransparencyVerifier(
                log_client.LocalTransparencyOperator(log),
                [
                    log_client.StaticRootMirror([rollback_root], identity_id="rollback-mirror-a"),
                    log_client.StaticRootMirror([rollback_root], identity_id="rollback-mirror-b"),
                ],
                operator_public_key=public_key,
                observed_root_store=store,
                run_startup_check=False,
            )
            verifier.observe_root(new_root, ("custom", "baseline"))

            with self.assertRaisesRegex(
                log_client.ConsistencyProofError, "CRITICAL transparency log consistency failure"
            ):
                verifier.current_mirrored_root(now=1_700_000_130)

            status = store.status(old_root["log_id"])
            self.assertEqual(status["status"], "blacklisted")
            self.assertTrue(status["evidence_id"] in store.failures)

    def test_future_dated_current_root_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log, _private_key, public_key = self.make_log(temp_dir)
            log.append_entry_hash(ind_token.sha3_hex(b"entry"))
            future_root = log.publish_root(1_700_000_200)
            verifier = log_client.TransparencyVerifier(
                log_client.LocalTransparencyOperator(log),
                [
                    log_client.StaticRootMirror([future_root], identity_id="future-mirror-a"),
                    log_client.StaticRootMirror([future_root], identity_id="future-mirror-b"),
                ],
                operator_public_key=public_key,
                observed_root_store=self.memory_store(),
                run_startup_check=False,
            )

            with self.assertRaisesRegex(log_client.RootVerificationError, "too far in the future"):
                verifier.current_mirrored_root(now=1_700_000_000)

    def test_strict_mode_rejects_overly_loose_current_root_age_at_startup(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log, _private_key, public_key = self.make_log(temp_dir)

            with self.assertRaisesRegex(
                log_client.TransparencyLogError, "IND_LOG_MAX_CURRENT_ROOT_AGE_SECONDS=601"
            ):
                log_client.TransparencyVerifier(
                    log_client.LocalTransparencyOperator(log),
                    [
                        log_client.StaticRootMirror([], identity_id="strict-age-mirror-a"),
                        log_client.StaticRootMirror([], identity_id="strict-age-mirror-b"),
                    ],
                    operator_public_key=public_key,
                    strict_mode=True,
                    max_current_root_age_seconds=601,
                    current_root_future_skew_seconds=120,
                    observed_root_store=self.memory_store(),
                    run_startup_check=False,
                )

    def test_current_root_future_skew_config_is_bounded_at_startup(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log, _private_key, public_key = self.make_log(temp_dir)
            mirrors = [
                log_client.StaticRootMirror([], identity_id="skew-mirror-a"),
                log_client.StaticRootMirror([], identity_id="skew-mirror-b"),
            ]

            with self.assertRaisesRegex(log_client.TransparencyLogError, "must be smaller"):
                log_client.TransparencyVerifier(
                    log_client.LocalTransparencyOperator(log),
                    mirrors,
                    operator_public_key=public_key,
                    max_current_root_age_seconds=120,
                    current_root_future_skew_seconds=120,
                    observed_root_store=self.memory_store(),
                    run_startup_check=False,
                )
            with self.assertRaisesRegex(log_client.TransparencyLogError, "hard ceiling"):
                log_client.TransparencyVerifier(
                    log_client.LocalTransparencyOperator(log),
                    mirrors,
                    operator_public_key=public_key,
                    max_current_root_age_seconds=600,
                    current_root_future_skew_seconds=301,
                    observed_root_store=self.memory_store(),
                    run_startup_check=False,
                )

    def test_consistency_accepts_valid_append_only_root(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log, _private_key, public_key = self.make_log(temp_dir)
            log.append_entry_hash(ind_token.sha3_hex(b"first"))
            old_root = log.publish_root(1_700_000_000)
            log.append_entry_hash(ind_token.sha3_hex(b"second"))
            new_root = log.publish_root(1_700_000_060)
            store = self.memory_store()
            verifier = log_client.TransparencyVerifier(
                log_client.LocalTransparencyOperator(log),
                [
                    log_client.StaticRootMirror([new_root], identity_id="append-mirror-a"),
                    log_client.StaticRootMirror([new_root], identity_id="append-mirror-b"),
                ],
                operator_public_key=public_key,
                observed_root_store=store,
                run_startup_check=False,
            )

            verifier.observe_root(old_root, ("custom", "baseline"))
            verifier.observe_root(new_root, ("custom", "append-mirror-a"))

            self.assertEqual(
                store.latest_root(old_root["log_id"])["root_hash"], new_root["root_hash"]
            )
            self.assertEqual(store.status(old_root["log_id"])["status"], "active")

    def test_inconsistent_new_root_blacklists_operator_and_preserves_evidence(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log, private_key, public_key = self.make_log(temp_dir)
            log.append_entry_hash(ind_token.sha3_hex(b"honest-first"))
            old_root = log.publish_root(1_700_000_000)
            evil_log = log_server.TransparencyLog(
                str(Path(temp_dir) / "evil.db"), private_key, public_key
            )
            evil_log.append_entry_hash(ind_token.sha3_hex(b"evil-first"))
            evil_log.append_entry_hash(ind_token.sha3_hex(b"evil-second"))
            evil_root = evil_log.publish_root(1_700_000_060)

            class EvilOperator:
                identity_id = ("custom", "evil-operator")

                def consistency_proof(self, first_tree_size, second_tree_size):
                    return evil_log.consistency_proof(first_tree_size, second_tree_size)

            store = self.memory_store()
            verifier = log_client.TransparencyVerifier(
                EvilOperator(),
                [
                    log_client.StaticRootMirror([evil_root], identity_id="evil-mirror-a"),
                    log_client.StaticRootMirror([evil_root], identity_id="evil-mirror-b"),
                ],
                operator_public_key=public_key,
                observed_root_store=store,
                run_startup_check=False,
            )
            verifier.observe_root(old_root, ("custom", "baseline"))

            with self.assertRaisesRegex(
                log_client.ConsistencyProofError, "CRITICAL transparency log consistency failure"
            ):
                verifier.observe_root(evil_root, ("custom", "evil-mirror-a"))

            status = store.status(old_root["log_id"])
            self.assertEqual(status["status"], "blacklisted")
            self.assertTrue(status["evidence_id"] in store.failures)

    def test_unreachable_operator_during_consistency_check_is_not_blacklisted(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log, _private_key, public_key = self.make_log(temp_dir)
            log.append_entry_hash(ind_token.sha3_hex(b"first"))
            old_root = log.publish_root(1_700_000_000)
            log.append_entry_hash(ind_token.sha3_hex(b"second"))
            new_root = log.publish_root(1_700_000_060)

            class DownOperator:
                identity_id = ("custom", "down-operator")

                def consistency_proof(self, first_tree_size, second_tree_size):
                    raise TimeoutError("operator unreachable")

            store = self.memory_store()
            verifier = log_client.TransparencyVerifier(
                DownOperator(),
                [
                    log_client.StaticRootMirror([new_root], identity_id="down-mirror-a"),
                    log_client.StaticRootMirror([new_root], identity_id="down-mirror-b"),
                ],
                operator_public_key=public_key,
                observed_root_store=store,
                run_startup_check=False,
            )
            verifier.observe_root(old_root, ("custom", "baseline"))

            with warnings.catch_warnings():
                warnings.simplefilter("ignore", RuntimeWarning)
                verifier.observe_root(new_root, ("custom", "down-mirror-a"))

            status = store.status(old_root["log_id"])
            self.assertEqual(status["status"], "unresponsive")
            self.assertIsNone(status["evidence_id"])

    def test_submission_claim_is_not_trusted_without_actual_append(self):
        token = self.signed_transfer_token(timestamp=1_700_000_010)
        announcement = ind_token.create_transfer_announcement(token)

        class DroppingSubmitter:
            def submit_transfer_announcement(self, message):
                return {"accepted": True, "tree_size": 999}

        with tempfile.TemporaryDirectory() as temp_dir:
            store = ind_token.INDLocalStore(
                str(Path(temp_dir) / "ind.db"),
                transparency_submitter=DroppingSubmitter(),
                transparency_verifier=object(),
                require_transparency=True,
                transparency_submission_verify_timeout_seconds=0,
            )

            with self.assertRaises(ind_token.ValidationError):
                store.ingest_message(announcement)

    def test_duplicate_claim_is_not_trusted_without_inclusion_proof(self):
        token = self.signed_transfer_token(timestamp=1_700_000_010)
        announcement = ind_token.create_transfer_announcement(token)
        entry_hash = ind_token.transfer_hash(token["history"][-1])

        class LyingDuplicateSubmitter:
            def submit_transfer_announcement(self, message):
                return {
                    "accepted": True,
                    "duplicate": True,
                    "entry_hash": entry_hash,
                    "leaf_index": 0,
                    "tree_size": 1,
                }

        class NoProofVerifier:
            def mirrored_root_containing_leaf(self, timestamp, leaf_index):
                raise log_client.RootVerificationError("no mirrored root contains the claimed leaf")

        with tempfile.TemporaryDirectory() as temp_dir:
            store = ind_token.INDLocalStore(
                str(Path(temp_dir) / "ind.db"),
                transparency_submitter=LyingDuplicateSubmitter(),
                transparency_verifier=NoProofVerifier(),
                require_transparency=True,
                transparency_submission_verify_timeout_seconds=0,
            )

            with self.assertRaises(ind_token.ValidationError):
                store.ingest_message(announcement)


if __name__ == "__main__":
    unittest.main()
