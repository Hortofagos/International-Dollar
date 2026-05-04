import copy
import contextlib
import json
import os
import sqlite3
import threading
import time
import urllib.parse
import urllib.request
import warnings
from pathlib import Path

from pymerkle import verify_consistency as pymerkle_verify_consistency
from pymerkle import verify_inclusion as pymerkle_verify_inclusion
from pymerkle.hasher import MerkleHasher
from pymerkle.proof import InvalidProof, MerkleProof

from . import token as ind_token


LOG_ROOT_TYPE = "ind.transparency_root.v1"
LOG_INCLUSION_PROOF_TYPE = "ind.transparency_inclusion_proof.v1"
LOG_CONSISTENCY_PROOF_TYPE = "ind.transparency_consistency_proof.v1"
LOG_ROOT_ANNOUNCEMENT_TYPE = "ind.transparency_root_announcement.v1"
LOG_EQUIVOCATION_PROOF_TYPE = "ind.transparency_equivocation_proof.v1"
LOG_KEY_ROTATION_TYPE = "ind.transparency_operator_key_rotation.v1"
LOG_KEY_REVOCATION_TYPE = "ind.transparency_operator_key_revocation.v1"
LOG_VERSION = 1
LOG_HASH_ALGORITHM = "sha3_256"
LOG_TREE_ALGORITHM = "CT_STYLE_SHA3_256_V1"
LEGACY_LOG_TREE_ALGORITHM = "RFC6962_SHA3_256_PYMERKLE_V1"
LOG_SIGNATURE_ALGORITHM = "ECDSA_SECP256K1_SHA3_256_BASE85"
LOG_ROOT_SIGNATURE_DOMAIN = "IND_TRANSPARENCY_ROOT_V1"
LOG_KEY_ROTATION_SIGNATURE_DOMAIN = "IND_TRANSPARENCY_KEY_ROTATION_V1"
LOG_KEY_REVOCATION_SIGNATURE_DOMAIN = "IND_TRANSPARENCY_KEY_REVOCATION_V1"
DEFAULT_MAX_ROOT_LAG_SECONDS = 120
DEFAULT_MAX_CURRENT_ROOT_AGE_SECONDS = 300
DEFAULT_CURRENT_ROOT_FUTURE_SKEW_SECONDS = 120
STRICT_MAX_CURRENT_ROOT_AGE_SECONDS = 600
MAX_CURRENT_ROOT_FUTURE_SKEW_SECONDS = 300
DEFAULT_MIN_ROOT_MIRRORS = 2
DEFAULT_OBSERVED_ROOTS_DB = "files/transparency_observed_roots.db"
DEFAULT_CONSISTENCY_CHECK_INTERVAL_SECONDS = 900
DEFAULT_CONSISTENCY_MAX_STALE_SECONDS = 3600
DEFAULT_KEY_ROTATION_OVERLAP_SECONDS = 7 * 24 * 60 * 60
DEFAULT_PEER_ROOT_CAP_PER_LOG_ID = 5000
DEFAULT_UNKNOWN_PEER_ROOT_CAP_PER_LOG_ID = 100
UNSAFE_SINGLE_MIRROR_ENV = "IND_LOG_UNSAFE_SINGLE_MIRROR"
ACCEPT_LEGACY_ALGORITHM_NAMES_ENV = "IND_LOG_ACCEPT_LEGACY_ALGORITHM_NAMES"
STRICT_UNSAFE_SINGLE_MIRROR_ERROR = (
    "IND_REQUIRE_TRANSPARENCY_LOG=1 and IND_LOG_UNSAFE_SINGLE_MIRROR=1 are incompatible. "
    "Strict transparency mode requires at least 2 independent root mirrors. "
    "Either configure additional mirrors or disable strict mode."
)


class TransparencyLogError(Exception):
    """Base error for IND transparency log verification failures."""


class RootVerificationError(TransparencyLogError):
    """Raised when a signed log root is malformed or has an invalid signature."""


class InclusionProofError(TransparencyLogError):
    """Raised when an inclusion proof does not resolve to a mirrored root."""


class ConsistencyProofError(TransparencyLogError):
    """Raised when a consistency proof does not link two signed roots."""


class MirrorDisagreementError(TransparencyLogError):
    """Raised when mirrors show valid conflicting roots for one log timestamp."""

    def __init__(self, evidence):
        self.evidence = evidence
        super().__init__("mirrors disagree about a signed transparency log root")


class ConsistencyUnavailableError(TransparencyLogError):
    """Raised when a consistency check cannot reach the operator."""


class KeyRotationError(TransparencyLogError):
    """Raised when an operator key rotation record is invalid."""


class KeyRevocationError(TransparencyLogError):
    """Raised when an operator key revocation record is invalid."""


def canonical_json(data):
    """Serialize transparency-log records in the canonical IND JSON form."""

    return ind_token.canonical_json(data)


def canonical_bytes(data):
    return canonical_json(data).encode("utf-8")


def _env_true(name):
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _env_false(name):
    return os.environ.get(name, "").strip().lower() in {"0", "false", "no", "off"}


def accept_legacy_algorithm_names():
    return not _env_false(ACCEPT_LEGACY_ALGORITHM_NAMES_ENV)


def accepted_tree_algorithms():
    algorithms = {LOG_TREE_ALGORITHM}
    # Deprecated: legacy signed roots used this misleading identifier before
    # the protocol clarified that IND is CT-style SHA3-256, not RFC 6962.
    if accept_legacy_algorithm_names():
        algorithms.add(LEGACY_LOG_TREE_ALGORITHM)
    return algorithms


def log_id_from_public_key(public_key_base85):
    """Derive the stable log id from the operator signing key."""

    return ind_token.sha3_hex(public_key_base85.strip().encode("utf-8"))


def root_signature_payload(root):
    """Return the bytes covered by the signed-root signature."""

    unsigned = copy.deepcopy(root)
    unsigned.pop("signature", None)
    return ind_token.signature_payload(LOG_ROOT_SIGNATURE_DOMAIN, unsigned)


def signed_root_id(root):
    """Return a stable id for one complete signed root record."""

    return ind_token.sha3_hex(canonical_bytes(root))


def _root_fingerprint(root):
    return (int(root["tree_size"]), root["root_hash"])


def equivocation_collision_type(root_a, root_b):
    """Return the collision type if two valid roots prove operator equivocation."""

    if root_a["log_id"] != root_b["log_id"]:
        return None
    if signed_root_id(root_a) == signed_root_id(root_b):
        return None
    if int(root_a["tree_size"]) == int(root_b["tree_size"]) and root_a["root_hash"] != root_b["root_hash"]:
        return "same_tree_size"
    if int(root_a["timestamp"]) == int(root_b["timestamp"]):
        if int(root_a["tree_size"]) != int(root_b["tree_size"]) or root_a["root_hash"] != root_b["root_hash"]:
            return "same_timestamp"
    return None


def make_signed_root(tree_size, root_hash, timestamp, private_key_base85, public_key_base85):
    """Build and sign a transparency log root record."""

    root = {
        "type": LOG_ROOT_TYPE,
        "version": LOG_VERSION,
        "log_id": log_id_from_public_key(public_key_base85),
        "tree_algorithm": LOG_TREE_ALGORITHM,
        "hash_algorithm": LOG_HASH_ALGORITHM,
        "signature_algorithm": LOG_SIGNATURE_ALGORITHM,
        "tree_size": int(tree_size),
        "root_hash": str(root_hash).lower(),
        "timestamp": int(timestamp),
        "operator_public_key": public_key_base85,
    }
    root["signature"] = ind_token.b85_sign(private_key_base85, root_signature_payload(root))
    return root


def verify_signed_root(root, operator_public_key=None):
    """Validate a signed root and its operator signature."""

    required = {
        "type",
        "version",
        "log_id",
        "tree_algorithm",
        "hash_algorithm",
        "signature_algorithm",
        "tree_size",
        "root_hash",
        "timestamp",
        "operator_public_key",
        "signature",
    }
    if not isinstance(root, dict) or not required.issubset(root):
        raise RootVerificationError("malformed signed transparency root")
    if root["type"] != LOG_ROOT_TYPE or int(root["version"]) != LOG_VERSION:
        raise RootVerificationError("unsupported transparency root version")
    if root["tree_algorithm"] not in accepted_tree_algorithms():
        raise RootVerificationError("unsupported transparency tree algorithm")
    if root["hash_algorithm"] != LOG_HASH_ALGORITHM:
        raise RootVerificationError("unsupported transparency hash algorithm")
    if root["signature_algorithm"] != LOG_SIGNATURE_ALGORITHM:
        raise RootVerificationError("unsupported transparency root signature algorithm")
    if int(root["tree_size"]) < 0:
        raise RootVerificationError("negative transparency tree size")
    if len(str(root["root_hash"])) != 64:
        raise RootVerificationError("invalid transparency root hash")
    try:
        bytes.fromhex(root["root_hash"])
    except ValueError as exc:
        raise RootVerificationError("invalid transparency root hash") from exc
    root_public_key = root["operator_public_key"].strip()
    if operator_public_key and root_public_key != operator_public_key.strip():
        raise RootVerificationError("transparency root was signed by an unexpected operator")
    if root["log_id"] != log_id_from_public_key(root_public_key):
        raise RootVerificationError("transparency root log id does not match operator key")
    if not ind_token.b85_verify(root_public_key, root["signature"], root_signature_payload(root)):
        raise RootVerificationError("invalid transparency root signature")
    return True


def make_root_announcement(root, observed_at=None):
    """Wrap a signed root in the peer gossip format."""

    verify_signed_root(root)
    return {
        "type": LOG_ROOT_ANNOUNCEMENT_TYPE,
        "version": LOG_VERSION,
        "root": copy.deepcopy(root),
        "observed_at": int(observed_at or time.time()),
    }


def verify_root_announcement(message, operator_public_key=None):
    """Validate a peer-gossiped signed root announcement."""

    if not isinstance(message, dict) or message.get("type") != LOG_ROOT_ANNOUNCEMENT_TYPE:
        raise RootVerificationError("not a transparency root announcement")
    if int(message.get("version", 0)) != LOG_VERSION:
        raise RootVerificationError("unsupported transparency root announcement version")
    root = message.get("root")
    verify_signed_root(root, operator_public_key=operator_public_key)
    int(message.get("observed_at", 0))
    return root


def make_equivocation_proof(root_a, root_b, collision_type=None, detected_at=None):
    """Build the peer-gossip proof that an operator signed conflicting roots."""

    verify_signed_root(root_a)
    verify_signed_root(root_b)
    collision_type = collision_type or equivocation_collision_type(root_a, root_b)
    if collision_type not in {"same_tree_size", "same_timestamp"}:
        raise MirrorDisagreementError({"root_a": root_a, "root_b": root_b})
    return {
        "type": LOG_EQUIVOCATION_PROOF_TYPE,
        "version": LOG_VERSION,
        "log_id": root_a["log_id"],
        "collision_type": collision_type,
        "root_a": copy.deepcopy(root_a),
        "root_b": copy.deepcopy(root_b),
        "detected_at": int(detected_at or time.time()),
    }


def verify_equivocation_proof(message, operator_public_key=None):
    """Validate a self-contained signed-root equivocation proof."""

    if not isinstance(message, dict) or message.get("type") != LOG_EQUIVOCATION_PROOF_TYPE:
        raise RootVerificationError("not a transparency equivocation proof")
    if int(message.get("version", 0)) != LOG_VERSION:
        raise RootVerificationError("unsupported transparency equivocation proof version")
    claimed_log_id = str(message.get("log_id", "")).strip()
    collision_type = message.get("collision_type")
    if collision_type not in {"same_tree_size", "same_timestamp"}:
        raise MirrorDisagreementError({"error": "unsupported transparency equivocation collision type"})
    root_a = message.get("root_a")
    root_b = message.get("root_b")
    verify_signed_root(root_a, operator_public_key=operator_public_key)
    verify_signed_root(root_b, operator_public_key=operator_public_key)
    public_key_a = root_a["operator_public_key"].strip()
    public_key_b = root_b["operator_public_key"].strip()
    if public_key_a != public_key_b:
        raise RootVerificationError("equivocation proof roots were signed by different operators")
    if root_a["log_id"] != claimed_log_id or root_b["log_id"] != claimed_log_id:
        raise RootVerificationError("equivocation proof log id does not match both roots")
    if log_id_from_public_key(public_key_a) != claimed_log_id:
        raise RootVerificationError("equivocation proof operator key does not derive the claimed log id")
    actual_collision = equivocation_collision_type(root_a, root_b)
    if actual_collision != collision_type:
        raise MirrorDisagreementError({"root_a": root_a, "root_b": root_b, "claimed": collision_type})
    return {
        "log_id": claimed_log_id,
        "collision_type": collision_type,
        "root_a": root_a,
        "root_b": root_b,
    }


def _without_signatures(record, signature_fields):
    unsigned = copy.deepcopy(record)
    for field in signature_fields:
        unsigned.pop(field, None)
    return unsigned


def key_rotation_signature_payload(record):
    return ind_token.signature_payload(
        LOG_KEY_ROTATION_SIGNATURE_DOMAIN,
        _without_signatures(record, {"signature_by_old_key", "signature_by_new_key"}),
    )


def key_rotation_id(record):
    return ind_token.sha3_hex(canonical_bytes(record))


def make_key_rotation(
    old_private_key,
    old_public_key,
    new_private_key,
    new_public_key,
    rotation_timestamp,
    effective_from_tree_size,
    overlap_until_timestamp=None,
    reason="scheduled",
    log_id=None,
):
    """Create a signed operator-key rotation record."""

    rotation_timestamp = int(rotation_timestamp)
    effective_from_tree_size = int(effective_from_tree_size)
    overlap_until_timestamp = int(
        overlap_until_timestamp
        if overlap_until_timestamp is not None
        else rotation_timestamp + DEFAULT_KEY_ROTATION_OVERLAP_SECONDS
    )
    old_public_key = old_public_key.strip()
    new_public_key = new_public_key.strip()
    record = {
        "type": LOG_KEY_ROTATION_TYPE,
        "version": LOG_VERSION,
        "log_id": log_id or log_id_from_public_key(old_public_key),
        "old_public_key": old_public_key,
        "new_public_key": new_public_key,
        "new_log_id": log_id_from_public_key(new_public_key),
        "rotation_timestamp": rotation_timestamp,
        "effective_from_tree_size": effective_from_tree_size,
        "overlap_until_timestamp": overlap_until_timestamp,
        "reason": str(reason or "scheduled"),
        "signature_algorithm": LOG_SIGNATURE_ALGORITHM,
    }
    payload = key_rotation_signature_payload(record)
    record["signature_by_old_key"] = ind_token.b85_sign(old_private_key, payload)
    record["signature_by_new_key"] = ind_token.b85_sign(new_private_key, payload)
    return record


def verify_key_rotation(record, expected_log_id=None, old_public_key=None, new_public_key=None):
    required = {
        "type",
        "version",
        "log_id",
        "old_public_key",
        "new_public_key",
        "new_log_id",
        "rotation_timestamp",
        "effective_from_tree_size",
        "overlap_until_timestamp",
        "reason",
        "signature_algorithm",
        "signature_by_old_key",
        "signature_by_new_key",
    }
    if not isinstance(record, dict) or not required.issubset(record):
        raise KeyRotationError("malformed transparency operator key rotation")
    if record["type"] != LOG_KEY_ROTATION_TYPE or int(record["version"]) != LOG_VERSION:
        raise KeyRotationError("unsupported transparency operator key rotation version")
    if record["signature_algorithm"] != LOG_SIGNATURE_ALGORITHM:
        raise KeyRotationError("unsupported transparency operator key rotation signature algorithm")
    if expected_log_id and record["log_id"] != expected_log_id:
        raise KeyRotationError("operator key rotation is for an unexpected log id")
    if old_public_key and record["old_public_key"].strip() != old_public_key.strip():
        raise KeyRotationError("operator key rotation old key does not match expected key")
    if new_public_key and record["new_public_key"].strip() != new_public_key.strip():
        raise KeyRotationError("operator key rotation new key does not match expected key")
    if record["log_id"] != log_id_from_public_key(record["old_public_key"].strip()):
        raise KeyRotationError("operator key rotation log id does not match old key")
    if record["new_log_id"] != log_id_from_public_key(record["new_public_key"].strip()):
        raise KeyRotationError("operator key rotation new log id does not match new key")
    if int(record["effective_from_tree_size"]) < 0:
        raise KeyRotationError("operator key rotation has negative effective tree size")
    if int(record["overlap_until_timestamp"]) < int(record["rotation_timestamp"]):
        raise KeyRotationError("operator key rotation overlap ends before rotation timestamp")
    payload = key_rotation_signature_payload(record)
    if not ind_token.b85_verify(record["old_public_key"].strip(), record["signature_by_old_key"], payload):
        raise KeyRotationError("invalid operator key rotation old-key signature")
    if not ind_token.b85_verify(record["new_public_key"].strip(), record["signature_by_new_key"], payload):
        raise KeyRotationError("invalid operator key rotation new-key signature")
    return True


def key_revocation_signature_payload(record):
    return ind_token.signature_payload(
        LOG_KEY_REVOCATION_SIGNATURE_DOMAIN,
        _without_signatures(record, {"signature_by_successor_key"}),
    )


def key_revocation_id(record):
    return ind_token.sha3_hex(canonical_bytes(record))


def make_key_revocation(
    successor_private_key,
    rotation_record,
    revocation_timestamp,
    reason="compromise",
):
    verify_key_rotation(rotation_record)
    record = {
        "type": LOG_KEY_REVOCATION_TYPE,
        "version": LOG_VERSION,
        "log_id": rotation_record["log_id"],
        "revoked_public_key": rotation_record["old_public_key"],
        "successor_public_key": rotation_record["new_public_key"],
        "rotation_record_hash": key_rotation_id(rotation_record),
        "revocation_timestamp": int(revocation_timestamp),
        "reason": str(reason or "compromise"),
        "signature_algorithm": LOG_SIGNATURE_ALGORITHM,
    }
    record["signature_by_successor_key"] = ind_token.b85_sign(
        successor_private_key,
        key_revocation_signature_payload(record),
    )
    return record


def verify_key_revocation(record, rotation_record=None):
    required = {
        "type",
        "version",
        "log_id",
        "revoked_public_key",
        "successor_public_key",
        "rotation_record_hash",
        "revocation_timestamp",
        "reason",
        "signature_algorithm",
        "signature_by_successor_key",
    }
    if not isinstance(record, dict) or not required.issubset(record):
        raise KeyRevocationError("malformed transparency operator key revocation")
    if record["type"] != LOG_KEY_REVOCATION_TYPE or int(record["version"]) != LOG_VERSION:
        raise KeyRevocationError("unsupported transparency operator key revocation version")
    if record["signature_algorithm"] != LOG_SIGNATURE_ALGORITHM:
        raise KeyRevocationError("unsupported transparency operator key revocation signature algorithm")
    if record["log_id"] != log_id_from_public_key(record["revoked_public_key"].strip()):
        raise KeyRevocationError("operator key revocation log id does not match revoked key")
    if not ind_token.b85_verify(
        record["successor_public_key"].strip(),
        record["signature_by_successor_key"],
        key_revocation_signature_payload(record),
    ):
        raise KeyRevocationError("invalid operator key revocation successor-key signature")
    if rotation_record is not None:
        verify_key_rotation(rotation_record)
        if record["rotation_record_hash"] != key_rotation_id(rotation_record):
            raise KeyRevocationError("operator key revocation does not reference the supplied rotation")
        if record["log_id"] != rotation_record["log_id"]:
            raise KeyRevocationError("operator key revocation log id does not match rotation")
        if record["revoked_public_key"] != rotation_record["old_public_key"]:
            raise KeyRevocationError("operator key revocation old key does not match rotation")
        if record["successor_public_key"] != rotation_record["new_public_key"]:
            raise KeyRevocationError("operator key revocation successor key does not match rotation")
    return True


def _entry_hash_bytes(entry_hash):
    entry_hash = str(entry_hash).lower()
    if len(entry_hash) != 64:
        raise InclusionProofError("invalid transparency entry hash")
    try:
        return bytes.fromhex(entry_hash)
    except ValueError as exc:
        raise InclusionProofError("invalid transparency entry hash") from exc


def log_leaf_hash(entry_hash):
    """Return the CT-style SHA3-256 leaf hash for a transfer entry hash."""

    return MerkleHasher(LOG_HASH_ALGORITHM, True).hash_buff(_entry_hash_bytes(entry_hash))


def transfer_entry_hash(transfer):
    """Return the log entry hash for a signed transfer."""

    return ind_token.transfer_hash(transfer)


def verify_inclusion_proof(entry_hash, proof_response, signed_root, operator_public_key=None):
    """Verify that an entry is included in the signed mirrored tree root."""

    verify_signed_root(signed_root, operator_public_key=operator_public_key)
    required = {"type", "version", "log_id", "entry_hash", "leaf_hash", "leaf_index", "tree_size", "proof"}
    if not isinstance(proof_response, dict) or not required.issubset(proof_response):
        raise InclusionProofError("malformed transparency inclusion proof")
    if proof_response["type"] != LOG_INCLUSION_PROOF_TYPE or int(proof_response["version"]) != LOG_VERSION:
        raise InclusionProofError("unsupported transparency inclusion proof version")
    if proof_response["log_id"] != signed_root["log_id"]:
        raise InclusionProofError("inclusion proof is for a different transparency log")
    if int(proof_response["tree_size"]) != int(signed_root["tree_size"]):
        raise InclusionProofError("inclusion proof tree size does not match mirrored root")
    if int(proof_response["leaf_index"]) < 0:
        raise InclusionProofError("invalid transparency leaf index")
    entry_hash = str(entry_hash).lower()
    if str(proof_response["entry_hash"]).lower() != entry_hash:
        raise InclusionProofError("inclusion proof is for a different entry")

    leaf_hash = log_leaf_hash(entry_hash)
    if proof_response["leaf_hash"] != leaf_hash.hex():
        raise InclusionProofError("inclusion proof leaf hash mismatch")

    proof = MerkleProof.deserialize(proof_response["proof"])
    if proof.algorithm != LOG_HASH_ALGORITHM or not proof.security:
        raise InclusionProofError("unsupported transparency proof hash settings")
    if int(proof.size) != int(signed_root["tree_size"]):
        raise InclusionProofError("inclusion proof metadata tree size mismatch")
    try:
        pymerkle_verify_inclusion(leaf_hash, bytes.fromhex(signed_root["root_hash"]), proof)
    except (InvalidProof, ValueError) as exc:
        raise InclusionProofError(str(exc)) from exc
    return True


def verify_consistency_proof(
    old_root,
    new_root,
    proof_response,
    operator_public_key=None,
    allow_log_id_transition=False,
):
    """Verify that new_root is an append-only extension of old_root."""

    verify_signed_root(old_root, operator_public_key=operator_public_key)
    verify_signed_root(new_root, operator_public_key=operator_public_key)
    if old_root["log_id"] != new_root["log_id"] and not allow_log_id_transition:
        raise ConsistencyProofError("consistency roots are for different transparency logs")
    old_size = int(old_root["tree_size"])
    new_size = int(new_root["tree_size"])
    if new_size < old_size:
        raise ConsistencyProofError("transparency tree size went backwards")
    if old_size == new_size:
        if old_root["root_hash"] != new_root["root_hash"]:
            raise ConsistencyProofError("same-size transparency roots disagree")
        return True
    if old_size == 0:
        return True

    required = {"type", "version", "log_id", "first_tree_size", "second_tree_size", "proof"}
    if not isinstance(proof_response, dict) or not required.issubset(proof_response):
        raise ConsistencyProofError("malformed transparency consistency proof")
    if proof_response["type"] != LOG_CONSISTENCY_PROOF_TYPE or int(proof_response["version"]) != LOG_VERSION:
        raise ConsistencyProofError("unsupported transparency consistency proof version")
    allowed_proof_log_ids = {old_root["log_id"]}
    if allow_log_id_transition:
        allowed_proof_log_ids.add(new_root["log_id"])
    if proof_response["log_id"] not in allowed_proof_log_ids:
        raise ConsistencyProofError("consistency proof is for a different transparency log")
    if int(proof_response["first_tree_size"]) != old_size:
        raise ConsistencyProofError("consistency proof first tree size mismatch")
    if int(proof_response["second_tree_size"]) != new_size:
        raise ConsistencyProofError("consistency proof second tree size mismatch")

    proof = MerkleProof.deserialize(proof_response["proof"])
    if proof.algorithm != LOG_HASH_ALGORITHM or not proof.security:
        raise ConsistencyProofError("unsupported transparency proof hash settings")
    if int(proof.size) != new_size:
        raise ConsistencyProofError("consistency proof metadata tree size mismatch")
    try:
        pymerkle_verify_consistency(
            bytes.fromhex(old_root["root_hash"]),
            bytes.fromhex(new_root["root_hash"]),
            proof,
        )
    except (InvalidProof, ValueError) as exc:
        raise ConsistencyProofError(str(exc)) from exc
    return True


def detect_mirror_disagreement(roots, operator_public_key=None):
    """Raise if mirrors expose two valid roots for one log id timestamp or tree size."""

    by_timestamp = {}
    by_tree_size = {}
    for root in roots:
        verify_signed_root(root, operator_public_key=operator_public_key)
        timestamp_key = (root["log_id"], int(root["timestamp"]))
        tree_size_key = (root["log_id"], int(root["tree_size"]))
        fingerprint = _root_fingerprint(root)
        previous = by_timestamp.get(timestamp_key)
        if previous and previous["fingerprint"] != fingerprint:
            evidence = {
                "log_id": root["log_id"],
                "collision_type": "same_timestamp",
                "timestamp": int(root["timestamp"]),
                "root_a": previous["root"],
                "root_b": root,
            }
            raise MirrorDisagreementError(evidence)
        previous = by_tree_size.get(tree_size_key)
        if previous and previous["root"]["root_hash"] != root["root_hash"]:
            evidence = {
                "log_id": root["log_id"],
                "collision_type": "same_tree_size",
                "tree_size": int(root["tree_size"]),
                "root_a": previous["root"],
                "root_b": root,
            }
            raise MirrorDisagreementError(evidence)
        by_timestamp[timestamp_key] = {"fingerprint": fingerprint, "root": root}
        by_tree_size[tree_size_key] = {"fingerprint": fingerprint, "root": root}
    return True


def _effective_port(parsed_url):
    try:
        port = parsed_url.port
    except ValueError as exc:
        raise TransparencyLogError("invalid transparency source port") from exc
    if port is not None:
        return int(port)
    if parsed_url.scheme.lower() == "https":
        return 443
    return 80


def _http_origin_identity(url):
    parsed = urllib.parse.urlparse(str(url).strip())
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        return None
    host = (parsed.hostname or "").strip().lower().rstrip(".")
    if not host:
        raise TransparencyLogError(f"invalid transparency source URL: {url}")
    return ("http-origin", f"{scheme}://{host}:{_effective_port(parsed)}")


def _directory_identity(path):
    resolved = Path(str(path)).expanduser().resolve(strict=False)
    return ("directory", os.path.normcase(str(resolved)))


def _configured_identity(source):
    identity = getattr(source, "identity_id", None)
    if identity is None:
        identity = getattr(source, "source_identity", None)
    if callable(identity):
        identity = identity()
    if identity is None:
        return None
    identity = str(identity).strip()
    if not identity:
        return None
    return ("custom", identity)


def transparency_source_identity(source):
    """Return the source identity used for mirror independence checks."""

    if isinstance(source, str):
        origin = _http_origin_identity(source)
        if origin:
            return origin
        return _directory_identity(source)
    if isinstance(source, HTTPTransparencyOperator):
        return source.identity_id
    if isinstance(source, HTTPRootMirror):
        return source.identity_id
    if isinstance(source, DirectoryRootMirror):
        return source.identity_id
    if isinstance(source, LocalTransparencyOperator):
        return source.identity_id
    return _configured_identity(source)


def _identity_label(identity):
    return f"{identity[0]} {identity[1]}"


def _source_label(source):
    if isinstance(source, str):
        return source
    return source.__class__.__name__


def _identity_text(identity):
    if isinstance(identity, (list, tuple)) and len(identity) == 2:
        return _identity_label(tuple(identity))
    return str(identity)


def _status_row_to_dict(row):
    if row is None:
        return None
    return {
        "log_id": row["log_id"],
        "operator_public_key": row["operator_public_key"],
        "status": row["status"],
        "reason": row["reason"],
        "evidence_id": row["evidence_id"],
        "updated_at": row["updated_at"],
        "last_successful_consistency_at": row["last_successful_consistency_at"],
    }


class SQLiteObservedRootStore:
    """Persistent observed-root store used to enforce append-only consistency."""

    def __init__(self, path=DEFAULT_OBSERVED_ROOTS_DB):
        self.path = str(Path(path))
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self):
        conn = sqlite3.connect(self.path, timeout=5)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _with_retry(self, action):
        for attempt in range(2):
            try:
                return action()
            except sqlite3.OperationalError as exc:
                if attempt == 0 and "locked" in str(exc).lower():
                    time.sleep(0.2)
                    continue
                raise

    def _init_db(self):
        def action():
            with contextlib.closing(self._connect()) as conn, conn:
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS observed_roots (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        log_id TEXT NOT NULL,
                        tree_size INTEGER NOT NULL,
                        root_hash TEXT NOT NULL,
                        timestamp INTEGER NOT NULL,
                        signature TEXT NOT NULL,
                        operator_public_key TEXT NOT NULL,
                        source_identity TEXT NOT NULL,
                        signed_root_json TEXT NOT NULL,
                        observed_at INTEGER NOT NULL,
                        consistency_checked_at INTEGER,
                        UNIQUE(log_id, tree_size, root_hash, source_identity)
                    );
                    CREATE INDEX IF NOT EXISTS idx_observed_roots_latest
                    ON observed_roots(log_id, tree_size, timestamp);

                    CREATE TABLE IF NOT EXISTS consistency_failures (
                        evidence_id TEXT PRIMARY KEY,
                        log_id TEXT NOT NULL,
                        old_tree_size INTEGER NOT NULL,
                        old_root_hash TEXT NOT NULL,
                        old_root_json TEXT NOT NULL,
                        new_tree_size INTEGER NOT NULL,
                        new_root_hash TEXT NOT NULL,
                        new_root_json TEXT NOT NULL,
                        error TEXT NOT NULL,
                        detected_at INTEGER NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS peer_observed_roots (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        root_id TEXT NOT NULL,
                        log_id TEXT NOT NULL,
                        tree_size INTEGER NOT NULL,
                        root_hash TEXT NOT NULL,
                        timestamp INTEGER NOT NULL,
                        signature TEXT NOT NULL,
                        operator_public_key TEXT NOT NULL,
                        signed_root_json TEXT NOT NULL,
                        peer_id TEXT NOT NULL,
                        message_hash TEXT NOT NULL,
                        received_at INTEGER NOT NULL,
                        UNIQUE(root_id, peer_id)
                    );
                    CREATE INDEX IF NOT EXISTS idx_peer_observed_roots_log
                    ON peer_observed_roots(log_id, tree_size, timestamp);
                    CREATE INDEX IF NOT EXISTS idx_peer_observed_roots_peer
                    ON peer_observed_roots(peer_id, log_id, received_at);

                    CREATE TABLE IF NOT EXISTS equivocation_evidence (
                        evidence_id TEXT PRIMARY KEY,
                        log_id TEXT NOT NULL,
                        collision_type TEXT NOT NULL,
                        root_a_id TEXT NOT NULL,
                        root_b_id TEXT NOT NULL,
                        root_a_json TEXT NOT NULL,
                        root_b_json TEXT NOT NULL,
                        detected_at INTEGER NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS operator_key_rotations (
                        rotation_record_hash TEXT PRIMARY KEY,
                        log_id TEXT NOT NULL,
                        old_public_key TEXT NOT NULL,
                        new_public_key TEXT NOT NULL,
                        new_log_id TEXT NOT NULL,
                        effective_from_tree_size INTEGER NOT NULL,
                        rotation_timestamp INTEGER NOT NULL,
                        overlap_until_timestamp INTEGER NOT NULL,
                        signed_record_json TEXT NOT NULL,
                        observed_at INTEGER NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_operator_key_rotations_log
                    ON operator_key_rotations(log_id, effective_from_tree_size);
                    CREATE INDEX IF NOT EXISTS idx_operator_key_rotations_new_log
                    ON operator_key_rotations(new_log_id);

                    CREATE TABLE IF NOT EXISTS operator_key_revocations (
                        revocation_record_hash TEXT PRIMARY KEY,
                        log_id TEXT NOT NULL,
                        revoked_public_key TEXT NOT NULL,
                        successor_public_key TEXT NOT NULL,
                        rotation_record_hash TEXT NOT NULL,
                        revocation_timestamp INTEGER NOT NULL,
                        signed_record_json TEXT NOT NULL,
                        observed_at INTEGER NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_operator_key_revocations_key
                    ON operator_key_revocations(log_id, revoked_public_key);

                    CREATE TABLE IF NOT EXISTS operator_status (
                        log_id TEXT PRIMARY KEY,
                        operator_public_key TEXT,
                        status TEXT NOT NULL,
                        reason TEXT,
                        evidence_id TEXT,
                        updated_at INTEGER NOT NULL,
                        last_successful_consistency_at INTEGER
                    );
                    """
                )

        self._with_retry(action)

    def evidence_location(self):
        return self.path

    def record_root(self, root, source_identity, observed_at=None, consistency_checked_at=None):
        observed_at = int(observed_at or time.time())
        source_identity = _identity_text(source_identity)
        signed_root_json = canonical_json(root)

        def action():
            with contextlib.closing(self._connect()) as conn, conn:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO observed_roots (
                        log_id, tree_size, root_hash, timestamp, signature,
                        operator_public_key, source_identity, signed_root_json,
                        observed_at, consistency_checked_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        root["log_id"],
                        int(root["tree_size"]),
                        root["root_hash"],
                        int(root["timestamp"]),
                        root["signature"],
                        root["operator_public_key"],
                        source_identity,
                        signed_root_json,
                        observed_at,
                        consistency_checked_at,
                    ),
                )
                if consistency_checked_at is not None:
                    conn.execute(
                        """
                        UPDATE observed_roots
                        SET consistency_checked_at = ?
                        WHERE log_id = ? AND tree_size = ? AND root_hash = ?
                        """,
                        (int(consistency_checked_at), root["log_id"], int(root["tree_size"]), root["root_hash"]),
                    )

        self._with_retry(action)

    def latest_root(self, log_id):
        def action():
            with contextlib.closing(self._connect()) as conn, conn:
                row = conn.execute(
                    """
                    SELECT signed_root_json FROM observed_roots
                    WHERE log_id = ?
                    ORDER BY tree_size DESC, timestamp DESC, id DESC
                    LIMIT 1
                    """,
                    (log_id,),
                ).fetchone()
            return json.loads(row["signed_root_json"]) if row else None

        return self._with_retry(action)

    def observed_position(self, log_id):
        def action():
            with contextlib.closing(self._connect()) as conn, conn:
                row = conn.execute(
                    """
                    SELECT MAX(tree_size) AS highest_tree_size, MAX(timestamp) AS latest_timestamp
                    FROM observed_roots
                    WHERE log_id = ?
                    """,
                    (log_id,),
                ).fetchone()
            if not row or row["highest_tree_size"] is None:
                return None
            return {
                "highest_tree_size": int(row["highest_tree_size"]),
                "latest_timestamp": int(row["latest_timestamp"]),
            }

        return self._with_retry(action)

    def known_log_ids(self):
        def action():
            with contextlib.closing(self._connect()) as conn, conn:
                rows = conn.execute(
                    """
                    SELECT log_id FROM observed_roots
                    UNION
                    SELECT log_id FROM peer_observed_roots
                    """
                ).fetchall()
            return [row["log_id"] for row in rows]

        return self._with_retry(action)

    def roots_for_log(self, log_id):
        def action():
            with contextlib.closing(self._connect()) as conn, conn:
                rows = conn.execute(
                    """
                    SELECT signed_root_json FROM observed_roots WHERE log_id = ?
                    UNION
                    SELECT signed_root_json FROM peer_observed_roots WHERE log_id = ?
                    """,
                    (log_id, log_id),
                ).fetchall()
            return [json.loads(row["signed_root_json"]) for row in rows]

        return self._with_retry(action)

    def find_equivocation(self, root):
        root_id = signed_root_id(root)
        for previous in self.roots_for_log(root["log_id"]):
            if signed_root_id(previous) == root_id:
                continue
            collision_type = equivocation_collision_type(previous, root)
            if collision_type:
                return {
                    "collision_type": collision_type,
                    "root_a": previous,
                    "root_b": root,
                }
        return None

    def record_key_rotation(self, record, observed_at=None):
        verify_key_rotation(record)
        observed_at = int(observed_at or time.time())
        record_hash = key_rotation_id(record)
        signed_record_json = canonical_json(record)

        def action():
            with contextlib.closing(self._connect()) as conn, conn:
                existing = conn.execute(
                    "SELECT rotation_record_hash FROM operator_key_rotations WHERE rotation_record_hash = ?",
                    (record_hash,),
                ).fetchone()
                if existing:
                    return record_hash
                latest = conn.execute(
                    """
                    SELECT effective_from_tree_size FROM operator_key_rotations
                    WHERE log_id = ?
                    ORDER BY effective_from_tree_size DESC
                    LIMIT 1
                    """,
                    (record["log_id"],),
                ).fetchone()
                effective = int(record["effective_from_tree_size"])
                if latest and effective <= int(latest["effective_from_tree_size"]):
                    raise KeyRotationError(
                        "operator key rotation records must be strictly monotonic in effective_from_tree_size"
                    )
                conn.execute(
                    """
                    INSERT INTO operator_key_rotations (
                        rotation_record_hash, log_id, old_public_key, new_public_key, new_log_id,
                        effective_from_tree_size, rotation_timestamp, overlap_until_timestamp,
                        signed_record_json, observed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record_hash,
                        record["log_id"],
                        record["old_public_key"],
                        record["new_public_key"],
                        record["new_log_id"],
                        int(record["effective_from_tree_size"]),
                        int(record["rotation_timestamp"]),
                        int(record["overlap_until_timestamp"]),
                        signed_record_json,
                        observed_at,
                    ),
                )
                return record_hash

        return self._with_retry(action)

    def key_rotation_by_hash(self, record_hash):
        def action():
            with contextlib.closing(self._connect()) as conn, conn:
                row = conn.execute(
                    "SELECT signed_record_json FROM operator_key_rotations WHERE rotation_record_hash = ?",
                    (record_hash,),
                ).fetchone()
            return json.loads(row["signed_record_json"]) if row else None

        return self._with_retry(action)

    def key_rotations_for_log(self, log_id):
        def action():
            with contextlib.closing(self._connect()) as conn, conn:
                rows = conn.execute(
                    """
                    SELECT signed_record_json FROM operator_key_rotations
                    WHERE log_id = ?
                    ORDER BY effective_from_tree_size ASC
                    """,
                    (log_id,),
                ).fetchall()
            return [json.loads(row["signed_record_json"]) for row in rows]

        return self._with_retry(action)

    def key_rotation_for_successor_log_id(self, new_log_id):
        def action():
            with contextlib.closing(self._connect()) as conn, conn:
                row = conn.execute(
                    """
                    SELECT signed_record_json FROM operator_key_rotations
                    WHERE new_log_id = ?
                    ORDER BY effective_from_tree_size DESC
                    LIMIT 1
                    """,
                    (new_log_id,),
                ).fetchone()
            return json.loads(row["signed_record_json"]) if row else None

        return self._with_retry(action)

    def record_key_revocation(self, record, observed_at=None):
        rotation = self.key_rotation_by_hash(record.get("rotation_record_hash", ""))
        if not rotation:
            raise KeyRevocationError("operator key revocation references an unknown rotation record")
        verify_key_revocation(record, rotation_record=rotation)
        observed_at = int(observed_at or time.time())
        record_hash = key_revocation_id(record)

        def action():
            with contextlib.closing(self._connect()) as conn, conn:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO operator_key_revocations (
                        revocation_record_hash, log_id, revoked_public_key, successor_public_key,
                        rotation_record_hash, revocation_timestamp, signed_record_json, observed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record_hash,
                        record["log_id"],
                        record["revoked_public_key"],
                        record["successor_public_key"],
                        record["rotation_record_hash"],
                        int(record["revocation_timestamp"]),
                        canonical_json(record),
                        observed_at,
                    ),
                )
                return record_hash

        return self._with_retry(action)

    def key_revocation_for_key(self, log_id, public_key):
        def action():
            with contextlib.closing(self._connect()) as conn, conn:
                row = conn.execute(
                    """
                    SELECT signed_record_json FROM operator_key_revocations
                    WHERE log_id = ? AND revoked_public_key = ?
                    ORDER BY revocation_timestamp DESC
                    LIMIT 1
                    """,
                    (log_id, public_key),
                ).fetchone()
            return json.loads(row["signed_record_json"]) if row else None

        return self._with_retry(action)

    def status(self, log_id):
        def action():
            with contextlib.closing(self._connect()) as conn, conn:
                row = conn.execute("SELECT * FROM operator_status WHERE log_id = ?", (log_id,)).fetchone()
            return _status_row_to_dict(row)

        return self._with_retry(action)

    def mark_active(self, log_id, operator_public_key, checked_at=None):
        checked_at = int(checked_at or time.time())

        def action():
            with contextlib.closing(self._connect()) as conn, conn:
                conn.execute(
                    """
                    INSERT INTO operator_status (
                        log_id, operator_public_key, status, reason, evidence_id,
                        updated_at, last_successful_consistency_at
                    ) VALUES (?, ?, 'active', NULL, NULL, ?, ?)
                    ON CONFLICT(log_id) DO UPDATE SET
                        operator_public_key = excluded.operator_public_key,
                        status = 'active',
                        reason = NULL,
                        evidence_id = NULL,
                        updated_at = excluded.updated_at,
                        last_successful_consistency_at = excluded.last_successful_consistency_at
                    """,
                    (log_id, operator_public_key, checked_at, checked_at),
                )

        self._with_retry(action)

    def mark_unresponsive(self, log_id, operator_public_key, reason, updated_at=None):
        updated_at = int(updated_at or time.time())

        def action():
            with contextlib.closing(self._connect()) as conn, conn:
                conn.execute(
                    """
                    INSERT INTO operator_status (
                        log_id, operator_public_key, status, reason, evidence_id,
                        updated_at, last_successful_consistency_at
                    ) VALUES (?, ?, 'unresponsive', ?, NULL, ?, NULL)
                    ON CONFLICT(log_id) DO UPDATE SET
                        operator_public_key = excluded.operator_public_key,
                        status = CASE WHEN operator_status.status = 'blacklisted' THEN 'blacklisted' ELSE 'unresponsive' END,
                        reason = excluded.reason,
                        updated_at = excluded.updated_at
                    """,
                    (log_id, operator_public_key, str(reason), updated_at),
                )

        self._with_retry(action)

    def save_consistency_failure(self, old_root, new_root, error, detected_at=None):
        detected_at = int(detected_at or time.time())
        evidence = {
            "type": "ind.transparency_consistency_failure.v1",
            "version": 1,
            "log_id": old_root["log_id"],
            "old_root": old_root,
            "new_root": new_root,
            "error": str(error),
            "detected_at": detected_at,
        }
        evidence_id = ind_token.sha3_hex(canonical_bytes(evidence))

        def action():
            with contextlib.closing(self._connect()) as conn, conn:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO consistency_failures (
                        evidence_id, log_id, old_tree_size, old_root_hash, old_root_json,
                        new_tree_size, new_root_hash, new_root_json, error, detected_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        evidence_id,
                        old_root["log_id"],
                        int(old_root["tree_size"]),
                        old_root["root_hash"],
                        canonical_json(old_root),
                        int(new_root["tree_size"]),
                        new_root["root_hash"],
                        canonical_json(new_root),
                        str(error),
                        detected_at,
                    ),
                )
            return evidence_id

        return self._with_retry(action)

    def record_peer_root(
        self,
        root,
        peer_id,
        message_hash,
        received_at=None,
        max_roots_for_log=DEFAULT_PEER_ROOT_CAP_PER_LOG_ID,
        max_total_roots_for_log=None,
    ):
        received_at = int(received_at or time.time())
        root_id = signed_root_id(root)
        peer_id = str(peer_id or "unknown-peer")
        message_hash = str(message_hash or root_id)

        def action():
            with contextlib.closing(self._connect()) as conn, conn:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO peer_observed_roots (
                        root_id, log_id, tree_size, root_hash, timestamp, signature,
                        operator_public_key, signed_root_json, peer_id, message_hash, received_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        root_id,
                        root["log_id"],
                        int(root["tree_size"]),
                        root["root_hash"],
                        int(root["timestamp"]),
                        root["signature"],
                        root["operator_public_key"],
                        canonical_json(root),
                        peer_id,
                        message_hash,
                        received_at,
                    ),
                )
                self._prune_peer_roots(conn, peer_id, root["log_id"], int(max_roots_for_log))
                if max_total_roots_for_log is not None:
                    self._prune_peer_roots_for_log(conn, root["log_id"], int(max_total_roots_for_log))

        self._with_retry(action)

    def _prune_peer_roots(self, conn, peer_id, log_id, max_roots_for_log):
        if max_roots_for_log <= 0:
            return
        # Evidence-bound roots are never deleted regardless of cap policy.
        conn.execute(
            """
            DELETE FROM peer_observed_roots
            WHERE id IN (
                SELECT id FROM peer_observed_roots
                WHERE peer_id = ?
                  AND log_id = ?
                  AND root_id NOT IN (
                      SELECT root_a_id FROM equivocation_evidence
                      UNION
                      SELECT root_b_id FROM equivocation_evidence
                  )
                ORDER BY received_at DESC, id DESC
                LIMIT -1 OFFSET ?
            )
            """,
            (peer_id, log_id, int(max_roots_for_log)),
        )

    def _prune_peer_roots_for_log(self, conn, log_id, max_roots_for_log):
        if max_roots_for_log <= 0:
            return
        # Evidence-bound roots are never deleted regardless of cap policy.
        conn.execute(
            """
            DELETE FROM peer_observed_roots
            WHERE id IN (
                SELECT id FROM peer_observed_roots
                WHERE log_id = ?
                  AND root_id NOT IN (
                      SELECT root_a_id FROM equivocation_evidence
                      UNION
                      SELECT root_b_id FROM equivocation_evidence
                  )
                ORDER BY received_at DESC, id DESC
                LIMIT -1 OFFSET ?
            )
            """,
            (log_id, int(max_roots_for_log)),
        )

    def save_equivocation_evidence(self, root_a, root_b, collision_type, detected_at=None):
        detected_at = int(detected_at or time.time())
        proof = make_equivocation_proof(root_a, root_b, collision_type=collision_type, detected_at=detected_at)
        evidence_id = ind_token.sha3_hex(canonical_bytes(proof))
        root_a_id = signed_root_id(root_a)
        root_b_id = signed_root_id(root_b)

        def action():
            with contextlib.closing(self._connect()) as conn, conn:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO equivocation_evidence (
                        evidence_id, log_id, collision_type, root_a_id, root_b_id,
                        root_a_json, root_b_json, detected_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        evidence_id,
                        root_a["log_id"],
                        collision_type,
                        root_a_id,
                        root_b_id,
                        canonical_json(root_a),
                        canonical_json(root_b),
                        detected_at,
                    ),
                )
            return evidence_id, proof

        return self._with_retry(action)

    def equivocation_messages(self, limit=100):
        def action():
            with contextlib.closing(self._connect()) as conn, conn:
                rows = conn.execute(
                    """
                    SELECT log_id, collision_type, root_a_json, root_b_json, detected_at
                    FROM equivocation_evidence
                    ORDER BY detected_at DESC
                    LIMIT ?
                    """,
                    (int(limit),),
                ).fetchall()
            return [
                make_equivocation_proof(
                    json.loads(row["root_a_json"]),
                    json.loads(row["root_b_json"]),
                    collision_type=row["collision_type"],
                    detected_at=int(row["detected_at"]),
                )
                for row in rows
            ]

        return self._with_retry(action)

    def mark_blacklisted(self, log_id, operator_public_key, reason, evidence_id, updated_at=None):
        updated_at = int(updated_at or time.time())

        def action():
            with contextlib.closing(self._connect()) as conn, conn:
                conn.execute(
                    """
                    INSERT INTO operator_status (
                        log_id, operator_public_key, status, reason, evidence_id,
                        updated_at, last_successful_consistency_at
                    ) VALUES (?, ?, 'blacklisted', ?, ?, ?, NULL)
                    ON CONFLICT(log_id) DO UPDATE SET
                        operator_public_key = excluded.operator_public_key,
                        status = 'blacklisted',
                        reason = excluded.reason,
                        evidence_id = excluded.evidence_id,
                        updated_at = excluded.updated_at
                    """,
                    (log_id, operator_public_key, str(reason), evidence_id, updated_at),
                )

        self._with_retry(action)


class InMemoryObservedRootStore:
    """In-memory observed-root store for tests and short-lived local tools."""

    def __init__(self):
        self.roots = []
        self.peer_roots = []
        self.statuses = {}
        self.failures = {}
        self.equivocations = {}
        self.key_rotations = {}
        self.key_revocations = {}

    def evidence_location(self):
        return "in-memory transparency evidence store"

    def record_root(self, root, source_identity, observed_at=None, consistency_checked_at=None):
        observed_at = int(observed_at or time.time())
        source_identity = _identity_text(source_identity)
        key = (root["log_id"], int(root["tree_size"]), root["root_hash"], source_identity)
        for existing in self.roots:
            if existing["key"] == key:
                if consistency_checked_at is not None:
                    existing["consistency_checked_at"] = int(consistency_checked_at)
                return
        self.roots.append(
            {
                "key": key,
                "root": copy.deepcopy(root),
                "source_identity": source_identity,
                "observed_at": observed_at,
                "consistency_checked_at": consistency_checked_at,
            }
        )

    def latest_root(self, log_id):
        candidates = [item["root"] for item in self.roots if item["root"]["log_id"] == log_id]
        if not candidates:
            return None
        return copy.deepcopy(sorted(candidates, key=lambda root: (int(root["tree_size"]), int(root["timestamp"])))[-1])

    def observed_position(self, log_id):
        candidates = [item["root"] for item in self.roots if item["root"]["log_id"] == log_id]
        if not candidates:
            return None
        return {
            "highest_tree_size": max(int(root["tree_size"]) for root in candidates),
            "latest_timestamp": max(int(root["timestamp"]) for root in candidates),
        }

    def known_log_ids(self):
        return sorted(
            {item["root"]["log_id"] for item in self.roots}
            | {item["root"]["log_id"] for item in self.peer_roots}
        )

    def roots_for_log(self, log_id):
        roots = [item["root"] for item in self.roots if item["root"]["log_id"] == log_id]
        roots.extend(item["root"] for item in self.peer_roots if item["root"]["log_id"] == log_id)
        deduped = {}
        for root in roots:
            deduped[signed_root_id(root)] = copy.deepcopy(root)
        return list(deduped.values())

    def find_equivocation(self, root):
        root_id = signed_root_id(root)
        for previous in self.roots_for_log(root["log_id"]):
            if signed_root_id(previous) == root_id:
                continue
            collision_type = equivocation_collision_type(previous, root)
            if collision_type:
                return {
                    "collision_type": collision_type,
                    "root_a": previous,
                    "root_b": root,
                }
        return None

    def record_key_rotation(self, record, observed_at=None):
        verify_key_rotation(record)
        record_hash = key_rotation_id(record)
        if record_hash in self.key_rotations:
            return record_hash
        latest = None
        for item in self.key_rotations.values():
            if item["record"]["log_id"] == record["log_id"]:
                if latest is None or int(item["record"]["effective_from_tree_size"]) > int(latest["effective_from_tree_size"]):
                    latest = item["record"]
        if latest and int(record["effective_from_tree_size"]) <= int(latest["effective_from_tree_size"]):
            raise KeyRotationError(
                "operator key rotation records must be strictly monotonic in effective_from_tree_size"
            )
        self.key_rotations[record_hash] = {
            "record": copy.deepcopy(record),
            "observed_at": int(observed_at or time.time()),
        }
        return record_hash

    def key_rotation_by_hash(self, record_hash):
        item = self.key_rotations.get(record_hash)
        return copy.deepcopy(item["record"]) if item else None

    def key_rotations_for_log(self, log_id):
        records = [
            item["record"]
            for item in self.key_rotations.values()
            if item["record"]["log_id"] == log_id
        ]
        return [
            copy.deepcopy(record)
            for record in sorted(records, key=lambda item: int(item["effective_from_tree_size"]))
        ]

    def key_rotation_for_successor_log_id(self, new_log_id):
        records = [
            item["record"]
            for item in self.key_rotations.values()
            if item["record"]["new_log_id"] == new_log_id
        ]
        if not records:
            return None
        return copy.deepcopy(
            sorted(records, key=lambda item: int(item["effective_from_tree_size"]))[-1]
        )

    def record_key_revocation(self, record, observed_at=None):
        rotation = self.key_rotation_by_hash(record.get("rotation_record_hash", ""))
        if not rotation:
            raise KeyRevocationError("operator key revocation references an unknown rotation record")
        verify_key_revocation(record, rotation_record=rotation)
        record_hash = key_revocation_id(record)
        self.key_revocations[record_hash] = {
            "record": copy.deepcopy(record),
            "observed_at": int(observed_at or time.time()),
        }
        return record_hash

    def key_revocation_for_key(self, log_id, public_key):
        records = [
            item["record"]
            for item in self.key_revocations.values()
            if item["record"]["log_id"] == log_id and item["record"]["revoked_public_key"] == public_key
        ]
        if not records:
            return None
        return copy.deepcopy(sorted(records, key=lambda item: int(item["revocation_timestamp"]))[-1])

    def status(self, log_id):
        current = self.statuses.get(log_id)
        return copy.deepcopy(current) if current else None

    def mark_active(self, log_id, operator_public_key, checked_at=None):
        checked_at = int(checked_at or time.time())
        self.statuses[log_id] = {
            "log_id": log_id,
            "operator_public_key": operator_public_key,
            "status": "active",
            "reason": None,
            "evidence_id": None,
            "updated_at": checked_at,
            "last_successful_consistency_at": checked_at,
        }

    def mark_unresponsive(self, log_id, operator_public_key, reason, updated_at=None):
        updated_at = int(updated_at or time.time())
        current = self.statuses.get(log_id, {})
        if current.get("status") == "blacklisted":
            return
        self.statuses[log_id] = {
            "log_id": log_id,
            "operator_public_key": operator_public_key,
            "status": "unresponsive",
            "reason": str(reason),
            "evidence_id": None,
            "updated_at": updated_at,
            "last_successful_consistency_at": current.get("last_successful_consistency_at"),
        }

    def save_consistency_failure(self, old_root, new_root, error, detected_at=None):
        detected_at = int(detected_at or time.time())
        evidence = {
            "type": "ind.transparency_consistency_failure.v1",
            "version": 1,
            "log_id": old_root["log_id"],
            "old_root": old_root,
            "new_root": new_root,
            "error": str(error),
            "detected_at": detected_at,
        }
        evidence_id = ind_token.sha3_hex(canonical_bytes(evidence))
        self.failures[evidence_id] = evidence
        return evidence_id

    def record_peer_root(
        self,
        root,
        peer_id,
        message_hash,
        received_at=None,
        max_roots_for_log=DEFAULT_PEER_ROOT_CAP_PER_LOG_ID,
        max_total_roots_for_log=None,
    ):
        received_at = int(received_at or time.time())
        peer_id = str(peer_id or "unknown-peer")
        root_id = signed_root_id(root)
        key = (root_id, peer_id)
        for existing in self.peer_roots:
            if existing["key"] == key:
                return
        self.peer_roots.append(
            {
                "key": key,
                "root_id": root_id,
                "root": copy.deepcopy(root),
                "peer_id": peer_id,
                "message_hash": str(message_hash or root_id),
                "received_at": received_at,
            }
        )
        self._prune_peer_roots(peer_id, root["log_id"], int(max_roots_for_log))
        if max_total_roots_for_log is not None:
            self._prune_peer_roots_for_log(root["log_id"], int(max_total_roots_for_log))

    def _prune_peer_roots(self, peer_id, log_id, max_roots_for_log):
        if max_roots_for_log <= 0:
            return
        evidence_bound = set()
        for item in self.equivocations.values():
            evidence_bound.add(signed_root_id(item["root_a"]))
            evidence_bound.add(signed_root_id(item["root_b"]))
        matching = [
            item for item in self.peer_roots
            if item["peer_id"] == peer_id and item["root"]["log_id"] == log_id
        ]
        overflow = len(matching) - max_roots_for_log
        if overflow <= 0:
            return
        removable = sorted(
            [item for item in matching if item["root_id"] not in evidence_bound],
            key=lambda item: (item["received_at"], item["root_id"]),
        )[:overflow]
        remove_keys = {item["key"] for item in removable}
        self.peer_roots = [item for item in self.peer_roots if item["key"] not in remove_keys]

    def _prune_peer_roots_for_log(self, log_id, max_roots_for_log):
        if max_roots_for_log <= 0:
            return
        evidence_bound = set()
        for item in self.equivocations.values():
            evidence_bound.add(signed_root_id(item["root_a"]))
            evidence_bound.add(signed_root_id(item["root_b"]))
        matching = [item for item in self.peer_roots if item["root"]["log_id"] == log_id]
        overflow = len(matching) - max_roots_for_log
        if overflow <= 0:
            return
        removable = sorted(
            [item for item in matching if item["root_id"] not in evidence_bound],
            key=lambda item: (item["received_at"], item["root_id"]),
        )[:overflow]
        remove_keys = {item["key"] for item in removable}
        self.peer_roots = [item for item in self.peer_roots if item["key"] not in remove_keys]

    def save_equivocation_evidence(self, root_a, root_b, collision_type, detected_at=None):
        detected_at = int(detected_at or time.time())
        proof = make_equivocation_proof(root_a, root_b, collision_type=collision_type, detected_at=detected_at)
        evidence_id = ind_token.sha3_hex(canonical_bytes(proof))
        self.equivocations[evidence_id] = proof
        return evidence_id, copy.deepcopy(proof)

    def equivocation_messages(self, limit=100):
        items = sorted(self.equivocations.values(), key=lambda item: int(item["detected_at"]), reverse=True)
        return [copy.deepcopy(item) for item in items[:int(limit)]]

    def mark_blacklisted(self, log_id, operator_public_key, reason, evidence_id, updated_at=None):
        updated_at = int(updated_at or time.time())
        self.statuses[log_id] = {
            "log_id": log_id,
            "operator_public_key": operator_public_key,
            "status": "blacklisted",
            "reason": str(reason),
            "evidence_id": evidence_id,
            "updated_at": updated_at,
            "last_successful_consistency_at": None,
        }


class HTTPJSONClient:
    """Small JSON-over-HTTP client used by operators and mirrors."""

    def __init__(self, base_url, timeout=10):
        self.base_url = base_url.rstrip("/")
        self.timeout = int(timeout)
        self.identity_id = _http_origin_identity(self.base_url)

    def _url(self, path, params=None):
        url = self.base_url + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        return url

    def get_json(self, path, params=None):
        with urllib.request.urlopen(self._url(path, params), timeout=self.timeout) as response:
            return json.loads(response.read().decode("utf-8"))

    def post_json(self, path, data):
        payload = canonical_json(data).encode("utf-8")
        request = urllib.request.Request(
            self._url(path),
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            return json.loads(response.read().decode("utf-8"))


class HTTPTransparencyOperator:
    """Client for the log operator's proof endpoints."""

    def __init__(self, base_url, timeout=10):
        self.http = HTTPJSONClient(base_url, timeout=timeout)
        self.identity_id = self.http.identity_id

    def inclusion_proof(self, entry_hash, tree_size):
        return self.http.get_json("/v1/proof", {"entry_hash": entry_hash, "tree_size": int(tree_size)})

    def consistency_proof(self, first_tree_size, second_tree_size):
        return self.http.get_json(
            "/v1/consistency",
            {"first": int(first_tree_size), "second": int(second_tree_size)},
        )

    def submit_transfer_announcement(self, announcement):
        return self.http.post_json("/v1/append", announcement)

    def latest_root(self):
        return self.http.get_json("/v1/root")


class HTTPRootMirror:
    """Client for an HTTP mirror serving signed roots."""

    def __init__(self, base_url, timeout=10):
        self.http = HTTPJSONClient(base_url, timeout=timeout)
        self.identity_id = self.http.identity_id

    def root_at(self, timestamp):
        return self.http.get_json("/v1/root-at", {"timestamp": int(timestamp)})

    def latest_root(self):
        return self.http.get_json("/v1/root")


class DirectoryRootMirror:
    """Read signed roots from a local mirror directory or JSON/JSONL file."""

    def __init__(self, path):
        self.path = Path(path)
        self.identity_id = _directory_identity(self.path)

    def _roots_from_file(self, path):
        if not path.exists() or not path.is_file():
            return []
        text = path.read_text(encoding="utf-8").strip()
        if not text:
            return []
        if path.suffix.lower() == ".jsonl":
            return [json.loads(line) for line in text.splitlines() if line.strip()]
        data = json.loads(text)
        if isinstance(data, list):
            return data
        return [data]

    def roots(self):
        def dedupe(items):
            seen = set()
            result = []
            for root in items:
                current_id = signed_root_id(root)
                if current_id in seen:
                    continue
                seen.add(current_id)
                result.append(root)
            return result

        if self.path.is_file():
            return dedupe(self._roots_from_file(self.path))
        roots = []
        roots.extend(self._roots_from_file(self.path / "roots.jsonl"))
        roots_dir = self.path / "roots"
        if roots_dir.exists():
            for path in sorted(roots_dir.glob("*.json")):
                roots.extend(self._roots_from_file(path))
        for path in sorted(self.path.glob("root_*.json")):
            roots.extend(self._roots_from_file(path))
        return dedupe(roots)

    def root_at(self, timestamp):
        timestamp = int(timestamp)
        candidates = [root for root in self.roots() if int(root.get("timestamp", -1)) >= timestamp]
        if not candidates:
            raise RootVerificationError("mirror has no historical root for timestamp")
        return sorted(candidates, key=lambda root: (int(root["timestamp"]), int(root["tree_size"])))[0]

    def latest_root(self):
        roots = self.roots()
        if not roots:
            raise RootVerificationError("mirror has no signed roots")
        return sorted(roots, key=lambda root: (int(root["timestamp"]), int(root["tree_size"])))[-1]


class StaticRootMirror:
    """In-memory mirror used by tests and local tooling."""

    def __init__(self, roots, identity_id=None):
        self._roots = list(roots)
        self.identity_id = str(identity_id).strip() if identity_id else None

    def roots(self):
        return list(self._roots)

    def root_at(self, timestamp):
        timestamp = int(timestamp)
        candidates = [root for root in self._roots if int(root.get("timestamp", -1)) >= timestamp]
        if not candidates:
            raise RootVerificationError("mirror has no historical root for timestamp")
        return sorted(candidates, key=lambda root: (int(root["timestamp"]), int(root["tree_size"])))[0]

    def latest_root(self):
        if not self._roots:
            raise RootVerificationError("mirror has no signed roots")
        return sorted(self._roots, key=lambda root: (int(root["timestamp"]), int(root["tree_size"])))[-1]


class LocalTransparencyOperator:
    """Adapter around log_server.TransparencyLog for tests and local tools."""

    def __init__(self, log):
        self.log = log
        self.identity_id = ("local-log", os.path.normcase(str(Path(log.db_path).resolve(strict=False))))

    def inclusion_proof(self, entry_hash, tree_size):
        return self.log.inclusion_proof(entry_hash, int(tree_size))

    def consistency_proof(self, first_tree_size, second_tree_size):
        return self.log.consistency_proof(int(first_tree_size), int(second_tree_size))

    def submit_transfer_announcement(self, announcement):
        return self.log.append_transfer_announcement(announcement)

    def latest_root(self):
        return self.log.latest_root()


def _coerce_operator(operator):
    if isinstance(operator, str):
        return HTTPTransparencyOperator(operator)
    return operator


def _coerce_mirror(mirror):
    if isinstance(mirror, str) and mirror.startswith(("http://", "https://")):
        return HTTPRootMirror(mirror)
    if isinstance(mirror, str):
        return DirectoryRootMirror(mirror)
    return mirror


class TransparencyVerifier:
    """Client-side verifier for IND transfer transparency proofs."""

    def __init__(
        self,
        operator,
        mirrors,
        operator_public_key=None,
        max_root_lag_seconds=DEFAULT_MAX_ROOT_LAG_SECONDS,
        min_mirrors=DEFAULT_MIN_ROOT_MIRRORS,
        allow_unsafe_single_mirror=False,
        strict_mode=False,
        observed_root_store=None,
        observed_roots_path=None,
        consistency_anchor=None,
        consistency_anchor_path=None,
        consistency_check_interval_seconds=DEFAULT_CONSISTENCY_CHECK_INTERVAL_SECONDS,
        consistency_max_stale_seconds=DEFAULT_CONSISTENCY_MAX_STALE_SECONDS,
        max_current_root_age_seconds=DEFAULT_MAX_CURRENT_ROOT_AGE_SECONDS,
        current_root_future_skew_seconds=DEFAULT_CURRENT_ROOT_FUTURE_SKEW_SECONDS,
        start_background_checks=False,
        run_startup_check=True,
    ):
        self.strict_mode = bool(strict_mode)
        self.allow_unsafe_single_mirror = bool(allow_unsafe_single_mirror)
        if self.strict_mode and self.allow_unsafe_single_mirror:
            raise TransparencyLogError(STRICT_UNSAFE_SINGLE_MIRROR_ERROR)
        self.min_mirrors = self._validated_min_mirrors(min_mirrors)
        self.mirror_identities = self._validate_mirror_sources(operator, mirrors)
        self.operator = _coerce_operator(operator)
        self.mirrors = [_coerce_mirror(mirror) for mirror in mirrors]
        self.operator_public_key = operator_public_key
        self.max_root_lag_seconds = int(max_root_lag_seconds)
        self.max_current_root_age_seconds = int(max_current_root_age_seconds)
        self.current_root_future_skew_seconds = int(current_root_future_skew_seconds)
        self._validate_current_root_freshness_config()
        self.consistency_check_interval_seconds = int(consistency_check_interval_seconds)
        self.consistency_max_stale_seconds = int(consistency_max_stale_seconds)
        self._consistency_pairs_checked = set()
        self._pending_gossip_messages = []
        self._queued_root_ids = set()
        self._queued_evidence_ids = set()
        self._background_stop = threading.Event()
        self._background_thread = None
        self.observed_root_store = self._build_observed_root_store(observed_root_store, observed_roots_path)
        self._load_consistency_anchor(consistency_anchor=consistency_anchor, consistency_anchor_path=consistency_anchor_path)
        if run_startup_check:
            self._run_startup_consistency_check()
        if start_background_checks and self.consistency_check_interval_seconds > 0:
            self.start_background_consistency_checks()

    def _build_observed_root_store(self, observed_root_store, observed_roots_path):
        if observed_root_store is not None:
            return observed_root_store
        try:
            return SQLiteObservedRootStore(observed_roots_path or DEFAULT_OBSERVED_ROOTS_DB)
        except Exception as exc:
            if self.strict_mode:
                raise TransparencyLogError(f"transparency observed-root store is unavailable: {exc}") from exc
            warnings.warn(
                f"transparency observed-root persistence is unavailable; consistency checks are not durable: {exc}",
                RuntimeWarning,
                stacklevel=3,
            )
            return InMemoryObservedRootStore()

    def _load_consistency_anchor(self, consistency_anchor=None, consistency_anchor_path=None):
        if consistency_anchor_path:
            text = Path(consistency_anchor_path).read_text(encoding="utf-8")
            consistency_anchor = json.loads(text)
        if not consistency_anchor:
            return
        verify_signed_root(consistency_anchor, operator_public_key=self.operator_public_key)
        now = int(time.time())
        self.observed_root_store.record_root(
            consistency_anchor,
            ("configured-anchor", str(consistency_anchor.get("log_id", ""))),
            observed_at=now,
            consistency_checked_at=now,
        )
        self.observed_root_store.mark_active(
            consistency_anchor["log_id"],
            consistency_anchor["operator_public_key"],
            checked_at=now,
        )

    def _run_startup_consistency_check(self):
        try:
            self.check_latest_consistency()
        except Exception as exc:
            if self.strict_mode:
                self._enforce_known_log_status()
            warnings.warn(f"startup transparency consistency check did not complete: {exc}", RuntimeWarning, stacklevel=3)
        if self.strict_mode:
            self._enforce_known_log_status()

    def _validated_min_mirrors(self, min_mirrors):
        requested = int(min_mirrors)
        floor = 1 if self.allow_unsafe_single_mirror else DEFAULT_MIN_ROOT_MIRRORS
        if requested < floor:
            raise TransparencyLogError(
                f"IND_LOG_MIN_MIRRORS={requested} is below the required floor of {floor} independent root mirrors"
            )
        if self.allow_unsafe_single_mirror:
            requested = 1
            warnings.warn(
                "UNSAFE transparency log mode: accepting one root mirror. "
                "This does not defend against operator/mirror split-view attacks and must not be used with "
                "IND_REQUIRE_TRANSPARENCY_LOG=1.",
                RuntimeWarning,
                stacklevel=3,
            )
        return requested

    def _validate_current_root_freshness_config(self):
        if self.max_current_root_age_seconds <= 0:
            raise TransparencyLogError(
                "IND_LOG_MAX_CURRENT_ROOT_AGE_SECONDS must be greater than 0 for current root replay protection"
            )
        if self.current_root_future_skew_seconds < 0:
            raise TransparencyLogError("IND_LOG_CURRENT_ROOT_FUTURE_SKEW_SECONDS must not be negative")
        if self.current_root_future_skew_seconds > MAX_CURRENT_ROOT_FUTURE_SKEW_SECONDS:
            raise TransparencyLogError(
                f"IND_LOG_CURRENT_ROOT_FUTURE_SKEW_SECONDS={self.current_root_future_skew_seconds} exceeds "
                f"the hard ceiling of {MAX_CURRENT_ROOT_FUTURE_SKEW_SECONDS} seconds. A system clock that is "
                "more than five minutes wrong must be fixed with NTP, not accommodated by the protocol."
            )
        if self.current_root_future_skew_seconds >= self.max_current_root_age_seconds:
            raise TransparencyLogError(
                f"IND_LOG_CURRENT_ROOT_FUTURE_SKEW_SECONDS={self.current_root_future_skew_seconds} must be "
                f"smaller than IND_LOG_MAX_CURRENT_ROOT_AGE_SECONDS={self.max_current_root_age_seconds}; "
                "future-dated roots cannot be allowed to extend the replay window."
            )
        if self.strict_mode and self.max_current_root_age_seconds > STRICT_MAX_CURRENT_ROOT_AGE_SECONDS:
            raise TransparencyLogError(
                f"IND_LOG_MAX_CURRENT_ROOT_AGE_SECONDS={self.max_current_root_age_seconds} is too loose for "
                "IND_REQUIRE_TRANSPARENCY_LOG=1. Strict transparency mode requires current roots no older "
                f"than {STRICT_MAX_CURRENT_ROOT_AGE_SECONDS} seconds. This ceiling covers the 60-second "
                "signing interval, normal mirror propagation, allowed clock skew, and safety margin; "
                "configure fresher mirrors or disable strict mode."
            )

    def _validate_mirror_sources(self, operator, mirrors):
        mirrors = list(mirrors)
        operator_identity = transparency_source_identity(operator)
        identities = []
        seen = {}
        for index, mirror in enumerate(mirrors):
            identity = transparency_source_identity(mirror)
            if identity is None:
                raise TransparencyLogError(
                    f"root mirror {index} ({_source_label(mirror)}) must configure identity_id so its "
                    "independent source can be checked"
                )
            if operator_identity and identity == operator_identity:
                raise TransparencyLogError(
                    f"root mirror {index} ({_source_label(mirror)}) has same {_identity_label(identity)} "
                    f"as operator ({_source_label(operator)})"
                )
            if identity in seen:
                previous = seen[identity]
                raise TransparencyLogError(
                    f"root mirrors {previous} and {index} share {_identity_label(identity)}; "
                    "mirror sources must be independent"
                )
            seen[identity] = index
            identities.append(identity)
        if len(identities) < self.min_mirrors:
            raise TransparencyLogError(
                f"configured {len(identities)} independent root mirror(s), but IND_LOG_MIN_MIRRORS="
                f"{self.min_mirrors} requires at least {self.min_mirrors}"
            )
        return identities

    def _known_log_ids_for_status_checks(self):
        ids = set()
        configured = self._configured_log_id()
        if configured:
            ids.add(configured)
            return sorted(ids)
        try:
            ids.update(self.observed_root_store.known_log_ids())
        except Exception:
            if self.strict_mode:
                raise
        return sorted(ids)

    def _enforce_known_log_status(self):
        for log_id in self._known_log_ids_for_status_checks():
            self._enforce_consistency_freshness(log_id)

    def _blacklisted_message(self, log_id, status):
        evidence_location = self.observed_root_store.evidence_location()
        reason = str(status.get("reason"))
        if "equivocation" in reason:
            return (
                f"CRITICAL transparency log equivocation detected: operator {log_id} signed conflicting roots. "
                f"Evidence saved to {evidence_location}. To investigate: inspect evidence at {evidence_location}, "
                "verify operator status via independent channels, and consider switching to an alternate operator. "
                f"Use ind-cli transparency unblacklist {log_id} only after confirming the evidence was caused by "
                "local error, not operator misbehavior."
            )
        return (
            f"CRITICAL transparency log consistency failure: operator {log_id} is locally blacklisted "
            f"because {status.get('reason')}. Evidence saved to {evidence_location}. "
            f"To investigate: inspect evidence at {evidence_location}, verify operator status via independent "
            "channels, and consider switching to an alternate operator. Use ind-cli transparency unblacklist "
            f"{log_id} only after confirming the failure was due to local error, not operator misbehavior."
        )

    def _configured_log_id(self):
        if not self.operator_public_key:
            return None
        return log_id_from_public_key(self.operator_public_key)

    def _is_configured_log(self, log_id):
        configured = self._configured_log_id()
        if configured is None or log_id == configured:
            return True
        try:
            rotation = self.observed_root_store.key_rotation_for_successor_log_id(log_id)
        except Exception:
            return False
        return bool(rotation and rotation["log_id"] == configured)

    def _lineage_log_id_for_root(self, root):
        configured = self._configured_log_id()
        if not configured:
            return root["log_id"]
        if root["log_id"] == configured:
            return configured
        rotation = self.observed_root_store.key_rotation_for_successor_log_id(root["log_id"])
        if (
            rotation
            and rotation["log_id"] == configured
            and rotation["new_public_key"] == root["operator_public_key"]
        ):
            return configured
        return root["log_id"]

    def _rotation_for_root(self, root):
        configured = self._configured_log_id()
        if not configured:
            return None
        for rotation in self.observed_root_store.key_rotations_for_log(configured):
            if (
                root["log_id"] == rotation["log_id"]
                and root["operator_public_key"] == rotation["old_public_key"]
            ):
                return rotation
            if (
                root["log_id"] == rotation["new_log_id"]
                and root["operator_public_key"] == rotation["new_public_key"]
            ):
                return rotation
        return None

    def _roots_share_lineage(self, old_root, new_root):
        return self._lineage_log_id_for_root(old_root) == self._lineage_log_id_for_root(new_root)

    def _verify_signed_root_for_lineage(self, root):
        verify_signed_root(root)
        if not self.operator_public_key:
            return True
        configured_key = self.operator_public_key.strip()
        configured_log_id = log_id_from_public_key(configured_key)
        root_key = root["operator_public_key"].strip()
        root_size = int(root["tree_size"])
        root_timestamp = int(root["timestamp"])

        if root["log_id"] == configured_log_id and root_key == configured_key:
            revocation = self.observed_root_store.key_revocation_for_key(configured_log_id, configured_key)
            if revocation and root_timestamp >= int(revocation["revocation_timestamp"]):
                raise RootVerificationError("transparency root was signed by a revoked operator key")
            rotations = self.observed_root_store.key_rotations_for_log(configured_log_id)
            if rotations:
                latest = rotations[-1]
                if (
                    root_size >= int(latest["effective_from_tree_size"])
                    and root_timestamp > int(latest["overlap_until_timestamp"])
                ):
                    raise RootVerificationError("transparency root was signed by the old operator key after rotation overlap")
            return True

        rotation = self._rotation_for_root(root)
        if rotation and root_key == rotation["new_public_key"] and root["log_id"] == rotation["new_log_id"]:
            if root_size < int(rotation["effective_from_tree_size"]):
                raise RootVerificationError("transparency root was signed by successor key before rotation effective tree size")
            return True

        raise RootVerificationError("transparency root was signed by an unexpected operator")

    def observe_key_rotation(self, record, observed_at=None):
        if self.operator_public_key:
            expected_log_id = self._configured_log_id()
            verify_key_rotation(record, expected_log_id=expected_log_id)
        else:
            verify_key_rotation(record)
        return self.observed_root_store.record_key_rotation(record, observed_at=observed_at)

    def observe_key_revocation(self, record, observed_at=None):
        if self.operator_public_key and record.get("log_id") != self._configured_log_id():
            raise KeyRevocationError("operator key revocation is for an unexpected log id")
        return self.observed_root_store.record_key_revocation(record, observed_at=observed_at)

    def _peer_root_cap_for_log(self, log_id):
        return (
            DEFAULT_PEER_ROOT_CAP_PER_LOG_ID
            if self._is_configured_log(log_id)
            else DEFAULT_UNKNOWN_PEER_ROOT_CAP_PER_LOG_ID
        )

    def _queue_gossip_message(self, message):
        self._pending_gossip_messages.append(message)

    def _queue_root_announcement(self, root):
        root_id = signed_root_id(root)
        if root_id in self._queued_root_ids:
            return
        self._queued_root_ids.add(root_id)
        self._queue_gossip_message(make_root_announcement(root))

    def _queue_equivocation_proof(self, proof):
        evidence_id = ind_token.sha3_hex(canonical_bytes(proof))
        if evidence_id in self._queued_evidence_ids:
            return
        self._queued_evidence_ids.add(evidence_id)
        self._queue_gossip_message(proof)

    def consume_pending_gossip_messages(self):
        messages = list(self._pending_gossip_messages)
        self._pending_gossip_messages = []
        return messages

    def persisted_equivocation_messages(self, limit=100):
        return self.observed_root_store.equivocation_messages(limit=limit)

    def _handle_equivocation(self, root_a, root_b, collision_type):
        detected_at = int(time.time())
        evidence_id, proof = self.observed_root_store.save_equivocation_evidence(
            root_a,
            root_b,
            collision_type,
            detected_at=detected_at,
        )
        self.observed_root_store.mark_blacklisted(
            root_a["log_id"],
            root_a["operator_public_key"],
            f"equivocation {collision_type}",
            evidence_id,
            updated_at=detected_at,
        )
        self._queue_equivocation_proof(proof)
        status = self.observed_root_store.status(root_a["log_id"])
        raise MirrorDisagreementError(
            {
                "log_id": root_a["log_id"],
                "collision_type": collision_type,
                "root_a": root_a,
                "root_b": root_b,
                "message": self._blacklisted_message(root_a["log_id"], status),
            }
        )

    def _detect_and_handle_equivocation(self, root):
        evidence = self.observed_root_store.find_equivocation(root)
        if not evidence:
            return None
        self._handle_equivocation(evidence["root_a"], evidence["root_b"], evidence["collision_type"])

    def _enforce_consistency_freshness(self, log_id):
        status = self.observed_root_store.status(log_id)
        if status and status.get("status") == "blacklisted":
            raise ConsistencyProofError(self._blacklisted_message(log_id, status))
        last_success = status.get("last_successful_consistency_at") if status else None
        if self.strict_mode:
            if not last_success:
                raise ConsistencyUnavailableError(
                    f"strict transparency mode has no successful consistency baseline for operator {log_id}"
                )
            age = int(time.time()) - int(last_success)
            if age > self.consistency_max_stale_seconds:
                raise ConsistencyUnavailableError(
                    f"strict transparency mode requires a successful consistency check within "
                    f"{self.consistency_max_stale_seconds} seconds for operator {log_id}; last success was "
                    f"{age} seconds ago"
                )

    def _handle_consistency_failure(self, old_root, new_root, error):
        evidence_id = self.observed_root_store.save_consistency_failure(old_root, new_root, error)
        self.observed_root_store.mark_blacklisted(
            old_root["log_id"],
            new_root.get("operator_public_key", old_root.get("operator_public_key", "")),
            str(error),
            evidence_id,
        )
        status = self.observed_root_store.status(old_root["log_id"])
        raise ConsistencyProofError(self._blacklisted_message(old_root["log_id"], status)) from error

    def _current_time(self, now=None):
        return int(time.time() if now is None else now)

    def _validate_current_root_freshness(self, root, now):
        root_timestamp = int(root["timestamp"])
        now = int(now)
        future_skew = root_timestamp - now
        if future_skew > self.current_root_future_skew_seconds:
            raise RootVerificationError(
                f"transparency root is too far in the future for current verification: root timestamp "
                f"{root_timestamp}, local time {now}, allowed future skew "
                f"{self.current_root_future_skew_seconds} seconds"
            )
        age = now - root_timestamp
        if age > self.max_current_root_age_seconds:
            raise RootVerificationError(
                f"transparency root is stale for current verification: root timestamp {root_timestamp}, "
                f"local time {now}, age {age} seconds exceeds "
                f"IND_LOG_MAX_CURRENT_ROOT_AGE_SECONDS={self.max_current_root_age_seconds}"
            )
        return True

    def _validate_current_root_monotonicity(self, root):
        position = self.observed_root_store.observed_position(root["log_id"])
        if not position:
            return True
        root_size = int(root["tree_size"])
        root_timestamp = int(root["timestamp"])
        highest_size = int(position["highest_tree_size"])
        latest_timestamp = int(position["latest_timestamp"])
        if root_size < highest_size:
            if root_timestamp > latest_timestamp:
                previous = self.observed_root_store.latest_root(root["log_id"])
                error = ConsistencyProofError(
                    f"operator signed a current root with tree_size {root_size} after this client had "
                    f"already observed tree_size {highest_size}"
                )
                self._handle_consistency_failure(previous, root, error)
            raise RootVerificationError(
                f"transparency root replayed an older tree for current verification: tree_size "
                f"{root_size} is below previously observed tree_size {highest_size}"
            )
        if root_timestamp < latest_timestamp:
            raise RootVerificationError(
                f"transparency root replayed an older timestamp for current verification: timestamp "
                f"{root_timestamp} is below previously observed timestamp {latest_timestamp}"
            )
        return True

    def _current_roots_from_mirrors(self, now=None, error_context="current verification"):
        now = self._current_time(now)
        roots_by_identity = {}
        errors = []
        for mirror, identity in zip(self.mirrors, self.mirror_identities):
            try:
                root = mirror.latest_root()
                self._verify_signed_root_for_lineage(root)
                self._validate_current_root_freshness(root, now)
                self._validate_current_root_monotonicity(root)
                roots_by_identity[identity] = root
            except (ConsistencyProofError, MirrorDisagreementError):
                raise
            except Exception as exc:
                errors.append(str(exc))
        roots = list(roots_by_identity.values())
        if len(roots) < self.min_mirrors:
            detail = "; ".join(errors) if errors else "no mirrors configured"
            raise RootVerificationError(f"not enough usable current transparency root mirrors for {error_context}: {detail}")
        detect_mirror_disagreement(roots)
        self._observe_roots(roots_by_identity)
        return roots

    def observe_root(self, root, source_identity):
        """Persist and consistency-check a signed root observed from a mirror."""

        self._verify_signed_root_for_lineage(root)
        now = int(time.time())
        log_id = root["log_id"]
        lineage_log_id = self._lineage_log_id_for_root(root)
        status = self.observed_root_store.status(log_id) or self.observed_root_store.status(lineage_log_id)
        if status and status.get("status") == "blacklisted":
            raise ConsistencyProofError(self._blacklisted_message(lineage_log_id, status))
        self._detect_and_handle_equivocation(root)
        previous = self.observed_root_store.latest_root(log_id)
        if lineage_log_id != log_id:
            lineage_previous = self.observed_root_store.latest_root(lineage_log_id)
            if lineage_previous and (
                previous is None
                or int(lineage_previous["tree_size"]) > int(previous["tree_size"])
            ):
                previous = lineage_previous
        if previous is None:
            self.observed_root_store.record_root(root, source_identity, observed_at=now, consistency_checked_at=now)
            self.observed_root_store.mark_active(log_id, root["operator_public_key"], checked_at=now)
            self._queue_root_announcement(root)
            return root

        old_size = int(previous["tree_size"])
        new_size = int(root["tree_size"])
        if old_size == new_size and previous["root_hash"] == root["root_hash"]:
            self.observed_root_store.record_root(root, source_identity, observed_at=now)
            self._queue_root_announcement(root)
            self._enforce_consistency_freshness(log_id)
            return root
        if old_size == new_size:
            error = ConsistencyProofError("new observed root is not an append-only extension of the stored root")
            self._handle_consistency_failure(previous, root, error)

        if new_size < old_size:
            first_root = root
            second_root = previous
            first_size = new_size
            second_size = old_size
        else:
            first_root = previous
            second_root = root
            first_size = old_size
            second_size = new_size

        pair_key = (log_id, first_size, first_root["root_hash"], second_size, second_root["root_hash"])
        try:
            if pair_key not in self._consistency_pairs_checked:
                proof = self.operator.consistency_proof(first_size, second_size)
                verify_consistency_proof(
                    first_root,
                    second_root,
                    proof,
                    allow_log_id_transition=self._roots_share_lineage(first_root, second_root),
                )
                self._consistency_pairs_checked.add(pair_key)
            self.observed_root_store.record_root(root, source_identity, observed_at=now, consistency_checked_at=now)
            self.observed_root_store.mark_active(log_id, root["operator_public_key"], checked_at=now)
            self._queue_root_announcement(root)
        except ConsistencyProofError as exc:
            self._handle_consistency_failure(previous, root, exc)
        except Exception as exc:
            self.observed_root_store.mark_unresponsive(log_id, root["operator_public_key"], exc, updated_at=now)
            warnings.warn(
                f"transparency consistency proof unavailable for operator {log_id}: {exc}",
                RuntimeWarning,
                stacklevel=3,
            )
            self._enforce_consistency_freshness(log_id)
        return root

    def _observe_roots(self, roots_by_identity):
        for identity, root in roots_by_identity.items():
            self.observe_root(root, identity)

    def check_latest_consistency(self, now=None):
        return self._current_roots_from_mirrors(now=now, error_context="consistency check")

    def process_root_announcement(self, message, peer_id=None, message_hash=None):
        """Store a peer-gossiped signed root and check it for equivocation."""

        root = verify_root_announcement(message)
        received_at = int(time.time())
        self.observed_root_store.record_peer_root(
            root,
            peer_id=peer_id,
            message_hash=message_hash or signed_root_id(root),
            received_at=received_at,
            max_roots_for_log=self._peer_root_cap_for_log(root["log_id"]),
            max_total_roots_for_log=None if self._is_configured_log(root["log_id"]) else DEFAULT_UNKNOWN_PEER_ROOT_CAP_PER_LOG_ID,
        )
        self._detect_and_handle_equivocation(root)
        return root

    def process_equivocation_proof(self, message, peer_id=None, message_hash=None):
        """Verify, persist, blacklist, and queue a peer-gossiped equivocation proof."""

        evidence = verify_equivocation_proof(message)
        root_a = evidence["root_a"]
        root_b = evidence["root_b"]
        collision_type = evidence["collision_type"]
        received_at = int(time.time())
        self.observed_root_store.record_peer_root(
            root_a,
            peer_id=peer_id,
            message_hash=message_hash or signed_root_id(root_a),
            received_at=received_at,
            max_roots_for_log=self._peer_root_cap_for_log(root_a["log_id"]),
            max_total_roots_for_log=None if self._is_configured_log(root_a["log_id"]) else DEFAULT_UNKNOWN_PEER_ROOT_CAP_PER_LOG_ID,
        )
        self.observed_root_store.record_peer_root(
            root_b,
            peer_id=peer_id,
            message_hash=message_hash or signed_root_id(root_b),
            received_at=received_at,
            max_roots_for_log=self._peer_root_cap_for_log(root_b["log_id"]),
            max_total_roots_for_log=None if self._is_configured_log(root_b["log_id"]) else DEFAULT_UNKNOWN_PEER_ROOT_CAP_PER_LOG_ID,
        )
        evidence_id, proof = self.observed_root_store.save_equivocation_evidence(
            root_a,
            root_b,
            collision_type,
            detected_at=int(message.get("detected_at", received_at)),
        )
        self.observed_root_store.mark_blacklisted(
            root_a["log_id"],
            root_a["operator_public_key"],
            f"equivocation {collision_type}",
            evidence_id,
            updated_at=received_at,
        )
        self._queue_equivocation_proof(proof)
        return proof

    def start_background_consistency_checks(self):
        if self._background_thread and self._background_thread.is_alive():
            return

        def loop():
            while not self._background_stop.wait(self.consistency_check_interval_seconds):
                try:
                    self.check_latest_consistency()
                except Exception as exc:
                    warnings.warn(
                        f"scheduled transparency consistency check failed: {exc}",
                        RuntimeWarning,
                        stacklevel=2,
                    )

        self._background_thread = threading.Thread(target=loop, name="ind-transparency-consistency", daemon=True)
        self._background_thread.start()

    def stop_background_consistency_checks(self):
        self._background_stop.set()

    def mirrored_root_for_timestamp(self, timestamp):
        timestamp = int(timestamp)
        roots_by_identity = {}
        errors = []
        for mirror, identity in zip(self.mirrors, self.mirror_identities):
            try:
                root = mirror.root_at(timestamp)
                self._verify_signed_root_for_lineage(root)
                roots_by_identity[identity] = root
            except Exception as exc:
                errors.append(str(exc))
        roots = list(roots_by_identity.values())
        if len(roots) < self.min_mirrors:
            detail = "; ".join(errors) if errors else "no mirrors configured"
            raise RootVerificationError(f"not enough usable transparency root mirrors: {detail}")
        detect_mirror_disagreement(roots)
        self._observe_roots(roots_by_identity)
        candidates = []
        for root in roots:
            lag = int(root["timestamp"]) - timestamp
            if lag < 0:
                continue
            if self.max_root_lag_seconds is not None and lag > self.max_root_lag_seconds:
                continue
            candidates.append(root)
        if not candidates:
            raise RootVerificationError("no mirrored transparency root close enough to transfer timestamp")
        return sorted(candidates, key=lambda root: (int(root["timestamp"]), int(root["tree_size"])))[0]

    def mirrored_root_containing_leaf(self, timestamp, leaf_index):
        timestamp = int(timestamp)
        min_tree_size = int(leaf_index) + 1
        roots_by_identity = {}
        errors = []
        for mirror, identity in zip(self.mirrors, self.mirror_identities):
            next_timestamp = timestamp
            seen_timestamps = set()
            while True:
                try:
                    root = mirror.root_at(next_timestamp)
                    self._verify_signed_root_for_lineage(root)
                    root_timestamp = int(root["timestamp"])
                    if root_timestamp in seen_timestamps:
                        raise RootVerificationError("mirror returned the same root repeatedly")
                    seen_timestamps.add(root_timestamp)
                    lag = root_timestamp - timestamp
                    if lag < 0:
                        raise RootVerificationError("mirror returned a root before the requested timestamp")
                    if self.max_root_lag_seconds is not None and lag > self.max_root_lag_seconds:
                        raise RootVerificationError("no mirrored transparency root close enough to transfer timestamp")
                    if int(root["tree_size"]) >= min_tree_size:
                        roots_by_identity[identity] = root
                        break
                    next_timestamp = root_timestamp + 1
                except Exception as exc:
                    errors.append(str(exc))
                    break
        roots = list(roots_by_identity.values())
        if len(roots) < self.min_mirrors:
            detail = "; ".join(errors) if errors else "no mirrors configured"
            raise RootVerificationError(f"not enough usable transparency root mirrors containing leaf: {detail}")
        detect_mirror_disagreement(roots)
        self._observe_roots(roots_by_identity)
        return sorted(roots, key=lambda root: (int(root["timestamp"]), int(root["tree_size"])))[0]

    def current_mirrored_root(self, now=None):
        roots = self._current_roots_from_mirrors(now=now)
        return sorted(roots, key=lambda root: (int(root["tree_size"]), int(root["timestamp"])))[-1]

    def verify_current_root(self, now=None):
        self.current_mirrored_root(now=now)
        return True

    def verify_transfer(self, transfer):
        timestamp = int(transfer["timestamp"])
        entry_hash = transfer_entry_hash(transfer)
        root = self.mirrored_root_for_timestamp(timestamp)
        proof = self.operator.inclusion_proof(entry_hash, int(root["tree_size"]))
        verify_inclusion_proof(
            entry_hash,
            proof,
            root,
            operator_public_key=root["operator_public_key"],
        )
        return True

    def verify_token(self, token, now=None, require_current_root=True):
        for transfer in token.get("history", []):
            self.verify_transfer(transfer)
        if require_current_root:
            self.verify_current_root(now=now)
        return True

    def verify_token_history(self, token):
        return self.verify_token(token, require_current_root=False)

    def verify_consistency_between(self, old_root, new_root):
        proof = self.operator.consistency_proof(old_root["tree_size"], new_root["tree_size"])
        return verify_consistency_proof(
            old_root,
            new_root,
            proof,
            allow_log_id_transition=self._roots_share_lineage(old_root, new_root),
        )


def verifier_from_environment(strict_mode=None):
    """Build a verifier from IND transparency environment variables."""

    try:
        import ind_settings
        settings = ind_settings.load_security_settings()
        operator_url = ind_settings.transparency_operator_url(settings)
        mirrors = ind_settings.trusted_root_mirrors(settings)
        operator_public_key = ind_settings.transparency_operator_public_key(settings) or None
        max_lag = ind_settings.max_root_lag_seconds(settings)
        max_current_age = ind_settings.max_current_root_age_seconds(settings)
        current_future_skew = ind_settings.current_root_future_skew_seconds(settings)
        min_mirrors = ind_settings.min_root_mirrors(settings)
        observed_roots_path = ind_settings.transparency_observed_roots_db(settings)
        consistency_anchor_path = ind_settings.transparency_consistency_anchor_path(settings) or None
        consistency_interval = ind_settings.transparency_consistency_check_interval_seconds(settings)
        consistency_max_stale = ind_settings.transparency_consistency_max_stale_seconds(settings)
        if strict_mode is None:
            strict_mode = ind_settings.require_transparency_log(settings)
    except Exception:
        operator_url = os.environ.get("IND_LOG_OPERATOR_URL", "").strip()
        mirrors_raw = os.environ.get("IND_LOG_MIRROR_URLS", "").strip()
        operator_public_key = os.environ.get("IND_LOG_OPERATOR_PUBLIC_KEY", "").strip() or None
        mirrors = [item.strip() for item in mirrors_raw.split(",") if item.strip()]
        max_lag = int(os.environ.get("IND_LOG_MAX_ROOT_LAG_SECONDS", DEFAULT_MAX_ROOT_LAG_SECONDS))
        max_current_age = int(
            os.environ.get("IND_LOG_MAX_CURRENT_ROOT_AGE_SECONDS", DEFAULT_MAX_CURRENT_ROOT_AGE_SECONDS)
        )
        current_future_skew = int(
            os.environ.get("IND_LOG_CURRENT_ROOT_FUTURE_SKEW_SECONDS", DEFAULT_CURRENT_ROOT_FUTURE_SKEW_SECONDS)
        )
        min_mirrors = int(os.environ.get("IND_LOG_MIN_MIRRORS", str(DEFAULT_MIN_ROOT_MIRRORS)))
        observed_roots_path = os.environ.get("IND_LOG_OBSERVED_ROOTS_DB", DEFAULT_OBSERVED_ROOTS_DB)
        consistency_anchor_path = os.environ.get("IND_LOG_CONSISTENCY_ANCHOR", "").strip() or None
        consistency_interval = int(
            os.environ.get(
                "IND_LOG_CONSISTENCY_CHECK_INTERVAL_SECONDS",
                DEFAULT_CONSISTENCY_CHECK_INTERVAL_SECONDS,
            )
        )
        consistency_max_stale = int(
            os.environ.get("IND_LOG_CONSISTENCY_MAX_STALE_SECONDS", DEFAULT_CONSISTENCY_MAX_STALE_SECONDS)
        )
        if strict_mode is None:
            strict_mode = _env_true("IND_REQUIRE_TRANSPARENCY_LOG")
    allow_unsafe_single_mirror = _env_true(UNSAFE_SINGLE_MIRROR_ENV)
    if bool(strict_mode) and allow_unsafe_single_mirror:
        raise TransparencyLogError(STRICT_UNSAFE_SINGLE_MIRROR_ERROR)
    if allow_unsafe_single_mirror and "IND_LOG_MIN_MIRRORS" not in os.environ:
        min_mirrors = 1
    if not operator_url or not mirrors:
        return None
    return TransparencyVerifier(
        operator_url,
        mirrors,
        operator_public_key=operator_public_key,
        max_root_lag_seconds=max_lag,
        max_current_root_age_seconds=max_current_age,
        current_root_future_skew_seconds=current_future_skew,
        min_mirrors=min_mirrors,
        allow_unsafe_single_mirror=allow_unsafe_single_mirror,
        strict_mode=bool(strict_mode),
        observed_roots_path=observed_roots_path,
        consistency_anchor_path=consistency_anchor_path,
        consistency_check_interval_seconds=consistency_interval,
        consistency_max_stale_seconds=consistency_max_stale,
        start_background_checks=True,
    )


def submitter_from_environment():
    """Build a log submitter from IND transparency environment variables."""

    try:
        import ind_settings
        operator_url = ind_settings.transparency_operator_url()
    except Exception:
        operator_url = os.environ.get("IND_LOG_OPERATOR_URL", "").strip()
    if not operator_url:
        return None
    return HTTPTransparencyOperator(operator_url)
