# Client and local-operator helpers for IND transparency log verification.

import contextlib
import base64
import copy
import json
import logging
import os
import sqlite3
import threading
import time
import urllib.parse
import urllib.request
import warnings
from hashlib import sha3_256
from pathlib import Path

from pymerkle import verify_consistency as pymerkle_verify_consistency
from pymerkle import verify_inclusion as pymerkle_verify_inclusion
from pymerkle.concrete.inmemory import InmemoryTree
from pymerkle.core import InvalidChallenge
from pymerkle.hasher import MerkleHasher
from pymerkle.proof import InvalidProof, MerkleProof

from . import keys_v3
from . import protocol as ind_token
from .transparency_policy import TransparencyVerifierPolicy

logger = logging.getLogger(__name__)
LOG_ROOT_TYPE = "ind.transparency_root.v3"
LOG_INCLUSION_PROOF_TYPE = "ind.transparency_inclusion_proof.v3"
LOG_CONSISTENCY_PROOF_TYPE = "ind.transparency_consistency_proof.v3"
LOG_ROOT_ANNOUNCEMENT_TYPE = "ind.transparency_root_announcement.v3"
LOG_EQUIVOCATION_PROOF_TYPE = "ind.transparency_equivocation_proof.v3"
LOG_OPERATOR_POLICY_VIOLATION_TYPE = "ind.transparency_operator_policy_violation.v3"
LOG_KEY_ROTATION_TYPE = "ind.transparency_operator_key_rotation.v3"
LOG_KEY_REVOCATION_TYPE = "ind.transparency_operator_key_revocation.v3"
LOG_SPEND_MAP_PROOF_TYPE = "ind.transparency_spend_map_proof.v3"
LOG_PROOF_ARCHIVE_TYPE = "ind.transparency_proof_archive.v3"
LOG_RECOVERY_WITNESS_TYPE = "ind.operator_recovery_witness.v3"
LOG_VERSION = 3
LOG_HASH_ALGORITHM = "sha3_256"
LOG_EMPTY_ROOT_HASH = sha3_256(b"IND-TRANSPARENCY-EMPTY-LOG-V3").hexdigest()
LOG_TREE_ALGORITHM = "CT_STYLE_SHA3_256_V3"
LOG_SPEND_MAP_ALGORITHM = "IND_SPARSE_SPEND_MAP_SHA3_256_V3"
LEGACY_LOG_TREE_ALGORITHM = "RFC6962_SHA3_256_PYMERKLE_V3"
LOG_SIGNATURE_ALGORITHM = "ED25519_BASE85"
LEGACY_LOG_SIGNATURE_ALGORITHM = "ECDSA_SECP256K1_SHA3_256_BASE85"
LOG_ROOT_SIGNATURE_DOMAIN = "IND_TRANSPARENCY_ROOT_V3"
LOG_KEY_ROTATION_SIGNATURE_DOMAIN = "IND_TRANSPARENCY_KEY_ROTATION_V3"
LOG_KEY_REVOCATION_SIGNATURE_DOMAIN = "IND_TRANSPARENCY_KEY_REVOCATION_V3"
LOG_RECOVERY_WITNESS_SIGNATURE_DOMAIN = "IND_OPERATOR_RECOVERY_WITNESS_V3"
DEFAULT_MAX_ROOT_LAG_SECONDS = 120
DEFAULT_OPERATOR_RECOVERY_MIN_FEEDS = 2
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


# Base error for IND transparency log verification failures.
class TransparencyLogError(Exception):
    pass


# Raised when a signed log root is malformed or has an invalid signature.
class RootVerificationError(TransparencyLogError):
    pass


# Raised when an inclusion proof does not resolve to a mirrored root.
class InclusionProofError(TransparencyLogError):
    pass


# Raised when a signed root proves the operator violated log policy.
class OperatorPolicyViolationError(InclusionProofError):
    def __init__(self, message, evidence):
        self.evidence = evidence
        super().__init__(message)


# Raised when a consistency proof does not link two signed roots.
class ConsistencyProofError(TransparencyLogError):
    pass


# Raised when mirrors show valid conflicting roots for one log timestamp.
class MirrorDisagreementError(TransparencyLogError):
    def __init__(self, evidence):
        self.evidence = evidence
        super().__init__("mirrors disagree about a signed transparency log root")


# Raised when a consistency check cannot reach the operator.
class ConsistencyUnavailableError(TransparencyLogError):
    pass


# Raised when an operator key rotation record is invalid.
class KeyRotationError(TransparencyLogError):
    pass


# Raised when an operator key revocation record is invalid.
class KeyRevocationError(TransparencyLogError):
    pass


# Serialize transparency-log records in the canonical IND JSON form.
def canonical_json(data):
    return ind_token.canonical_json(data)


def canonical_bytes(data):
    return canonical_json(data).encode("utf-8")


def _env_true(name):
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _settings_module():
    try:
        from . import settings as ind_settings

        return ind_settings
    except ImportError:
        try:
            import ind_settings

            return ind_settings
        except ImportError:
            return None


def _production_security_mode_enabled():
    ind_settings = _settings_module()
    if ind_settings is None:
        return (
            _env_true("IND_PRODUCTION")
            or os.environ.get("IND_SECURITY_PROFILE", "").strip().lower() == "production"
        )
    settings = ind_settings.load_security_settings(validate_production=False)
    return ind_settings.production_mode(settings)


def _testnet_mode_enabled():
    ind_settings = _settings_module()
    if ind_settings is None:
        return os.environ.get("IND_NETWORK", "").strip().lower() == "testnet"
    settings = ind_settings.load_security_settings(validate_production=False)
    return ind_settings.is_testnet(settings)


def _env_false(name):
    return os.environ.get(name, "").strip().lower() in {"0", "false", "no", "off"}


def accept_legacy_algorithm_names():
    return not _env_false(ACCEPT_LEGACY_ALGORITHM_NAMES_ENV)


# Return current and configured legacy transparency tree algorithm names.
def accepted_tree_algorithms():
    algorithms = {LOG_TREE_ALGORITHM}
    if accept_legacy_algorithm_names():
        algorithms.add(LEGACY_LOG_TREE_ALGORITHM)
    return algorithms


# Derive the stable log id from the operator signing key.
def log_id_from_public_key(public_key_base85):
    return ind_token.sha3_hex(public_key_base85.strip().encode("utf-8"))


def _signature_algorithms_for_verification():
    algorithms = {LOG_SIGNATURE_ALGORITHM}
    if accept_legacy_algorithm_names():
        algorithms.add(LEGACY_LOG_SIGNATURE_ALGORITHM)
    return algorithms


def _sign_operator_payload(private_key, payload):
    private_key = str(private_key).strip()
    if not private_key.startswith(keys_v3.PRIVATE_KEY_PREFIX):
        raise TransparencyLogError("operator signing key must be an indsk3 Ed25519 key")
    signature = keys_v3.sign(private_key, payload)
    return base64.b85encode(signature).decode("ascii")


def _verify_operator_payload(public_key, signature, payload, signature_algorithm):
    public_key = str(public_key).strip()
    signature_algorithm = str(signature_algorithm).strip()
    try:
        signature_bytes = base64.b85decode(str(signature).strip().encode("ascii"))
    except Exception:
        return False
    if signature_algorithm == LOG_SIGNATURE_ALGORITHM:
        if not public_key.startswith(keys_v3.PUBLIC_KEY_PREFIX):
            return False
        return keys_v3.verify(public_key, signature_bytes, payload)
    if signature_algorithm == LEGACY_LOG_SIGNATURE_ALGORITHM and accept_legacy_algorithm_names():
        if public_key.startswith(keys_v3.PUBLIC_KEY_PREFIX):
            return False
        return ind_token.b85_verify(public_key, signature, payload)
    return False


# Return the bytes covered by the signed-root signature.
def root_signature_payload(root):
    unsigned = copy.deepcopy(root)
    unsigned.pop("signature", None)
    return ind_token.signature_payload(LOG_ROOT_SIGNATURE_DOMAIN, unsigned)


# Return a stable id for one complete signed root record.
def signed_root_id(root):
    return ind_token.sha3_hex(canonical_bytes(root))


def _hex32(value, label):
    value = str(value).lower()
    if len(value) != 64:
        raise RootVerificationError(f"invalid {label}")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise RootVerificationError(f"invalid {label}") from exc
    return value


def _require_exact_keys(data, required, label, optional=(), error_cls=None):
    error_cls = error_cls or TransparencyLogError
    if not isinstance(data, dict):
        raise error_cls(f"malformed {label}")
    required = set(required)
    allowed = required | set(optional)
    present = set(data)
    missing = required - present
    if missing:
        raise error_cls(f"malformed {label}: missing {sorted(missing)[0]}")
    extra = present - allowed
    if extra:
        raise error_cls(f"malformed {label}: unknown field {sorted(extra)[0]}")
    return True


def _require_keys(data, required, label, optional=()):
    return _require_exact_keys(data, required, label, optional=optional)


def _require_int_for(value, label, minimum=None, maximum=None, error_cls=None):
    error_cls = error_cls or TransparencyLogError
    if type(value) is not int:
        raise error_cls(f"{label} must be an integer")
    if minimum is not None and value < int(minimum):
        raise error_cls(f"{label} is below the allowed range")
    if maximum is not None and value > int(maximum):
        raise error_cls(f"{label} is above the allowed range")
    return value


def _require_int(value, label, minimum=None, maximum=None):
    return _require_int_for(value, label, minimum=minimum, maximum=maximum)


def _require_str(value, label, error_cls=None):
    error_cls = error_cls or TransparencyLogError
    if not isinstance(value, str):
        raise error_cls(f"{label} must be a string")
    return value.strip()


def _require_list(value, label, error_cls=None):
    error_cls = error_cls or TransparencyLogError
    if not isinstance(value, list):
        raise error_cls(f"{label} must be a list")
    return value


SPEND_MAP_KEY_BITS = 256
_SPEND_MAP_EMPTY_HASHES = None


def _spend_map_empty_hashes():
    global _SPEND_MAP_EMPTY_HASHES
    if _SPEND_MAP_EMPTY_HASHES is not None:
        return _SPEND_MAP_EMPTY_HASHES
    hashes = [None] * (SPEND_MAP_KEY_BITS + 1)
    hashes[SPEND_MAP_KEY_BITS] = ind_token.sha3_hex(b"IND-SPEND-MAP-EMPTY-LEAF-V3")
    for depth in range(SPEND_MAP_KEY_BITS - 1, -1, -1):
        hashes[depth] = _spend_map_branch_hash(hashes[depth + 1], hashes[depth + 1])
    _SPEND_MAP_EMPTY_HASHES = hashes
    return hashes


def _spend_map_empty_root():
    return _spend_map_empty_hashes()[0]


# Return the globally indexed key for one spend of a previous bill state.
def spend_key_for_transfer(transfer):
    key_material = {
        "token_id": transfer["token_id"],
        "previous_hash": transfer["previous_hash"],
        "sequence": int(transfer["sequence"]),
        "sender_address": transfer["sender_address"],
    }
    return ind_token.sha3_hex(canonical_bytes(key_material))


# Build the public spend-map record committed by signed transparency roots.
def spend_claim_for_transfer(transfer, log_id, transfer_leaf_index, accepted_at):
    transfer_hash = ind_token.transfer_hash(transfer)
    claim = {
        "type": "ind.transparency_spend_claim.v3",
        "version": LOG_VERSION,
        "log_id": str(log_id),
        "spend_key": spend_key_for_transfer(transfer),
        "token_id": transfer["token_id"],
        "previous_hash": transfer["previous_hash"],
        "sequence": int(transfer["sequence"]),
        "sender_address": transfer["sender_address"],
        "sender_public_key": transfer["sender_public_key"],
        "transfer_hash": transfer_hash,
        "transfer_leaf_index": int(transfer_leaf_index),
        "accepted_at": int(accepted_at),
        "transfer": copy.deepcopy(transfer),
    }
    return claim


_SPEND_CLAIM_REQUIRED = {
    "type",
    "version",
    "log_id",
    "spend_key",
    "token_id",
    "previous_hash",
    "sequence",
    "sender_address",
    "sender_public_key",
    "transfer_hash",
    "transfer_leaf_index",
    "accepted_at",
}
_SPEND_CLAIM_OPTIONAL = {"transfer"}


# Return the canonical spend-claim shape used for inclusion verification.
def _normalize_spend_claim(claim, error_cls=None):
    error_cls = error_cls or InclusionProofError
    _require_exact_keys(
        claim,
        _SPEND_CLAIM_REQUIRED,
        "transparency spend claim",
        optional=_SPEND_CLAIM_OPTIONAL,
        error_cls=error_cls,
    )
    if (
        claim["type"] != "ind.transparency_spend_claim.v3"
        or _require_int_for(
            claim["version"],
            "transparency spend claim version",
            error_cls=error_cls,
        )
        != LOG_VERSION
    ):
        raise error_cls("unsupported transparency spend claim version")
    normalized = {
        "type": "ind.transparency_spend_claim.v3",
        "version": LOG_VERSION,
        "log_id": _require_str(
            claim["log_id"], "transparency spend claim log id", error_cls=error_cls
        ),
        "spend_key": _hex32(claim["spend_key"], "spend key"),
        "token_id": _require_str(
            claim["token_id"], "transparency spend claim bill id", error_cls=error_cls
        ),
        "previous_hash": _hex32(claim["previous_hash"], "transparency spend claim previous hash"),
        "sequence": _require_int_for(
            claim["sequence"],
            "transparency spend claim sequence",
            minimum=1,
            error_cls=error_cls,
        ),
        "sender_address": _require_str(
            claim["sender_address"], "transparency spend claim sender", error_cls=error_cls
        ),
        "sender_public_key": _require_str(
            claim["sender_public_key"], "transparency spend claim sender key", error_cls=error_cls
        ),
        "transfer_hash": _hex32(claim["transfer_hash"], "transparency spend claim transfer hash"),
        "transfer_leaf_index": _require_int_for(
            claim["transfer_leaf_index"],
            "transparency spend claim leaf index",
            minimum=0,
            error_cls=error_cls,
        ),
        "accepted_at": _require_int_for(
            claim["accepted_at"],
            "transparency spend claim accepted_at",
            minimum=0,
            error_cls=error_cls,
        ),
    }
    if "transfer" in claim:
        transfer = copy.deepcopy(claim["transfer"])
        try:
            if (
                isinstance(transfer, dict)
                and transfer.get("type") == "ind.transfer.v3"
                and "network_id" in transfer
            ):
                from . import protocol_v3

                protocol_v3._validate_transfer_shape(
                    transfer,
                    int(transfer["network_id"]),
                )
                protocol_v3.verify_transfer_signature(transfer)
                transfer_hash_value = protocol_v3.transfer_hash(transfer)
                spend_key_value = protocol_v3.spend_key_for_transfer(transfer)
            else:
                ind_token._verify_transfer_signature(transfer)
                transfer_hash_value = ind_token.transfer_hash(transfer)
                spend_key_value = spend_key_for_transfer(transfer)
        except Exception as exc:
            raise error_cls("transparency spend claim transfer signature is invalid") from exc
        if transfer_hash_value != normalized["transfer_hash"]:
            raise error_cls("transparency spend claim transfer hash mismatch")
        if spend_key_value != normalized["spend_key"]:
            raise error_cls("transparency spend claim transfer spend key mismatch")
        for field in ("token_id", "previous_hash", "sender_address", "sender_public_key"):
            if transfer[field] != normalized[field]:
                raise error_cls(f"transparency spend claim transfer {field} mismatch")
        if int(transfer["sequence"]) != int(normalized["sequence"]):
            raise error_cls("transparency spend claim transfer sequence mismatch")
        normalized["transfer"] = transfer
    return normalized


def _spend_claim_sort_key(claim):
    return (
        claim["spend_key"],
        claim["transfer_hash"],
        int(claim["transfer_leaf_index"]),
        int(claim["accepted_at"]),
    )


def _spend_map_slot_hash(spend_key, claims):
    key_bytes = bytes.fromhex(str(spend_key))
    slot = {
        "spend_key": str(spend_key),
        "claims": sorted((copy.deepcopy(claim) for claim in claims), key=_spend_claim_sort_key),
    }
    return ind_token.sha3_hex(b"IND-SPEND-MAP-SLOT-V3:" + key_bytes + canonical_bytes(slot))


def _spend_map_branch_hash(left_hash, right_hash):
    left = bytes.fromhex(str(left_hash))
    right = bytes.fromhex(str(right_hash))
    return ind_token.sha3_hex(b"IND-SPEND-MAP-BRANCH-V3:" + left + right)


def _spend_key_position(spend_key):
    return int(_hex32(spend_key, "spend key"), 16)


def _spend_map_levels(claims):
    empty_hashes = _spend_map_empty_hashes()
    leaves = {}
    claims_by_key = {}
    for claim in claims:
        claim = _normalize_spend_claim(claim)
        spend_key = _hex32(claim["spend_key"], "spend key")
        position = int(spend_key, 16)
        claims_by_hash = claims_by_key.setdefault(position, {})
        existing = claims_by_hash.get(claim["transfer_hash"])
        if existing is not None and existing != claim:
            raise InclusionProofError(
                "transparency spend map contains inconsistent duplicate claims"
            )
        claims_by_hash[claim["transfer_hash"]] = claim

    for position, claims_by_hash in claims_by_key.items():
        claim_list = sorted(claims_by_hash.values(), key=_spend_claim_sort_key)
        spend_key = claim_list[0]["spend_key"]
        claims_by_key[position] = claim_list
        leaves[position] = _spend_map_slot_hash(spend_key, claim_list)

    levels = [None] * (SPEND_MAP_KEY_BITS + 1)
    levels[SPEND_MAP_KEY_BITS] = leaves
    for depth in range(SPEND_MAP_KEY_BITS - 1, -1, -1):
        child_level = levels[depth + 1]
        parents = {}
        for parent_position in {position >> 1 for position in child_level}:
            left = child_level.get(parent_position << 1, empty_hashes[depth + 1])
            right = child_level.get((parent_position << 1) + 1, empty_hashes[depth + 1])
            parent_hash = _spend_map_branch_hash(left, right)
            if parent_hash != empty_hashes[depth]:
                parents[parent_position] = parent_hash
        levels[depth] = parents
    total_claims = sum(len(claim_list) for claim_list in claims_by_key.values())
    return levels, claims_by_key, total_claims


# Compute the sparse spend-map root for the supplied public spend claims.
def spend_map_root(claims):
    levels, _claims_by_key, _total_claims = _spend_map_levels(claims)
    return levels[0].get(0, _spend_map_empty_root())


# Build an inclusion proof for one spend key in the sparse spend map.
def build_spend_map_proof(claims, spend_key, tree_size):
    spend_key = _hex32(spend_key, "spend key")
    position = _spend_key_position(spend_key)
    levels, claims_by_key, total_claims = _spend_map_levels(claims)
    if position not in claims_by_key:
        raise InclusionProofError("spend key is not in the transparency spend map")

    audit_path = []
    node_position = position
    empty_hashes = _spend_map_empty_hashes()
    for child_depth in range(SPEND_MAP_KEY_BITS, 0, -1):
        sibling_position = node_position ^ 1
        sibling_hash = levels[child_depth].get(sibling_position, empty_hashes[child_depth])
        side = "right" if node_position % 2 == 0 else "left"
        audit_path.append({"side": side, "hash": sibling_hash})
        node_position >>= 1

    return {
        "type": LOG_SPEND_MAP_PROOF_TYPE,
        "version": LOG_VERSION,
        "algorithm": LOG_SPEND_MAP_ALGORITHM,
        "spend_key": spend_key,
        "tree_size": int(tree_size),
        "map_size": total_claims,
        "spend_claims": copy.deepcopy(claims_by_key[position]),
        "audit_path": audit_path,
    }


# Verify that a spend claim is included in a signed root's spend-map commitment.
def verify_spend_map_proof(proof, signed_root):
    verify_signed_root(signed_root)
    required = {
        "type",
        "version",
        "algorithm",
        "spend_key",
        "tree_size",
        "map_size",
        "spend_claims",
        "audit_path",
    }
    legacy_required = (required - {"spend_claims"}) | {"spend_claim"}
    if not isinstance(proof, dict) or (set(proof) != required and set(proof) != legacy_required):
        raise InclusionProofError("malformed transparency spend-map proof")
    if (
        proof["type"] != LOG_SPEND_MAP_PROOF_TYPE
        or _require_int_for(
            proof["version"],
            "transparency spend-map proof version",
            error_cls=InclusionProofError,
        )
        != LOG_VERSION
    ):
        raise InclusionProofError("unsupported transparency spend-map proof version")
    if proof["algorithm"] != LOG_SPEND_MAP_ALGORITHM:
        raise InclusionProofError("unsupported transparency spend-map algorithm")
    for field in ("spend_map_root", "spend_map_size", "spend_map_algorithm"):
        if field not in signed_root:
            raise InclusionProofError("signed root does not commit to a transparency spend map")
    if signed_root["spend_map_algorithm"] != LOG_SPEND_MAP_ALGORITHM:
        raise InclusionProofError("signed root uses an unsupported spend-map algorithm")
    if _require_int_for(
        proof["tree_size"],
        "transparency spend-map proof tree size",
        minimum=0,
        error_cls=InclusionProofError,
    ) != _require_int_for(
        signed_root["tree_size"],
        "transparency root tree size",
        minimum=0,
        error_cls=InclusionProofError,
    ):
        raise InclusionProofError("spend-map proof tree size does not match signed root")
    if _require_int_for(
        proof["map_size"],
        "transparency spend-map proof size",
        minimum=0,
        error_cls=InclusionProofError,
    ) != _require_int_for(
        signed_root["spend_map_size"],
        "transparency root spend-map size",
        minimum=0,
        error_cls=InclusionProofError,
    ):
        raise InclusionProofError("spend-map proof size does not match signed root")
    if "spend_claims" in proof:
        if not isinstance(proof["spend_claims"], list) or not proof["spend_claims"]:
            raise InclusionProofError("transparency spend-map proof has no spend claims")
        claims = [_normalize_spend_claim(claim) for claim in proof["spend_claims"]]
    else:
        claims = [_normalize_spend_claim(proof["spend_claim"])]
    transfer_hashes = set()
    for claim in claims:
        if claim["log_id"] != signed_root["log_id"]:
            raise InclusionProofError("spend claim is for a different transparency log")
        if claim["spend_key"] != proof["spend_key"]:
            raise InclusionProofError("spend-map proof is for a different spend key")
        if int(claim["transfer_leaf_index"]) >= int(signed_root["tree_size"]):
            raise InclusionProofError("spend claim references a transfer outside the signed root")
        if claim["transfer_hash"] in transfer_hashes:
            raise InclusionProofError("spend-map proof contains duplicate transfer claims")
        transfer_hashes.add(claim["transfer_hash"])

    current_hash = _spend_map_slot_hash(proof["spend_key"], claims)
    node_position = _spend_key_position(proof["spend_key"])
    if len(proof["audit_path"]) != SPEND_MAP_KEY_BITS:
        raise InclusionProofError("invalid spend-map audit path length")
    for step in proof["audit_path"]:
        if not isinstance(step, dict) or set(step) != {"side", "hash"}:
            raise InclusionProofError("malformed spend-map audit path")
        sibling_hash = _hex32(step["hash"], "spend-map sibling hash")
        expected_side = "right" if node_position % 2 == 0 else "left"
        if step["side"] != expected_side:
            raise InclusionProofError("spend-map audit path does not follow the spend key")
        if step["side"] == "left":
            current_hash = _spend_map_branch_hash(sibling_hash, current_hash)
        elif step["side"] == "right":
            current_hash = _spend_map_branch_hash(current_hash, sibling_hash)
        else:
            raise InclusionProofError("invalid spend-map audit side")
        node_position >>= 1
    if current_hash != signed_root["spend_map_root"]:
        raise InclusionProofError("spend-map proof does not match signed root")
    return sorted(claims, key=_spend_claim_sort_key)


# Build portable evidence that an operator signed a policy-violating root.
def make_operator_policy_violation_proof(
    root, spend_proof, violation_type="accepted_conflicting_spend", detected_at=None
):
    proof = {
        "type": LOG_OPERATOR_POLICY_VIOLATION_TYPE,
        "version": LOG_VERSION,
        "violation_type": str(violation_type),
        "log_id": root["log_id"],
        "root": copy.deepcopy(root),
        "spend_proof": copy.deepcopy(spend_proof),
        "detected_at": int(detected_at or time.time()),
    }
    verify_operator_policy_violation_proof(proof)
    return proof


# Verify self-contained evidence that a signed root accepted a double spend.
def verify_operator_policy_violation_proof(proof, operator_public_key=None):
    required = {"type", "version", "violation_type", "log_id", "root", "spend_proof", "detected_at"}
    _require_exact_keys(
        proof,
        required,
        "operator policy violation proof",
        error_cls=InclusionProofError,
    )
    if (
        proof["type"] != LOG_OPERATOR_POLICY_VIOLATION_TYPE
        or _require_int_for(
            proof["version"],
            "operator policy violation proof version",
            error_cls=InclusionProofError,
        )
        != LOG_VERSION
    ):
        raise InclusionProofError("unsupported operator policy violation proof version")
    if proof["violation_type"] != "accepted_conflicting_spend":
        raise InclusionProofError("unsupported operator policy violation type")
    _require_int_for(
        proof["detected_at"],
        "operator policy violation detected_at",
        minimum=0,
        error_cls=InclusionProofError,
    )
    root = copy.deepcopy(proof["root"])
    verify_signed_root(root, operator_public_key=operator_public_key)
    if proof["log_id"] != root["log_id"]:
        raise InclusionProofError("operator policy violation log id mismatch")
    claims = verify_spend_map_proof(proof["spend_proof"], root)
    if len({claim["transfer_hash"] for claim in claims}) < 2:
        raise InclusionProofError("operator policy violation proof has no conflicting spend")
    missing_transfer = [claim for claim in claims if "transfer" not in claim]
    if missing_transfer:
        raise InclusionProofError(
            "operator policy violation proof is missing conflicting transfer bodies"
        )
    spend_keys = {claim["spend_key"] for claim in claims}
    if len(spend_keys) != 1:
        raise InclusionProofError("operator policy violation proof mixes spend keys")
    first = claims[0]
    for claim in claims[1:]:
        for field in (
            "token_id",
            "previous_hash",
            "sequence",
            "sender_address",
            "sender_public_key",
        ):
            if claim[field] != first[field]:
                raise InclusionProofError("operator policy violation proof claims are not siblings")
    return copy.deepcopy(proof)


# Verify that the signed root maps this transfer's spend key to this transfer hash.
def verify_spend_map_proof_for_transfer(
    transfer,
    proof,
    signed_root,
    operator_public_key=None,
):
    verify_signed_root(signed_root, operator_public_key=operator_public_key)
    claims = verify_spend_map_proof(proof, signed_root)
    if isinstance(transfer, dict) and transfer.get("type") == "ind.transfer.v3":
        from . import protocol_v3

        expected_spend_key = protocol_v3.spend_key_for_transfer(transfer)
        expected_transfer_hash = protocol_v3.transfer_hash(transfer)
    else:
        expected_spend_key = spend_key_for_transfer(transfer)
        expected_transfer_hash = ind_token.transfer_hash(transfer)
    claim = next((item for item in claims if item["transfer_hash"] == expected_transfer_hash), None)
    if claim is None:
        raise InclusionProofError("spend proof does not contain this transfer")
    if claim["spend_key"] != expected_spend_key:
        raise InclusionProofError("spend proof is for a different bill state")
    if claim["transfer_hash"] != expected_transfer_hash:
        raise InclusionProofError("spend proof maps the spend key to a different transfer")
    if claim["token_id"] != transfer["token_id"]:
        raise InclusionProofError("spend proof bill id mismatch")
    if claim["previous_hash"] != transfer["previous_hash"]:
        raise InclusionProofError("spend proof previous hash mismatch")
    if int(claim["sequence"]) != int(transfer["sequence"]):
        raise InclusionProofError("spend proof sequence mismatch")
    if claim["sender_address"] != transfer["sender_address"]:
        raise InclusionProofError("spend proof sender mismatch")
    if claim["sender_public_key"] != transfer["sender_public_key"]:
        raise InclusionProofError("spend proof sender key mismatch")
    conflicting_claims = [
        item for item in claims if item["transfer_hash"] != expected_transfer_hash
    ]
    if conflicting_claims:
        all_claims = [claim, *conflicting_claims]
        if all("transfer" in item for item in all_claims):
            evidence = make_operator_policy_violation_proof(signed_root, proof)
            raise OperatorPolicyViolationError(
                "operator accepted conflicting spend claims", evidence
            )
        raise InclusionProofError("spend proof contains an unverifiable conflicting sibling claim")
    return True


# Verify that a checkpoint's settled tip has a non-conflicting spend-map claim.
def verify_spend_map_proof_for_checkpoint(
    checkpoint,
    proof,
    signed_root,
    operator_public_key=None,
):
    verify_signed_root(signed_root, operator_public_key=operator_public_key)
    claims = verify_spend_map_proof(proof, signed_root)
    expected_transfer_hash = str(checkpoint["last_transfer_hash"]).lower()
    claim = next((item for item in claims if item["transfer_hash"] == expected_transfer_hash), None)
    if claim is None:
        raise InclusionProofError("checkpoint spend proof does not contain its settled transfer")
    if claim["token_id"] != checkpoint["token_id"]:
        raise InclusionProofError("checkpoint spend proof bill id mismatch")
    if int(claim["sequence"]) != int(checkpoint["sequence"]):
        raise InclusionProofError("checkpoint spend proof sequence mismatch")
    if "transfer" not in claim:
        raise InclusionProofError("checkpoint spend proof is missing the settled transfer body")
    transfer = claim["transfer"]
    try:
        ind_token._verify_transfer_signature(transfer)
    except Exception as exc:
        raise InclusionProofError("checkpoint spend proof transfer signature is invalid") from exc
    if ind_token.transfer_hash(transfer) != expected_transfer_hash:
        raise InclusionProofError("checkpoint spend proof transfer hash mismatch")
    if transfer["recipient_address"] != checkpoint["owner_address"]:
        raise InclusionProofError("checkpoint spend proof owner mismatch")
    if int(transfer["timestamp"]) != int(checkpoint["last_transfer_timestamp"]):
        raise InclusionProofError("checkpoint spend proof timestamp mismatch")
    conflicting_claims = [
        item for item in claims if item["transfer_hash"] != expected_transfer_hash
    ]
    if conflicting_claims:
        all_claims = [claim, *conflicting_claims]
        if all("transfer" in item for item in all_claims):
            evidence = make_operator_policy_violation_proof(signed_root, proof)
            raise OperatorPolicyViolationError(
                "operator accepted conflicting spend claims", evidence
            )
        raise InclusionProofError(
            "checkpoint spend proof contains an unverifiable conflicting sibling claim"
        )
    return True


# Build an unsigned proof archive snapshot for one signed root.
def make_proof_archive(signed_root, entries, spend_claims):
    verify_signed_root(signed_root)
    tree_size = _require_int_for(
        signed_root["tree_size"],
        "proof archive tree size",
        minimum=0,
        error_cls=InclusionProofError,
    )
    return {
        "type": LOG_PROOF_ARCHIVE_TYPE,
        "version": LOG_VERSION,
        "log_id": signed_root["log_id"],
        "tree_size": tree_size,
        "root_hash": signed_root["root_hash"],
        "signed_root_id": signed_root_id(signed_root),
        "entries": copy.deepcopy(entries),
        "spend_claims": copy.deepcopy(spend_claims),
    }


def _archive_entries_tree(entries, tree_size):
    tree_size = int(tree_size)
    if not isinstance(entries, list):
        raise InclusionProofError("proof archive entries must be a list")
    if len(entries) != tree_size:
        raise InclusionProofError("proof archive entry count does not match signed root")
    tree = InmemoryTree(algorithm=LOG_HASH_ALGORITHM)
    entry_by_hash = {}
    for expected_index, entry in enumerate(entries):
        _require_exact_keys(
            entry,
            {"leaf_index", "entry_hash", "submitted_at"},
            "proof archive entry",
            optional={"entry_kind", "entry"},
            error_cls=InclusionProofError,
        )
        leaf_index = _require_int_for(
            entry["leaf_index"],
            "proof archive leaf index",
            minimum=0,
            error_cls=InclusionProofError,
        )
        if leaf_index != expected_index:
            raise InclusionProofError("proof archive entries are not contiguous")
        entry_hash = _hex32(entry["entry_hash"], "proof archive entry hash")
        _require_int_for(
            entry["submitted_at"],
            "proof archive submitted_at",
            minimum=0,
            error_cls=InclusionProofError,
        )
        tree.append_entry(bytes.fromhex(entry_hash))
        entry_by_hash[entry_hash] = copy.deepcopy(entry)
    return tree, entry_by_hash


# Verify that an archive can reproduce the signed root and spend-map root.
def verify_proof_archive(archive, signed_root, operator_public_key=None):
    verify_signed_root(signed_root, operator_public_key=operator_public_key)
    required = {
        "type",
        "version",
        "log_id",
        "tree_size",
        "root_hash",
        "signed_root_id",
        "entries",
        "spend_claims",
    }
    _require_exact_keys(archive, required, "proof archive", error_cls=InclusionProofError)
    if (
        archive["type"] != LOG_PROOF_ARCHIVE_TYPE
        or _require_int_for(
            archive["version"],
            "proof archive version",
            error_cls=InclusionProofError,
        )
        != LOG_VERSION
    ):
        raise InclusionProofError("unsupported proof archive version")
    if archive["log_id"] != signed_root["log_id"]:
        raise InclusionProofError("proof archive is for a different log")
    if _require_int_for(
        archive["tree_size"], "proof archive tree size", minimum=0, error_cls=InclusionProofError
    ) != int(signed_root["tree_size"]):
        raise InclusionProofError("proof archive tree size mismatch")
    if _hex32(archive["root_hash"], "proof archive root hash") != signed_root["root_hash"]:
        raise InclusionProofError("proof archive root hash mismatch")
    if _hex32(archive["signed_root_id"], "proof archive signed root id") != signed_root_id(
        signed_root
    ):
        raise InclusionProofError("proof archive signed root id mismatch")
    tree, _entry_by_hash = _archive_entries_tree(archive["entries"], int(signed_root["tree_size"]))
    if (
        int(signed_root["tree_size"]) > 0
        and tree.get_state(int(signed_root["tree_size"])).hex() != signed_root["root_hash"]
    ):
        raise InclusionProofError("proof archive entries do not reproduce the signed root")
    claims = archive["spend_claims"]
    if not isinstance(claims, list):
        raise InclusionProofError("proof archive spend claims must be a list")
    for claim in claims:
        proof = build_spend_map_proof(claims, claim["spend_key"], signed_root["tree_size"])
        verify_spend_map_proof(proof, signed_root)
    if spend_map_root(claims) != signed_root.get("spend_map_root"):
        raise InclusionProofError("proof archive spend claims do not reproduce the spend-map root")
    if len(claims) != int(signed_root.get("spend_map_size", 0)):
        raise InclusionProofError("proof archive spend claim count mismatch")
    return True


def inclusion_proof_from_archive(archive, entry_hash, signed_root, operator_public_key=None):
    verify_proof_archive(archive, signed_root, operator_public_key=operator_public_key)
    tree, entry_by_hash = _archive_entries_tree(archive["entries"], int(signed_root["tree_size"]))
    entry_hash = _hex32(entry_hash, "proof archive inclusion entry hash")
    entry = entry_by_hash.get(entry_hash)
    if entry is None:
        raise InclusionProofError("entry is not in the proof archive")
    leaf_index = int(entry["leaf_index"])
    try:
        proof = tree.prove_inclusion(leaf_index + 1, int(signed_root["tree_size"]))
    except (InvalidChallenge, InvalidProof) as exc:
        raise InclusionProofError(str(exc)) from exc
    return {
        "type": LOG_INCLUSION_PROOF_TYPE,
        "version": LOG_VERSION,
        "log_id": signed_root["log_id"],
        "entry_hash": entry_hash,
        "leaf_hash": log_leaf_hash(entry_hash).hex(),
        "leaf_index": leaf_index,
        "tree_size": int(signed_root["tree_size"]),
        "proof": proof.serialize(),
    }


def spend_map_proof_from_archive(archive, spend_key, signed_root, operator_public_key=None):
    verify_proof_archive(archive, signed_root, operator_public_key=operator_public_key)
    return build_spend_map_proof(archive["spend_claims"], spend_key, int(signed_root["tree_size"]))


def _root_fingerprint(root):
    return (
        int(root["tree_size"]),
        root["root_hash"],
        root.get("spend_map_root"),
        int(root.get("spend_map_size", 0)),
    )


# Return the collision type if two valid roots prove operator equivocation.
def equivocation_collision_type(root_a, root_b):
    if root_a["log_id"] != root_b["log_id"]:
        return None
    if signed_root_id(root_a) == signed_root_id(root_b):
        return None
    if int(root_a["tree_size"]) == int(root_b["tree_size"]) and _root_fingerprint(
        root_a
    ) != _root_fingerprint(root_b):
        return "same_tree_size"
    if int(root_a["timestamp"]) == int(root_b["timestamp"]) and _root_fingerprint(
        root_a
    ) != _root_fingerprint(root_b):
        return "same_timestamp"
    return None


# Build and sign a transparency log root record.
def make_signed_root(
    tree_size,
    root_hash,
    timestamp,
    private_key_base85,
    public_key_base85,
    spend_map_root=None,
    spend_map_size=0,
):
    root = {
        "type": LOG_ROOT_TYPE,
        "version": LOG_VERSION,
        "log_id": log_id_from_public_key(public_key_base85),
        "tree_algorithm": LOG_TREE_ALGORITHM,
        "hash_algorithm": LOG_HASH_ALGORITHM,
        "signature_algorithm": LOG_SIGNATURE_ALGORITHM,
        "tree_size": int(tree_size),
        "root_hash": str(root_hash).lower(),
        "spend_map_algorithm": LOG_SPEND_MAP_ALGORITHM,
        "spend_map_root": str(spend_map_root or _spend_map_empty_root()).lower(),
        "spend_map_size": int(spend_map_size),
        "timestamp": int(timestamp),
        "operator_public_key": public_key_base85,
    }
    root["signature"] = _sign_operator_payload(private_key_base85, root_signature_payload(root))
    return root


# Validate a signed root and its operator signature.
def verify_signed_root(root, operator_public_key=None):
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
    spend_map_fields = {"spend_map_algorithm", "spend_map_root", "spend_map_size"}
    _require_exact_keys(
        root,
        required,
        "signed transparency root",
        optional=spend_map_fields,
        error_cls=RootVerificationError,
    )
    if (
        root["type"] != LOG_ROOT_TYPE
        or _require_int_for(
            root["version"],
            "transparency root version",
            error_cls=RootVerificationError,
        )
        != LOG_VERSION
    ):
        raise RootVerificationError("unsupported transparency root version")
    if root["tree_algorithm"] not in accepted_tree_algorithms():
        raise RootVerificationError("unsupported transparency tree algorithm")
    if root["hash_algorithm"] != LOG_HASH_ALGORITHM:
        raise RootVerificationError("unsupported transparency hash algorithm")
    if root["signature_algorithm"] not in _signature_algorithms_for_verification():
        raise RootVerificationError("unsupported transparency root signature algorithm")
    _require_int_for(
        root["tree_size"], "transparency tree size", minimum=0, error_cls=RootVerificationError
    )
    _require_int_for(
        root["timestamp"], "transparency root timestamp", minimum=0, error_cls=RootVerificationError
    )
    _hex32(root["root_hash"], "transparency root hash")
    if spend_map_fields & set(root):
        if not spend_map_fields.issubset(root):
            raise RootVerificationError("incomplete transparency spend-map commitment")
        if root["spend_map_algorithm"] != LOG_SPEND_MAP_ALGORITHM:
            raise RootVerificationError("unsupported transparency spend-map algorithm")
        _hex32(root["spend_map_root"], "transparency spend-map root hash")
        _require_int_for(
            root["spend_map_size"],
            "transparency spend-map size",
            minimum=0,
            error_cls=RootVerificationError,
        )
    root_public_key = root["operator_public_key"].strip()
    if operator_public_key and root_public_key != operator_public_key.strip():
        raise RootVerificationError("transparency root was signed by an unexpected operator")
    if root["log_id"] != log_id_from_public_key(root_public_key):
        raise RootVerificationError("transparency root log id does not match operator key")
    if not _verify_operator_payload(
        root_public_key,
        root["signature"],
        root_signature_payload(root),
        root["signature_algorithm"],
    ):
        raise RootVerificationError("invalid transparency root signature")
    return True


# Wrap a signed root in the peer gossip format.
def make_root_announcement(root, observed_at=None):
    verify_signed_root(root)
    return {
        "type": LOG_ROOT_ANNOUNCEMENT_TYPE,
        "version": LOG_VERSION,
        "root": copy.deepcopy(root),
        "observed_at": int(observed_at or time.time()),
    }


# Validate a peer-gossiped signed root announcement.
def verify_root_announcement(message, operator_public_key=None):
    _require_exact_keys(
        message,
        {"type", "version", "root", "observed_at"},
        "transparency root announcement",
        error_cls=RootVerificationError,
    )
    if message.get("type") != LOG_ROOT_ANNOUNCEMENT_TYPE:
        raise RootVerificationError("not a transparency root announcement")
    if (
        _require_int_for(
            message["version"],
            "transparency root announcement version",
            error_cls=RootVerificationError,
        )
        != LOG_VERSION
    ):
        raise RootVerificationError("unsupported transparency root announcement version")
    root = message.get("root")
    verify_signed_root(root, operator_public_key=operator_public_key)
    _require_int_for(
        message["observed_at"],
        "transparency root observed_at",
        minimum=0,
        error_cls=RootVerificationError,
    )
    return root


def recovery_witness_signature_payload(witness):
    unsigned = copy.deepcopy(witness)
    unsigned.pop("signature", None)
    return ind_token.signature_payload(LOG_RECOVERY_WITNESS_SIGNATURE_DOMAIN, unsigned)


def make_recovery_witness(
    message_hash,
    feed_id,
    first_seen,
    source_segment_hash,
    feed_private_key,
    feed_public_key,
):
    witness = {
        "type": LOG_RECOVERY_WITNESS_TYPE,
        "version": LOG_VERSION,
        "signature_algorithm": LOG_SIGNATURE_ALGORITHM,
        "message_hash": _hex32(message_hash, "recovery witness message hash"),
        "feed_id": str(feed_id),
        "feed_public_key": str(feed_public_key).strip(),
        "first_seen": int(first_seen),
        "source_segment_hash": _hex32(
            source_segment_hash, "recovery witness source segment hash"
        ),
    }
    witness["signature"] = _sign_operator_payload(
        feed_private_key, recovery_witness_signature_payload(witness)
    )
    return witness


def verify_recovery_witness(witness, trusted_feed_public_keys=None):
    _require_exact_keys(
        witness,
        {
            "type",
            "version",
            "signature_algorithm",
            "message_hash",
            "feed_id",
            "feed_public_key",
            "first_seen",
            "source_segment_hash",
            "signature",
        },
        "operator recovery witness",
        error_cls=RootVerificationError,
    )
    if witness["type"] != LOG_RECOVERY_WITNESS_TYPE:
        raise RootVerificationError("not an operator recovery witness")
    if (
        _require_int_for(
            witness["version"],
            "operator recovery witness version",
            error_cls=RootVerificationError,
        )
        != LOG_VERSION
    ):
        raise RootVerificationError("unsupported operator recovery witness version")
    if witness["signature_algorithm"] not in _signature_algorithms_for_verification():
        raise RootVerificationError("unsupported operator recovery witness signature algorithm")
    message_hash = _hex32(witness["message_hash"], "recovery witness message hash")
    source_segment_hash = _hex32(
        witness["source_segment_hash"], "recovery witness source segment hash"
    )
    feed_id = _require_str(
        witness["feed_id"], "operator recovery witness feed id", error_cls=RootVerificationError
    )
    feed_public_key = _require_str(
        witness["feed_public_key"],
        "operator recovery witness feed public key",
        error_cls=RootVerificationError,
    )
    _require_int_for(
        witness["first_seen"],
        "operator recovery witness first_seen",
        minimum=0,
        error_cls=RootVerificationError,
    )
    if trusted_feed_public_keys is not None:
        trusted = {str(item).strip() for item in trusted_feed_public_keys if str(item).strip()}
        if feed_public_key not in trusted:
            raise RootVerificationError("operator recovery witness feed key is not trusted")
    if not _verify_operator_payload(
        feed_public_key,
        witness["signature"],
        recovery_witness_signature_payload(witness),
        witness["signature_algorithm"],
    ):
        raise RootVerificationError("invalid operator recovery witness signature")
    normalized = copy.deepcopy(witness)
    normalized["message_hash"] = message_hash
    normalized["source_segment_hash"] = source_segment_hash
    normalized["feed_id"] = feed_id
    normalized["feed_public_key"] = feed_public_key
    normalized["first_seen"] = int(witness["first_seen"])
    return normalized


def recovery_witness_quorum(
    witnesses,
    message_hash,
    transfer_timestamp,
    min_witnesses=DEFAULT_OPERATOR_RECOVERY_MIN_FEEDS,
    max_root_lag_seconds=DEFAULT_MAX_ROOT_LAG_SECONDS,
    trusted_feed_public_keys=None,
):
    message_hash = _hex32(message_hash, "recovery witness message hash")
    transfer_timestamp = int(transfer_timestamp)
    max_root_lag_seconds = int(max_root_lag_seconds)
    min_witnesses = int(min_witnesses)
    accepted = {}
    errors = []
    for witness in witnesses or []:
        try:
            normalized = verify_recovery_witness(
                witness, trusted_feed_public_keys=trusted_feed_public_keys
            )
            if normalized["message_hash"] != message_hash:
                raise RootVerificationError("operator recovery witness message hash mismatch")
            first_seen = int(normalized["first_seen"])
            if first_seen < transfer_timestamp:
                raise RootVerificationError("operator recovery witness predates transfer")
            if first_seen - transfer_timestamp > max_root_lag_seconds:
                raise RootVerificationError("operator recovery witness saw transfer too late")
            identity = (normalized["feed_id"], normalized["feed_public_key"])
            accepted.setdefault(identity, normalized)
        except Exception as exc:
            errors.append(str(exc))
    if len(accepted) < min_witnesses:
        detail = "; ".join(errors) if errors else "not enough recovery witnesses"
        raise RootVerificationError(
            f"operator recovery witness quorum not satisfied: {detail}"
        )
    return sorted(
        accepted.values(), key=lambda item: (item["feed_id"], item["feed_public_key"])
    )


# Build the peer-gossip proof that an operator signed conflicting roots.
def make_equivocation_proof(root_a, root_b, collision_type=None, detected_at=None):
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


# Validate a self-contained signed-root equivocation proof.
def verify_equivocation_proof(message, operator_public_key=None):
    _require_exact_keys(
        message,
        {"type", "version", "log_id", "collision_type", "root_a", "root_b", "detected_at"},
        "transparency equivocation proof",
        error_cls=RootVerificationError,
    )
    if message.get("type") != LOG_EQUIVOCATION_PROOF_TYPE:
        raise RootVerificationError("not a transparency equivocation proof")
    if (
        _require_int_for(
            message["version"],
            "transparency equivocation proof version",
            error_cls=RootVerificationError,
        )
        != LOG_VERSION
    ):
        raise RootVerificationError("unsupported transparency equivocation proof version")
    _require_int_for(
        message["detected_at"],
        "transparency equivocation detected_at",
        minimum=0,
        error_cls=RootVerificationError,
    )
    claimed_log_id = str(message.get("log_id", "")).strip()
    collision_type = message.get("collision_type")
    if collision_type not in {"same_tree_size", "same_timestamp"}:
        raise MirrorDisagreementError(
            {"error": "unsupported transparency equivocation collision type"}
        )
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
        raise RootVerificationError(
            "equivocation proof operator key does not derive the claimed log id"
        )
    actual_collision = equivocation_collision_type(root_a, root_b)
    if actual_collision != collision_type:
        raise MirrorDisagreementError(
            {"root_a": root_a, "root_b": root_b, "claimed": collision_type}
        )
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


# Create a signed operator-key rotation record.
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
    record["signature_by_old_key"] = _sign_operator_payload(old_private_key, payload)
    record["signature_by_new_key"] = _sign_operator_payload(new_private_key, payload)
    return record


# Verify a dual-signed transparency operator key rotation record.
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
    _require_exact_keys(
        record,
        required,
        "transparency operator key rotation",
        error_cls=KeyRotationError,
    )
    if (
        record["type"] != LOG_KEY_ROTATION_TYPE
        or _require_int_for(
            record["version"],
            "operator key rotation version",
            error_cls=KeyRotationError,
        )
        != LOG_VERSION
    ):
        raise KeyRotationError("unsupported transparency operator key rotation version")
    if record["signature_algorithm"] not in _signature_algorithms_for_verification():
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
    _require_int_for(
        record["rotation_timestamp"],
        "operator key rotation timestamp",
        minimum=0,
        error_cls=KeyRotationError,
    )
    _require_int_for(
        record["effective_from_tree_size"],
        "operator key rotation effective tree size",
        minimum=0,
        error_cls=KeyRotationError,
    )
    overlap_until = _require_int_for(
        record["overlap_until_timestamp"],
        "operator key rotation overlap timestamp",
        minimum=0,
        error_cls=KeyRotationError,
    )
    if overlap_until < record["rotation_timestamp"]:
        raise KeyRotationError("operator key rotation overlap ends before rotation timestamp")
    payload = key_rotation_signature_payload(record)
    # Both keys sign the same payload to prove continuity across the rotation.
    if not _verify_operator_payload(
        record["old_public_key"].strip(),
        record["signature_by_old_key"],
        payload,
        record["signature_algorithm"],
    ):
        raise KeyRotationError("invalid operator key rotation old-key signature")
    if not _verify_operator_payload(
        record["new_public_key"].strip(),
        record["signature_by_new_key"],
        payload,
        record["signature_algorithm"],
    ):
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
    record["signature_by_successor_key"] = _sign_operator_payload(
        successor_private_key,
        key_revocation_signature_payload(record),
    )
    return record


# Verify a successor-signed revocation for a prior operator key.
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
    _require_exact_keys(
        record,
        required,
        "transparency operator key revocation",
        error_cls=KeyRevocationError,
    )
    if (
        record["type"] != LOG_KEY_REVOCATION_TYPE
        or _require_int_for(
            record["version"],
            "operator key revocation version",
            error_cls=KeyRevocationError,
        )
        != LOG_VERSION
    ):
        raise KeyRevocationError("unsupported transparency operator key revocation version")
    if record["signature_algorithm"] not in _signature_algorithms_for_verification():
        raise KeyRevocationError(
            "unsupported transparency operator key revocation signature algorithm"
        )
    _require_int_for(
        record["revocation_timestamp"],
        "operator key revocation timestamp",
        minimum=0,
        error_cls=KeyRevocationError,
    )
    if record["log_id"] != log_id_from_public_key(record["revoked_public_key"].strip()):
        raise KeyRevocationError("operator key revocation log id does not match revoked key")
    if not _verify_operator_payload(
        record["successor_public_key"].strip(),
        record["signature_by_successor_key"],
        key_revocation_signature_payload(record),
        record["signature_algorithm"],
    ):
        raise KeyRevocationError("invalid operator key revocation successor-key signature")
    if rotation_record is not None:
        verify_key_rotation(rotation_record)
        if record["rotation_record_hash"] != key_rotation_id(rotation_record):
            raise KeyRevocationError(
                "operator key revocation does not reference the supplied rotation"
            )
        if record["log_id"] != rotation_record["log_id"]:
            raise KeyRevocationError("operator key revocation log id does not match rotation")
        if record["revoked_public_key"] != rotation_record["old_public_key"]:
            raise KeyRevocationError("operator key revocation old key does not match rotation")
        if record["successor_public_key"] != rotation_record["new_public_key"]:
            raise KeyRevocationError(
                "operator key revocation successor key does not match rotation"
            )
    return True


def _entry_hash_bytes(entry_hash):
    entry_hash = str(entry_hash).lower()
    if len(entry_hash) != 64:
        raise InclusionProofError("invalid transparency entry hash")
    try:
        return bytes.fromhex(entry_hash)
    except ValueError as exc:
        raise InclusionProofError("invalid transparency entry hash") from exc


# Return the CT-style SHA3-256 leaf hash for a transfer entry hash.
def log_leaf_hash(entry_hash):
    return MerkleHasher(LOG_HASH_ALGORITHM, True).hash_buff(_entry_hash_bytes(entry_hash))


# Return the log entry hash for a signed transfer.
def transfer_entry_hash(transfer):
    return ind_token.transfer_hash(transfer)


# Verify that an entry is included in the signed mirrored tree root.
def verify_inclusion_proof(entry_hash, proof_response, signed_root, operator_public_key=None):
    verify_signed_root(signed_root, operator_public_key=operator_public_key)
    required = {
        "type",
        "version",
        "log_id",
        "entry_hash",
        "leaf_hash",
        "leaf_index",
        "tree_size",
        "proof",
    }
    _require_exact_keys(
        proof_response,
        required,
        "transparency inclusion proof",
        error_cls=InclusionProofError,
    )
    if (
        proof_response["type"] != LOG_INCLUSION_PROOF_TYPE
        or _require_int_for(
            proof_response["version"],
            "transparency inclusion proof version",
            error_cls=InclusionProofError,
        )
        != LOG_VERSION
    ):
        raise InclusionProofError("unsupported transparency inclusion proof version")
    if proof_response["log_id"] != signed_root["log_id"]:
        raise InclusionProofError("inclusion proof is for a different transparency log")
    proof_tree_size = _require_int_for(
        proof_response["tree_size"],
        "transparency inclusion proof tree size",
        minimum=0,
        error_cls=InclusionProofError,
    )
    root_tree_size = _require_int_for(
        signed_root["tree_size"],
        "transparency root tree size",
        minimum=0,
        error_cls=InclusionProofError,
    )
    if proof_tree_size != root_tree_size:
        raise InclusionProofError("inclusion proof tree size does not match mirrored root")
    _require_int_for(
        proof_response["leaf_index"],
        "transparency leaf index",
        minimum=0,
        error_cls=InclusionProofError,
    )
    entry_hash = str(entry_hash).lower()
    if str(proof_response["entry_hash"]).lower() != entry_hash:
        raise InclusionProofError("inclusion proof is for a different entry")

    leaf_hash = log_leaf_hash(entry_hash)
    if proof_response["leaf_hash"] != leaf_hash.hex():
        raise InclusionProofError("inclusion proof leaf hash mismatch")

    proof = MerkleProof.deserialize(proof_response["proof"])
    if proof.algorithm != LOG_HASH_ALGORITHM or not proof.security:
        raise InclusionProofError("unsupported transparency proof hash settings")
    if int(proof.size) != root_tree_size:
        raise InclusionProofError("inclusion proof metadata tree size mismatch")
    try:
        pymerkle_verify_inclusion(leaf_hash, bytes.fromhex(signed_root["root_hash"]), proof)
    except (InvalidProof, ValueError) as exc:
        raise InclusionProofError(str(exc)) from exc
    return True


# Verify that new_root is an append-only extension of old_root.
def verify_consistency_proof(
    old_root,
    new_root,
    proof_response,
    operator_public_key=None,
    allow_log_id_transition=False,
):
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
    _require_exact_keys(
        proof_response,
        required,
        "transparency consistency proof",
        error_cls=ConsistencyProofError,
    )
    if (
        proof_response["type"] != LOG_CONSISTENCY_PROOF_TYPE
        or _require_int_for(
            proof_response["version"],
            "transparency consistency proof version",
            error_cls=ConsistencyProofError,
        )
        != LOG_VERSION
    ):
        raise ConsistencyProofError("unsupported transparency consistency proof version")
    allowed_proof_log_ids = {old_root["log_id"]}
    if allow_log_id_transition:
        allowed_proof_log_ids.add(new_root["log_id"])
    if proof_response["log_id"] not in allowed_proof_log_ids:
        raise ConsistencyProofError("consistency proof is for a different transparency log")
    if (
        _require_int_for(
            proof_response["first_tree_size"],
            "transparency consistency first tree size",
            minimum=0,
            error_cls=ConsistencyProofError,
        )
        != old_size
    ):
        raise ConsistencyProofError("consistency proof first tree size mismatch")
    if (
        _require_int_for(
            proof_response["second_tree_size"],
            "transparency consistency second tree size",
            minimum=0,
            error_cls=ConsistencyProofError,
        )
        != new_size
    ):
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


# Raise if mirrors expose two valid roots for one log id timestamp or tree size.
def detect_mirror_disagreement(roots, operator_public_key=None):
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
        if previous and previous["fingerprint"] != fingerprint:
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


def _safe_http_base_url(url):
    parsed = urllib.parse.urlparse(str(url).strip())
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        return False
    if not parsed.hostname or parsed.query or parsed.fragment:
        return False
    decoded_path = parsed.path or ""
    for _ in range(3):
        next_path = urllib.parse.unquote(decoded_path)
        if next_path == decoded_path:
            break
        decoded_path = next_path
    return "\\" not in decoded_path and not any(
        segment == ".." for segment in decoded_path.split("/")
    )


def _normalize_http_base_url(url):
    url = str(url).strip()
    if not _safe_http_base_url(url):
        raise TransparencyLogError(f"unsafe transparency source URL: {url}")
    return url.rstrip("/")


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


# Return the source identity used for mirror independence checks.
def transparency_source_identity(source):
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


# Persistent observed-root store used to enforce append-only consistency.
class SQLiteObservedRootStore:
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
                conn.executescript("""
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

                    CREATE TABLE IF NOT EXISTS operator_policy_violations (
                        evidence_id TEXT PRIMARY KEY,
                        log_id TEXT NOT NULL,
                        violation_type TEXT NOT NULL,
                        root_id TEXT NOT NULL,
                        root_json TEXT NOT NULL,
                        spend_proof_json TEXT NOT NULL,
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
                    """)

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
                        (
                            int(consistency_checked_at),
                            root["log_id"],
                            int(root["tree_size"]),
                            root["root_hash"],
                        ),
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
                rows = conn.execute("""
                    SELECT log_id FROM observed_roots
                    UNION
                    SELECT log_id FROM peer_observed_roots
                    """).fetchall()
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
            raise KeyRevocationError(
                "operator key revocation references an unknown rotation record"
            )
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
                row = conn.execute(
                    "SELECT * FROM operator_status WHERE log_id = ?", (log_id,)
                ).fetchone()
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
            "type": "ind.transparency_consistency_failure.v3",
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
                    self._prune_peer_roots_for_log(
                        conn, root["log_id"], int(max_total_roots_for_log)
                    )

        self._with_retry(action)

    def _prune_peer_roots(self, conn, peer_id, log_id, max_roots_for_log):
        if max_roots_for_log <= 0:
            return
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
        proof = make_equivocation_proof(
            root_a, root_b, collision_type=collision_type, detected_at=detected_at
        )
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

    def save_operator_policy_violation(self, proof):
        proof = verify_operator_policy_violation_proof(proof)
        evidence_id = ind_token.sha3_hex(canonical_bytes(proof))
        root = proof["root"]

        def action():
            with contextlib.closing(self._connect()) as conn, conn:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO operator_policy_violations (
                        evidence_id, log_id, violation_type, root_id,
                        root_json, spend_proof_json, detected_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        evidence_id,
                        proof["log_id"],
                        proof["violation_type"],
                        signed_root_id(root),
                        canonical_json(root),
                        canonical_json(proof["spend_proof"]),
                        int(proof["detected_at"]),
                    ),
                )
            return evidence_id, proof

        return self._with_retry(action)

    def operator_policy_violation_messages(self, limit=100):
        def action():
            with contextlib.closing(self._connect()) as conn, conn:
                rows = conn.execute(
                    """
                    SELECT log_id, violation_type, root_json, spend_proof_json, detected_at
                    FROM operator_policy_violations
                    ORDER BY detected_at DESC
                    LIMIT ?
                    """,
                    (int(limit),),
                ).fetchall()
            messages = []
            for row in rows:
                proof = {
                    "type": LOG_OPERATOR_POLICY_VIOLATION_TYPE,
                    "version": LOG_VERSION,
                    "violation_type": row["violation_type"],
                    "log_id": row["log_id"],
                    "root": json.loads(row["root_json"]),
                    "spend_proof": json.loads(row["spend_proof_json"]),
                    "detected_at": int(row["detected_at"]),
                }
                messages.append(verify_operator_policy_violation_proof(proof))
            return messages

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


# In-memory observed-root store for tests and short-lived local tools.
class InMemoryObservedRootStore:
    def __init__(self):
        self.roots = []
        self.peer_roots = []
        self.statuses = {}
        self.failures = {}
        self.equivocations = {}
        self.policy_violations = {}
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
        return copy.deepcopy(
            sorted(candidates, key=lambda root: (int(root["tree_size"]), int(root["timestamp"])))[
                -1
            ]
        )

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
            if item["record"]["log_id"] == record["log_id"] and (
                latest is None
                or int(item["record"]["effective_from_tree_size"])
                > int(latest["effective_from_tree_size"])
            ):
                latest = item["record"]
        if latest and int(record["effective_from_tree_size"]) <= int(
            latest["effective_from_tree_size"]
        ):
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
            raise KeyRevocationError(
                "operator key revocation references an unknown rotation record"
            )
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
            if item["record"]["log_id"] == log_id
            and item["record"]["revoked_public_key"] == public_key
        ]
        if not records:
            return None
        return copy.deepcopy(
            sorted(records, key=lambda item: int(item["revocation_timestamp"]))[-1]
        )

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
            "type": "ind.transparency_consistency_failure.v3",
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
            item
            for item in self.peer_roots
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
        proof = make_equivocation_proof(
            root_a, root_b, collision_type=collision_type, detected_at=detected_at
        )
        evidence_id = ind_token.sha3_hex(canonical_bytes(proof))
        self.equivocations[evidence_id] = proof
        return evidence_id, copy.deepcopy(proof)

    def equivocation_messages(self, limit=100):
        items = sorted(
            self.equivocations.values(), key=lambda item: int(item["detected_at"]), reverse=True
        )
        return [copy.deepcopy(item) for item in items[: int(limit)]]

    def save_operator_policy_violation(self, proof):
        proof = verify_operator_policy_violation_proof(proof)
        evidence_id = ind_token.sha3_hex(canonical_bytes(proof))
        self.policy_violations[evidence_id] = copy.deepcopy(proof)
        return evidence_id, copy.deepcopy(proof)

    def operator_policy_violation_messages(self, limit=100):
        items = sorted(
            self.policy_violations.values(), key=lambda item: int(item["detected_at"]), reverse=True
        )
        return [copy.deepcopy(item) for item in items[: int(limit)]]

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


# Small JSON-over-HTTP client used by operators and mirrors.
class HTTPJSONClient:
    def __init__(self, base_url, timeout=10):
        self.base_url = _normalize_http_base_url(base_url)
        self.timeout = int(timeout)
        self.identity_id = _http_origin_identity(self.base_url)

    def _url(self, path, params=None):
        url = self.base_url + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        return url

    def get_json(self, path, params=None):
        request = urllib.request.Request(
            self._url(path, params),
            headers={"User-Agent": "International-Dollar-transparency-client/1"},
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            return json.loads(response.read().decode("utf-8"))

    def post_json(self, path, data):
        payload = canonical_json(data).encode("utf-8")
        request = urllib.request.Request(
            self._url(path),
            data=payload,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "International-Dollar-transparency-client/1",
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            return json.loads(response.read().decode("utf-8"))


# Client for the log operator's proof endpoints.
class HTTPTransparencyOperator:
    def __init__(self, base_url, timeout=10, operator_public_key=None):
        self.http = HTTPJSONClient(base_url, timeout=timeout)
        self.identity_id = self.http.identity_id
        self.operator_public_key = str(operator_public_key or "").strip() or None
        self.log_id = (
            log_id_from_public_key(self.operator_public_key)
            if self.operator_public_key
            else None
        )

    def inclusion_proof(self, entry_hash, tree_size):
        return self.http.get_json(
            "/v3/proof", {"entry_hash": entry_hash, "tree_size": int(tree_size)}
        )

    def consistency_proof(self, first_tree_size, second_tree_size):
        return self.http.get_json(
            "/v3/consistency",
            {"first": int(first_tree_size), "second": int(second_tree_size)},
        )

    def spend_map_proof(self, spend_key, tree_size):
        return self.http.get_json(
            "/v3/spend-proof", {"spend_key": spend_key, "tree_size": int(tree_size)}
        )

    def submit_transfer_announcement(self, announcement):
        return self.http.post_json("/v3/append", announcement)

    def submit_checkpoint_announcement(self, announcement):
        return self.http.post_json("/v3/append", announcement)

    def latest_root(self):
        return self.http.get_json("/v3/root")

    def status(self):
        return self.http.get_json("/v3/status")


# Client for an HTTP mirror serving signed roots.
class HTTPRootMirror:
    def __init__(self, base_url, timeout=10):
        self.http = HTTPJSONClient(base_url, timeout=timeout)
        self.identity_id = self.http.identity_id

    def root_at(self, timestamp):
        return self.http.get_json("/v3/root-at", {"timestamp": int(timestamp)})

    def latest_root(self):
        return self.http.get_json("/v3/root")

    def inclusion_proof(self, entry_hash, tree_size):
        return self.http.get_json(
            "/v3/proof", {"entry_hash": entry_hash, "tree_size": int(tree_size)}
        )

    def spend_map_proof(self, spend_key, tree_size):
        return self.http.get_json(
            "/v3/spend-proof", {"spend_key": spend_key, "tree_size": int(tree_size)}
        )


class VerifyOnlyTransparencyOperator:
    def __init__(self, operator_public_key):
        self.operator_public_key = str(operator_public_key or "").strip()
        self.log_id = log_id_from_public_key(self.operator_public_key) if self.operator_public_key else ""
        label = self.operator_public_key or "unconfigured"
        self.identity_id = ("verify-only-operator", label)

    def _unavailable(self):
        raise TransparencyLogError("verify-only transparency operator has no append API")

    def latest_root(self):
        self._unavailable()

    def inclusion_proof(self, entry_hash, tree_size):
        self._unavailable()

    def consistency_proof(self, first_tree_size, second_tree_size):
        self._unavailable()

    def spend_map_proof(self, spend_key, tree_size):
        self._unavailable()

    def submit_transfer_announcement(self, announcement):
        self._unavailable()

    def submit_checkpoint_announcement(self, announcement):
        self._unavailable()


# Client for a static HTTP root mirror produced by operator_tools.root_streamer.
class HTTPStaticRootMirror:
    def __init__(self, base_url, timeout=10):
        self.http = HTTPJSONClient(base_url, timeout=timeout)
        self.identity_id = self.http.identity_id

    def _roots_from_jsonl(self):
        request = urllib.request.Request(
            self.http._url("/roots.jsonl"),
            headers={"User-Agent": "International-Dollar-transparency-client/1"},
        )
        with urllib.request.urlopen(request, timeout=self.http.timeout) as response:
            text = response.read().decode("utf-8")
        return [json.loads(line) for line in text.splitlines() if line.strip()]

    def roots(self):
        roots = []
        seen = set()
        for root in self._roots_from_jsonl():
            current_id = signed_root_id(root)
            if current_id in seen:
                continue
            seen.add(current_id)
            roots.append(root)
        return roots

    def root_at(self, timestamp):
        timestamp = int(timestamp)
        candidates = [root for root in self.roots() if int(root.get("timestamp", -1)) >= timestamp]
        if not candidates:
            raise RootVerificationError("static HTTP mirror has no historical root for timestamp")
        return sorted(
            candidates, key=lambda root: (int(root["timestamp"]), int(root["tree_size"]))
        )[0]

    def latest_root(self):
        return self.http.get_json("/latest.json")


# Read signed roots from a local mirror directory or JSON/JSONL file.
class DirectoryRootMirror:
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
        return sorted(
            candidates, key=lambda root: (int(root["timestamp"]), int(root["tree_size"]))
        )[0]

    def latest_root(self):
        latest_path = self.path / "latest.json"
        if latest_path.exists() and latest_path.is_file():
            data = self._roots_from_file(latest_path)
            if data:
                return data[0]
        roots = self.roots()
        if not roots:
            raise RootVerificationError("mirror has no signed roots")
        return sorted(roots, key=lambda root: (int(root["timestamp"]), int(root["tree_size"])))[-1]

    def _proof_archive_path(self, tree_size):
        return self.path / "proof_archives" / f"root_{int(tree_size):012d}.json"

    def proof_archive(self, signed_root):
        archive_path = self._proof_archive_path(signed_root["tree_size"])
        if not archive_path.exists():
            raise InclusionProofError("mirror has no proof archive for signed root")
        archive = json.loads(archive_path.read_text(encoding="utf-8"))
        verify_proof_archive(
            archive,
            signed_root,
            operator_public_key=signed_root.get("operator_public_key"),
        )
        return archive

    def inclusion_proof(self, entry_hash, tree_size):
        candidates = [item for item in self.roots() if int(item["tree_size"]) == int(tree_size)]
        if not candidates:
            raise InclusionProofError("mirror has no signed root for inclusion proof tree size")
        root = sorted(candidates, key=lambda item: int(item["timestamp"]))[-1]
        archive = self.proof_archive(root)
        return inclusion_proof_from_archive(
            archive,
            entry_hash,
            root,
            operator_public_key=root.get("operator_public_key"),
        )

    def spend_map_proof(self, spend_key, tree_size):
        candidates = [item for item in self.roots() if int(item["tree_size"]) == int(tree_size)]
        if not candidates:
            raise InclusionProofError("mirror has no signed root for spend proof tree size")
        root = sorted(candidates, key=lambda item: int(item["timestamp"]))[-1]
        archive = self.proof_archive(root)
        return spend_map_proof_from_archive(
            archive,
            spend_key,
            root,
            operator_public_key=root.get("operator_public_key"),
        )


# In-memory mirror used by tests and local tooling.
class StaticRootMirror:
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
        return sorted(
            candidates, key=lambda root: (int(root["timestamp"]), int(root["tree_size"]))
        )[0]

    def latest_root(self):
        if not self._roots:
            raise RootVerificationError("mirror has no signed roots")
        return sorted(
            self._roots, key=lambda root: (int(root["timestamp"]), int(root["tree_size"]))
        )[-1]


# Adapter around log_server.TransparencyLog for tests and local tools.
class LocalTransparencyOperator:
    def __init__(self, log):
        self.log = log
        self.operator_public_key = str(getattr(log, "public_key", "") or "").strip() or None
        self.log_id = str(getattr(log, "log_id", "") or "").strip()
        if not self.log_id and self.operator_public_key:
            self.log_id = log_id_from_public_key(self.operator_public_key)
        self.identity_id = (
            "local-log",
            os.path.normcase(str(Path(log.db_path).resolve(strict=False))),
        )

    def inclusion_proof(self, entry_hash, tree_size):
        return self.log.inclusion_proof(entry_hash, int(tree_size))

    def consistency_proof(self, first_tree_size, second_tree_size):
        return self.log.consistency_proof(int(first_tree_size), int(second_tree_size))

    def spend_map_proof(self, spend_key, tree_size):
        return self.log.spend_map_proof(spend_key, int(tree_size))

    def submit_transfer_announcement(self, announcement):
        return self.log.append_transfer_announcement(announcement)

    def submit_checkpoint_announcement(self, announcement):
        result = self.log.append_checkpoint_announcement(announcement)
        try:
            self.log.publish_root(int(time.time()))
        except Exception as exc:
            logger.warning(
                "local transparency root publish failed after checkpoint append: %s", exc
            )
        return result

    def latest_root(self):
        return self.log.latest_root()

    def root_at(self, timestamp):
        return self.log.root_at(int(timestamp))

    def status(self):
        status = getattr(self.log, "status", None)
        if callable(status):
            return status()
        return {"state": "active", "tree_size": int(self.log.tree_size())}


class MultiTransparencySubmitter:
    def __init__(self, operators):
        self.operators = [_coerce_operator(operator) for operator in operators]
        self.identity_id = ("multi-operator", str(len(self.operators)))

    def operator_identities(self):
        return [
            identity
            for identity in (operator_identity(operator) for operator in self.operators)
            if identity.get("log_id")
        ]

    def _active_operators(self):
        for operator in self.operators:
            status_method = getattr(operator, "status", None)
            if callable(status_method):
                try:
                    status = status_method()
                except Exception:
                    continue
                state = str(status.get("state", "active")).strip().lower()
                if state != "active":
                    continue
            yield operator

    def _operator_matches(self, operator, operator_public_key=None, log_id=None):
        if operator_public_key:
            configured = str(getattr(operator, "operator_public_key", "") or "").strip()
            return bool(configured and configured == str(operator_public_key).strip())
        if log_id:
            configured = str(getattr(operator, "operator_public_key", "") or "").strip()
            if not configured:
                return False
            return log_id_from_public_key(configured) == str(log_id).strip()
        return True

    def _submit(self, method_name, announcement, *, operator_public_key=None, log_id=None):
        errors = []
        for operator in self._active_operators():
            if not self._operator_matches(
                operator,
                operator_public_key=operator_public_key,
                log_id=log_id,
            ):
                continue
            method = getattr(operator, method_name)
            try:
                return method(announcement)
            except Exception as exc:
                errors.append(f"{_source_label(operator)}: {exc}")
        detail = "; ".join(errors) if errors else "no matching active transparency operator"
        raise TransparencyLogError(f"no active transparency operator accepted append: {detail}")

    def submit_transfer_announcement(self, announcement):
        return self._submit("submit_transfer_announcement", announcement)

    def submit_transfer_announcement_to_all(self, announcement):
        results = []
        for operator in self.operators:
            identity = operator_identity(operator)
            result = {
                "log_id": identity.get("log_id", ""),
                "operator_public_key": identity.get("operator_public_key", ""),
                "accepted": False,
                "response": None,
                "error": "",
            }
            try:
                status_method = getattr(operator, "status", None)
                if callable(status_method):
                    status = status_method()
                    state = str(status.get("state", "active")).strip().lower()
                    if state != "active":
                        raise TransparencyLogError(f"operator is {state or 'not active'}")
                response = operator.submit_transfer_announcement(announcement)
                result["response"] = response
                result["accepted"] = bool(isinstance(response, dict) and response.get("accepted"))
            except Exception as exc:
                result["error"] = str(exc)
            results.append(result)
        return results

    def submit_transfer_announcement_for_operator(
        self, announcement, *, operator_public_key=None, log_id=None
    ):
        return self._submit(
            "submit_transfer_announcement",
            announcement,
            operator_public_key=operator_public_key,
            log_id=log_id,
        )

    def submit_checkpoint_announcement(self, announcement):
        return self._submit("submit_checkpoint_announcement", announcement)

    def submit_checkpoint_announcement_for_operator(
        self, announcement, *, operator_public_key=None, log_id=None
    ):
        return self._submit(
            "submit_checkpoint_announcement",
            announcement,
            operator_public_key=operator_public_key,
            log_id=log_id,
        )


def _coerce_operator(operator):
    if isinstance(operator, str):
        return HTTPTransparencyOperator(operator)
    if isinstance(operator, dict):
        url = str(operator.get("url", "")).strip()
        if url:
            return HTTPTransparencyOperator(
                url,
                operator_public_key=str(operator.get("public_key") or "").strip() or None,
            )
    return operator


def operator_identity(operator):
    public_key = str(getattr(operator, "operator_public_key", "") or "").strip()
    log_id = str(getattr(operator, "log_id", "") or "").strip()
    if not public_key and hasattr(operator, "log"):
        public_key = str(getattr(operator.log, "public_key", "") or "").strip()
    if not log_id and hasattr(operator, "log"):
        log_id = str(getattr(operator.log, "log_id", "") or "").strip()
    if not log_id and public_key:
        log_id = log_id_from_public_key(public_key)
    return {"log_id": log_id, "operator_public_key": public_key}


def _coerce_mirror(mirror):
    if isinstance(mirror, str) and mirror.startswith(("http://", "https://")):
        parsed = urllib.parse.urlparse(mirror)
        path = parsed.path.rstrip("/")
        path_name = path.rsplit("/", 1)[-1]
        if path_name.endswith("transparency") or path.endswith("/roots"):
            return HTTPStaticRootMirror(mirror)
        return HTTPRootMirror(mirror)
    if isinstance(mirror, str):
        return DirectoryRootMirror(mirror)
    return mirror


class TransparencyVerifier:
    """Client-side verifier for IND transfer transparency proofs.

    Security invariants:
    current ownership checks require fresh independently mirrored roots, while
    historical checks use the root that actually contains the transfer leaf.
    Equivocation and consistency failures are persisted before the operator is
    locally blacklisted.
    """

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
        proof_archives=None,
        operator_recovery_min_feeds=DEFAULT_OPERATOR_RECOVERY_MIN_FEEDS,
        recovery_feed_public_keys=None,
        start_background_checks=False,
        run_startup_check=True,
    ):
        # The policy object centralizes bounds before the verifier stores derived fields.
        self.policy = TransparencyVerifierPolicy.from_values(
            max_root_lag_seconds=max_root_lag_seconds,
            min_mirrors=min_mirrors,
            allow_unsafe_single_mirror=allow_unsafe_single_mirror,
            strict_mode=strict_mode,
            consistency_check_interval_seconds=consistency_check_interval_seconds,
            consistency_max_stale_seconds=consistency_max_stale_seconds,
            max_current_root_age_seconds=max_current_root_age_seconds,
            current_root_future_skew_seconds=current_root_future_skew_seconds,
        )
        self.strict_mode = self.policy.strict_mode
        self.allow_unsafe_single_mirror = self.policy.allow_unsafe_single_mirror
        if self.strict_mode and self.allow_unsafe_single_mirror:
            raise TransparencyLogError(STRICT_UNSAFE_SINGLE_MIRROR_ERROR)
        # Mirror identity validation happens before coercion so URLs/paths stay auditable.
        self.min_mirrors = self._validated_min_mirrors(self.policy.min_mirrors)
        self.mirror_identities = self._validate_mirror_sources(operator, mirrors)
        self.operator = _coerce_operator(operator)
        self.mirrors = [_coerce_mirror(mirror) for mirror in mirrors]
        self.proof_archives = [_coerce_mirror(source) for source in (proof_archives or [])]
        self.operator_public_key = operator_public_key
        self.max_root_lag_seconds = self.policy.max_root_lag_seconds
        self.operator_recovery_min_feeds = int(operator_recovery_min_feeds)
        self.recovery_feed_public_keys = (
            {str(item).strip() for item in recovery_feed_public_keys if str(item).strip()}
            if recovery_feed_public_keys is not None
            else None
        )
        self.max_current_root_age_seconds = self.policy.max_current_root_age_seconds
        self.current_root_future_skew_seconds = self.policy.current_root_future_skew_seconds
        self._validate_current_root_freshness_config()
        self.consistency_check_interval_seconds = self.policy.consistency_check_interval_seconds
        self.consistency_max_stale_seconds = self.policy.consistency_max_stale_seconds
        self._consistency_pairs_checked = set()
        self._pending_gossip_messages = []
        self._queued_root_ids = set()
        self._queued_evidence_ids = set()
        self._background_stop = threading.Event()
        self._background_thread = None
        # Durable observed roots are what let the client detect split-view behavior later.
        self.observed_root_store = self._build_observed_root_store(
            observed_root_store, observed_roots_path
        )
        self._load_consistency_anchor(
            consistency_anchor=consistency_anchor, consistency_anchor_path=consistency_anchor_path
        )
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
                raise TransparencyLogError(
                    f"transparency observed-root store is unavailable: {exc}"
                ) from exc
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
            warnings.warn(
                f"startup transparency consistency check did not complete: {exc}",
                RuntimeWarning,
                stacklevel=3,
            )
        if self.strict_mode:
            self._enforce_known_log_status()

    def _validated_min_mirrors(self, min_mirrors):
        requested = int(min_mirrors)
        floor = (
            1
            if self.allow_unsafe_single_mirror or _testnet_mode_enabled()
            else DEFAULT_MIN_ROOT_MIRRORS
        )
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
            raise TransparencyLogError(
                "IND_LOG_CURRENT_ROOT_FUTURE_SKEW_SECONDS must not be negative"
            )
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
        if (
            self.strict_mode
            and self.max_current_root_age_seconds > STRICT_MAX_CURRENT_ROOT_AGE_SECONDS
        ):
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

    def _proof_sources(self):
        sources = [self.operator]
        sources.extend(self.proof_archives)
        sources.extend(self.mirrors)
        deduped = []
        seen = set()
        for source in sources:
            identity = transparency_source_identity(source) or ("object", id(source))
            if identity in seen:
                continue
            seen.add(identity)
            deduped.append(source)
        return deduped

    def _first_proof(self, method_name, *args):
        errors = []
        for source in self._proof_sources():
            method = getattr(source, method_name, None)
            if not callable(method):
                continue
            try:
                return method(*args)
            except Exception as exc:
                errors.append(f"{_source_label(source)}: {exc}")
        detail = "; ".join(errors) if errors else "no proof archive or operator supports this proof"
        raise InclusionProofError(f"transparency proof unavailable: {detail}")

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
        if "operator policy violation" in reason:
            return (
                f"CRITICAL transparency operator policy violation detected for {log_id}: {reason}. "
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
            revocation = self.observed_root_store.key_revocation_for_key(
                configured_log_id, configured_key
            )
            if revocation and root_timestamp >= int(revocation["revocation_timestamp"]):
                raise RootVerificationError(
                    "transparency root was signed by a revoked operator key"
                )
            rotations = self.observed_root_store.key_rotations_for_log(configured_log_id)
            if rotations:
                latest = rotations[-1]
                if root_size >= int(latest["effective_from_tree_size"]) and root_timestamp > int(
                    latest["overlap_until_timestamp"]
                ):
                    raise RootVerificationError(
                        "transparency root was signed by the old operator key after rotation overlap"
                    )
            return True

        rotation = self._rotation_for_root(root)
        if (
            rotation
            and root_key == rotation["new_public_key"]
            and root["log_id"] == rotation["new_log_id"]
        ):
            if root_size < int(rotation["effective_from_tree_size"]):
                raise RootVerificationError(
                    "transparency root was signed by successor key before rotation effective tree size"
                )
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

    def _queue_operator_policy_violation_proof(self, proof):
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

    def persisted_operator_policy_violation_messages(self, limit=100):
        persisted = getattr(self.observed_root_store, "operator_policy_violation_messages", None)
        if not callable(persisted):
            return []
        return persisted(limit=limit)

    def _handle_operator_policy_violation(self, proof):
        proof = verify_operator_policy_violation_proof(
            proof, operator_public_key=self.operator_public_key
        )
        root = proof["root"]
        evidence_id, stored_proof = self.observed_root_store.save_operator_policy_violation(proof)
        self.observed_root_store.mark_blacklisted(
            root["log_id"],
            root["operator_public_key"],
            f"operator policy violation: {proof['violation_type']}",
            evidence_id,
            updated_at=int(proof["detected_at"]),
        )
        self._queue_operator_policy_violation_proof(stored_proof)
        return stored_proof

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
        self._handle_equivocation(
            evidence["root_a"], evidence["root_b"], evidence["collision_type"]
        )

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
        raise ConsistencyProofError(
            self._blacklisted_message(old_root["log_id"], status)
        ) from error

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
            return ""
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
            return (
                f"mirror is lagging current verification: tree_size {root_size} is below "
                f"previously observed tree_size {highest_size}"
            )
        if root_timestamp < latest_timestamp:
            raise RootVerificationError(
                f"transparency root replayed an older timestamp for current verification: timestamp "
                f"{root_timestamp} is below previously observed timestamp {latest_timestamp}"
            )
        return ""

    def _current_roots_from_mirrors(self, now=None, error_context="current verification"):
        now = self._current_time(now)
        roots_by_identity = {}
        errors = []
        for mirror, identity in zip(self.mirrors, self.mirror_identities, strict=False):
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
            raise RootVerificationError(
                f"not enough usable current transparency root mirrors for {error_context}: {detail}"
            )
        detect_mirror_disagreement(roots)
        self._observe_roots(roots_by_identity)
        return roots

    # Persist and consistency-check a signed root observed from a mirror.
    def observe_root(self, root, source_identity):
        self._verify_signed_root_for_lineage(root)
        now = int(time.time())
        log_id = root["log_id"]
        lineage_log_id = self._lineage_log_id_for_root(root)
        status = self.observed_root_store.status(log_id) or self.observed_root_store.status(
            lineage_log_id
        )
        if status and status.get("status") == "blacklisted":
            raise ConsistencyProofError(self._blacklisted_message(lineage_log_id, status))
        self._detect_and_handle_equivocation(root)
        previous = self.observed_root_store.latest_root(log_id)
        if lineage_log_id != log_id:
            lineage_previous = self.observed_root_store.latest_root(lineage_log_id)
            if lineage_previous and (
                previous is None or int(lineage_previous["tree_size"]) > int(previous["tree_size"])
            ):
                previous = lineage_previous
        if previous is None:
            self.observed_root_store.record_root(
                root, source_identity, observed_at=now, consistency_checked_at=now
            )
            self.observed_root_store.mark_active(
                log_id, root["operator_public_key"], checked_at=now
            )
            self._queue_root_announcement(root)
            return root

        old_size = int(previous["tree_size"])
        new_size = int(root["tree_size"])
        if old_size == new_size and previous["root_hash"] == root["root_hash"]:
            self.observed_root_store.record_root(
                root, source_identity, observed_at=now, consistency_checked_at=now
            )
            self.observed_root_store.mark_active(
                log_id, root["operator_public_key"], checked_at=now
            )
            self._queue_root_announcement(root)
            self._enforce_consistency_freshness(log_id)
            return root
        if old_size == new_size:
            error = ConsistencyProofError(
                "new observed root is not an append-only extension of the stored root"
            )
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

        pair_key = (
            log_id,
            first_size,
            first_root["root_hash"],
            second_size,
            second_root["root_hash"],
        )
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
            self.observed_root_store.record_root(
                root, source_identity, observed_at=now, consistency_checked_at=now
            )
            self.observed_root_store.mark_active(
                log_id, root["operator_public_key"], checked_at=now
            )
            self._queue_root_announcement(root)
        except ConsistencyProofError as exc:
            self._handle_consistency_failure(previous, root, exc)
        except Exception as exc:
            self.observed_root_store.mark_unresponsive(
                log_id, root["operator_public_key"], exc, updated_at=now
            )
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

    # Store a peer-gossiped signed root and check it for equivocation.
    def process_root_announcement(self, message, peer_id=None, message_hash=None):
        root = verify_root_announcement(message)
        received_at = int(time.time())
        self.observed_root_store.record_peer_root(
            root,
            peer_id=peer_id,
            message_hash=message_hash or signed_root_id(root),
            received_at=received_at,
            max_roots_for_log=self._peer_root_cap_for_log(root["log_id"]),
            max_total_roots_for_log=(
                None
                if self._is_configured_log(root["log_id"])
                else DEFAULT_UNKNOWN_PEER_ROOT_CAP_PER_LOG_ID
            ),
        )
        self._detect_and_handle_equivocation(root)
        return root

    # Verify, persist, blacklist, and queue a peer-gossiped equivocation proof.
    def process_equivocation_proof(self, message, peer_id=None, message_hash=None):
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
            max_total_roots_for_log=(
                None
                if self._is_configured_log(root_a["log_id"])
                else DEFAULT_UNKNOWN_PEER_ROOT_CAP_PER_LOG_ID
            ),
        )
        self.observed_root_store.record_peer_root(
            root_b,
            peer_id=peer_id,
            message_hash=message_hash or signed_root_id(root_b),
            received_at=received_at,
            max_roots_for_log=self._peer_root_cap_for_log(root_b["log_id"]),
            max_total_roots_for_log=(
                None
                if self._is_configured_log(root_b["log_id"])
                else DEFAULT_UNKNOWN_PEER_ROOT_CAP_PER_LOG_ID
            ),
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

    # Verify, persist, blacklist, and queue a peer-gossiped operator policy violation.
    def process_operator_policy_violation_proof(self, message, peer_id=None, message_hash=None):
        proof = verify_operator_policy_violation_proof(
            message, operator_public_key=self.operator_public_key
        )
        root = proof["root"]
        received_at = int(time.time())
        self.observed_root_store.record_peer_root(
            root,
            peer_id=peer_id,
            message_hash=message_hash or signed_root_id(root),
            received_at=received_at,
            max_roots_for_log=self._peer_root_cap_for_log(root["log_id"]),
            max_total_roots_for_log=(
                None
                if self._is_configured_log(root["log_id"])
                else DEFAULT_UNKNOWN_PEER_ROOT_CAP_PER_LOG_ID
            ),
        )
        return self._handle_operator_policy_violation(proof)

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

        self._background_thread = threading.Thread(
            target=loop, name="ind-transparency-consistency", daemon=True
        )
        self._background_thread.start()

    def stop_background_consistency_checks(self):
        self._background_stop.set()

    def mirrored_root_for_timestamp(self, timestamp):
        timestamp = int(timestamp)
        roots_by_identity = {}
        errors = []
        for mirror, identity in zip(self.mirrors, self.mirror_identities, strict=False):
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
            raise RootVerificationError(
                "no mirrored transparency root close enough to transfer timestamp"
            )
        return sorted(
            candidates, key=lambda root: (int(root["timestamp"]), int(root["tree_size"]))
        )[0]

    def _recovery_witnesses_allow_late_root(self, witnesses, message_hash, timestamp):
        if not witnesses or not message_hash:
            return False
        try:
            recovery_witness_quorum(
                witnesses,
                message_hash,
                int(timestamp),
                min_witnesses=self.operator_recovery_min_feeds,
                max_root_lag_seconds=self.max_root_lag_seconds,
                trusted_feed_public_keys=self.recovery_feed_public_keys,
            )
            return True
        except Exception:
            return False

    def mirrored_root_containing_leaf(
        self,
        timestamp,
        leaf_index,
        recovery_witnesses=None,
        recovery_message_hash=None,
    ):
        timestamp = int(timestamp)
        min_tree_size = int(leaf_index) + 1
        late_root_allowed = self._recovery_witnesses_allow_late_root(
            recovery_witnesses, recovery_message_hash, timestamp
        )
        roots_by_identity = {}
        errors = []
        for mirror, identity in zip(self.mirrors, self.mirror_identities, strict=False):
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
                        raise RootVerificationError(
                            "mirror returned a root before the requested timestamp"
                        )
                    if (
                        self.max_root_lag_seconds is not None
                        and lag > self.max_root_lag_seconds
                        and not late_root_allowed
                    ):
                        raise RootVerificationError(
                            "no mirrored transparency root close enough to transfer timestamp"
                        )
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
            raise RootVerificationError(
                f"not enough usable transparency root mirrors containing leaf: {detail}"
            )
        detect_mirror_disagreement(roots)
        self._observe_roots(roots_by_identity)
        return sorted(roots, key=lambda root: (int(root["timestamp"]), int(root["tree_size"])))[0]

    def current_mirrored_root(self, now=None):
        roots = self._current_roots_from_mirrors(now=now)
        return sorted(roots, key=lambda root: (int(root["tree_size"]), int(root["timestamp"])))[-1]

    def verify_current_root(self, now=None):
        self.current_mirrored_root(now=now)
        return True

    def _leaf_index_for_entry(self, entry_hash):
        errors = []
        for source in self._proof_sources():
            latest_root = None
            try:
                latest_root = source.latest_root()
                self._verify_signed_root_for_lineage(latest_root)
                proof = source.inclusion_proof(entry_hash, int(latest_root["tree_size"]))
                verify_inclusion_proof(
                    entry_hash,
                    proof,
                    latest_root,
                    operator_public_key=latest_root["operator_public_key"],
                )
                return int(proof["leaf_index"])
            except Exception as exc:
                errors.append(f"{_source_label(source)}: {exc}")
        detail = "; ".join(errors) if errors else "no proof source available"
        raise InclusionProofError(f"could not discover transparency leaf index: {detail}")

    # Verify that this transfer was logged in a root close to its timestamp.
    def _transfer_recovery_witnesses(self, transfer):
        transparency = transfer.get("transparency") if isinstance(transfer, dict) else None
        if isinstance(transparency, dict):
            return (
                transparency.get("recovery_witnesses") or [],
                transparency.get("recovery_message_hash"),
            )
        return (
            transfer.get("recovery_witnesses", []) if isinstance(transfer, dict) else [],
            transfer.get("recovery_message_hash") if isinstance(transfer, dict) else None,
        )

    def verify_transfer_history(
        self,
        transfer,
        recovery_witnesses=None,
        recovery_message_hash=None,
    ):
        timestamp = int(transfer["timestamp"])
        entry_hash = transfer_entry_hash(transfer)
        if recovery_witnesses is None and recovery_message_hash is None:
            recovery_witnesses, recovery_message_hash = self._transfer_recovery_witnesses(
                transfer
            )
        recovery_message_hash = recovery_message_hash or entry_hash
        leaf_index = self._leaf_index_for_entry(entry_hash)
        root = self.mirrored_root_containing_leaf(
            timestamp,
            leaf_index,
            recovery_witnesses=recovery_witnesses,
            recovery_message_hash=recovery_message_hash,
        )
        proof = self._first_proof("inclusion_proof", entry_hash, int(root["tree_size"]))
        verify_inclusion_proof(
            entry_hash,
            proof,
            root,
            operator_public_key=root["operator_public_key"],
        )
        spend_proof = self._first_proof(
            "spend_map_proof", spend_key_for_transfer(transfer), int(root["tree_size"])
        )
        try:
            verify_spend_map_proof_for_transfer(
                transfer,
                spend_proof,
                root,
                operator_public_key=root["operator_public_key"],
            )
        except OperatorPolicyViolationError as exc:
            self._handle_operator_policy_violation(exc.evidence)
            raise
        return root

    # Verify the transfer's spend key against the freshest mirrored root.
    def verify_transfer_current_spend(self, transfer, now=None, current_root=None):
        root = current_root if current_root is not None else self.current_mirrored_root(now=now)
        spend_proof = self._first_proof(
            "spend_map_proof", spend_key_for_transfer(transfer), int(root["tree_size"])
        )
        try:
            verify_spend_map_proof_for_transfer(
                transfer,
                spend_proof,
                root,
                operator_public_key=root["operator_public_key"],
            )
        except OperatorPolicyViolationError as exc:
            self._handle_operator_policy_violation(exc.evidence)
            raise
        return True

    # Verify a compact checkpoint against independently mirrored historical roots.
    def verify_checkpoint_history(self, checkpoint):
        transparency = checkpoint.get("transparency")
        if not isinstance(transparency, dict):
            raise InclusionProofError("checkpoint is missing transparency proof")
        entry_hash = str(checkpoint["checkpoint_hash"]).lower()
        root = transparency["root"]
        self._verify_signed_root_for_lineage(root)
        verify_inclusion_proof(
            entry_hash,
            transparency["inclusion_proof"],
            root,
            operator_public_key=root["operator_public_key"],
        )
        try:
            verify_spend_map_proof_for_checkpoint(
                checkpoint,
                transparency["spend_proof"],
                root,
                operator_public_key=root["operator_public_key"],
            )
        except OperatorPolicyViolationError as exc:
            self._handle_operator_policy_violation(exc.evidence)
            raise
        leaf_index = int(transparency["inclusion_proof"]["leaf_index"])
        mirrored_root = self.mirrored_root_containing_leaf(int(root["timestamp"]), leaf_index)
        mirrored_inclusion = self._first_proof(
            "inclusion_proof", entry_hash, int(mirrored_root["tree_size"])
        )
        verify_inclusion_proof(
            entry_hash,
            mirrored_inclusion,
            mirrored_root,
            operator_public_key=mirrored_root["operator_public_key"],
        )
        spend_proof = self._first_proof(
            "spend_map_proof",
            transparency["spend_proof"]["spend_key"],
            int(mirrored_root["tree_size"]),
        )
        try:
            verify_spend_map_proof_for_checkpoint(
                checkpoint,
                spend_proof,
                mirrored_root,
                operator_public_key=mirrored_root["operator_public_key"],
            )
        except OperatorPolicyViolationError as exc:
            self._handle_operator_policy_violation(exc.evidence)
            raise
        return mirrored_root

    # Verify a compact checkpoint against the freshest mirrored log state.
    def verify_checkpoint_current_spend(self, checkpoint, now=None, current_root=None):
        transparency = checkpoint.get("transparency")
        if not isinstance(transparency, dict):
            raise InclusionProofError("checkpoint is missing transparency proof")
        entry_hash = str(checkpoint["checkpoint_hash"]).lower()
        root = current_root if current_root is not None else self.current_mirrored_root(now=now)
        inclusion_proof = self._first_proof("inclusion_proof", entry_hash, int(root["tree_size"]))
        verify_inclusion_proof(
            entry_hash,
            inclusion_proof,
            root,
            operator_public_key=root["operator_public_key"],
        )
        spend_proof = self._first_proof(
            "spend_map_proof",
            transparency["spend_proof"]["spend_key"],
            int(root["tree_size"]),
        )
        try:
            verify_spend_map_proof_for_checkpoint(
                checkpoint,
                spend_proof,
                root,
                operator_public_key=root["operator_public_key"],
            )
        except OperatorPolicyViolationError as exc:
            self._handle_operator_policy_violation(exc.evidence)
            raise
        return True

    def verify_checkpoint(self, checkpoint, now=None, require_current_root=True):
        self.verify_checkpoint_history(checkpoint)
        if require_current_root:
            self.verify_checkpoint_current_spend(checkpoint, now=now)
        return True

    def verify_transfer(self, transfer, now=None, require_current_root=True):
        self.verify_transfer_history(transfer)
        if require_current_root:
            self.verify_transfer_current_spend(transfer, now=now)
        return True

    def verify_token(self, token, now=None, require_current_root=True):
        history = (
            token.get("recent_history", [])
            if token.get("type") == ind_token.BILL_TYPE
            else token.get("history", [])
        )
        for transfer in history:
            self.verify_transfer(transfer, require_current_root=False)
        if require_current_root:
            current_root = self.current_mirrored_root(now=now)
            for transfer in history:
                self.verify_transfer_current_spend(transfer, current_root=current_root)
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


class MultiTransparencyVerifier:
    def __init__(self, verifiers):
        self.verifiers = [verifier for verifier in verifiers if verifier is not None]
        if not self.verifiers:
            raise TransparencyLogError("multi-operator transparency verifier requires operators")
        self.default_verifier = self.verifiers[0]
        self.operator = self.default_verifier.operator
        self.operator_public_key = self.default_verifier.operator_public_key
        self.identity_id = ("multi-transparency-verifier", str(len(self.verifiers)))

    def __getattr__(self, name):
        return getattr(self.default_verifier, name)

    def verifier_for_signed_root(self, root):
        errors = []
        for verifier in self.verifiers:
            try:
                verifier._verify_signed_root_for_lineage(root)
                return verifier
            except Exception as exc:
                errors.append(f"{_source_label(verifier.operator)}: {exc}")
        detail = "; ".join(errors) if errors else "no configured operators"
        raise RootVerificationError(f"untrusted transparency operator: {detail}")

    def verifier_for_operator(self, *, operator_public_key=None, log_id=None):
        operator_public_key = str(operator_public_key or "").strip()
        log_id = str(log_id or "").strip()
        errors = []
        for verifier in self.verifiers:
            configured_key = str(getattr(verifier, "operator_public_key", "") or "").strip()
            configured_log_id = log_id_from_public_key(configured_key) if configured_key else ""
            if operator_public_key and configured_key == operator_public_key:
                return verifier
            if log_id and configured_log_id == log_id:
                return verifier
            errors.append(_source_label(verifier.operator))
        detail = ", ".join(errors) if errors else "no configured operators"
        raise RootVerificationError(f"untrusted transparency operator: {detail}")

    def _verifier_for_message_root(self, root):
        try:
            return self.verifier_for_signed_root(root)
        except Exception:
            return self.default_verifier

    def consume_pending_gossip_messages(self):
        messages = []
        for verifier in self.verifiers:
            messages.extend(verifier.consume_pending_gossip_messages())
        return messages

    def persisted_equivocation_messages(self, limit=100):
        messages = []
        for verifier in self.verifiers:
            messages.extend(verifier.persisted_equivocation_messages(limit=limit))
        return messages[: max(0, int(limit))]

    def persisted_operator_policy_violation_messages(self, limit=100):
        messages = []
        for verifier in self.verifiers:
            persisted = getattr(verifier, "persisted_operator_policy_violation_messages", None)
            if callable(persisted):
                messages.extend(persisted(limit=limit))
        return messages[: max(0, int(limit))]

    def process_root_announcement(self, message, peer_id=None, message_hash=None):
        root = verify_root_announcement(message)
        return self._verifier_for_message_root(root).process_root_announcement(
            message, peer_id=peer_id, message_hash=message_hash
        )

    def process_equivocation_proof(self, message, peer_id=None, message_hash=None):
        evidence = verify_equivocation_proof(message)
        root = evidence["root_a"]
        return self._verifier_for_message_root(root).process_equivocation_proof(
            message, peer_id=peer_id, message_hash=message_hash
        )

    def process_operator_policy_violation_proof(self, message, peer_id=None, message_hash=None):
        proof = verify_operator_policy_violation_proof(message)
        root = proof["root"]
        return self._verifier_for_message_root(root).process_operator_policy_violation_proof(
            message, peer_id=peer_id, message_hash=message_hash
        )


def _select_active_operator_config(operator_configs):
    configs = [item for item in operator_configs if item.get("url")]
    if len(configs) <= 1:
        return configs[0] if configs else None
    for config in configs:
        try:
            status = HTTPTransparencyOperator(config["url"], timeout=3).status()
        except Exception:
            continue
        if str(status.get("state", "active")).strip().lower() == "active":
            return config
    return None


def _operator_configs_from_env_json():
    operators_raw = os.environ.get("IND_LOG_OPERATORS", "").strip()
    operator_configs = []
    if not operators_raw:
        return operator_configs
    try:
        parsed_operators = json.loads(operators_raw)
    except json.JSONDecodeError:
        parsed_operators = []
    if not isinstance(parsed_operators, list):
        return operator_configs
    for item in parsed_operators:
        if not isinstance(item, dict):
            continue
        url = str(item.get("url", "")).strip()
        public_key = str(item.get("public_key", "")).strip()
        mirrors = list(item.get("mirrors") or [])
        proof_archives = list(item.get("proof_archives") or [])
        if url or public_key or mirrors or proof_archives:
            operator_configs.append(
                {
                    "url": url,
                    "public_key": public_key,
                    "mirrors": mirrors,
                    "proof_archives": proof_archives,
                }
            )
    return operator_configs


def _with_legacy_operator_config(operator_configs, operator_url, public_key, mirrors, proof_archives):
    operator_configs = [dict(item) for item in operator_configs]
    operator_url = str(operator_url or "").strip()
    if not operator_url:
        return operator_configs
    normalized_url = operator_url.rstrip("/")
    if any(str(item.get("url", "")).strip().rstrip("/") == normalized_url for item in operator_configs):
        return operator_configs
    operator_configs.insert(
        0,
        {
            "url": operator_url,
            "public_key": str(public_key or "").strip(),
            "mirrors": list(mirrors or []),
            "proof_archives": list(proof_archives or []),
        },
    )
    return operator_configs


def _ordered_operator_configs(operator_configs):
    operator_configs = [dict(item) for item in operator_configs if isinstance(item, dict)]
    active_config = _select_active_operator_config(operator_configs)
    if active_config is None:
        return operator_configs
    ordered = [active_config]
    ordered.extend(item for item in operator_configs if item is not active_config)
    return ordered


def _build_transparency_verifier_from_config(
    config,
    *,
    default_mirrors,
    default_proof_archives,
    default_public_key,
    use_default_sources,
    require_pinned_operator,
    max_lag,
    operator_recovery_min_feeds,
    max_current_age,
    current_future_skew,
    min_mirrors,
    allow_unsafe_single_mirror,
    strict_mode,
    observed_roots_path,
    consistency_anchor_path,
    consistency_interval,
    consistency_max_stale,
):
    operator_url = str(config.get("url", "")).strip()
    operator_public_key = str(config.get("public_key") or "").strip()
    if not operator_public_key and use_default_sources:
        operator_public_key = str(default_public_key or "").strip()
    mirrors = list(config.get("mirrors") or (default_mirrors if use_default_sources else []))
    proof_archives = list(
        config.get("proof_archives")
        or (default_proof_archives if use_default_sources else [])
    )
    if require_pinned_operator and not operator_public_key:
        raise TransparencyLogError("multi-operator transparency config must pin public_key")
    if not operator_url and not operator_public_key:
        raise TransparencyLogError("verify-only transparency operator must pin public_key")
    if not mirrors:
        return None
    operator = (
        operator_url
        if operator_url
        else VerifyOnlyTransparencyOperator(operator_public_key)
    )
    return TransparencyVerifier(
        operator,
        mirrors,
        operator_public_key=operator_public_key or None,
        max_root_lag_seconds=max_lag,
        max_current_root_age_seconds=max_current_age,
        current_root_future_skew_seconds=current_future_skew,
        proof_archives=proof_archives,
        min_mirrors=min_mirrors,
        allow_unsafe_single_mirror=allow_unsafe_single_mirror,
        strict_mode=bool(strict_mode),
        observed_roots_path=observed_roots_path,
        consistency_anchor_path=consistency_anchor_path,
        consistency_check_interval_seconds=consistency_interval,
        consistency_max_stale_seconds=consistency_max_stale,
        operator_recovery_min_feeds=operator_recovery_min_feeds,
        start_background_checks=True,
    )


# Build a verifier from IND transparency environment variables.
def verifier_from_environment(strict_mode=None):
    ind_settings = _settings_module()
    if ind_settings is not None:
        settings = ind_settings.load_security_settings()
        operator_configs = ind_settings.transparency_operators(settings)
        default_mirrors = ind_settings.trusted_root_mirrors(settings)
        default_proof_archives = ind_settings.transparency_proof_archives(settings)
        default_public_key = ind_settings.transparency_operator_public_key(settings)
        operator_configs = _with_legacy_operator_config(
            operator_configs,
            ind_settings.transparency_operator_url(settings),
            default_public_key,
            default_mirrors,
            default_proof_archives,
        )
        max_lag = ind_settings.max_root_lag_seconds(settings)
        operator_recovery_min_feeds = ind_settings.operator_recovery_min_feeds(settings)
        max_current_age = ind_settings.max_current_root_age_seconds(settings)
        current_future_skew = ind_settings.current_root_future_skew_seconds(settings)
        min_mirrors = ind_settings.min_root_mirrors(settings)
        observed_roots_path = ind_settings.transparency_observed_roots_db(settings)
        consistency_anchor_path = (
            ind_settings.transparency_consistency_anchor_path(settings) or None
        )
        consistency_interval = ind_settings.transparency_consistency_check_interval_seconds(
            settings
        )
        consistency_max_stale = ind_settings.transparency_consistency_max_stale_seconds(settings)
        if strict_mode is None:
            strict_mode = ind_settings.require_transparency_log(settings)
    else:
        operator_configs = _operator_configs_from_env_json()
        mirrors_raw = os.environ.get("IND_LOG_MIRROR_URLS", "").strip()
        default_mirrors = [item.strip() for item in mirrors_raw.split(",") if item.strip()]
        proof_archives_raw = os.environ.get("IND_LOG_PROOF_ARCHIVES", "").strip()
        default_proof_archives = [
            item.strip()
            for item in proof_archives_raw.replace("\n", ",").split(",")
            if item.strip()
        ]
        default_public_key = os.environ.get("IND_LOG_OPERATOR_PUBLIC_KEY", "").strip()
        operator_configs = _with_legacy_operator_config(
            operator_configs,
            os.environ.get("IND_LOG_OPERATOR_URL", "").strip(),
            default_public_key,
            default_mirrors,
            default_proof_archives,
        )
        max_lag = int(os.environ.get("IND_LOG_MAX_ROOT_LAG_SECONDS", DEFAULT_MAX_ROOT_LAG_SECONDS))
        operator_recovery_min_feeds = int(
            os.environ.get(
                "IND_OPERATOR_RECOVERY_MIN_FEEDS",
                str(DEFAULT_OPERATOR_RECOVERY_MIN_FEEDS),
            )
        )
        max_current_age = int(
            os.environ.get(
                "IND_LOG_MAX_CURRENT_ROOT_AGE_SECONDS", DEFAULT_MAX_CURRENT_ROOT_AGE_SECONDS
            )
        )
        current_future_skew = int(
            os.environ.get(
                "IND_LOG_CURRENT_ROOT_FUTURE_SKEW_SECONDS", DEFAULT_CURRENT_ROOT_FUTURE_SKEW_SECONDS
            )
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
            os.environ.get(
                "IND_LOG_CONSISTENCY_MAX_STALE_SECONDS", DEFAULT_CONSISTENCY_MAX_STALE_SECONDS
            )
        )
        if strict_mode is None:
            strict_mode = _env_true("IND_REQUIRE_TRANSPARENCY_LOG")
    allow_unsafe_single_mirror = _env_true(UNSAFE_SINGLE_MIRROR_ENV)
    if bool(strict_mode) and allow_unsafe_single_mirror:
        raise TransparencyLogError(STRICT_UNSAFE_SINGLE_MIRROR_ERROR)
    if allow_unsafe_single_mirror and "IND_LOG_MIN_MIRRORS" not in os.environ:
        min_mirrors = 1
    operator_configs = _ordered_operator_configs(operator_configs)
    if not operator_configs:
        return None
    use_default_sources = len(operator_configs) == 1
    require_pinned_operator = len(operator_configs) > 1
    verifiers = []
    for config in operator_configs:
        verifier = _build_transparency_verifier_from_config(
            config,
            default_mirrors=default_mirrors,
            default_proof_archives=default_proof_archives,
            default_public_key=default_public_key,
            use_default_sources=use_default_sources,
            require_pinned_operator=require_pinned_operator,
            max_lag=max_lag,
            operator_recovery_min_feeds=operator_recovery_min_feeds,
            max_current_age=max_current_age,
            current_future_skew=current_future_skew,
            min_mirrors=min_mirrors,
            allow_unsafe_single_mirror=allow_unsafe_single_mirror,
            strict_mode=strict_mode,
            observed_roots_path=observed_roots_path,
            consistency_anchor_path=consistency_anchor_path,
            consistency_interval=consistency_interval,
            consistency_max_stale=consistency_max_stale,
        )
        if verifier is not None:
            verifiers.append(verifier)
    if not verifiers:
        return None
    if len(verifiers) == 1:
        return verifiers[0]
    return MultiTransparencyVerifier(verifiers)


# Build a log submitter from IND transparency environment variables.
def submitter_from_environment():
    ind_settings = _settings_module()
    if ind_settings is not None:
        settings = ind_settings.load_security_settings()
        operator_configs = ind_settings.transparency_operators(settings)
        operator_configs = _with_legacy_operator_config(
            operator_configs,
            ind_settings.transparency_operator_url(settings),
            ind_settings.transparency_operator_public_key(settings),
            ind_settings.trusted_root_mirrors(settings),
            ind_settings.transparency_proof_archives(settings),
        )
    else:
        operator_configs = _operator_configs_from_env_json()
        operator_configs = _with_legacy_operator_config(
            operator_configs,
            os.environ.get("IND_LOG_OPERATOR_URL", "").strip(),
            os.environ.get("IND_LOG_OPERATOR_PUBLIC_KEY", "").strip(),
            [],
            [],
        )
    operator_items = [item for item in operator_configs if item.get("url")]
    if not operator_items:
        return None
    if len(operator_items) == 1:
        item = operator_items[0]
        return HTTPTransparencyOperator(
            item["url"],
            operator_public_key=str(item.get("public_key") or "").strip() or None,
        )
    return MultiTransparencySubmitter(operator_items)
