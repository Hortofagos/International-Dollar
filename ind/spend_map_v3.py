# Compressed sparse spend-map proofs for IND V3.

import copy

from . import transparency_client as log_client

COMPRESSED_SPEND_MAP_PROOF_TYPE = "ind.transparency_compressed_spend_map_proof.v3"
COMPRESSED_SPEND_MAP_PROOF_VERSION = 3
COMPRESSED_SPEND_MAP_ALGORITHM = "IND_SPARSE_SPEND_MAP_SHA3_256_COMPRESSED_V3"
DEFAULT_NETWORK_ID = 1


def _require_int(value, label, minimum=None, maximum=None):
    if type(value) is not int:
        raise log_client.InclusionProofError(f"{label} must be an integer")
    if minimum is not None and value < int(minimum):
        raise log_client.InclusionProofError(f"{label} is below the allowed range")
    if maximum is not None and value > int(maximum):
        raise log_client.InclusionProofError(f"{label} is above the allowed range")
    return value


def _require_exact_keys(data, required, label):
    if not isinstance(data, dict) or set(data) != set(required):
        raise log_client.InclusionProofError(f"malformed {label}")
    return True


def _spend_key_position(spend_key):
    spend_key = log_client._hex32(spend_key, "spend key")
    return int(spend_key, 16)


def _expected_side_by_depth(spend_key):
    position = _spend_key_position(spend_key)
    sides = {}
    for child_depth in range(log_client.SPEND_MAP_KEY_BITS, 0, -1):
        sides[child_depth] = "right" if position % 2 == 0 else "left"
        position >>= 1
    return sides


def _compress_audit_path(audit_path):
    empty_hashes = log_client._spend_map_empty_hashes()
    siblings = []
    for index, step in enumerate(audit_path):
        child_depth = log_client.SPEND_MAP_KEY_BITS - index
        sibling_hash = log_client._hex32(step["hash"], "spend-map sibling hash")
        if sibling_hash != empty_hashes[child_depth]:
            siblings.append(
                {
                    "depth": child_depth,
                    "side": step["side"],
                    "hash": sibling_hash,
                }
            )
    return siblings


# Build a V3 compressed proof from the current V2 sparse-map semantics.
def build_compressed_spend_map_proof(claims, spend_key, tree_size, network_id=DEFAULT_NETWORK_ID):
    full_proof = log_client.build_spend_map_proof(claims, spend_key, tree_size)
    siblings = _compress_audit_path(full_proof["audit_path"])
    return {
        "type": COMPRESSED_SPEND_MAP_PROOF_TYPE,
        "version": COMPRESSED_SPEND_MAP_PROOF_VERSION,
        "network_id": int(network_id),
        "algorithm": COMPRESSED_SPEND_MAP_ALGORITHM,
        "spend_key": full_proof["spend_key"],
        "tree_size": int(full_proof["tree_size"]),
        "map_size": int(full_proof["map_size"]),
        "spend_claims": copy.deepcopy(full_proof["spend_claims"]),
        "non_empty_sibling_count": len(siblings),
        "non_empty_siblings": siblings,
    }


def _validate_compressed_header(proof, expected_network_id=None):
    required = {
        "type",
        "version",
        "network_id",
        "algorithm",
        "spend_key",
        "tree_size",
        "map_size",
        "spend_claims",
        "non_empty_sibling_count",
        "non_empty_siblings",
    }
    _require_exact_keys(proof, required, "compressed spend-map proof")
    if proof["type"] != COMPRESSED_SPEND_MAP_PROOF_TYPE:
        raise log_client.InclusionProofError("malformed compressed spend-map proof")
    if (
        _require_int(proof["version"], "compressed spend-map proof version")
        != COMPRESSED_SPEND_MAP_PROOF_VERSION
    ):
        raise log_client.InclusionProofError("unsupported compressed spend-map proof version")
    network_id = _require_int(
        proof["network_id"], "compressed spend-map proof network id", minimum=0
    )
    if expected_network_id is not None and network_id != int(expected_network_id):
        raise log_client.InclusionProofError("compressed spend-map proof network id mismatch")
    if proof["algorithm"] != COMPRESSED_SPEND_MAP_ALGORITHM:
        raise log_client.InclusionProofError("unsupported compressed spend-map proof algorithm")
    spend_key = log_client._hex32(proof["spend_key"], "spend key")
    _require_int(proof["tree_size"], "compressed spend-map proof tree size", minimum=0)
    _require_int(proof["map_size"], "compressed spend-map proof map size", minimum=0)
    if not isinstance(proof["spend_claims"], list) or not proof["spend_claims"]:
        raise log_client.InclusionProofError("compressed spend-map proof has no spend claims")
    if not isinstance(proof["non_empty_siblings"], list):
        raise log_client.InclusionProofError("compressed spend-map proof siblings must be a list")
    if _require_int(
        proof["non_empty_sibling_count"],
        "compressed spend-map proof sibling count",
        minimum=0,
        maximum=log_client.SPEND_MAP_KEY_BITS,
    ) != len(proof["non_empty_siblings"]):
        raise log_client.InclusionProofError("compressed spend-map proof sibling count mismatch")
    return spend_key


def _expanded_audit_path(proof, spend_key):
    empty_hashes = log_client._spend_map_empty_hashes()
    expected_sides = _expected_side_by_depth(spend_key)
    siblings_by_depth = {}
    previous_depth = log_client.SPEND_MAP_KEY_BITS + 1
    for sibling in proof["non_empty_siblings"]:
        _require_exact_keys(sibling, {"depth", "side", "hash"}, "compressed spend-map sibling")
        depth = _require_int(
            sibling["depth"],
            "compressed spend-map sibling depth",
            minimum=1,
            maximum=log_client.SPEND_MAP_KEY_BITS,
        )
        if depth in siblings_by_depth:
            raise log_client.InclusionProofError(
                "compressed spend-map proof has duplicate sibling depths"
            )
        if depth >= previous_depth:
            raise log_client.InclusionProofError("compressed spend-map siblings are not canonical")
        previous_depth = depth
        side = sibling["side"]
        if side != expected_sides[depth]:
            raise log_client.InclusionProofError(
                "compressed spend-map sibling does not follow the spend key"
            )
        sibling_hash = log_client._hex32(sibling["hash"], "compressed spend-map sibling hash")
        if sibling_hash == empty_hashes[depth]:
            raise log_client.InclusionProofError(
                "compressed spend-map proof explicitly stores an empty sibling"
            )
        siblings_by_depth[depth] = {"side": side, "hash": sibling_hash}

    audit_path = []
    for child_depth in range(log_client.SPEND_MAP_KEY_BITS, 0, -1):
        audit_path.append(
            siblings_by_depth.get(
                child_depth,
                {
                    "side": expected_sides[child_depth],
                    "hash": empty_hashes[child_depth],
                },
            )
        )
    return audit_path


# Return the equivalent full V2-style sparse spend-map proof.
def expand_compressed_spend_map_proof(proof, expected_network_id=None):
    spend_key = _validate_compressed_header(proof, expected_network_id=expected_network_id)
    return {
        "type": log_client.LOG_SPEND_MAP_PROOF_TYPE,
        "version": log_client.LOG_VERSION,
        "algorithm": log_client.LOG_SPEND_MAP_ALGORITHM,
        "spend_key": spend_key,
        "tree_size": int(proof["tree_size"]),
        "map_size": int(proof["map_size"]),
        "spend_claims": copy.deepcopy(proof["spend_claims"]),
        "audit_path": _expanded_audit_path(proof, spend_key),
    }


# Verify a compressed proof against an existing signed transparency root.
def verify_compressed_spend_map_proof(proof, signed_root, expected_network_id=DEFAULT_NETWORK_ID):
    full_proof = expand_compressed_spend_map_proof(
        proof,
        expected_network_id=expected_network_id,
    )
    return log_client.verify_spend_map_proof(full_proof, signed_root)
