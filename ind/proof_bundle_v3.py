"""ProofBundleV3 validation for thin V3 compact bills."""

import copy

from . import binary_v3
from . import protocol as ind_token
from . import spend_map_v3
from . import transparency_client as log_client

PROOF_BUNDLE_TYPE = "ind.proof_bundle.v3"
PROOF_BUNDLE_REF_TYPE = "ind.proof_bundle_ref.v3"
PROOF_ARCHIVE_SEGMENT_TYPE = "ind.proof_bundle_archive_segment.v3"
PROOF_BUNDLE_VERSION = 3
PROOF_BUNDLE_ALGORITHM = 1
PROOF_BUNDLE_MAGIC = b"IND3PBDL"
DEFAULT_NETWORK_ID = spend_map_v3.DEFAULT_NETWORK_ID
SOURCE_FORMAT_V3_ARCHIVE_SEGMENT = "ind.archive_segment.v3"

PROOF_BUNDLE_FIELDS = {
    "type",
    "version",
    "network_id",
    "algorithm",
    "log_id",
    "checkpoint_hash",
    "signed_root",
    "checkpoint_inclusion_proof",
    "compressed_spend_map_proof",
    "source_evidence",
    "created_at",
    "proof_bundle_hash",
}
PROOF_BUNDLE_REF_FIELDS = {
    "type",
    "version",
    "network_id",
    "log_id",
    "signed_root_hash",
    "tree_size",
    "proof_bundle_algorithm",
    "proof_bundle_hash",
}
ARCHIVE_SEGMENT_SOURCE_FIELDS = {
    "type",
    "version",
    "network_id",
    "source_format",
    "archive_segment_hash",
    "source_checkpoint_hash",
    "previous_proof_bundle_hash",
    "archive_segment",
}


# Raised when a V3 proof bundle fails closed.
class ProofBundleV3Error(ind_token.ValidationError):
    pass


def _require_exact_fields(data, required, label):
    if not isinstance(data, dict) or set(data) != set(required):
        raise ProofBundleV3Error(f"malformed {label}")


def _require_int(value, label, minimum=None):
    if type(value) is not int:
        raise ProofBundleV3Error(f"{label} must be an integer")
    if minimum is not None and value < int(minimum):
        raise ProofBundleV3Error(f"{label} is below the allowed range")
    return value


def _hex32(value, label):
    if not isinstance(value, str) or len(value) != 64:
        raise ProofBundleV3Error(f"invalid {label}")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise ProofBundleV3Error(f"invalid {label}") from exc
    return value.lower()


def _canonical_payload_bytes(data):
    return ind_token.canonical_json(data).encode("utf-8")


def _unsigned_bundle(bundle):
    unsigned = copy.deepcopy(bundle)
    unsigned.pop("proof_bundle_hash", None)
    return unsigned


# Encode a ProofBundleV3 dict in a canonical V3 binary envelope.
def encode_proof_bundle(bundle, include_hash=True):
    if not isinstance(bundle, dict):
        raise ProofBundleV3Error("proof bundle must be a dict")
    network_id = _require_int(bundle.get("network_id"), "proof bundle network id", minimum=0)
    payload = bundle if include_hash else _unsigned_bundle(bundle)
    return b"".join(
        (
            PROOF_BUNDLE_MAGIC,
            binary_v3.encode_uvarint(PROOF_BUNDLE_VERSION),
            binary_v3.encode_uvarint(network_id),
            binary_v3.encode_bytes(_canonical_payload_bytes(payload)),
        )
    )


# Decode a ProofBundleV3 binary envelope.
def decode_proof_bundle(data):
    reader = binary_v3.Reader(data)
    magic = reader.read(len(PROOF_BUNDLE_MAGIC), "proof bundle magic")
    if magic != PROOF_BUNDLE_MAGIC:
        raise ProofBundleV3Error("invalid proof bundle magic")
    version = reader.read_uvarint("proof bundle version")
    if version != PROOF_BUNDLE_VERSION:
        raise ProofBundleV3Error("unsupported proof bundle version")
    network_id = reader.read_uvarint("proof bundle network id")
    payload = reader.read_bytes("proof bundle payload")
    reader.require_eof()
    bundle = ind_token._load_json(payload.decode("utf-8"))
    if _require_int(bundle.get("network_id"), "proof bundle network id", minimum=0) != network_id:
        raise ProofBundleV3Error("proof bundle network id mismatch")
    return bundle


# Return the raw 32-byte hash of a ProofBundleV3 without its hash field.
def proof_bundle_hash(bundle):
    return binary_v3.object_hash(
        PROOF_BUNDLE_TYPE,
        encode_proof_bundle(bundle, include_hash=False),
    )


# Return the ProofBundleV3 content hash as lowercase hex.
def proof_bundle_hash_hex(bundle):
    return proof_bundle_hash(bundle).hex()


# Return a copy with its self-hash filled in.
def finalize_proof_bundle(bundle):
    result = copy.deepcopy(bundle)
    result["proof_bundle_hash"] = proof_bundle_hash_hex(result)
    return result


# Build source evidence from a verified ArchiveSegmentV3.
def make_archive_segment_evidence(
    archive_segment,
    network_id=DEFAULT_NETWORK_ID,
    include_segment=False,
    previous_proof_bundle_hash=None,
    previous_segment_resolver=None,
):
    from . import archive_segment_v3

    checkpoint = archive_segment_v3.verify_archive_segment(
        archive_segment,
        expected_network_id=network_id,
        previous_segment_resolver=previous_segment_resolver,
    )
    if (
        checkpoint.get("previous_checkpoint_hash") is not None
        and previous_proof_bundle_hash is None
    ):
        raise ProofBundleV3Error("previous proof bundle hash is required")
    if previous_proof_bundle_hash is not None:
        previous_proof_bundle_hash = _hex32(
            previous_proof_bundle_hash, "previous proof bundle hash"
        )
    segment_hash = archive_segment_v3.archive_segment_hash_hex(archive_segment)
    return {
        "type": PROOF_ARCHIVE_SEGMENT_TYPE,
        "version": PROOF_BUNDLE_VERSION,
        "network_id": int(network_id),
        "source_format": SOURCE_FORMAT_V3_ARCHIVE_SEGMENT,
        "archive_segment_hash": segment_hash,
        "source_checkpoint_hash": checkpoint["checkpoint_hash"],
        "previous_proof_bundle_hash": previous_proof_bundle_hash,
        "archive_segment": copy.deepcopy(archive_segment) if include_segment else None,
    }


# Build and hash one ProofBundleV3.
def make_proof_bundle(
    checkpoint,
    signed_root,
    checkpoint_inclusion_proof,
    compressed_spend_map_proof,
    source_evidence,
    network_id=DEFAULT_NETWORK_ID,
    created_at=0,
):
    checkpoint_hash = _hex32(checkpoint["checkpoint_hash"], "checkpoint hash")
    root = copy.deepcopy(signed_root)
    bundle = {
        "type": PROOF_BUNDLE_TYPE,
        "version": PROOF_BUNDLE_VERSION,
        "network_id": int(network_id),
        "algorithm": PROOF_BUNDLE_ALGORITHM,
        "log_id": str(root["log_id"]),
        "checkpoint_hash": checkpoint_hash,
        "signed_root": root,
        "checkpoint_inclusion_proof": copy.deepcopy(checkpoint_inclusion_proof),
        "compressed_spend_map_proof": copy.deepcopy(compressed_spend_map_proof),
        "source_evidence": copy.deepcopy(source_evidence),
        "created_at": int(created_at),
        "proof_bundle_hash": "",
    }
    return finalize_proof_bundle(bundle)


# Return the compact reference carried by a thin V3 bill.
def proof_bundle_ref(bundle):
    verify_self_hash(bundle)
    signed_root = bundle["signed_root"]
    return {
        "type": PROOF_BUNDLE_REF_TYPE,
        "version": PROOF_BUNDLE_VERSION,
        "network_id": int(bundle["network_id"]),
        "log_id": str(bundle["log_id"]),
        "signed_root_hash": log_client.signed_root_id(signed_root),
        "tree_size": int(signed_root["tree_size"]),
        "proof_bundle_algorithm": int(bundle["algorithm"]),
        "proof_bundle_hash": bundle["proof_bundle_hash"],
    }


# Check that a ProofBundleV3 carries its own canonical hash.
def verify_self_hash(bundle):
    _require_exact_fields(bundle, PROOF_BUNDLE_FIELDS, "proof bundle")
    expected = proof_bundle_hash_hex(bundle)
    if bundle["proof_bundle_hash"] != expected:
        raise ProofBundleV3Error("proof bundle hash mismatch")
    return True


# Check that a bill's compact proof reference resolves to this bundle.
def verify_proof_bundle_ref(ref, bundle, expected_network_id=DEFAULT_NETWORK_ID):
    _require_exact_fields(ref, PROOF_BUNDLE_REF_FIELDS, "proof bundle reference")
    if ref["type"] != PROOF_BUNDLE_REF_TYPE:
        raise ProofBundleV3Error("malformed proof bundle reference")
    if _require_int(ref["version"], "proof bundle reference version") != PROOF_BUNDLE_VERSION:
        raise ProofBundleV3Error("unsupported proof bundle reference version")
    network_id = _require_int(ref["network_id"], "proof bundle reference network id", minimum=0)
    if expected_network_id is not None and network_id != int(expected_network_id):
        raise ProofBundleV3Error("proof bundle reference network id mismatch")
    if ref["proof_bundle_hash"] != bundle.get("proof_bundle_hash"):
        raise ProofBundleV3Error("proof bundle reference hash mismatch")
    if ref["proof_bundle_hash"] != proof_bundle_hash_hex(bundle):
        raise ProofBundleV3Error("proof bundle hash mismatch")
    signed_root = bundle["signed_root"]
    if ref["log_id"] != bundle["log_id"] or ref["log_id"] != signed_root["log_id"]:
        raise ProofBundleV3Error("proof bundle reference log id mismatch")
    if ref["signed_root_hash"] != log_client.signed_root_id(signed_root):
        raise ProofBundleV3Error("proof bundle reference root hash mismatch")
    if _require_int(ref["tree_size"], "proof bundle reference tree size", minimum=0) != int(
        signed_root["tree_size"]
    ):
        raise ProofBundleV3Error("proof bundle reference tree size mismatch")
    if (
        _require_int(ref["proof_bundle_algorithm"], "proof bundle reference algorithm")
        != PROOF_BUNDLE_ALGORITHM
    ):
        raise ProofBundleV3Error("unsupported proof bundle reference algorithm")
    return True


def _operator_key_for_policy(
    signed_root, transparency_verifier=None, trusted_operator_public_key=None
):
    if transparency_verifier is not None:
        operator_key = transparency_verifier.operator_public_key
        log_client.verify_signed_root(signed_root, operator_public_key=operator_key)
        leaf_index = None
        return operator_key, leaf_index
    if ind_token._production_mode():
        raise ProofBundleV3Error(
            "proof bundle requires a mirrored transparency verifier in production"
        )
    if not trusted_operator_public_key:
        raise ProofBundleV3Error(
            "proof bundle requires a trusted transparency verifier or pinned operator key"
        )
    log_client.verify_signed_root(signed_root, operator_public_key=trusted_operator_public_key)
    return trusted_operator_public_key, None


def _verify_mirrored_root(bundle, transparency_verifier):
    if transparency_verifier is None:
        return True
    signed_root = bundle["signed_root"]
    leaf_index = int(bundle["checkpoint_inclusion_proof"]["leaf_index"])
    mirrored = transparency_verifier.mirrored_root_containing_leaf(
        int(signed_root["timestamp"]),
        leaf_index,
    )
    if log_client.signed_root_id(mirrored) != log_client.signed_root_id(signed_root):
        raise ProofBundleV3Error("proof bundle signed root was not mirrored exactly")
    return True


def _verify_archive_segment_source(
    source_evidence,
    expected_network_id,
    archive_segment_resolver=None,
    proof_bundle_resolver=None,
    transparency_verifier=None,
    trusted_operator_public_key=None,
    seen_bundle_hashes=None,
):
    _require_exact_fields(
        source_evidence,
        ARCHIVE_SEGMENT_SOURCE_FIELDS,
        "proof bundle archive segment evidence",
    )
    if source_evidence["type"] != PROOF_ARCHIVE_SEGMENT_TYPE:
        raise ProofBundleV3Error("unsupported proof bundle source evidence")
    if _require_int(source_evidence["version"], "source evidence version") != PROOF_BUNDLE_VERSION:
        raise ProofBundleV3Error("unsupported source evidence version")
    network_id = _require_int(
        source_evidence["network_id"], "source evidence network id", minimum=0
    )
    if network_id != int(expected_network_id):
        raise ProofBundleV3Error("source evidence network id mismatch")
    if source_evidence["source_format"] != SOURCE_FORMAT_V3_ARCHIVE_SEGMENT:
        raise ProofBundleV3Error("unsupported source evidence format")
    from . import archive_segment_v3

    segment_hash = _hex32(source_evidence["archive_segment_hash"], "archive segment hash")
    archive_segment = source_evidence["archive_segment"]
    if archive_segment is None:
        if archive_segment_resolver is None:
            raise ProofBundleV3Error("archive segment resolver is required")
        archive_segment = archive_segment_resolver(segment_hash)
    if archive_segment_v3.archive_segment_hash_hex(archive_segment) != segment_hash:
        raise ProofBundleV3Error("archive segment hash mismatch")
    checkpoint = archive_segment_v3.verify_archive_segment(
        archive_segment,
        expected_network_id=network_id,
        previous_segment_resolver=archive_segment_resolver,
    )
    if source_evidence["source_checkpoint_hash"] != checkpoint["checkpoint_hash"]:
        raise ProofBundleV3Error("archive segment checkpoint hash mismatch")
    previous_checkpoint_hash = checkpoint.get("previous_checkpoint_hash")
    previous_bundle_hash = source_evidence["previous_proof_bundle_hash"]
    if previous_checkpoint_hash is not None:
        if previous_bundle_hash is None:
            raise ProofBundleV3Error("previous proof bundle hash is required")
        if proof_bundle_resolver is None:
            raise ProofBundleV3Error("previous proof bundle resolver is required")
        previous_bundle_hash = _hex32(previous_bundle_hash, "previous proof bundle hash")
        if seen_bundle_hashes and previous_bundle_hash in seen_bundle_hashes:
            raise ProofBundleV3Error("proof bundle recursion cycle")
        previous_bundle = proof_bundle_resolver(previous_bundle_hash)
        if previous_bundle is None:
            raise ProofBundleV3Error("previous proof bundle is required")
        if previous_bundle.get("proof_bundle_hash") != previous_bundle_hash:
            raise ProofBundleV3Error("previous proof bundle hash mismatch")
        verify_proof_bundle(
            previous_bundle,
            expected_checkpoint_hash=previous_checkpoint_hash,
            expected_network_id=network_id,
            transparency_verifier=transparency_verifier,
            trusted_operator_public_key=trusted_operator_public_key,
            archive_segment_resolver=archive_segment_resolver,
            proof_bundle_resolver=proof_bundle_resolver,
            _seen_bundle_hashes=seen_bundle_hashes,
        )
    elif previous_bundle_hash is not None:
        raise ProofBundleV3Error("previous proof bundle supplied without previous checkpoint")
    return checkpoint


def _verify_source_evidence(
    source_evidence,
    expected_network_id,
    archive_segment_resolver=None,
    proof_bundle_resolver=None,
    transparency_verifier=None,
    trusted_operator_public_key=None,
    seen_bundle_hashes=None,
):
    if not isinstance(source_evidence, dict):
        raise ProofBundleV3Error("missing proof bundle source evidence")
    if source_evidence.get("type") == PROOF_ARCHIVE_SEGMENT_TYPE:
        return _verify_archive_segment_source(
            source_evidence,
            expected_network_id,
            archive_segment_resolver=archive_segment_resolver,
            proof_bundle_resolver=proof_bundle_resolver,
            transparency_verifier=transparency_verifier,
            trusted_operator_public_key=trusted_operator_public_key,
            seen_bundle_hashes=seen_bundle_hashes,
        )
    raise ProofBundleV3Error("unsupported proof bundle source evidence")


def _checkpoint_with_transparency(checkpoint, bundle):
    checkpoint = copy.deepcopy(checkpoint)
    checkpoint["transparency"] = {
        "type": "ind.checkpoint_transparency.v2",
        "version": ind_token.BILL_VERSION,
        "root": copy.deepcopy(bundle["signed_root"]),
        "inclusion_proof": copy.deepcopy(bundle["checkpoint_inclusion_proof"]),
        "spend_proof": spend_map_v3.expand_compressed_spend_map_proof(
            bundle["compressed_spend_map_proof"],
            expected_network_id=bundle["network_id"],
        ),
    }
    return checkpoint


def _verify_v3_checkpoint_spend_proof(checkpoint, proof, signed_root, operator_public_key):
    from . import protocol_v3

    log_client.verify_signed_root(signed_root, operator_public_key=operator_public_key)
    claims = spend_map_v3.verify_compressed_spend_map_proof(
        proof,
        signed_root,
        expected_network_id=checkpoint["network_id"],
    )
    expected_transfer_hash = checkpoint["last_transfer_hash"]
    claim = next((item for item in claims if item["transfer_hash"] == expected_transfer_hash), None)
    if claim is None:
        raise ProofBundleV3Error("checkpoint spend proof does not contain its settled transfer")
    if claim["token_id"] != checkpoint["token_id"]:
        raise ProofBundleV3Error("checkpoint spend proof bill id mismatch")
    if int(claim["sequence"]) != int(checkpoint["sequence"]):
        raise ProofBundleV3Error("checkpoint spend proof sequence mismatch")
    if "transfer" not in claim:
        raise ProofBundleV3Error("checkpoint spend proof is missing the settled transfer body")
    transfer = claim["transfer"]
    protocol_v3._validate_transfer_shape(transfer, int(checkpoint["network_id"]))
    protocol_v3.verify_transfer_signature(transfer)
    if protocol_v3.transfer_hash(transfer) != expected_transfer_hash:
        raise ProofBundleV3Error("checkpoint spend proof transfer hash mismatch")
    if claim["spend_key"] != protocol_v3.spend_key_for_transfer(transfer):
        raise ProofBundleV3Error("checkpoint spend proof is for a different bill state")
    if transfer["recipient_address"] != checkpoint["owner_address"]:
        raise ProofBundleV3Error("checkpoint spend proof owner mismatch")
    if int(transfer["timestamp"]) != int(checkpoint["last_transfer_timestamp"]):
        raise ProofBundleV3Error("checkpoint spend proof timestamp mismatch")
    conflicting_claims = [
        item for item in claims if item["transfer_hash"] != expected_transfer_hash
    ]
    if conflicting_claims:
        raise ProofBundleV3Error("checkpoint spend proof contains a conflicting sibling claim")
    return True


def verify_proof_bundle(
    bundle,
    expected_checkpoint_hash=None,
    expected_network_id=DEFAULT_NETWORK_ID,
    transparency_verifier=None,
    trusted_operator_public_key=None,
    archive_segment_resolver=None,
    proof_bundle_resolver=None,
    _seen_bundle_hashes=None,
):
    """Validate a ProofBundleV3 and return the proven checkpoint core.

    This verifies all three facts a compact bill needs:
    the checkpoint hash is included in a trusted root, the spend map proves the
    settled transfer is not conflicted, and the checkpoint was derived from a
    valid source chain.
    """

    _require_exact_fields(bundle, PROOF_BUNDLE_FIELDS, "proof bundle")
    if bundle["type"] != PROOF_BUNDLE_TYPE:
        raise ProofBundleV3Error("malformed proof bundle")
    if _require_int(bundle["version"], "proof bundle version") != PROOF_BUNDLE_VERSION:
        raise ProofBundleV3Error("unsupported proof bundle version")
    network_id = _require_int(bundle["network_id"], "proof bundle network id", minimum=0)
    if expected_network_id is not None and network_id != int(expected_network_id):
        raise ProofBundleV3Error("proof bundle network id mismatch")
    if _require_int(bundle["algorithm"], "proof bundle algorithm") != PROOF_BUNDLE_ALGORITHM:
        raise ProofBundleV3Error("unsupported proof bundle algorithm")
    verify_self_hash(bundle)
    seen_bundle_hashes = set(_seen_bundle_hashes or set())
    if bundle["proof_bundle_hash"] in seen_bundle_hashes:
        raise ProofBundleV3Error("proof bundle recursion cycle")
    seen_bundle_hashes.add(bundle["proof_bundle_hash"])
    checkpoint_hash = _hex32(bundle["checkpoint_hash"], "checkpoint hash")
    if expected_checkpoint_hash is not None and checkpoint_hash != _hex32(
        expected_checkpoint_hash, "expected checkpoint hash"
    ):
        raise ProofBundleV3Error("proof bundle checkpoint hash mismatch")
    signed_root = bundle["signed_root"]
    if bundle["log_id"] != signed_root.get("log_id"):
        raise ProofBundleV3Error("proof bundle log id mismatch")
    operator_key, _leaf_index = _operator_key_for_policy(
        signed_root,
        transparency_verifier=transparency_verifier,
        trusted_operator_public_key=trusted_operator_public_key,
    )
    log_client.verify_inclusion_proof(
        checkpoint_hash,
        bundle["checkpoint_inclusion_proof"],
        signed_root,
        operator_public_key=operator_key,
    )
    _verify_mirrored_root(bundle, transparency_verifier)
    checkpoint = _verify_source_evidence(
        bundle["source_evidence"],
        network_id,
        archive_segment_resolver=archive_segment_resolver,
        proof_bundle_resolver=proof_bundle_resolver,
        transparency_verifier=transparency_verifier,
        trusted_operator_public_key=trusted_operator_public_key,
        seen_bundle_hashes=seen_bundle_hashes,
    )
    if checkpoint["checkpoint_hash"] != checkpoint_hash:
        raise ProofBundleV3Error("source chain does not produce proof bundle checkpoint")
    if checkpoint.get("type") == "ind.checkpoint_core.v3":
        _verify_v3_checkpoint_spend_proof(
            checkpoint,
            bundle["compressed_spend_map_proof"],
            signed_root,
            operator_public_key=operator_key,
        )
    else:
        checkpoint_for_proof = _checkpoint_with_transparency(checkpoint, bundle)
        log_client.verify_spend_map_proof_for_checkpoint(
            checkpoint_for_proof,
            checkpoint_for_proof["transparency"]["spend_proof"],
            signed_root,
            operator_public_key=operator_key,
        )
    return checkpoint
