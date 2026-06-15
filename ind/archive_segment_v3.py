# ArchiveSegmentV3 storage proofs for old native V3 transfer bodies.

import copy

from . import binary_v3
from . import protocol as ind_token
from . import protocol_v3

ARCHIVE_SEGMENT_TYPE = "ind.archive_segment.v3"
ARCHIVE_SEGMENT_VERSION = 3
ARCHIVE_SEGMENT_MAGIC = b"IND3ARCH"
DEFAULT_NETWORK_ID = protocol_v3.DEFAULT_NETWORK_ID

ARCHIVE_SEGMENT_FIELDS = {
    "type",
    "version",
    "network_id",
    "token_id",
    "value",
    "display_id",
    "genesis_ref",
    "base_state",
    "start_sequence",
    "end_sequence",
    "previous_segment_hash",
    "previous_checkpoint_hash",
    "checkpoint_hash",
    "transfer_count",
    "transfers",
    "segment_hash",
}


# Raised when an ArchiveSegmentV3 fails validation.
class ArchiveSegmentV3Error(ind_token.ValidationError):
    pass


def _require_exact_fields(data, required, label):
    if not isinstance(data, dict) or set(data) != set(required):
        raise ArchiveSegmentV3Error(f"malformed {label}")


def _require_int(value, label, minimum=None):
    if type(value) is not int:
        raise ArchiveSegmentV3Error(f"{label} must be an integer")
    if minimum is not None and value < int(minimum):
        raise ArchiveSegmentV3Error(f"{label} is below the allowed range")
    return value


def _hex32(value, label):
    if not isinstance(value, str) or len(value) != 64:
        raise ArchiveSegmentV3Error(f"invalid {label}")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise ArchiveSegmentV3Error(f"invalid {label}") from exc
    return value.lower()


def _canonical_payload_bytes(data):
    return ind_token.canonical_json(data).encode("utf-8")


def _unsigned_segment(segment):
    unsigned = copy.deepcopy(segment)
    unsigned.pop("segment_hash", None)
    return unsigned


# Encode an ArchiveSegmentV3 dict in a canonical V3 binary envelope.
def encode_archive_segment(segment, include_hash=True):
    if not isinstance(segment, dict):
        raise ArchiveSegmentV3Error("archive segment must be a dict")
    network_id = _require_int(segment.get("network_id"), "archive segment network id", minimum=0)
    payload = segment if include_hash else _unsigned_segment(segment)
    return b"".join(
        (
            ARCHIVE_SEGMENT_MAGIC,
            binary_v3.encode_uvarint(ARCHIVE_SEGMENT_VERSION),
            binary_v3.encode_uvarint(network_id),
            binary_v3.encode_bytes(_canonical_payload_bytes(payload)),
        )
    )


# Decode a canonical ArchiveSegmentV3 binary envelope.
def decode_archive_segment(data):
    reader = binary_v3.Reader(data)
    magic = reader.read(len(ARCHIVE_SEGMENT_MAGIC), "archive segment magic")
    if magic != ARCHIVE_SEGMENT_MAGIC:
        raise ArchiveSegmentV3Error("invalid archive segment magic")
    version = reader.read_uvarint("archive segment version")
    if version != ARCHIVE_SEGMENT_VERSION:
        raise ArchiveSegmentV3Error("unsupported archive segment version")
    network_id = reader.read_uvarint("archive segment network id")
    payload = reader.read_bytes("archive segment payload")
    reader.require_eof()
    segment = ind_token._load_json(payload.decode("utf-8"))
    if (
        _require_int(segment.get("network_id"), "archive segment network id", minimum=0)
        != network_id
    ):
        raise ArchiveSegmentV3Error("archive segment network id mismatch")
    return segment


# Return the raw 32-byte content hash for an unsigned archive segment.
def archive_segment_hash(segment):
    return binary_v3.object_hash(
        ARCHIVE_SEGMENT_TYPE,
        encode_archive_segment(segment, include_hash=False),
    )


# Return the archive segment content hash as lowercase hex.
def archive_segment_hash_hex(segment):
    return archive_segment_hash(segment).hex()


# Return a copy with the segment self-hash filled in.
def finalize_archive_segment(segment):
    result = copy.deepcopy(segment)
    result["segment_hash"] = archive_segment_hash_hex(result)
    return result


# Build one content-addressed archive segment from native V3 transfers.
def make_archive_segment(
    token_id,
    genesis_ref,
    base_state,
    transfers,
    previous_segment_hash=None,
    previous_checkpoint_hash=None,
    network_id=DEFAULT_NETWORK_ID,
):
    if not isinstance(transfers, list) or not transfers:
        raise ArchiveSegmentV3Error("archive segment requires at least one transfer")
    if previous_segment_hash is None and previous_checkpoint_hash is not None:
        raise ArchiveSegmentV3Error("previous checkpoint requires a previous segment")
    if previous_segment_hash is not None and previous_checkpoint_hash is None:
        raise ArchiveSegmentV3Error("previous segment requires a previous checkpoint")
    base_state = copy.deepcopy(base_state)
    final_state = protocol_v3.verify_transfer_sequence_from_state(
        token_id,
        base_state,
        transfers,
        network_id=network_id,
    )
    checkpoint_core = protocol_v3.checkpoint_core_from_state(
        token_id,
        genesis_ref["genesis_hash"],
        final_state,
        previous_checkpoint_hash=previous_checkpoint_hash,
        network_id=network_id,
    )
    segment = {
        "type": ARCHIVE_SEGMENT_TYPE,
        "version": ARCHIVE_SEGMENT_VERSION,
        "network_id": int(network_id),
        "token_id": token_id,
        "value": int(final_state["value"]),
        "display_id": str(final_state["display_id"]),
        "genesis_ref": copy.deepcopy(genesis_ref),
        "base_state": base_state,
        "start_sequence": int(base_state["sequence"]) + 1,
        "end_sequence": int(final_state["sequence"]),
        "previous_segment_hash": previous_segment_hash,
        "previous_checkpoint_hash": previous_checkpoint_hash,
        "checkpoint_hash": checkpoint_core["checkpoint_hash"],
        "transfer_count": len(transfers),
        "transfers": copy.deepcopy(transfers),
        "segment_hash": "",
    }
    return finalize_archive_segment(segment)


def _validate_header(segment, expected_network_id=None):
    _require_exact_fields(segment, ARCHIVE_SEGMENT_FIELDS, "archive segment")
    if segment["type"] != ARCHIVE_SEGMENT_TYPE:
        raise ArchiveSegmentV3Error("malformed archive segment")
    if _require_int(segment["version"], "archive segment version") != ARCHIVE_SEGMENT_VERSION:
        raise ArchiveSegmentV3Error("unsupported archive segment version")
    network_id = _require_int(segment["network_id"], "archive segment network id", minimum=0)
    if expected_network_id is not None and network_id != int(expected_network_id):
        raise ArchiveSegmentV3Error("archive segment network id mismatch")
    _hex32(segment["token_id"], "archive segment token id")
    _require_int(segment["value"], "archive segment value", minimum=1)
    if segment["previous_segment_hash"] is not None:
        _hex32(segment["previous_segment_hash"], "previous archive segment hash")
    if segment["previous_checkpoint_hash"] is not None:
        _hex32(segment["previous_checkpoint_hash"], "previous checkpoint hash")
    _hex32(segment["checkpoint_hash"], "archive segment checkpoint hash")
    _require_int(segment["start_sequence"], "archive segment start sequence", minimum=1)
    _require_int(segment["end_sequence"], "archive segment end sequence", minimum=1)
    if int(segment["end_sequence"]) < int(segment["start_sequence"]):
        raise ArchiveSegmentV3Error("archive segment sequence range is invalid")
    if not isinstance(segment["transfers"], list):
        raise ArchiveSegmentV3Error("archive segment transfers must be a list")
    if _require_int(segment["transfer_count"], "archive segment transfer count", minimum=1) != len(
        segment["transfers"]
    ):
        raise ArchiveSegmentV3Error("archive segment transfer count mismatch")
    if segment["segment_hash"] != archive_segment_hash_hex(segment):
        raise ArchiveSegmentV3Error("archive segment hash mismatch")
    return network_id


def _state_from_checkpoint_core(core):
    return {
        "sequence": int(core["sequence"]),
        "owner_address": core["owner_address"],
        "last_transfer_hash": core["last_transfer_hash"],
        "last_transfer_timestamp": int(core["last_transfer_timestamp"]),
        "last_transfer_day": int(core["last_transfer_day"]),
        "transfers_in_last_day": int(core["transfers_in_last_day"]),
        "display_id": core["display_id"],
        "value": int(core["value"]),
    }


# Verify an ArchiveSegmentV3 and return the checkpoint core it derives.
def verify_archive_segment(
    segment,
    expected_network_id=DEFAULT_NETWORK_ID,
    previous_segment=None,
    previous_segment_resolver=None,
    now=None,
):
    if isinstance(segment, bytes):
        segment = decode_archive_segment(segment)
    network_id = _validate_header(segment, expected_network_id=expected_network_id)
    protocol_v3._validate_genesis_ref(segment["genesis_ref"], network_id)
    base_state = copy.deepcopy(segment["base_state"])
    if segment["previous_segment_hash"] is not None:
        if previous_segment is None:
            if previous_segment_resolver is None:
                raise ArchiveSegmentV3Error("previous archive segment resolver is required")
            previous_segment = previous_segment_resolver(segment["previous_segment_hash"])
        if previous_segment is None:
            raise ArchiveSegmentV3Error("previous archive segment is required")
        previous_core = verify_archive_segment(
            previous_segment,
            expected_network_id=network_id,
            previous_segment_resolver=previous_segment_resolver,
            now=now,
        )
        if segment["previous_segment_hash"] != archive_segment_hash_hex(previous_segment):
            raise ArchiveSegmentV3Error("previous archive segment hash mismatch")
        if segment["previous_checkpoint_hash"] != previous_core["checkpoint_hash"]:
            raise ArchiveSegmentV3Error("previous checkpoint hash mismatch")
        if base_state != _state_from_checkpoint_core(previous_core):
            raise ArchiveSegmentV3Error("archive segment does not connect to previous segment")
    else:
        if segment["previous_checkpoint_hash"] is not None:
            raise ArchiveSegmentV3Error("genesis archive segment cannot have previous checkpoint")
        if int(base_state.get("sequence", -1)) != 0:
            raise ArchiveSegmentV3Error(
                "archive segment without previous segment must start at genesis"
            )
        if base_state.get("last_transfer_hash") != segment["genesis_ref"]["genesis_hash"]:
            raise ArchiveSegmentV3Error("archive segment genesis base hash mismatch")
    if int(segment["start_sequence"]) != int(base_state["sequence"]) + 1:
        raise ArchiveSegmentV3Error("archive segment start sequence mismatch")
    final_state = protocol_v3.verify_transfer_sequence_from_state(
        segment["token_id"],
        base_state,
        segment["transfers"],
        network_id=network_id,
        now=now,
    )
    if int(final_state["sequence"]) != int(segment["end_sequence"]):
        raise ArchiveSegmentV3Error("archive segment end sequence mismatch")
    if int(final_state["value"]) != int(segment["value"]):
        raise ArchiveSegmentV3Error("archive segment value mismatch")
    if str(final_state["display_id"]) != str(segment["display_id"]):
        raise ArchiveSegmentV3Error("archive segment display id mismatch")
    checkpoint_core = protocol_v3.checkpoint_core_from_state(
        segment["token_id"],
        segment["genesis_ref"]["genesis_hash"],
        final_state,
        previous_checkpoint_hash=segment["previous_checkpoint_hash"],
        network_id=network_id,
    )
    if checkpoint_core["checkpoint_hash"] != segment["checkpoint_hash"]:
        raise ArchiveSegmentV3Error("archive segment checkpoint hash mismatch")
    return checkpoint_core
