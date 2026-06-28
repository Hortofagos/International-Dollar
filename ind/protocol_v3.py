"""Thin BillV3 verification built on ProofBundleV3.

This module verifies compact V3 bill state from a checkpoint core plus an
external ProofBundleV3.
"""

import base64
import copy
import os

from . import binary_v3, keys_v3, proof_bundle_v3
from . import protocol as ind_token

BILL_TYPE = "ind.bill.v3"
GENESIS_REF_TYPE = "ind.genesis_ref.v3"
CHECKPOINT_CORE_TYPE = "ind.checkpoint_core.v3"
TRANSFER_TYPE = "ind.transfer.v3"
RECEIPT_TYPE = "ind.receipt.v3"
TRANSFER_ANNOUNCEMENT_TYPE = "ind.transfer_announcement.v3"
RECEIPT_ANNOUNCEMENT_TYPE = "ind.receipt_announcement.v3"
CHECKPOINT_ANNOUNCEMENT_TYPE = "ind.checkpoint_announcement.v3"
PROOF_BUNDLE_ANNOUNCEMENT_TYPE = "ind.proof_bundle_announcement.v3"
ARCHIVE_SEGMENT_ANNOUNCEMENT_TYPE = "ind.archive_segment_announcement.v3"
CONFLICT_PROOF_TYPE = "ind.conflict_proof.v3"
VERSION = 3
BILL_MAGIC = b"IND3BILL"
TRANSFER_MAGIC = b"IND3XFER"
GENESIS_REF_MAGIC = b"IND3GENR"
CHECKPOINT_CORE_MAGIC = b"IND3CPNT"
RECEIPT_MAGIC = b"IND3RCPT"
CONFLICT_PROOF_MAGIC = b"IND3CFLP"
DEFAULT_NETWORK_ID = proof_bundle_v3.DEFAULT_NETWORK_ID
V3_PAYLOAD_ENCODING = "indb3-base85"
V3_PAYLOAD_PREFIX = "indb3:"

BILL_FIELDS = {
    "type",
    "version",
    "network_id",
    "token_id",
    "value",
    "genesis_ref",
    "checkpoint_core",
    "proof_bundle_ref",
    "recent_transfers",
}
GENESIS_REF_FIELDS = {
    "type",
    "version",
    "network_id",
    "genesis_hash",
    "manifest_hash",
    "issuer_key_id",
    "issue_index",
    "issued_at",
}
CHECKPOINT_CORE_FIELDS = {
    "type",
    "version",
    "network_id",
    "token_id",
    "genesis_hash",
    "sequence",
    "owner_address",
    "value",
    "display_id",
    "display_id_hash",
    "last_transfer_hash",
    "last_transfer_timestamp",
    "last_transfer_day",
    "transfers_in_last_day",
    "previous_checkpoint_hash",
    "checkpoint_hash",
}
TRANSFER_FIELDS = {
    "type",
    "version",
    "network_id",
    "signature_algorithm",
    "token_id",
    "sequence",
    "previous_hash",
    "sender_address",
    "sender_public_key",
    "recipient_address",
    "timestamp",
    "metadata",
    "signature",
}
RECEIPT_FIELDS = {
    "type",
    "version",
    "network_id",
    "signature_algorithm",
    "token_id",
    "transfer_hash",
    "sequence",
    "recipient_address",
    "recipient_public_key",
    "received_at",
    "signature",
}
RECEIPT_ANNOUNCEMENT_FIELDS = {
    "type",
    "version",
    "network_id",
    "bill",
    "receipt",
    "announced_at",
}
TRANSFER_ANNOUNCEMENT_FIELDS = {
    "type",
    "version",
    "network_id",
    "payload_encoding",
    "bill",
    "proof_bundle",
    "archive_segments",
    "announced_at",
}
CHECKPOINT_ANNOUNCEMENT_FIELDS = {
    "type",
    "version",
    "network_id",
    "payload_encoding",
    "checkpoint_core",
    "archive_segments",
    "announced_at",
}
PROOF_BUNDLE_ANNOUNCEMENT_FIELDS = {
    "type",
    "version",
    "network_id",
    "payload_encoding",
    "proof_bundle",
    "announced_at",
}
ARCHIVE_SEGMENT_ANNOUNCEMENT_FIELDS = {
    "type",
    "version",
    "network_id",
    "payload_encoding",
    "archive_segment",
    "announced_at",
}
CONFLICT_PROOF_FIELDS = {
    "type",
    "version",
    "network_id",
    "token_id",
    "previous_hash",
    "sequence",
    "sender_address",
    "spend_key",
    "transfer_hash_a",
    "transfer_hash_b",
    "transfer_a",
    "transfer_b",
    "detected_at",
    "proof_hash",
}
BASE_STATE_FIELDS = {
    "sequence",
    "owner_address",
    "last_transfer_hash",
    "last_transfer_timestamp",
    "last_transfer_day",
    "transfers_in_last_day",
    "display_id",
    "value",
}


# Raised when a BillV3 fails validation.
class ProtocolV3Error(ind_token.ValidationError):
    pass


def _require_exact_fields(data, required, label):
    if not isinstance(data, dict) or set(data) != set(required):
        raise ProtocolV3Error(f"malformed {label}")


def _require_int(value, label, minimum=None):
    if type(value) is not int:
        raise ProtocolV3Error(f"{label} must be an integer")
    if minimum is not None and value < int(minimum):
        raise ProtocolV3Error(f"{label} is below the allowed range")
    return value


def _require_bill_value(value, label):
    try:
        return ind_token.validate_bill_value(value, label)
    except ind_token.ValidationError as exc:
        raise ProtocolV3Error(str(exc)) from exc


def _require_display_serial(value, serial, label):
    try:
        return ind_token.validate_bill_serial(value, serial, label)
    except ind_token.ValidationError as exc:
        raise ProtocolV3Error(str(exc)) from exc


def _display_id_hash(display_id, label="display id"):
    if not isinstance(display_id, str) or display_id != display_id.strip():
        raise ProtocolV3Error(f"invalid {label}")
    try:
        payload = display_id.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ProtocolV3Error(f"invalid {label}") from exc
    return ind_token.sha3_hex(payload)


def _validate_display_id_value(display_id, value, label):
    parsed = parse_display_id(display_id, label)
    if int(parsed["value"]) != int(value):
        raise ProtocolV3Error(f"{label} value prefix does not match bill value")
    return parsed


# Parse a human bill id like "100x42" into canonical value and serial parts.
def parse_display_id(display_id, label="display id"):
    _display_id_hash(display_id, label)
    prefix, separator, suffix = display_id.partition("x")
    if separator != "x" or not prefix or not suffix or "x" in suffix:
        raise ProtocolV3Error(f"{label} must be formatted as valuexserial")
    if not prefix.isdigit() or not suffix.isdigit():
        raise ProtocolV3Error(f"{label} must be formatted as valuexserial")
    if len(prefix) > 1 and prefix.startswith("0"):
        raise ProtocolV3Error(f"{label} value must be canonical")
    if len(suffix) > 1 and suffix.startswith("0"):
        raise ProtocolV3Error(f"{label} serial must be canonical")
    value = _require_bill_value(int(prefix), f"{label} value")
    serial = _require_display_serial(value, int(suffix), f"{label} serial")
    return {"value": value, "serial": serial}


# Format a denomination and issue index into the canonical BillV3 display id.
def canonical_display_id(value, issue_index):
    value = _require_bill_value(value, "display id value")
    issue_index = _require_display_serial(value, issue_index, "display id issue index")
    return f"{value}x{issue_index}"


def _validate_display_id_issue_index(display_id, value, issue_index, label):
    parsed = _validate_display_id_value(display_id, value, label)
    issue_index = _require_display_serial(value, issue_index, f"{label} issue index")
    if int(parsed["serial"]) != issue_index:
        raise ProtocolV3Error(f"{label} serial does not match genesis issue index")
    return parsed


def _validate_checkpoint_genesis_display_id(genesis_ref, checkpoint_core, label):
    value = _require_bill_value(checkpoint_core["value"], f"{label} value")
    return _validate_display_id_issue_index(
        checkpoint_core["display_id"],
        value,
        genesis_ref["issue_index"],
        label,
    )


def _hex32(value, label):
    if not isinstance(value, str) or len(value) != 64:
        raise ProtocolV3Error(f"invalid {label}")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise ProtocolV3Error(f"invalid {label}") from exc
    return value.lower()


def _validate_v3_address(address, label):
    try:
        return keys_v3.validate_address(address, label)
    except ind_token.ValidationError as exc:
        raise ProtocolV3Error(str(exc)) from exc


def _canonical_payload_bytes(data):
    return ind_token.canonical_json(data).encode("utf-8")


def _json_field_bytes(data, label):
    try:
        return _canonical_payload_bytes(data)
    except Exception as exc:
        raise ProtocolV3Error(f"invalid {label}") from exc


def _decode_json_field(raw, label):
    try:
        return ind_token._load_json(raw.decode("utf-8"))
    except Exception as exc:
        raise ProtocolV3Error(f"invalid {label}") from exc


def _encode_envelope(magic, network_id, body):
    return b"".join(
        (
            magic,
            binary_v3.encode_uvarint(VERSION),
            binary_v3.encode_uvarint(network_id),
            body,
        )
    )


def _read_envelope(reader, magic, label):
    actual = reader.read(len(magic), f"{label} magic")
    if actual != magic:
        raise ProtocolV3Error(f"invalid {label} magic")
    version = reader.read_uvarint(f"{label} version")
    if version != VERSION:
        raise ProtocolV3Error(f"unsupported {label} version")
    return reader.read_uvarint(f"{label} network id")


# Decode a complete typed envelope and fail closed on trailing or malformed bytes.
def _decode_envelope(data, magic, label, body_decoder):
    try:
        reader = binary_v3.Reader(data)
        network_id = _read_envelope(reader, magic, label)
        value = body_decoder(reader, network_id)
        reader.require_eof()
        return value
    except binary_v3.BinaryV3Error as exc:
        raise ProtocolV3Error(f"malformed {label}") from exc


def _encode_signature_hex(value, label):
    try:
        raw = bytes.fromhex(value)
    except Exception as exc:
        raise ProtocolV3Error(f"invalid {label}") from exc
    if len(raw) != 64:
        raise ProtocolV3Error(f"invalid {label}")
    return raw


def _decode_signature_hex(reader, label):
    return reader.read_fixed_bytes(64, label).hex()


def _encode_public_key(public_key, label):
    try:
        return keys_v3.decode_public_key(public_key)
    except Exception as exc:
        raise ProtocolV3Error(f"invalid {label}") from exc


def _decode_public_key(reader, label):
    return keys_v3.encode_public_key(reader.read_fixed_bytes(32, label))


# Encode the manifest-derived genesis reference embedded in every BillV3.
def encode_genesis_ref_body(genesis_ref):
    _validate_genesis_ref(genesis_ref, int(genesis_ref.get("network_id")))
    return b"".join(
        (
            binary_v3.encode_hash_hex(genesis_ref["genesis_hash"]),
            binary_v3.encode_hash_hex_nullable(genesis_ref["manifest_hash"]),
            binary_v3.encode_hash_hex_nullable(genesis_ref["issuer_key_id"]),
            binary_v3.encode_uvarint(int(genesis_ref["issue_index"])),
            binary_v3.encode_uvarint(int(genesis_ref["issued_at"])),
        )
    )


# Decode the binary genesis reference body after the envelope has supplied network id.
def decode_genesis_ref_body(reader, network_id):
    return {
        "type": GENESIS_REF_TYPE,
        "version": VERSION,
        "network_id": int(network_id),
        "genesis_hash": reader.read_hash_hex("GenesisRefV3 genesis hash"),
        "manifest_hash": reader.read_nullable_hash_hex("GenesisRefV3 manifest hash"),
        "issuer_key_id": reader.read_nullable_hash_hex("GenesisRefV3 issuer key id"),
        "issue_index": reader.read_uvarint("GenesisRefV3 issue index"),
        "issued_at": reader.read_uvarint("GenesisRefV3 issued_at"),
    }


# Encode a GenesisRefV3 dict in its canonical binary envelope.
def encode_genesis_ref(genesis_ref):
    network_id = _require_int(genesis_ref.get("network_id"), "GenesisRefV3 network id", minimum=0)
    return _encode_envelope(GENESIS_REF_MAGIC, network_id, encode_genesis_ref_body(genesis_ref))


# Decode a GenesisRefV3 canonical binary envelope.
def decode_genesis_ref(data):
    return _decode_envelope(data, GENESIS_REF_MAGIC, "GenesisRefV3", decode_genesis_ref_body)


# Encode the sequence-zero state that later transfers build on.
def encode_base_state_body(state):
    _validate_base_state(state)
    return b"".join(
        (
            binary_v3.encode_uvarint(int(state["sequence"])),
            binary_v3.encode_ascii(state["owner_address"], max_length=128),
            binary_v3.encode_hash_hex(state["last_transfer_hash"]),
            binary_v3.encode_uvarint(int(state["last_transfer_timestamp"])),
            binary_v3.encode_uvarint(int(state["last_transfer_day"])),
            binary_v3.encode_uvarint(int(state["transfers_in_last_day"])),
            binary_v3.encode_ascii(state["display_id"], max_length=64),
            binary_v3.encode_uvarint(int(state["value"])),
        )
    )


# Decode a sequence-zero state body from a BillV3 or checkpoint context.
def decode_base_state_body(reader):
    return {
        "sequence": reader.read_uvarint("V3 base sequence"),
        "owner_address": reader.read_ascii("V3 base owner address", max_length=128),
        "last_transfer_hash": reader.read_hash_hex("V3 base last transfer hash"),
        "last_transfer_timestamp": reader.read_uvarint("V3 base timestamp"),
        "last_transfer_day": reader.read_uvarint("V3 base day"),
        "transfers_in_last_day": reader.read_uvarint("V3 base day count"),
        "display_id": reader.read_ascii("V3 base display id", max_length=64),
        "value": reader.read_uvarint("V3 base value"),
    }


# Encode the compact checkpoint state proven by a transparency proof bundle.
def encode_checkpoint_core_body(core, include_hash=True):
    core_for_validation = copy.deepcopy(core)
    if not include_hash:
        core_for_validation["checkpoint_hash"] = "00" * 32
    _validate_checkpoint_core(core_for_validation, int(core_for_validation.get("network_id")))
    checkpoint_hash = core["checkpoint_hash"] if include_hash else "00" * 32
    return b"".join(
        (
            binary_v3.encode_hash_hex(core["token_id"]),
            binary_v3.encode_hash_hex(core["genesis_hash"]),
            binary_v3.encode_uvarint(int(core["sequence"])),
            binary_v3.encode_ascii(core["owner_address"], max_length=128),
            binary_v3.encode_uvarint(int(core["value"])),
            binary_v3.encode_ascii(core["display_id"], max_length=64),
            binary_v3.encode_hash_hex(core["display_id_hash"]),
            binary_v3.encode_hash_hex(core["last_transfer_hash"]),
            binary_v3.encode_uvarint(int(core["last_transfer_timestamp"])),
            binary_v3.encode_uvarint(int(core["last_transfer_day"])),
            binary_v3.encode_uvarint(int(core["transfers_in_last_day"])),
            binary_v3.encode_hash_hex_nullable(core["previous_checkpoint_hash"]),
            binary_v3.encode_hash_hex(checkpoint_hash),
        )
    )


# Decode a CheckpointCoreV3 body after the envelope has supplied network id.
def decode_checkpoint_core_body(reader, network_id):
    return {
        "type": CHECKPOINT_CORE_TYPE,
        "version": VERSION,
        "network_id": int(network_id),
        "token_id": reader.read_hash_hex("CheckpointCoreV3 token id"),
        "genesis_hash": reader.read_hash_hex("CheckpointCoreV3 genesis hash"),
        "sequence": reader.read_uvarint("CheckpointCoreV3 sequence"),
        "owner_address": reader.read_ascii("CheckpointCoreV3 owner address", max_length=128),
        "value": reader.read_uvarint("CheckpointCoreV3 value"),
        "display_id": reader.read_ascii("CheckpointCoreV3 display id", max_length=64),
        "display_id_hash": reader.read_hash_hex("CheckpointCoreV3 display id hash"),
        "last_transfer_hash": reader.read_hash_hex("CheckpointCoreV3 last transfer hash"),
        "last_transfer_timestamp": reader.read_uvarint("CheckpointCoreV3 timestamp"),
        "last_transfer_day": reader.read_uvarint("CheckpointCoreV3 day"),
        "transfers_in_last_day": reader.read_uvarint("CheckpointCoreV3 day count"),
        "previous_checkpoint_hash": reader.read_nullable_hash_hex(
            "CheckpointCoreV3 previous checkpoint hash"
        ),
        "checkpoint_hash": reader.read_hash_hex("CheckpointCoreV3 checkpoint hash"),
    }


def encode_checkpoint_core(core, include_hash=True):
    network_id = _require_int(core.get("network_id"), "CheckpointCoreV3 network id", minimum=0)
    return _encode_envelope(
        CHECKPOINT_CORE_MAGIC,
        network_id,
        encode_checkpoint_core_body(core, include_hash=include_hash),
    )


def decode_checkpoint_core(data):
    return _decode_envelope(
        data, CHECKPOINT_CORE_MAGIC, "CheckpointCoreV3", decode_checkpoint_core_body
    )


# Encode the signed transfer body, optionally replacing the signature with a placeholder.
def encode_transfer_body(transfer, include_signature=True):
    network_id = _require_int(transfer.get("network_id"), "TransferV3 network id", minimum=0)
    _validate_transfer_shape(transfer, network_id, require_signature=include_signature)
    parts = [
        binary_v3.encode_hash_hex(transfer["token_id"]),
        binary_v3.encode_uvarint(int(transfer["sequence"])),
        binary_v3.encode_hash_hex(transfer["previous_hash"]),
        binary_v3.encode_ascii(transfer["sender_address"], max_length=128),
        _encode_public_key(transfer["sender_public_key"], "TransferV3 sender public key"),
        binary_v3.encode_ascii(transfer["recipient_address"], max_length=128),
        binary_v3.encode_uvarint(int(transfer["timestamp"])),
        binary_v3.encode_bytes(
            _json_field_bytes(transfer["metadata"], "TransferV3 metadata"),
            max_length=ind_token.MAX_TRANSFER_METADATA_BYTES,
        ),
        binary_v3.encode_uvarint(int(transfer["signature_algorithm"])),
    ]
    if include_signature:
        parts.append(_encode_signature_hex(transfer["signature"], "TransferV3 signature"))
    return b"".join(parts)


# Decode one TransferV3 body after the envelope has supplied network id.
def decode_transfer_body(reader, network_id, require_signature=True):
    transfer = {
        "type": TRANSFER_TYPE,
        "version": VERSION,
        "network_id": int(network_id),
        "signature_algorithm": None,
        "token_id": reader.read_hash_hex("TransferV3 token id"),
        "sequence": reader.read_uvarint("TransferV3 sequence"),
        "previous_hash": reader.read_hash_hex("TransferV3 previous hash"),
        "sender_address": reader.read_ascii("TransferV3 sender address", max_length=128),
        "sender_public_key": _decode_public_key(reader, "TransferV3 sender public key"),
        "recipient_address": reader.read_ascii("TransferV3 recipient address", max_length=128),
        "timestamp": reader.read_uvarint("TransferV3 timestamp"),
        "metadata": _decode_json_field(
            reader.read_bytes(
                "TransferV3 metadata", max_length=ind_token.MAX_TRANSFER_METADATA_BYTES
            ),
            "TransferV3 metadata",
        ),
    }
    transfer["signature_algorithm"] = reader.read_uvarint("TransferV3 signature algorithm")
    transfer["signature"] = (
        _decode_signature_hex(reader, "TransferV3 signature") if require_signature else ""
    )
    return transfer


# Encode a TransferV3 dict in a canonical V3 binary envelope.
def encode_transfer(transfer, include_signature=True):
    network_id = _require_int(transfer.get("network_id"), "TransferV3 network id", minimum=0)
    return _encode_envelope(
        TRANSFER_MAGIC,
        network_id,
        encode_transfer_body(transfer, include_signature=include_signature),
    )


# Decode a canonical TransferV3 binary envelope.
def decode_transfer(data):
    return _decode_envelope(data, TRANSFER_MAGIC, "TransferV3", decode_transfer_body)


# Encode a BillV3 dict in a canonical V3 binary envelope.
def encode_bill(bill):
    if not isinstance(bill, dict):
        raise ProtocolV3Error("BillV3 must be a dict")
    network_id = _require_int(bill.get("network_id"), "BillV3 network id", minimum=0)
    _require_exact_fields(bill, BILL_FIELDS, "BillV3")
    if bill["type"] != BILL_TYPE or int(bill["version"]) != VERSION:
        raise ProtocolV3Error("malformed BillV3")
    if not isinstance(bill["recent_transfers"], list):
        raise ProtocolV3Error("BillV3 recent transfers must be a list")
    transfer_parts = [
        binary_v3.encode_uvarint(len(bill["recent_transfers"])),
        *[
            encode_transfer_body(transfer, include_signature=True)
            for transfer in bill["recent_transfers"]
        ],
    ]
    return _encode_envelope(
        BILL_MAGIC,
        network_id,
        b"".join(
            (
                binary_v3.encode_hash_hex(bill["token_id"]),
                binary_v3.encode_uvarint(int(bill["value"])),
                encode_genesis_ref_body(bill["genesis_ref"]),
                encode_checkpoint_core_body(bill["checkpoint_core"]),
                proof_bundle_v3.encode_proof_bundle_ref_body(bill["proof_bundle_ref"]),
                *transfer_parts,
            )
        ),
    )


# Decode a BillV3 binary envelope.
def decode_bill(data):
    def decode_body(reader, network_id):
        bill = {
            "type": BILL_TYPE,
            "version": VERSION,
            "network_id": int(network_id),
            "token_id": reader.read_hash_hex("BillV3 token id"),
            "value": reader.read_uvarint("BillV3 value"),
            "genesis_ref": decode_genesis_ref_body(reader, network_id),
            "checkpoint_core": decode_checkpoint_core_body(reader, network_id),
            "proof_bundle_ref": proof_bundle_v3.decode_proof_bundle_ref_body(reader, network_id),
            "recent_transfers": [],
        }
        count = reader.read_uvarint("BillV3 recent transfer count")
        bill["recent_transfers"] = [
            decode_transfer_body(reader, network_id, require_signature=True)
            for _ in range(count)
        ]
        return bill

    return _decode_envelope(data, BILL_MAGIC, "BillV3", decode_body)


# Hash a complete BillV3 binary envelope.
def bill_hash(bill):
    return binary_v3.object_hash(BILL_TYPE, encode_bill(bill))


# Encode binary V3 data into the text form used by gossip messages.
def encode_wire_payload(blob):
    if not isinstance(blob, (bytes, bytearray)):
        raise ProtocolV3Error("V3 wire payload must be bytes")
    return V3_PAYLOAD_PREFIX + base64.b85encode(bytes(blob)).decode("ascii")


# Decode the text wire payload back into canonical V3 bytes.
def decode_wire_payload(payload):
    if not isinstance(payload, str) or not payload.startswith(V3_PAYLOAD_PREFIX):
        raise ProtocolV3Error("invalid V3 wire payload")
    try:
        return base64.b85decode(payload[len(V3_PAYLOAD_PREFIX) :].encode("ascii"))
    except Exception as exc:
        raise ProtocolV3Error("invalid V3 wire payload") from exc


def _require_v3_payload_envelope(message, required_fields, expected_type, label):
    _require_exact_fields(message, required_fields, label)
    if message["type"] != expected_type:
        raise ProtocolV3Error(f"not a {label}")
    if _require_int(message["version"], f"{label} version") != VERSION:
        raise ProtocolV3Error(f"unsupported {label} version")
    network_id = _require_int(message["network_id"], f"{label} network id", minimum=0)
    if message["payload_encoding"] != V3_PAYLOAD_ENCODING:
        raise ProtocolV3Error(f"unsupported {label} payload encoding")
    _require_int(message["announced_at"], f"{label} announced_at", minimum=0)
    return network_id


def validate_gossip_envelope_shape(message):
    """Reject malformed V3 gossip envelopes before async ingest queues them."""

    def require_payload_string(value, label):
        if not isinstance(value, str):
            raise ProtocolV3Error(f"{label} must be a V3 wire payload")
        return value

    def require_decoded_network_id(decoded, expected_network_id, label):
        if not isinstance(decoded, dict):
            raise ProtocolV3Error(f"{label} payload is malformed")
        payload_network_id = _require_int(
            decoded.get("network_id"), f"{label} network id", minimum=0
        )
        if payload_network_id != int(expected_network_id):
            raise ProtocolV3Error(f"{label} network id mismatch")

    def validate_checkpoint_payload(checkpoint, expected_network_id, label):
        require_decoded_network_id(checkpoint, expected_network_id, label)
        _validate_checkpoint_core(checkpoint, int(expected_network_id))
        if checkpoint["checkpoint_hash"] != checkpoint_core_hash(checkpoint):
            raise ProtocolV3Error(f"{label} hash mismatch")

    def checkpoint_from_archive_segment_payload(segment, expected_network_id):
        require_decoded_network_id(segment, expected_network_id, "ArchiveSegmentV3")
        from . import archive_segment_v3

        try:
            if segment["segment_hash"] != archive_segment_v3.archive_segment_hash_hex(segment):
                raise ProtocolV3Error("ArchiveSegmentV3 hash mismatch")
        except ProtocolV3Error:
            raise
        except Exception as exc:
            raise ProtocolV3Error("malformed ArchiveSegmentV3") from exc
        _validate_genesis_ref(segment["genesis_ref"], int(expected_network_id))
        _validate_display_id_issue_index(
            segment["display_id"],
            segment["value"],
            segment["genesis_ref"]["issue_index"],
            "ArchiveSegmentV3 display id",
        )
        final_state = verify_transfer_sequence_from_state(
            segment["token_id"],
            copy.deepcopy(segment["base_state"]),
            segment["transfers"],
            network_id=expected_network_id,
        )
        if int(final_state["sequence"]) != int(segment["end_sequence"]):
            raise ProtocolV3Error("ArchiveSegmentV3 end sequence mismatch")
        if int(final_state["value"]) != int(segment["value"]):
            raise ProtocolV3Error("ArchiveSegmentV3 value mismatch")
        if str(final_state["display_id"]) != str(segment["display_id"]):
            raise ProtocolV3Error("ArchiveSegmentV3 display id mismatch")
        checkpoint = checkpoint_core_from_state(
            segment["token_id"],
            segment["genesis_ref"]["genesis_hash"],
            final_state,
            previous_checkpoint_hash=segment["previous_checkpoint_hash"],
            network_id=expected_network_id,
        )
        if checkpoint["checkpoint_hash"] != segment["checkpoint_hash"]:
            raise ProtocolV3Error("ArchiveSegmentV3 checkpoint hash mismatch")
        return checkpoint

    def validate_archive_segment_payload(segment, expected_network_id):
        checkpoint_from_archive_segment_payload(segment, expected_network_id)

    def validate_proof_bundle_payload(bundle, expected_network_id):
        require_decoded_network_id(bundle, expected_network_id, "ProofBundleV3")
        try:
            proof_bundle_v3.verify_self_hash(bundle)
            from . import transparency_client as log_client

            log_client.verify_signed_root(bundle["signed_root"])
        except Exception as exc:
            raise ProtocolV3Error(str(exc)) from exc
        source = bundle.get("source_evidence")
        if isinstance(source, dict):
            require_decoded_network_id(source, expected_network_id, "ProofBundleV3 source")
            embedded_segment = source.get("archive_segment")
            if embedded_segment is not None:
                checkpoint = checkpoint_from_archive_segment_payload(
                    embedded_segment, expected_network_id
                )
                if source.get("archive_segment_hash") != embedded_segment.get("segment_hash"):
                    raise ProtocolV3Error("ProofBundleV3 archive segment hash mismatch")
                if source.get("source_checkpoint_hash") != checkpoint["checkpoint_hash"]:
                    raise ProtocolV3Error("ProofBundleV3 source checkpoint hash mismatch")

    def validate_transfer_bill_payload(bill, expected_network_id):
        require_decoded_network_id(bill, expected_network_id, "BillV3")
        _require_exact_fields(bill, BILL_FIELDS, "BillV3")
        if bill["type"] != BILL_TYPE or int(bill["version"]) != VERSION:
            raise ProtocolV3Error("malformed BillV3")
        _validate_genesis_ref(bill["genesis_ref"], int(expected_network_id))
        validate_checkpoint_payload(
            bill["checkpoint_core"], expected_network_id, "CheckpointCoreV3"
        )
        _validate_checkpoint_genesis_display_id(
            bill["genesis_ref"], bill["checkpoint_core"], "CheckpointCoreV3 display id"
        )
        if bill["genesis_ref"]["genesis_hash"] != bill["checkpoint_core"]["genesis_hash"]:
            raise ProtocolV3Error("CheckpointCoreV3 genesis hash mismatch")
        proof_bundle_v3.encode_proof_bundle_ref_body(bill["proof_bundle_ref"])
        if not isinstance(bill["recent_transfers"], list) or not bill["recent_transfers"]:
            raise ProtocolV3Error("TransferAnnouncementV3 requires a recent TransferV3")
        verify_transfer_sequence_from_state(
            bill["token_id"],
            _initial_state_from_checkpoint_core(bill["checkpoint_core"]),
            bill["recent_transfers"],
            network_id=expected_network_id,
        )

    def decode_archive_segment_payload(payload, expected_network_id, label):
        from . import archive_segment_v3

        segment = archive_segment_v3.decode_archive_segment(
            decode_wire_payload(require_payload_string(payload, label))
        )
        require_decoded_network_id(segment, expected_network_id, label)
        validate_archive_segment_payload(segment, expected_network_id)
        return segment

    def decode_proof_bundle_payload(payload, expected_network_id, label):
        bundle = proof_bundle_v3.decode_proof_bundle(
            decode_wire_payload(require_payload_string(payload, label))
        )
        require_decoded_network_id(bundle, expected_network_id, label)
        validate_proof_bundle_payload(bundle, expected_network_id)
        return bundle

    def validate_payloads(expected_network_id):
        message_type = message["type"]
        if message_type == TRANSFER_ANNOUNCEMENT_TYPE:
            bill = decode_bill(decode_wire_payload(require_payload_string(message["bill"], "BillV3")))
            validate_transfer_bill_payload(bill, expected_network_id)
            if message["proof_bundle"] is not None:
                bundle = decode_proof_bundle_payload(
                    message["proof_bundle"], expected_network_id, "ProofBundleV3"
                )
                proof_bundle_v3.verify_proof_bundle_ref(
                    bill["proof_bundle_ref"], bundle, expected_network_id=expected_network_id
                )
            for index, payload in enumerate(message["archive_segments"]):
                decode_archive_segment_payload(
                    payload, expected_network_id, f"ArchiveSegmentV3[{index}]"
                )
        elif message_type == CHECKPOINT_ANNOUNCEMENT_TYPE:
            checkpoint = decode_checkpoint_core(
                decode_wire_payload(
                    require_payload_string(message["checkpoint_core"], "CheckpointCoreV3")
                )
            )
            validate_checkpoint_payload(checkpoint, expected_network_id, "CheckpointCoreV3")
            for index, payload in enumerate(message["archive_segments"]):
                segment = decode_archive_segment_payload(
                    payload, expected_network_id, f"ArchiveSegmentV3[{index}]"
                )
                if index == 0:
                    derived = checkpoint_from_archive_segment_payload(segment, expected_network_id)
                    for field in CHECKPOINT_CORE_FIELDS:
                        if checkpoint[field] != derived[field]:
                            raise ProtocolV3Error(
                                f"CheckpointCoreV3 does not match archive segment: {field}"
                            )
        elif message_type == PROOF_BUNDLE_ANNOUNCEMENT_TYPE:
            decode_proof_bundle_payload(
                message["proof_bundle"], expected_network_id, "ProofBundleV3"
            )
        elif message_type == ARCHIVE_SEGMENT_ANNOUNCEMENT_TYPE:
            decode_archive_segment_payload(
                message["archive_segment"], expected_network_id, "ArchiveSegmentV3"
            )

    envelope_specs = {
        TRANSFER_ANNOUNCEMENT_TYPE: (
            TRANSFER_ANNOUNCEMENT_FIELDS,
            TRANSFER_ANNOUNCEMENT_TYPE,
            "TransferAnnouncementV3",
        ),
        CHECKPOINT_ANNOUNCEMENT_TYPE: (
            CHECKPOINT_ANNOUNCEMENT_FIELDS,
            CHECKPOINT_ANNOUNCEMENT_TYPE,
            "CheckpointAnnouncementV3",
        ),
        PROOF_BUNDLE_ANNOUNCEMENT_TYPE: (
            PROOF_BUNDLE_ANNOUNCEMENT_FIELDS,
            PROOF_BUNDLE_ANNOUNCEMENT_TYPE,
            "ProofBundleAnnouncementV3",
        ),
        ARCHIVE_SEGMENT_ANNOUNCEMENT_TYPE: (
            ARCHIVE_SEGMENT_ANNOUNCEMENT_FIELDS,
            ARCHIVE_SEGMENT_ANNOUNCEMENT_TYPE,
            "ArchiveSegmentAnnouncementV3",
        ),
    }
    spec = envelope_specs.get(message.get("type") if isinstance(message, dict) else None)
    message_type = message.get("type") if isinstance(message, dict) else None
    if message_type == CONFLICT_PROOF_TYPE:
        _require_exact_fields(message, CONFLICT_PROOF_FIELDS, "ConflictProofV3")
        if _require_int(message["version"], "ConflictProofV3 version") != VERSION:
            raise ProtocolV3Error("unsupported ConflictProofV3 version")
        network_id = _require_int(message["network_id"], "ConflictProofV3 network id", minimum=0)
        _require_int(message["sequence"], "ConflictProofV3 sequence", minimum=1)
        _require_int(message["detected_at"], "ConflictProofV3 detected_at", minimum=0)
        verify_conflict_proof(message, expected_network_id=network_id)
        return True
    if spec is None:
        if isinstance(message_type, str) and message_type.startswith("ind.") and message_type.endswith(
            ".v3"
        ):
            raise ProtocolV3Error("unsupported V3 gossip message type")
        return False
    network_id = _require_v3_payload_envelope(message, *spec)
    if message["type"] in {TRANSFER_ANNOUNCEMENT_TYPE, CHECKPOINT_ANNOUNCEMENT_TYPE}:
        label = spec[2]
        if not isinstance(message["archive_segments"], list):
            raise ProtocolV3Error(f"{label} archive segments must be a list")
    validate_payloads(network_id)
    return True


# Hash a TransferV3 envelope for chain links and transparency leaves.
def transfer_hash(transfer):
    return binary_v3.object_hash(TRANSFER_TYPE, encode_transfer(transfer)).hex()


# Derive the transparency spend-map key from the transfer's spent state.
def spend_key_for_transfer(transfer):
    key_material = {
        "token_id": transfer["token_id"],
        "previous_hash": transfer["previous_hash"],
        "sequence": int(transfer["sequence"]),
        "sender_address": transfer["sender_address"],
    }
    return ind_token.sha3_hex(ind_token._canonical_bytes(key_material))


# Build the spend-map claim that the transparency log records for a transfer.
def spend_claim_for_transfer(transfer, log_id, transfer_leaf_index, accepted_at):
    return {
        "type": "ind.transparency_spend_claim.v3",
        "version": VERSION,
        "log_id": str(log_id),
        "spend_key": spend_key_for_transfer(transfer),
        "token_id": transfer["token_id"],
        "previous_hash": transfer["previous_hash"],
        "sequence": int(transfer["sequence"]),
        "sender_address": transfer["sender_address"],
        "sender_public_key": transfer["sender_public_key"],
        "transfer_hash": transfer_hash(transfer),
        "transfer_leaf_index": int(transfer_leaf_index),
        "accepted_at": int(accepted_at),
        "transfer": copy.deepcopy(transfer),
    }


def _transfer_signing_preimage(transfer):
    return binary_v3.signing_preimage(
        transfer["network_id"],
        TRANSFER_TYPE,
        VERSION,
        binary_v3.SIGNATURE_ALGORITHM_ID,
        TRANSFER_TYPE,
        encode_transfer(transfer, include_signature=False),
    )


# Validate transfer shape, timing, addresses, metadata, and chain-link fields.
def _validate_transfer_shape(transfer, network_id, require_signature=True, now=None):
    _require_exact_fields(transfer, TRANSFER_FIELDS, "TransferV3")
    if transfer["type"] != TRANSFER_TYPE:
        raise ProtocolV3Error("malformed TransferV3")
    if _require_int(transfer["version"], "TransferV3 version") != VERSION:
        raise ProtocolV3Error("unsupported TransferV3 version")
    if _require_int(transfer["network_id"], "TransferV3 network id", minimum=0) != network_id:
        raise ProtocolV3Error("TransferV3 network id mismatch")
    if (
        _require_int(transfer["signature_algorithm"], "TransferV3 signature algorithm")
        != binary_v3.SIGNATURE_ALGORITHM_ID
    ):
        raise ProtocolV3Error("unsupported TransferV3 signature algorithm")
    _hex32(transfer["token_id"], "TransferV3 token id")
    _require_int(transfer["sequence"], "TransferV3 sequence", minimum=1)
    _hex32(transfer["previous_hash"], "TransferV3 previous hash")
    keys_v3.validate_address(transfer["sender_address"], "TransferV3 sender address")
    keys_v3.validate_address(transfer["recipient_address"], "TransferV3 recipient address")
    keys_v3.decode_public_key(transfer["sender_public_key"])
    transfer_timestamp = _require_int(transfer["timestamp"], "TransferV3 timestamp", minimum=0)
    if (
        transfer_timestamp
        > ind_token.current_time(now) + ind_token.MAX_TRANSFER_FUTURE_SKEW_SECONDS
    ):
        raise ProtocolV3Error("TransferV3 timestamp is too far in the future")
    ind_token._require_metadata(
        transfer["metadata"],
        ind_token.MAX_TRANSFER_METADATA_BYTES,
        "TransferV3",
    )
    if require_signature:
        try:
            signature = bytes.fromhex(transfer["signature"])
        except Exception as exc:
            raise ProtocolV3Error("invalid TransferV3 signature") from exc
        if len(signature) != 64:
            raise ProtocolV3Error("invalid TransferV3 signature")


# Verify a TransferV3 signature against its sender key and signing preimage.
def verify_transfer_signature(transfer):
    if not keys_v3.public_key_matches_address(
        transfer["sender_public_key"], transfer["sender_address"]
    ):
        raise ProtocolV3Error("TransferV3 sender key does not match sender address")
    signature = bytes.fromhex(transfer["signature"])
    if not keys_v3.verify(
        transfer["sender_public_key"], signature, _transfer_signing_preimage(transfer)
    ):
        raise ProtocolV3Error("invalid TransferV3 signature")
    return True


def _initial_state_from_checkpoint_core(core):
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


def _validate_base_state(state):
    _require_exact_fields(state, BASE_STATE_FIELDS, "V3 base state")
    _require_int(state["sequence"], "V3 base sequence", minimum=0)
    _validate_v3_address(state["owner_address"], "V3 base owner address")
    _hex32(state["last_transfer_hash"], "V3 base last transfer hash")
    _require_int(state["last_transfer_timestamp"], "V3 base timestamp", minimum=0)
    _require_int(state["last_transfer_day"], "V3 base day", minimum=0)
    _require_int(state["transfers_in_last_day"], "V3 base day count", minimum=0)
    value = _require_bill_value(state["value"], "V3 base value")
    _validate_display_id_value(state["display_id"], value, "V3 base display id")
    return state


# Verify TransferV3 objects extending an already-proven state.
def verify_transfer_sequence_from_state(
    token_id,
    state,
    transfers,
    network_id=DEFAULT_NETWORK_ID,
    now=None,
):
    if not isinstance(transfers, list):
        raise ProtocolV3Error("TransferV3 sequence must be a list")
    state = copy.deepcopy(_validate_base_state(state))
    max_allowed_timestamp = ind_token.current_time(now) + ind_token.MAX_TRANSFER_FUTURE_SKEW_SECONDS
    for transfer in transfers:
        _validate_transfer_shape(transfer, int(network_id), now=now)
        if transfer["token_id"] != token_id:
            raise ProtocolV3Error("TransferV3 references a different bill")
        expected_sequence = int(state["sequence"]) + 1
        if int(transfer["sequence"]) != expected_sequence:
            raise ProtocolV3Error("TransferV3 sequence gap")
        if transfer["previous_hash"] != state["last_transfer_hash"]:
            raise ProtocolV3Error("TransferV3 does not extend the current tip")
        if transfer["sender_address"] != state["owner_address"]:
            raise ProtocolV3Error("TransferV3 sender is not the current owner")
        transfer_timestamp = _require_int(transfer["timestamp"], "TransferV3 timestamp", minimum=0)
        if transfer_timestamp <= int(state["last_transfer_timestamp"]):
            raise ProtocolV3Error("TransferV3 timestamps must be strictly increasing")
        if transfer_timestamp > max_allowed_timestamp:
            raise ProtocolV3Error("TransferV3 timestamp is too far in the future")
        transfer_day = transfer_timestamp // 86400
        if transfer_day == int(state["last_transfer_day"]):
            day_count = int(state["transfers_in_last_day"]) + 1
        else:
            day_count = 1
        if day_count > ind_token.MAX_TRANSFERS_PER_BILL_PER_DAY:
            raise ProtocolV3Error("BillV3 exceeds daily transfer limit")
        verify_transfer_signature(transfer)
        state.update(
            {
                "sequence": expected_sequence,
                "owner_address": transfer["recipient_address"],
                "last_transfer_hash": transfer_hash(transfer),
                "last_transfer_timestamp": transfer_timestamp,
                "last_transfer_day": transfer_day,
                "transfers_in_last_day": day_count,
            }
        )
    return state


# Create one signed TransferV3 extending a proven state.
def create_transfer_from_state(
    token_id,
    state,
    sender_private_key,
    sender_public_key,
    recipient_address,
    metadata=None,
    timestamp=None,
    network_id=DEFAULT_NETWORK_ID,
):
    state = copy.deepcopy(_validate_base_state(state))
    sender_address = keys_v3.address_from_public_key(sender_public_key)
    if sender_address != state["owner_address"]:
        raise ProtocolV3Error("TransferV3 sender key is not the current owner")
    transfer_timestamp = int(timestamp if timestamp is not None else ind_token.current_time(None))
    transfer_timestamp = max(transfer_timestamp, int(state["last_transfer_timestamp"]) + 1)
    transfer_unsigned = {
        "type": TRANSFER_TYPE,
        "version": VERSION,
        "network_id": int(network_id),
        "signature_algorithm": binary_v3.SIGNATURE_ALGORITHM_ID,
        "token_id": token_id,
        "sequence": int(state["sequence"]) + 1,
        "previous_hash": state["last_transfer_hash"],
        "sender_address": sender_address,
        "sender_public_key": sender_public_key,
        "recipient_address": keys_v3.validate_address(
            recipient_address, "TransferV3 recipient address"
        ),
        "timestamp": transfer_timestamp,
        "metadata": metadata or {},
        "signature": "",
    }
    _validate_transfer_shape(transfer_unsigned, int(network_id), require_signature=False)
    signature = keys_v3.sign(sender_private_key, _transfer_signing_preimage(transfer_unsigned))
    transfer_signed = copy.deepcopy(transfer_unsigned)
    transfer_signed["signature"] = signature.hex()
    verify_transfer_signature(transfer_signed)
    return transfer_signed


# Hash a CheckpointCoreV3 with its self-hash field cleared.
def checkpoint_core_hash(core):
    return binary_v3.object_hash(
        CHECKPOINT_CORE_TYPE,
        encode_checkpoint_core(core, include_hash=False),
    ).hex()


# Return a copy with the CheckpointCoreV3 self-hash filled in.
def finalize_checkpoint_core(core):
    result = copy.deepcopy(core)
    result["checkpoint_hash"] = checkpoint_core_hash(result)
    return result


# Build a CheckpointCoreV3 from the current native V3 state.
def checkpoint_core_from_state(
    token_id,
    genesis_hash,
    state,
    previous_checkpoint_hash=None,
    network_id=DEFAULT_NETWORK_ID,
):
    state = copy.deepcopy(_validate_base_state(state))
    core = {
        "type": CHECKPOINT_CORE_TYPE,
        "version": VERSION,
        "network_id": int(network_id),
        "token_id": token_id,
        "genesis_hash": _hex32(genesis_hash, "CheckpointCoreV3 genesis hash"),
        "sequence": int(state["sequence"]),
        "owner_address": state["owner_address"],
        "value": int(state["value"]),
        "display_id": str(state["display_id"]),
        "display_id_hash": _display_id_hash(str(state["display_id"]), "CheckpointCoreV3 display id"),
        "last_transfer_hash": state["last_transfer_hash"],
        "last_transfer_timestamp": int(state["last_transfer_timestamp"]),
        "last_transfer_day": int(state["last_transfer_day"]),
        "transfers_in_last_day": int(state["transfers_in_last_day"]),
        "previous_checkpoint_hash": previous_checkpoint_hash,
        "checkpoint_hash": "",
    }
    return finalize_checkpoint_core(core)


# Create a native thin BillV3 from a proven CheckpointCoreV3.
def create_bill_from_checkpoint_core(
    genesis_ref,
    checkpoint_core,
    proof_bundle,
    recent_transfers=None,
    network_id=DEFAULT_NETWORK_ID,
    transparency_verifier=None,
    trusted_operator_public_key=None,
    archive_segment_resolver=None,
    proof_bundle_resolver=None,
):
    _validate_genesis_ref(genesis_ref, int(network_id))
    _validate_checkpoint_core(checkpoint_core, int(network_id))
    _validate_checkpoint_genesis_display_id(
        genesis_ref,
        checkpoint_core,
        "CheckpointCoreV3 display id",
    )
    if genesis_ref["genesis_hash"] != checkpoint_core["genesis_hash"]:
        raise ProtocolV3Error("CheckpointCoreV3 genesis hash mismatch")
    proven = proof_bundle_v3.verify_proof_bundle(
        proof_bundle,
        expected_checkpoint_hash=checkpoint_core["checkpoint_hash"],
        expected_network_id=network_id,
        transparency_verifier=transparency_verifier,
        trusted_operator_public_key=trusted_operator_public_key,
        archive_segment_resolver=archive_segment_resolver,
        proof_bundle_resolver=proof_bundle_resolver,
    )
    _checkpoint_matches_core(proven, checkpoint_core)
    return {
        "type": BILL_TYPE,
        "version": VERSION,
        "network_id": int(network_id),
        "token_id": checkpoint_core["token_id"],
        "value": int(checkpoint_core["value"]),
        "genesis_ref": copy.deepcopy(genesis_ref),
        "checkpoint_core": copy.deepcopy(checkpoint_core),
        "proof_bundle_ref": proof_bundle_v3.proof_bundle_ref(proof_bundle),
        "recent_transfers": copy.deepcopy(recent_transfers or []),
    }


def _trusted_genesis_manifest_hashes():
    try:
        from . import settings as ind_settings

        values = ind_settings.trusted_genesis_manifest_hashes()
    except Exception:
        raw = os.environ.get("IND_TRUSTED_GENESIS_MANIFEST_HASHES", "")
        values = {item.strip() for item in raw.split(",") if item.strip()}
    return {str(item).strip().lower() for item in values if str(item).strip()}


# Return whether this node is allowed to accept genesis refs without trust pins.
def _allow_untrusted_genesis():
    try:
        from . import settings as ind_settings

        return ind_settings.allow_untrusted_genesis()
    except Exception:
        return os.environ.get("IND_ALLOW_UNTRUSTED_GENESIS", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }


# Enforce local trust policy for the manifest hash carried by a GenesisRefV3.
def _validate_genesis_ref_trust(genesis_ref):
    if _allow_untrusted_genesis():
        return
    trusted_hashes = _trusted_genesis_manifest_hashes()
    if not trusted_hashes:
        return
    manifest_hash = genesis_ref.get("manifest_hash")
    if manifest_hash is None:
        raise ProtocolV3Error("GenesisRefV3 manifest hash is not trusted by this node")
    if str(manifest_hash).lower() not in trusted_hashes:
        raise ProtocolV3Error("GenesisRefV3 manifest hash is not trusted by this node")


# Validate a genesis reference before it is accepted into a BillV3 state path.
def _validate_genesis_ref(genesis_ref, network_id):
    _require_exact_fields(genesis_ref, GENESIS_REF_FIELDS, "GenesisRefV3")
    if genesis_ref["type"] != GENESIS_REF_TYPE:
        raise ProtocolV3Error("malformed GenesisRefV3")
    if _require_int(genesis_ref["version"], "GenesisRefV3 version") != VERSION:
        raise ProtocolV3Error("unsupported GenesisRefV3 version")
    if _require_int(genesis_ref["network_id"], "GenesisRefV3 network id", minimum=0) != network_id:
        raise ProtocolV3Error("GenesisRefV3 network id mismatch")
    _hex32(genesis_ref["genesis_hash"], "GenesisRefV3 genesis hash")
    if genesis_ref["manifest_hash"] is not None:
        _hex32(genesis_ref["manifest_hash"], "GenesisRefV3 manifest hash")
    if genesis_ref["issuer_key_id"] is not None:
        _hex32(genesis_ref["issuer_key_id"], "GenesisRefV3 issuer key id")
    _require_int(genesis_ref["issue_index"], "GenesisRefV3 issue index", minimum=1)
    _require_int(genesis_ref["issued_at"], "GenesisRefV3 issued_at", minimum=0)
    _validate_genesis_ref_trust(genesis_ref)


# Validate the checkpoint core that anchors a thin BillV3.
def _validate_checkpoint_core(core, network_id):
    _require_exact_fields(core, CHECKPOINT_CORE_FIELDS, "CheckpointCoreV3")
    if core["type"] != CHECKPOINT_CORE_TYPE:
        raise ProtocolV3Error("malformed CheckpointCoreV3")
    if _require_int(core["version"], "CheckpointCoreV3 version") != VERSION:
        raise ProtocolV3Error("unsupported CheckpointCoreV3 version")
    if _require_int(core["network_id"], "CheckpointCoreV3 network id", minimum=0) != network_id:
        raise ProtocolV3Error("CheckpointCoreV3 network id mismatch")
    if not isinstance(core["token_id"], str) or not core["token_id"]:
        raise ProtocolV3Error("invalid CheckpointCoreV3 token id")
    _hex32(core["genesis_hash"], "CheckpointCoreV3 genesis hash")
    _require_int(core["sequence"], "CheckpointCoreV3 sequence", minimum=1)
    _validate_v3_address(core["owner_address"], "CheckpointCoreV3 owner address")
    value = _require_bill_value(core["value"], "CheckpointCoreV3 value")
    _validate_display_id_value(core["display_id"], value, "CheckpointCoreV3 display id")
    if core["display_id_hash"] != _display_id_hash(
        core["display_id"], "CheckpointCoreV3 display id"
    ):
        raise ProtocolV3Error("CheckpointCoreV3 display id hash mismatch")
    _hex32(core["last_transfer_hash"], "CheckpointCoreV3 last transfer hash")
    _require_int(core["last_transfer_timestamp"], "CheckpointCoreV3 timestamp", minimum=0)
    _require_int(core["last_transfer_day"], "CheckpointCoreV3 day", minimum=0)
    _require_int(core["transfers_in_last_day"], "CheckpointCoreV3 day count", minimum=1)
    if core["previous_checkpoint_hash"] is not None:
        _hex32(core["previous_checkpoint_hash"], "CheckpointCoreV3 previous checkpoint hash")
    _hex32(core["checkpoint_hash"], "CheckpointCoreV3 checkpoint hash")


# Validate that a BillV3 display id matches its value and genesis issue index.
def validate_bill_display_id(bill):
    if isinstance(bill, bytes):
        bill = decode_bill(bill)
    _require_exact_fields(bill, BILL_FIELDS, "BillV3")
    network_id = _require_int(bill["network_id"], "BillV3 network id", minimum=0)
    _validate_genesis_ref(bill["genesis_ref"], network_id)
    _validate_checkpoint_core(bill["checkpoint_core"], network_id)
    bill_value = _require_bill_value(bill["value"], "BillV3 value")
    if bill_value != int(bill["checkpoint_core"]["value"]):
        raise ProtocolV3Error("BillV3 value mismatch")
    return _validate_display_id_issue_index(
        bill["checkpoint_core"]["display_id"],
        bill_value,
        bill["genesis_ref"]["issue_index"],
        "BillV3 display id",
    )


def _checkpoint_matches_core(checkpoint, core):
    expected = checkpoint
    if not isinstance(expected, dict) or expected.get("type") != CHECKPOINT_CORE_TYPE:
        raise ProtocolV3Error("ProofBundleV3 did not prove a CheckpointCoreV3")
    for field in CHECKPOINT_CORE_FIELDS - {"type", "version", "network_id"}:
        if core[field] != expected[field]:
            raise ProtocolV3Error(f"CheckpointCoreV3 does not match proof bundle: {field}")


# Verify proof-bundle anchoring and replay recent transfers to get current state.
def _verify_bill_state(
    bill,
    proof_bundle=None,
    proof_bundle_resolver=None,
    expected_network_id=DEFAULT_NETWORK_ID,
    transparency_verifier=None,
    trusted_operator_public_key=None,
    archive_segment_resolver=None,
    now=None,
):
    if isinstance(bill, bytes):
        bill = decode_bill(bill)
    _require_exact_fields(bill, BILL_FIELDS, "BillV3")
    if bill["type"] != BILL_TYPE:
        raise ProtocolV3Error("malformed BillV3")
    if _require_int(bill["version"], "BillV3 version") != VERSION:
        raise ProtocolV3Error("unsupported BillV3 version")
    network_id = _require_int(bill["network_id"], "BillV3 network id", minimum=0)
    if expected_network_id is not None and network_id != int(expected_network_id):
        raise ProtocolV3Error("BillV3 network id mismatch")
    _validate_genesis_ref(bill["genesis_ref"], network_id)
    _validate_checkpoint_core(bill["checkpoint_core"], network_id)
    bill_value = _require_bill_value(bill["value"], "BillV3 value")
    if bill_value != int(bill["checkpoint_core"]["value"]):
        raise ProtocolV3Error("BillV3 value mismatch")
    _validate_display_id_issue_index(
        bill["checkpoint_core"]["display_id"],
        bill_value,
        bill["genesis_ref"]["issue_index"],
        "BillV3 display id",
    )
    if not isinstance(bill["recent_transfers"], list):
        raise ProtocolV3Error("BillV3 recent transfers must be a list")
    if proof_bundle is None and proof_bundle_resolver is not None:
        proof_bundle = proof_bundle_resolver(bill["proof_bundle_ref"]["proof_bundle_hash"])
    if proof_bundle is None:
        raise ProtocolV3Error("BillV3 proof bundle is required")
    proof_bundle_v3.verify_proof_bundle_ref(
        bill["proof_bundle_ref"],
        proof_bundle,
        expected_network_id=network_id,
    )
    checkpoint = proof_bundle_v3.verify_proof_bundle(
        proof_bundle,
        expected_checkpoint_hash=bill["checkpoint_core"]["checkpoint_hash"],
        expected_network_id=network_id,
        transparency_verifier=transparency_verifier,
        trusted_operator_public_key=trusted_operator_public_key,
        archive_segment_resolver=archive_segment_resolver,
        proof_bundle_resolver=proof_bundle_resolver,
    )
    _checkpoint_matches_core(checkpoint, bill["checkpoint_core"])
    if bill["token_id"] != checkpoint["token_id"]:
        raise ProtocolV3Error("BillV3 token id mismatch")
    if bill["genesis_ref"]["genesis_hash"] != checkpoint["genesis_hash"]:
        raise ProtocolV3Error("BillV3 genesis hash mismatch")
    return verify_transfer_sequence_from_state(
        bill["token_id"],
        _initial_state_from_checkpoint_core(bill["checkpoint_core"]),
        bill["recent_transfers"],
        network_id=network_id,
        now=now,
    )


# Verify a thin BillV3 and return the proven token state.
def verify_bill(
    bill,
    proof_bundle=None,
    proof_bundle_resolver=None,
    expected_network_id=DEFAULT_NETWORK_ID,
    transparency_verifier=None,
    trusted_operator_public_key=None,
    archive_segment_resolver=None,
    now=None,
):
    bill_obj = decode_bill(bill) if isinstance(bill, bytes) else bill
    state = _verify_bill_state(
        bill_obj,
        proof_bundle=proof_bundle,
        proof_bundle_resolver=proof_bundle_resolver,
        expected_network_id=expected_network_id,
        transparency_verifier=transparency_verifier,
        trusted_operator_public_key=trusted_operator_public_key,
        archive_segment_resolver=archive_segment_resolver,
        now=now,
    )
    return _token_state_from_v3_state(bill_obj["token_id"], state)


# Convert the native V3 state dict into the shared wallet/store TokenState object.
def _token_state_from_v3_state(token_id, state):
    return ind_token.TokenState(
        token_id=token_id,
        owner_address=state["owner_address"],
        last_transfer_hash=state["last_transfer_hash"],
        sequence=int(state["sequence"]),
        display_id=state["display_id"],
        value=int(state["value"]),
    )


# Append one signed native TransferV3 to a BillV3 recent-transfer list.
def create_transfer(
    bill,
    sender_private_key,
    sender_public_key,
    recipient_address,
    proof_bundle=None,
    proof_bundle_resolver=None,
    metadata=None,
    timestamp=None,
    expected_network_id=DEFAULT_NETWORK_ID,
    transparency_verifier=None,
    trusted_operator_public_key=None,
    archive_segment_resolver=None,
):
    if isinstance(bill, bytes):
        bill = decode_bill(bill)
    state = _verify_bill_state(
        bill,
        proof_bundle=proof_bundle,
        proof_bundle_resolver=proof_bundle_resolver,
        expected_network_id=expected_network_id,
        transparency_verifier=transparency_verifier,
        trusted_operator_public_key=trusted_operator_public_key,
        archive_segment_resolver=archive_segment_resolver,
    )
    transfer = create_transfer_from_state(
        bill["token_id"],
        state,
        sender_private_key,
        sender_public_key,
        recipient_address,
        metadata=metadata,
        timestamp=timestamp,
        network_id=bill["network_id"],
    )
    new_bill = copy.deepcopy(bill)
    new_bill["recent_transfers"] = [*new_bill["recent_transfers"], transfer]
    _verify_bill_state(
        new_bill,
        proof_bundle=proof_bundle,
        proof_bundle_resolver=proof_bundle_resolver,
        expected_network_id=expected_network_id,
        transparency_verifier=transparency_verifier,
        trusted_operator_public_key=trusted_operator_public_key,
        archive_segment_resolver=archive_segment_resolver,
    )
    return new_bill


# Build an embedded resolver for archive segments bundled beside a gossip message.
def _embedded_archive_resolver(archive_segments, fallback=None):
    segments = {}
    if archive_segments:
        from . import archive_segment_v3

        for segment in archive_segments:
            segments[archive_segment_v3.archive_segment_hash_hex(segment)] = segment

    def resolver(segment_hash):
        segment_hash = str(segment_hash).lower()
        if segment_hash in segments:
            return segments[segment_hash]
        if fallback is not None:
            return fallback(segment_hash)
        return None

    return resolver


# Wrap a BillV3 transfer tip in a binary V3 gossip envelope.
def create_transfer_announcement(
    bill,
    proof_bundle=None,
    archive_segments=None,
    now=None,
):
    bill_obj = decode_bill(bill) if isinstance(bill, bytes) else bill
    if not isinstance(bill_obj.get("recent_transfers"), list) or not bill_obj["recent_transfers"]:
        raise ProtocolV3Error("TransferAnnouncementV3 requires a recent TransferV3")
    network_id = _require_int(bill_obj["network_id"], "BillV3 network id", minimum=0)
    proof_payload = (
        encode_wire_payload(proof_bundle_v3.encode_proof_bundle(proof_bundle))
        if proof_bundle is not None
        else None
    )
    archive_payloads = []
    if archive_segments:
        from . import archive_segment_v3

        archive_payloads = [
            encode_wire_payload(archive_segment_v3.encode_archive_segment(segment))
            for segment in archive_segments
        ]
    return {
        "type": TRANSFER_ANNOUNCEMENT_TYPE,
        "version": VERSION,
        "network_id": int(network_id),
        "payload_encoding": V3_PAYLOAD_ENCODING,
        "bill": encode_wire_payload(encode_bill(bill_obj)),
        "proof_bundle": proof_payload,
        "archive_segments": archive_payloads,
        "announced_at": ind_token.current_time(now),
    }


# Decode a TransferAnnouncementV3 and its embedded binary evidence.
def decode_transfer_announcement(message):
    _require_v3_payload_envelope(
        message,
        TRANSFER_ANNOUNCEMENT_FIELDS,
        TRANSFER_ANNOUNCEMENT_TYPE,
        "TransferAnnouncementV3",
    )
    bill = decode_bill(decode_wire_payload(message["bill"]))
    proof_bundle = (
        proof_bundle_v3.decode_proof_bundle(decode_wire_payload(message["proof_bundle"]))
        if message["proof_bundle"] is not None
        else None
    )
    if not isinstance(message["archive_segments"], list):
        raise ProtocolV3Error("TransferAnnouncementV3 archive segments must be a list")
    archive_segments = []
    if message["archive_segments"]:
        from . import archive_segment_v3

        archive_segments = [
            archive_segment_v3.decode_archive_segment(decode_wire_payload(payload))
            for payload in message["archive_segments"]
        ]
    return bill, proof_bundle, archive_segments


# Verify a TransferAnnouncementV3 and return its decoded bill/evidence.
def verify_transfer_announcement(
    message,
    proof_bundle_resolver=None,
    expected_network_id=DEFAULT_NETWORK_ID,
    transparency_verifier=None,
    trusted_operator_public_key=None,
    archive_segment_resolver=None,
    now=None,
):
    network_id = _require_v3_payload_envelope(
        message,
        TRANSFER_ANNOUNCEMENT_FIELDS,
        TRANSFER_ANNOUNCEMENT_TYPE,
        "TransferAnnouncementV3",
    )
    if expected_network_id is not None and network_id != int(expected_network_id):
        raise ProtocolV3Error("TransferAnnouncementV3 network id mismatch")
    bill, embedded_bundle, archive_segments = decode_transfer_announcement(message)
    archive_resolver = _embedded_archive_resolver(
        archive_segments, fallback=archive_segment_resolver
    )
    state = verify_bill(
        bill,
        proof_bundle=embedded_bundle,
        proof_bundle_resolver=proof_bundle_resolver,
        expected_network_id=network_id,
        transparency_verifier=transparency_verifier,
        trusted_operator_public_key=trusted_operator_public_key,
        archive_segment_resolver=archive_resolver,
        now=now,
    )
    if not bill["recent_transfers"]:
        raise ProtocolV3Error("TransferAnnouncementV3 requires a recent TransferV3")
    return {
        "bill": bill,
        "proof_bundle": embedded_bundle,
        "archive_segments": archive_segments,
        "state": state,
    }


def create_checkpoint_announcement(checkpoint_core, archive_segments, now=None):
    from . import archive_segment_v3

    if not isinstance(archive_segments, list) or not archive_segments:
        raise ProtocolV3Error("CheckpointAnnouncementV3 requires archive segments")
    network_id = _require_int(
        checkpoint_core.get("network_id"), "CheckpointAnnouncementV3 network id", minimum=0
    )
    _validate_checkpoint_core(checkpoint_core, network_id)
    segment_payloads = [
        encode_wire_payload(archive_segment_v3.encode_archive_segment(segment))
        for segment in archive_segments
    ]
    return {
        "type": CHECKPOINT_ANNOUNCEMENT_TYPE,
        "version": VERSION,
        "network_id": int(network_id),
        "payload_encoding": V3_PAYLOAD_ENCODING,
        "checkpoint_core": encode_wire_payload(encode_checkpoint_core(checkpoint_core)),
        "archive_segments": segment_payloads,
        "announced_at": ind_token.current_time(now),
    }


def decode_checkpoint_announcement(message):
    from . import archive_segment_v3

    _require_v3_payload_envelope(
        message,
        CHECKPOINT_ANNOUNCEMENT_FIELDS,
        CHECKPOINT_ANNOUNCEMENT_TYPE,
        "CheckpointAnnouncementV3",
    )
    checkpoint_core = decode_checkpoint_core(decode_wire_payload(message["checkpoint_core"]))
    if not isinstance(message["archive_segments"], list) or not message["archive_segments"]:
        raise ProtocolV3Error("CheckpointAnnouncementV3 requires archive segments")
    archive_segments = [
        archive_segment_v3.decode_archive_segment(decode_wire_payload(payload))
        for payload in message["archive_segments"]
    ]
    return checkpoint_core, archive_segments


def verify_checkpoint_announcement(
    message,
    expected_network_id=DEFAULT_NETWORK_ID,
    previous_segment_resolver=None,
    previous_checkpoint_resolver=None,
):
    from . import archive_segment_v3

    network_id = _require_v3_payload_envelope(
        message,
        CHECKPOINT_ANNOUNCEMENT_FIELDS,
        CHECKPOINT_ANNOUNCEMENT_TYPE,
        "CheckpointAnnouncementV3",
    )
    if expected_network_id is not None and network_id != int(expected_network_id):
        raise ProtocolV3Error("CheckpointAnnouncementV3 network id mismatch")
    checkpoint_core, archive_segments = decode_checkpoint_announcement(message)
    segments_by_hash = {
        archive_segment_v3.archive_segment_hash_hex(segment): segment
        for segment in archive_segments
    }

    def resolver(segment_hash):
        segment_hash = str(segment_hash).lower()
        if segment_hash in segments_by_hash:
            return segments_by_hash[segment_hash]
        if previous_segment_resolver is not None:
            return previous_segment_resolver(segment_hash)
        return None

    derived = archive_segment_v3.verify_archive_segment(
        archive_segments[0],
        expected_network_id=network_id,
        previous_segment_resolver=resolver,
        previous_checkpoint_resolver=previous_checkpoint_resolver,
    )
    for field in CHECKPOINT_CORE_FIELDS:
        if checkpoint_core[field] != derived[field]:
            raise ProtocolV3Error(f"checkpoint does not match archive segment: {field}")
    if checkpoint_core["checkpoint_hash"] != checkpoint_core_hash(checkpoint_core):
        raise ProtocolV3Error("checkpoint hash mismatch")
    return {"checkpoint_core": checkpoint_core, "archive_segments": archive_segments}


# Wrap a ProofBundleV3 in a binary V3 gossip envelope.
def create_proof_bundle_announcement(proof_bundle, now=None):
    return {
        "type": PROOF_BUNDLE_ANNOUNCEMENT_TYPE,
        "version": VERSION,
        "network_id": int(proof_bundle["network_id"]),
        "payload_encoding": V3_PAYLOAD_ENCODING,
        "proof_bundle": encode_wire_payload(proof_bundle_v3.encode_proof_bundle(proof_bundle)),
        "announced_at": ind_token.current_time(now),
    }


# Decode and verify a ProofBundleAnnouncementV3.
def verify_proof_bundle_announcement(
    message,
    expected_network_id=DEFAULT_NETWORK_ID,
    transparency_verifier=None,
    trusted_operator_public_key=None,
    archive_segment_resolver=None,
    proof_bundle_resolver=None,
):
    network_id = _require_v3_payload_envelope(
        message,
        PROOF_BUNDLE_ANNOUNCEMENT_FIELDS,
        PROOF_BUNDLE_ANNOUNCEMENT_TYPE,
        "ProofBundleAnnouncementV3",
    )
    if expected_network_id is not None and network_id != int(expected_network_id):
        raise ProtocolV3Error("ProofBundleAnnouncementV3 network id mismatch")
    bundle = proof_bundle_v3.decode_proof_bundle(decode_wire_payload(message["proof_bundle"]))
    checkpoint = proof_bundle_v3.verify_proof_bundle(
        bundle,
        expected_network_id=network_id,
        transparency_verifier=transparency_verifier,
        trusted_operator_public_key=trusted_operator_public_key,
        archive_segment_resolver=archive_segment_resolver,
        proof_bundle_resolver=proof_bundle_resolver,
    )
    return {"proof_bundle": bundle, "checkpoint": checkpoint}


# Wrap an ArchiveSegmentV3 in a binary V3 gossip envelope.
def create_archive_segment_announcement(archive_segment, now=None):
    from . import archive_segment_v3

    return {
        "type": ARCHIVE_SEGMENT_ANNOUNCEMENT_TYPE,
        "version": VERSION,
        "network_id": int(archive_segment["network_id"]),
        "payload_encoding": V3_PAYLOAD_ENCODING,
        "archive_segment": encode_wire_payload(
            archive_segment_v3.encode_archive_segment(archive_segment)
        ),
        "announced_at": ind_token.current_time(now),
    }


# Decode and verify an ArchiveSegmentAnnouncementV3.
def verify_archive_segment_announcement(
    message,
    expected_network_id=DEFAULT_NETWORK_ID,
    previous_segment_resolver=None,
):
    from . import archive_segment_v3

    network_id = _require_v3_payload_envelope(
        message,
        ARCHIVE_SEGMENT_ANNOUNCEMENT_FIELDS,
        ARCHIVE_SEGMENT_ANNOUNCEMENT_TYPE,
        "ArchiveSegmentAnnouncementV3",
    )
    if expected_network_id is not None and network_id != int(expected_network_id):
        raise ProtocolV3Error("ArchiveSegmentAnnouncementV3 network id mismatch")
    segment = archive_segment_v3.decode_archive_segment(
        decode_wire_payload(message["archive_segment"])
    )
    checkpoint = archive_segment_v3.verify_archive_segment(
        segment,
        expected_network_id=network_id,
        previous_segment_resolver=previous_segment_resolver,
    )
    return {"archive_segment": segment, "checkpoint": checkpoint}


def _receipt_v3_disabled():
    raise ProtocolV3Error(
        "ReceiptV3 is not an active protocol message; wallet sync imports owner-addressed bills"
    )


def encode_receipt_body(receipt, include_signature=True):
    _receipt_v3_disabled()


def decode_receipt_body(reader, network_id, require_signature=True):
    _receipt_v3_disabled()


def encode_receipt(receipt, include_signature=True):
    _receipt_v3_disabled()


def decode_receipt(data):
    _receipt_v3_disabled()


def _receipt_signing_preimage(receipt):
    _receipt_v3_disabled()


def receipt_hash(receipt):
    _receipt_v3_disabled()


def _validate_receipt_shape(receipt, network_id, require_signature=True):
    _receipt_v3_disabled()


def verify_receipt_signature(receipt):
    _receipt_v3_disabled()


def create_receipt(
    bill,
    recipient_private_key,
    recipient_public_key,
    timestamp=None,
    now=None,
    proof_bundle=None,
    proof_bundle_resolver=None,
    expected_network_id=DEFAULT_NETWORK_ID,
    transparency_verifier=None,
    trusted_operator_public_key=None,
    archive_segment_resolver=None,
):
    _receipt_v3_disabled()


def verify_receipt(
    bill,
    receipt,
    proof_bundle=None,
    proof_bundle_resolver=None,
    expected_network_id=DEFAULT_NETWORK_ID,
    transparency_verifier=None,
    trusted_operator_public_key=None,
    archive_segment_resolver=None,
    now=None,
):
    _receipt_v3_disabled()


def create_receipt_announcement(
    bill,
    recipient_private_key,
    recipient_public_key,
    now=None,
    proof_bundle=None,
    proof_bundle_resolver=None,
    expected_network_id=DEFAULT_NETWORK_ID,
    transparency_verifier=None,
    trusted_operator_public_key=None,
    archive_segment_resolver=None,
):
    _receipt_v3_disabled()


def verify_receipt_announcement(
    message,
    proof_bundle=None,
    proof_bundle_resolver=None,
    expected_network_id=DEFAULT_NETWORK_ID,
    transparency_verifier=None,
    trusted_operator_public_key=None,
    archive_segment_resolver=None,
    now=None,
):
    _receipt_v3_disabled()


def _conflict_proof_unsigned(proof):
    unsigned = copy.deepcopy(proof)
    unsigned.pop("proof_hash", None)
    return unsigned


# Encode a ConflictProofV3 body, optionally zeroing its self-hash field.
def encode_conflict_proof_body(proof, include_hash=True):
    _require_exact_fields(proof, CONFLICT_PROOF_FIELDS, "ConflictProofV3")
    _require_int(proof["network_id"], "ConflictProofV3 network id", minimum=0)
    proof_hash = proof["proof_hash"] if include_hash else "00" * 32
    _hex32(proof_hash, "ConflictProofV3 proof hash")
    return b"".join(
        (
            binary_v3.encode_hash_hex(proof["token_id"]),
            binary_v3.encode_hash_hex(proof["previous_hash"]),
            binary_v3.encode_uvarint(int(proof["sequence"])),
            binary_v3.encode_ascii(proof["sender_address"], max_length=128),
            binary_v3.encode_hash_hex(proof["spend_key"]),
            binary_v3.encode_hash_hex(proof["transfer_hash_a"]),
            binary_v3.encode_hash_hex(proof["transfer_hash_b"]),
            encode_transfer_body(proof["transfer_a"], include_signature=True),
            encode_transfer_body(proof["transfer_b"], include_signature=True),
            binary_v3.encode_uvarint(int(proof["detected_at"])),
            binary_v3.encode_hash_hex(proof_hash),
        )
    )


# Decode a ConflictProofV3 body after the envelope has supplied network id.
def decode_conflict_proof_body(reader, network_id):
    return {
        "type": CONFLICT_PROOF_TYPE,
        "version": VERSION,
        "network_id": int(network_id),
        "token_id": reader.read_hash_hex("ConflictProofV3 token id"),
        "previous_hash": reader.read_hash_hex("ConflictProofV3 previous hash"),
        "sequence": reader.read_uvarint("ConflictProofV3 sequence"),
        "sender_address": reader.read_ascii("ConflictProofV3 sender address", max_length=128),
        "spend_key": reader.read_hash_hex("ConflictProofV3 spend key"),
        "transfer_hash_a": reader.read_hash_hex("ConflictProofV3 transfer hash a"),
        "transfer_hash_b": reader.read_hash_hex("ConflictProofV3 transfer hash b"),
        "transfer_a": decode_transfer_body(reader, network_id, require_signature=True),
        "transfer_b": decode_transfer_body(reader, network_id, require_signature=True),
        "detected_at": reader.read_uvarint("ConflictProofV3 detected_at"),
        "proof_hash": reader.read_hash_hex("ConflictProofV3 proof hash"),
    }


# Encode a ConflictProofV3 dict in its canonical binary envelope.
def encode_conflict_proof(proof, include_hash=True):
    network_id = _require_int(proof.get("network_id"), "ConflictProofV3 network id", minimum=0)
    return _encode_envelope(
        CONFLICT_PROOF_MAGIC,
        network_id,
        encode_conflict_proof_body(proof, include_hash=include_hash),
    )


# Decode a ConflictProofV3 canonical binary envelope.
def decode_conflict_proof(data):
    return _decode_envelope(
        data, CONFLICT_PROOF_MAGIC, "ConflictProofV3", decode_conflict_proof_body
    )


# Hash a ConflictProofV3 with its self-hash field removed.
def conflict_proof_hash(proof):
    return binary_v3.object_hash(
        CONFLICT_PROOF_TYPE,
        encode_conflict_proof(proof, include_hash=False),
    ).hex()


def _sorted_conflicting_transfers(transfer_a, transfer_b, network_id):
    _validate_transfer_shape(transfer_a, int(network_id))
    _validate_transfer_shape(transfer_b, int(network_id))
    verify_transfer_signature(transfer_a)
    verify_transfer_signature(transfer_b)
    if transfer_a["token_id"] != transfer_b["token_id"]:
        raise ProtocolV3Error("ConflictProofV3 transfers reference different bills")
    if int(transfer_a["sequence"]) != int(transfer_b["sequence"]):
        raise ProtocolV3Error("ConflictProofV3 transfers do not share a sequence")
    if transfer_a["previous_hash"] != transfer_b["previous_hash"]:
        raise ProtocolV3Error("ConflictProofV3 transfers do not share a previous hash")
    if transfer_a["sender_address"] != transfer_b["sender_address"]:
        raise ProtocolV3Error("ConflictProofV3 transfers do not share a sender")
    if spend_key_for_transfer(transfer_a) != spend_key_for_transfer(transfer_b):
        raise ProtocolV3Error("ConflictProofV3 transfers do not share a spend key")
    hash_a = transfer_hash(transfer_a)
    hash_b = transfer_hash(transfer_b)
    if hash_a == hash_b:
        raise ProtocolV3Error("ConflictProofV3 requires two different transfers")
    if hash_b < hash_a:
        return copy.deepcopy(transfer_b), copy.deepcopy(transfer_a), hash_b, hash_a
    return copy.deepcopy(transfer_a), copy.deepcopy(transfer_b), hash_a, hash_b


# Create a compact proof that two TransferV3 objects spend the same state.
def create_conflict_proof_from_transfers(
    transfer_a,
    transfer_b,
    detected_at=None,
    expected_network_id=DEFAULT_NETWORK_ID,
):
    network_id = _require_int(
        transfer_a.get("network_id") if isinstance(transfer_a, dict) else None,
        "ConflictProofV3 network id",
        minimum=0,
    )
    if expected_network_id is not None and network_id != int(expected_network_id):
        raise ProtocolV3Error("ConflictProofV3 network id mismatch")
    sorted_a, sorted_b, hash_a, hash_b = _sorted_conflicting_transfers(
        transfer_a,
        transfer_b,
        network_id,
    )
    proof = {
        "type": CONFLICT_PROOF_TYPE,
        "version": VERSION,
        "network_id": int(network_id),
        "token_id": sorted_a["token_id"],
        "previous_hash": sorted_a["previous_hash"],
        "sequence": int(sorted_a["sequence"]),
        "sender_address": sorted_a["sender_address"],
        "spend_key": spend_key_for_transfer(sorted_a),
        "transfer_hash_a": hash_a,
        "transfer_hash_b": hash_b,
        "transfer_a": sorted_a,
        "transfer_b": sorted_b,
        "detected_at": ind_token.current_time(detected_at),
        "proof_hash": "",
    }
    proof["proof_hash"] = conflict_proof_hash(proof)
    return proof


def _find_conflicting_transfer_pair(bill_a, bill_b):
    transfers_a = {}
    for transfer in bill_a.get("recent_transfers", []):
        transfers_a.setdefault(spend_key_for_transfer(transfer), []).append(transfer)
    for transfer_b in bill_b.get("recent_transfers", []):
        for transfer_a in transfers_a.get(spend_key_for_transfer(transfer_b), []):
            if transfer_hash(transfer_a) != transfer_hash(transfer_b):
                return transfer_a, transfer_b
    return None


# Create a ConflictProofV3 from two verified BillV3 branches.
def create_conflict_proof(
    bill_a,
    bill_b,
    detected_at=None,
    proof_bundle_a=None,
    proof_bundle_b=None,
    proof_bundle_resolver=None,
    expected_network_id=DEFAULT_NETWORK_ID,
    transparency_verifier=None,
    trusted_operator_public_key=None,
    archive_segment_resolver=None,
):
    if isinstance(bill_a, bytes):
        bill_a = decode_bill(bill_a)
    if isinstance(bill_b, bytes):
        bill_b = decode_bill(bill_b)
    _verify_bill_state(
        bill_a,
        proof_bundle=proof_bundle_a,
        proof_bundle_resolver=proof_bundle_resolver,
        expected_network_id=expected_network_id,
        transparency_verifier=transparency_verifier,
        trusted_operator_public_key=trusted_operator_public_key,
        archive_segment_resolver=archive_segment_resolver,
    )
    _verify_bill_state(
        bill_b,
        proof_bundle=proof_bundle_b,
        proof_bundle_resolver=proof_bundle_resolver,
        expected_network_id=expected_network_id,
        transparency_verifier=transparency_verifier,
        trusted_operator_public_key=trusted_operator_public_key,
        archive_segment_resolver=archive_segment_resolver,
    )
    if bill_a["token_id"] != bill_b["token_id"]:
        raise ProtocolV3Error("ConflictProofV3 bills reference different tokens")
    pair = _find_conflicting_transfer_pair(bill_a, bill_b)
    if not pair:
        raise ProtocolV3Error("BillV3 branches do not contain a conflict")
    return create_conflict_proof_from_transfers(
        pair[0],
        pair[1],
        detected_at=detected_at,
        expected_network_id=expected_network_id,
    )


# Build the stable dedupe key for a conflict proof, independent of detection time.
def conflict_proof_key(proof):
    if isinstance(proof, str):
        proof = ind_token._load_json(proof)
    _require_exact_fields(proof, CONFLICT_PROOF_FIELDS, "ConflictProofV3")
    hash_a = str(proof["transfer_hash_a"])
    hash_b = str(proof["transfer_hash_b"])
    if hash_b < hash_a:
        hash_a, hash_b = hash_b, hash_a
    identity = {
        "type": CONFLICT_PROOF_TYPE,
        "version": _require_int(proof["version"], "ConflictProofV3 version"),
        "network_id": _require_int(proof["network_id"], "ConflictProofV3 network id", minimum=0),
        "token_id": str(proof["token_id"]),
        "previous_hash": str(proof["previous_hash"]),
        "sequence": _require_int(proof["sequence"], "ConflictProofV3 sequence"),
        "sender_address": str(proof["sender_address"]),
        "transfer_hash_a": hash_a,
        "transfer_hash_b": hash_b,
    }
    return ind_token.sha3_hex(ind_token._canonical_bytes(identity))


# Verify a ConflictProofV3 made from two signed TransferV3 spends.
def verify_conflict_proof(proof, expected_network_id=DEFAULT_NETWORK_ID):
    if isinstance(proof, str):
        proof = ind_token._load_json(proof)
    _require_exact_fields(proof, CONFLICT_PROOF_FIELDS, "ConflictProofV3")
    if proof["type"] != CONFLICT_PROOF_TYPE:
        raise ProtocolV3Error("not a ConflictProofV3")
    if _require_int(proof["version"], "ConflictProofV3 version") != VERSION:
        raise ProtocolV3Error("unsupported ConflictProofV3 version")
    network_id = _require_int(proof["network_id"], "ConflictProofV3 network id", minimum=0)
    if expected_network_id is not None and network_id != int(expected_network_id):
        raise ProtocolV3Error("ConflictProofV3 network id mismatch")
    _hex32(proof["token_id"], "ConflictProofV3 token id")
    _hex32(proof["previous_hash"], "ConflictProofV3 previous hash")
    _require_int(proof["sequence"], "ConflictProofV3 sequence", minimum=1)
    keys_v3.validate_address(proof["sender_address"], "ConflictProofV3 sender address")
    _hex32(proof["spend_key"], "ConflictProofV3 spend key")
    _hex32(proof["transfer_hash_a"], "ConflictProofV3 transfer hash a")
    _hex32(proof["transfer_hash_b"], "ConflictProofV3 transfer hash b")
    _require_int(proof["detected_at"], "ConflictProofV3 detected_at", minimum=0)
    sorted_a, sorted_b, hash_a, hash_b = _sorted_conflicting_transfers(
        proof["transfer_a"],
        proof["transfer_b"],
        network_id,
    )
    expected = copy.deepcopy(proof)
    expected["token_id"] = sorted_a["token_id"]
    expected["previous_hash"] = sorted_a["previous_hash"]
    expected["sequence"] = int(sorted_a["sequence"])
    expected["sender_address"] = sorted_a["sender_address"]
    expected["spend_key"] = spend_key_for_transfer(sorted_a)
    expected["transfer_hash_a"] = hash_a
    expected["transfer_hash_b"] = hash_b
    expected["transfer_a"] = sorted_a
    expected["transfer_b"] = sorted_b
    if _conflict_proof_unsigned(proof) != _conflict_proof_unsigned(expected):
        raise ProtocolV3Error("ConflictProofV3 conflict fields mismatch")
    if proof["proof_hash"] != conflict_proof_hash(proof):
        raise ProtocolV3Error("ConflictProofV3 proof hash mismatch")
    return True
