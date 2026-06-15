"""Thin BillV3 verification built on ProofBundleV3.

This module is the first protocol-level V3 consumer of proof bundles. It does
not replace the existing V1/V2 wallet flow yet; it verifies compact V3 bill
state from a checkpoint core plus an external ProofBundleV3.
"""

import base64
import copy

from . import binary_v3, keys_v3, proof_bundle_v3
from . import protocol as ind_token

BILL_TYPE = "ind.bill.v3"
GENESIS_REF_TYPE = "ind.genesis_ref.v3"
CHECKPOINT_CORE_TYPE = "ind.checkpoint_core.v3"
TRANSFER_TYPE = "ind.transfer.v3"
RECEIPT_TYPE = "ind.receipt.v3"
TRANSFER_ANNOUNCEMENT_TYPE = "ind.transfer_announcement.v3"
RECEIPT_ANNOUNCEMENT_TYPE = "ind.receipt_announcement.v3"
PROOF_BUNDLE_ANNOUNCEMENT_TYPE = "ind.proof_bundle_announcement.v3"
ARCHIVE_SEGMENT_ANNOUNCEMENT_TYPE = "ind.archive_segment_announcement.v3"
CONFLICT_PROOF_TYPE = "ind.conflict_proof.v3"
VERSION = 3
BILL_MAGIC = b"IND3BILL"
TRANSFER_MAGIC = b"IND3XFER"
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


def _hex32(value, label):
    if not isinstance(value, str) or len(value) != 64:
        raise ProtocolV3Error(f"invalid {label}")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise ProtocolV3Error(f"invalid {label}") from exc
    return value.lower()


def _validate_any_address(address, label):
    if keys_v3.is_address(address):
        return keys_v3.validate_address(address, label)
    return ind_token.validate_address(address, label)


def _canonical_payload_bytes(data):
    return ind_token.canonical_json(data).encode("utf-8")


# Encode a BillV3 dict in a canonical V3 binary envelope.
def encode_bill(bill):
    if not isinstance(bill, dict):
        raise ProtocolV3Error("BillV3 must be a dict")
    network_id = _require_int(bill.get("network_id"), "BillV3 network id", minimum=0)
    return b"".join(
        (
            BILL_MAGIC,
            binary_v3.encode_uvarint(VERSION),
            binary_v3.encode_uvarint(network_id),
            binary_v3.encode_bytes(_canonical_payload_bytes(bill)),
        )
    )


# Decode a BillV3 binary envelope.
def decode_bill(data):
    reader = binary_v3.Reader(data)
    magic = reader.read(len(BILL_MAGIC), "BillV3 magic")
    if magic != BILL_MAGIC:
        raise ProtocolV3Error("invalid BillV3 magic")
    version = reader.read_uvarint("BillV3 version")
    if version != VERSION:
        raise ProtocolV3Error("unsupported BillV3 version")
    network_id = reader.read_uvarint("BillV3 network id")
    payload = reader.read_bytes("BillV3 payload")
    reader.require_eof()
    bill = ind_token._load_json(payload.decode("utf-8"))
    if _require_int(bill.get("network_id"), "BillV3 network id", minimum=0) != network_id:
        raise ProtocolV3Error("BillV3 network id mismatch")
    return bill


# Hash a complete BillV3 binary envelope.
def bill_hash(bill):
    return binary_v3.object_hash(BILL_TYPE, encode_bill(bill))


def _unsigned_transfer(transfer):
    unsigned = copy.deepcopy(transfer)
    unsigned.pop("signature", None)
    return unsigned


# Encode a TransferV3 dict in a canonical V3 binary envelope.
def encode_transfer(transfer, include_signature=True):
    if not isinstance(transfer, dict):
        raise ProtocolV3Error("TransferV3 must be a dict")
    network_id = _require_int(transfer.get("network_id"), "TransferV3 network id", minimum=0)
    payload = transfer if include_signature else _unsigned_transfer(transfer)
    return b"".join(
        (
            TRANSFER_MAGIC,
            binary_v3.encode_uvarint(VERSION),
            binary_v3.encode_uvarint(network_id),
            binary_v3.encode_bytes(_canonical_payload_bytes(payload)),
        )
    )


# Decode a canonical TransferV3 binary envelope.
def decode_transfer(data):
    reader = binary_v3.Reader(data)
    magic = reader.read(len(TRANSFER_MAGIC), "TransferV3 magic")
    if magic != TRANSFER_MAGIC:
        raise ProtocolV3Error("invalid TransferV3 magic")
    version = reader.read_uvarint("TransferV3 version")
    if version != VERSION:
        raise ProtocolV3Error("unsupported TransferV3 version")
    network_id = reader.read_uvarint("TransferV3 network id")
    payload = reader.read_bytes("TransferV3 payload")
    reader.require_eof()
    transfer = ind_token._load_json(payload.decode("utf-8"))
    if _require_int(transfer.get("network_id"), "TransferV3 network id", minimum=0) != network_id:
        raise ProtocolV3Error("TransferV3 network id mismatch")
    return transfer


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
        "type": "ind.transparency_spend_claim.v1",
        "version": 1,
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


def _validate_base_state(state, require_v3_owner=True):
    _require_exact_fields(state, BASE_STATE_FIELDS, "V3 base state")
    _require_int(state["sequence"], "V3 base sequence", minimum=0)
    if require_v3_owner:
        keys_v3.validate_address(state["owner_address"], "V3 base owner address")
    else:
        _validate_any_address(state["owner_address"], "V3 base owner address")
    _hex32(state["last_transfer_hash"], "V3 base last transfer hash")
    _require_int(state["last_transfer_timestamp"], "V3 base timestamp", minimum=0)
    _require_int(state["last_transfer_day"], "V3 base day", minimum=0)
    _require_int(state["transfers_in_last_day"], "V3 base day count", minimum=0)
    _require_int(state["value"], "V3 base value", minimum=1)
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
    state = copy.deepcopy(_validate_base_state(state, require_v3_owner=bool(transfers)))
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
    state = copy.deepcopy(_validate_base_state(state, require_v3_owner=True))
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
    unsigned = copy.deepcopy(core)
    unsigned["checkpoint_hash"] = ""
    return binary_v3.object_hash(
        CHECKPOINT_CORE_TYPE,
        _canonical_payload_bytes(unsigned),
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
    state = copy.deepcopy(_validate_base_state(state, require_v3_owner=True))
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
        "display_id_hash": ind_token.sha3_hex(str(state["display_id"]).encode("ascii")),
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
    _require_int(genesis_ref["issue_index"], "GenesisRefV3 issue index", minimum=0)
    _require_int(genesis_ref["issued_at"], "GenesisRefV3 issued_at", minimum=0)


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
    _validate_any_address(core["owner_address"], "CheckpointCoreV3 owner address")
    _require_int(core["value"], "CheckpointCoreV3 value", minimum=1)
    if core["display_id_hash"] != ind_token.sha3_hex(str(core["display_id"]).encode("ascii")):
        raise ProtocolV3Error("CheckpointCoreV3 display id hash mismatch")
    _hex32(core["last_transfer_hash"], "CheckpointCoreV3 last transfer hash")
    _require_int(core["last_transfer_timestamp"], "CheckpointCoreV3 timestamp", minimum=0)
    _require_int(core["last_transfer_day"], "CheckpointCoreV3 day", minimum=0)
    _require_int(core["transfers_in_last_day"], "CheckpointCoreV3 day count", minimum=1)
    if core["previous_checkpoint_hash"] is not None:
        _hex32(core["previous_checkpoint_hash"], "CheckpointCoreV3 previous checkpoint hash")
    _hex32(core["checkpoint_hash"], "CheckpointCoreV3 checkpoint hash")


def _checkpoint_matches_core(checkpoint, core):
    expected = checkpoint
    if not isinstance(expected, dict) or expected.get("type") != CHECKPOINT_CORE_TYPE:
        raise ProtocolV3Error("ProofBundleV3 did not prove a CheckpointCoreV3")
    for field in CHECKPOINT_CORE_FIELDS - {"type", "version", "network_id"}:
        if core[field] != expected[field]:
            raise ProtocolV3Error(f"CheckpointCoreV3 does not match proof bundle: {field}")


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
    if int(bill["value"]) != int(bill["checkpoint_core"]["value"]):
        raise ProtocolV3Error("BillV3 value mismatch")
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


def _unsigned_receipt(receipt):
    unsigned = copy.deepcopy(receipt)
    unsigned.pop("signature", None)
    return unsigned


def _receipt_signing_preimage(receipt):
    return binary_v3.signing_preimage(
        receipt["network_id"],
        RECEIPT_TYPE,
        VERSION,
        binary_v3.SIGNATURE_ALGORITHM_ID,
        RECEIPT_TYPE,
        _canonical_payload_bytes(_unsigned_receipt(receipt)),
    )


# Hash a ReceiptV3 for local indexing and dedupe.
def receipt_hash(receipt):
    return binary_v3.object_hash(RECEIPT_TYPE, _canonical_payload_bytes(receipt)).hex()


def _validate_receipt_shape(receipt, network_id, require_signature=True):
    _require_exact_fields(receipt, RECEIPT_FIELDS, "ReceiptV3")
    if receipt["type"] != RECEIPT_TYPE:
        raise ProtocolV3Error("malformed ReceiptV3")
    if _require_int(receipt["version"], "ReceiptV3 version") != VERSION:
        raise ProtocolV3Error("unsupported ReceiptV3 version")
    if _require_int(receipt["network_id"], "ReceiptV3 network id", minimum=0) != network_id:
        raise ProtocolV3Error("ReceiptV3 network id mismatch")
    if (
        _require_int(receipt["signature_algorithm"], "ReceiptV3 signature algorithm")
        != binary_v3.SIGNATURE_ALGORITHM_ID
    ):
        raise ProtocolV3Error("unsupported ReceiptV3 signature algorithm")
    _hex32(receipt["token_id"], "ReceiptV3 token id")
    _hex32(receipt["transfer_hash"], "ReceiptV3 transfer hash")
    _require_int(receipt["sequence"], "ReceiptV3 sequence", minimum=1)
    keys_v3.validate_address(receipt["recipient_address"], "ReceiptV3 recipient address")
    keys_v3.decode_public_key(receipt["recipient_public_key"])
    _require_int(receipt["received_at"], "ReceiptV3 received_at", minimum=0)
    if require_signature:
        try:
            signature = bytes.fromhex(receipt["signature"])
        except Exception as exc:
            raise ProtocolV3Error("invalid ReceiptV3 signature") from exc
        if len(signature) != 64:
            raise ProtocolV3Error("invalid ReceiptV3 signature")


# Verify a ReceiptV3 signature against the recipient key.
def verify_receipt_signature(receipt):
    if not keys_v3.public_key_matches_address(
        receipt["recipient_public_key"], receipt["recipient_address"]
    ):
        raise ProtocolV3Error("ReceiptV3 recipient key does not match recipient address")
    signature = bytes.fromhex(receipt["signature"])
    if not keys_v3.verify(
        receipt["recipient_public_key"], signature, _receipt_signing_preimage(receipt)
    ):
        raise ProtocolV3Error("invalid ReceiptV3 signature")
    return True


# Countersign a BillV3 tip with the current owner's Ed25519 key.
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
        now=now,
    )
    recipient_address = keys_v3.address_from_public_key(recipient_public_key)
    if recipient_address != state["owner_address"]:
        raise ProtocolV3Error("ReceiptV3 signer is not the bill recipient")
    wall_now = ind_token.current_time(now)
    received_at = _require_int(
        int(timestamp if timestamp is not None else wall_now),
        "ReceiptV3 received_at",
        minimum=0,
    )
    if timestamp is None:
        received_at = max(received_at, int(state["last_transfer_timestamp"]))
    if received_at < int(state["last_transfer_timestamp"]):
        raise ProtocolV3Error("ReceiptV3 timestamp predates transfer")
    if received_at > wall_now + ind_token.MAX_TRANSFER_FUTURE_SKEW_SECONDS:
        raise ProtocolV3Error("ReceiptV3 timestamp is too far in the future")
    receipt_unsigned = {
        "type": RECEIPT_TYPE,
        "version": VERSION,
        "network_id": int(bill["network_id"]),
        "signature_algorithm": binary_v3.SIGNATURE_ALGORITHM_ID,
        "token_id": bill["token_id"],
        "transfer_hash": state["last_transfer_hash"],
        "sequence": int(state["sequence"]),
        "recipient_address": recipient_address,
        "recipient_public_key": recipient_public_key,
        "received_at": int(received_at),
        "signature": "",
    }
    _validate_receipt_shape(receipt_unsigned, int(bill["network_id"]), require_signature=False)
    signature = keys_v3.sign(recipient_private_key, _receipt_signing_preimage(receipt_unsigned))
    receipt_signed = copy.deepcopy(receipt_unsigned)
    receipt_signed["signature"] = signature.hex()
    verify_receipt_signature(receipt_signed)
    return receipt_signed


# Validate a ReceiptV3 against the BillV3 tip it acknowledges.
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
        now=now,
    )
    network_id = int(bill["network_id"])
    _validate_receipt_shape(receipt, network_id)
    if receipt["token_id"] != bill["token_id"]:
        raise ProtocolV3Error("ReceiptV3 references a different bill")
    if receipt["transfer_hash"] != state["last_transfer_hash"]:
        raise ProtocolV3Error("ReceiptV3 does not reference the bill tip")
    if int(receipt["sequence"]) != int(state["sequence"]):
        raise ProtocolV3Error("ReceiptV3 sequence does not match bill tip")
    if receipt["recipient_address"] != state["owner_address"]:
        raise ProtocolV3Error("ReceiptV3 signer is not the bill recipient")
    if int(receipt["received_at"]) < int(state["last_transfer_timestamp"]):
        raise ProtocolV3Error("ReceiptV3 timestamp predates transfer")
    if (
        int(receipt["received_at"])
        > ind_token.current_time(now) + ind_token.MAX_TRANSFER_FUTURE_SKEW_SECONDS
    ):
        raise ProtocolV3Error("ReceiptV3 timestamp is too far in the future")
    verify_receipt_signature(receipt)
    return _token_state_from_v3_state(bill["token_id"], state)


# Wrap a ReceiptV3 in the V3 gossip envelope.
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
    receipt = create_receipt(
        bill,
        recipient_private_key,
        recipient_public_key,
        now=now,
        proof_bundle=proof_bundle,
        proof_bundle_resolver=proof_bundle_resolver,
        expected_network_id=expected_network_id,
        transparency_verifier=transparency_verifier,
        trusted_operator_public_key=trusted_operator_public_key,
        archive_segment_resolver=archive_segment_resolver,
    )
    bill_obj = decode_bill(bill) if isinstance(bill, bytes) else bill
    return {
        "type": RECEIPT_ANNOUNCEMENT_TYPE,
        "version": VERSION,
        "network_id": int(bill_obj["network_id"]),
        "bill": copy.deepcopy(bill_obj),
        "receipt": receipt,
        "announced_at": ind_token.current_time(now),
    }


# Validate a V3 receipt gossip envelope.
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
    if isinstance(message, str):
        message = ind_token._load_json(message)
    _require_exact_fields(message, RECEIPT_ANNOUNCEMENT_FIELDS, "ReceiptAnnouncementV3")
    if message["type"] != RECEIPT_ANNOUNCEMENT_TYPE:
        raise ProtocolV3Error("not a ReceiptAnnouncementV3")
    if _require_int(message["version"], "ReceiptAnnouncementV3 version") != VERSION:
        raise ProtocolV3Error("unsupported ReceiptAnnouncementV3 version")
    network_id = _require_int(message["network_id"], "ReceiptAnnouncementV3 network id", minimum=0)
    if expected_network_id is not None and network_id != int(expected_network_id):
        raise ProtocolV3Error("ReceiptAnnouncementV3 network id mismatch")
    _require_int(message["announced_at"], "ReceiptAnnouncementV3 announced_at", minimum=0)
    return verify_receipt(
        message["bill"],
        message["receipt"],
        proof_bundle=proof_bundle,
        proof_bundle_resolver=proof_bundle_resolver,
        expected_network_id=network_id,
        transparency_verifier=transparency_verifier,
        trusted_operator_public_key=trusted_operator_public_key,
        archive_segment_resolver=archive_segment_resolver,
        now=now,
    )


def _conflict_proof_unsigned(proof):
    unsigned = copy.deepcopy(proof)
    unsigned.pop("proof_hash", None)
    return unsigned


# Hash a ConflictProofV3 with its self-hash field removed.
def conflict_proof_hash(proof):
    return binary_v3.object_hash(
        CONFLICT_PROOF_TYPE,
        _canonical_payload_bytes(_conflict_proof_unsigned(proof)),
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
