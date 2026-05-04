import base64
import copy
import json
import os
import sqlite3
import time
import zlib
from dataclasses import dataclass
from hashlib import sha3_256
from pathlib import Path

import base58
import ecdsa
from ecdsa import util as ecdsa_util


def _env_int(name, default):
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return int(default)


MASTER_SUPPLY_NUMBER = 33
ANGEL_NUMBER = 777
MONEY_NUMBER = 8
BIRTHDAY_NUMBER = 9
BIRTHDAY_CODE = "09.10.2003"
TOTAL_SUPPLY = MASTER_SUPPLY_NUMBER * 1_000_000_000
TOKEN_VERSION = 1
ADDRESS_VERSION = "1"
ADDRESS_PREFIX = "x"
ADDRESS_SUFFIX = "x"
ADDRESS_TARGET_LENGTH = MASTER_SUPPLY_NUMBER
ADDRESS_CHECKSUM_BYTES = 4
ADDRESS_CHECKSUM_CHARS = 6
ADDRESS_PAYLOAD_CHARS = ADDRESS_TARGET_LENGTH - (
    len(ADDRESS_PREFIX) + len(ADDRESS_VERSION) + ADDRESS_CHECKSUM_CHARS + len(ADDRESS_SUFFIX)
)
ADDRESS_LENGTH = len(ADDRESS_PREFIX) + len(ADDRESS_VERSION) + ADDRESS_PAYLOAD_CHARS + ADDRESS_CHECKSUM_CHARS + len(ADDRESS_SUFFIX)
PREVIOUS_ADDRESS_PAYLOAD_CHARS = 28
PREVIOUS_ADDRESS_LENGTH = len(ADDRESS_PREFIX) + len(ADDRESS_VERSION) + PREVIOUS_ADDRESS_PAYLOAD_CHARS + ADDRESS_CHECKSUM_CHARS + len(ADDRESS_SUFFIX)
LEGACY_ADDRESS_LENGTH = 30
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
GENESIS_NONCE_SEED_PREFIX = f"IND-LAZY-GENESIS-v{TOKEN_VERSION}:{MASTER_SUPPLY_NUMBER}:{ANGEL_NUMBER}:{MONEY_NUMBER}:{BIRTHDAY_NUMBER}"
NUMEROLOGY_METADATA_KEY = "ind_alignment"

TOKEN_TYPE = "ind.token.v1"
TRANSFER_TYPE = "ind.transfer.v1"
TRANSFER_ANNOUNCEMENT_TYPE = "ind.transfer_announcement.v1"
RECEIPT_TYPE = "ind.receipt.v1"
RECEIPT_ANNOUNCEMENT_TYPE = "ind.receipt_announcement.v1"
CONFLICT_PROOF_TYPE = "ind.conflict_proof.v1"
TRANSPARENCY_ROOT_ANNOUNCEMENT_TYPE = "ind.transparency_root_announcement.v1"
TRANSPARENCY_EQUIVOCATION_PROOF_TYPE = "ind.transparency_equivocation_proof.v1"
TOKEN_STATE_REF_TYPE = "ind.token_state_ref.v1"
STORED_MESSAGE_REF_TYPE = "ind.stored_message_ref.v1"
GENESIS_MANIFEST_TYPE = "ind.genesis_manifest.v1"
GENESIS_MANIFEST_REF_TYPE = "ind.genesis_manifest_ref.v1"

GENESIS_SIGNATURE_DOMAIN = "IND_GENESIS_V1"
GENESIS_MANIFEST_SIGNATURE_DOMAIN = "IND_GENESIS_MANIFEST_V1"
TRANSFER_SIGNATURE_DOMAIN = "IND_TRANSFER_V1"
RECEIPT_SIGNATURE_DOMAIN = "IND_RECEIPT_V1"

TOKEN_FIELDS = {"type", "version", "token_id", "genesis", "history"}
GENESIS_FIELDS = {
    "type",
    "version",
    "index",
    "value",
    "owner_address",
    "issuer_public_key",
    "issued_at",
    "nonce",
    "success_commitment",
    "signature",
    "metadata",
}
GENESIS_MANIFEST_FIELDS = {
    "type",
    "version",
    "issuer_public_key",
    "issued_at",
    "total_token_count",
    "total_value",
    "ranges",
    "metadata",
    "signature",
}
GENESIS_MANIFEST_RANGE_FIELDS = {"start_index", "count", "value", "owner_address", "nonce_seed"}
GENESIS_MANIFEST_REF_FIELDS = {"type", "manifest_hash", "manifest"}
TRANSFER_FIELDS = {
    "type",
    "version",
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
TRANSFER_ANNOUNCEMENT_FIELDS = {"type", "version", "token", "announced_at"}
RECEIPT_FIELDS = {
    "type",
    "version",
    "token_id",
    "transfer_hash",
    "sequence",
    "recipient_address",
    "recipient_public_key",
    "received_at",
    "signature",
}
RECEIPT_ANNOUNCEMENT_FIELDS = {"type", "version", "token", "receipt", "announced_at"}
CONFLICT_PROOF_FIELDS = {
    "type",
    "version",
    "token_id",
    "previous_hash",
    "sequence",
    "transfer_hash_a",
    "transfer_hash_b",
    "token_a",
    "token_b",
    "detected_at",
    "proof_hash",
}
TRANSPARENCY_ROOT_ANNOUNCEMENT_FIELDS = {"type", "version", "root", "observed_at"}
TRANSPARENCY_EQUIVOCATION_PROOF_FIELDS = {
    "type",
    "version",
    "log_id",
    "collision_type",
    "root_a",
    "root_b",
    "detected_at",
}

WIRE_PACKED_PREFIX = "indz1:"
MIN_FINALITY_BUFFER_SECONDS = 60
FINALITY_BUFFER_SECONDS = max(
    MIN_FINALITY_BUFFER_SECONDS,
    _env_int("IND_FINALITY_BUFFER_SECONDS", MIN_FINALITY_BUFFER_SECONDS),
)
MAX_TRANSFERS_PER_TOKEN_PER_DAY = 100
MAX_TRANSFER_FUTURE_SKEW_SECONDS = 300
MAX_GENESIS_METADATA_BYTES = 1024
MAX_TRANSFER_METADATA_BYTES = 256
MAX_WIRE_COMPRESSED_BYTES = _env_int("IND_MAX_WIRE_COMPRESSED_BYTES", 16 * 1024 * 1024)
MAX_WIRE_DECOMPRESSED_BYTES = _env_int("IND_MAX_WIRE_DECOMPRESSED_BYTES", 64 * 1024 * 1024)
MAX_TRANSPARENCY_ROOT_GOSSIP_BYTES = _env_int("IND_MAX_TRANSPARENCY_ROOT_GOSSIP_BYTES", 16 * 1024)
MAX_TRANSPARENCY_EQUIVOCATION_GOSSIP_BYTES = _env_int("IND_MAX_TRANSPARENCY_EQUIVOCATION_GOSSIP_BYTES", 32 * 1024)
MAX_VERIFY_KEY_CACHE = _env_int("IND_MAX_VERIFY_KEY_CACHE", 4096)
MAX_JSON_DEPTH = _env_int("IND_MAX_JSON_DEPTH", 64)
MAX_JSON_LIST_ITEMS = _env_int("IND_MAX_JSON_LIST_ITEMS", 100_000)
MAX_JSON_OBJECT_KEYS = _env_int("IND_MAX_JSON_OBJECT_KEYS", 1024)
MAX_JSON_STRING_BYTES = _env_int("IND_MAX_JSON_STRING_BYTES", 64 * 1024)
MAX_JSON_INTEGER_ABS = _env_int("IND_MAX_JSON_INTEGER_ABS", 2**63 - 1)
DEFAULT_LOG_SUBMISSION_VERIFY_TIMEOUT_SECONDS = 30

DEFAULT_STORE_PATH = "ind_gossip.db"
SQLITE_BUSY_TIMEOUT_MS = 5000
_VERIFY_KEY_CACHE = {}


class TokenError(Exception):
    """Base exception for IND bearer-token validation failures."""


class ValidationError(TokenError):
    """Raised when a token, transfer, receipt, or proof is malformed."""


class ClosingConnection(sqlite3.Connection):
    """SQLite connection that always closes when its context manager exits."""

    def __exit__(self, exc_type, exc_value, traceback):
        result = super().__exit__(exc_type, exc_value, traceback)
        self.close()
        return result


def configure_sqlite_connection(conn):
    """Tune SQLite for short-lived threaded node connections."""

    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute(f"PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS}")
    return conn


@dataclass(frozen=True)
class TokenState:
    """Validated view of the current token tip used by wallets and nodes."""

    token_id: str
    owner_address: str
    last_transfer_hash: str
    sequence: int
    display_id: str
    value: int


def canonical_json(data):
    """Serialize protocol objects in the exact form used for hashes and signatures."""

    _validate_json_value(data, "protocol object")
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def _canonical_bytes(data):
    return canonical_json(data).encode("utf-8")


def _reject_duplicate_json_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value):
    raise ValidationError(f"invalid JSON numeric constant: {value}")


def _reject_json_float(value):
    raise ValidationError("JSON floating-point values are not part of the IND protocol")


def _json_loads_strict(raw):
    try:
        return json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_json_constant,
            parse_float=_reject_json_float,
        )
    except ValidationError:
        raise
    except Exception as exc:
        raise ValidationError("invalid JSON payload") from exc


def _validate_json_value(value, label, depth=0):
    if depth > MAX_JSON_DEPTH:
        raise ValidationError(f"{label} exceeds maximum JSON depth")
    if value is None or isinstance(value, bool):
        return True
    if isinstance(value, int):
        if abs(value) > MAX_JSON_INTEGER_ABS:
            raise ValidationError(f"{label} integer is outside protocol bounds")
        return True
    if isinstance(value, float):
        raise ValidationError(f"{label} contains a floating-point value")
    if isinstance(value, str):
        if len(value.encode("utf-8")) > MAX_JSON_STRING_BYTES:
            raise ValidationError(f"{label} string is too large")
        return True
    if isinstance(value, list):
        if len(value) > MAX_JSON_LIST_ITEMS:
            raise ValidationError(f"{label} list is too large")
        for item in value:
            _validate_json_value(item, label, depth + 1)
        return True
    if isinstance(value, dict):
        if len(value) > MAX_JSON_OBJECT_KEYS:
            raise ValidationError(f"{label} object has too many keys")
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValidationError(f"{label} object key is not a string")
            if len(key.encode("utf-8")) > MAX_JSON_STRING_BYTES:
                raise ValidationError(f"{label} object key is too large")
            _validate_json_value(item, label, depth + 1)
        return True
    raise ValidationError(f"{label} contains unsupported JSON value type")


def _require_exact_fields(data, required, label, optional=()):
    if not isinstance(data, dict):
        raise ValidationError(f"malformed {label}")
    required = set(required)
    allowed = required | set(optional)
    present = set(data)
    missing = required - present
    if missing:
        raise ValidationError(f"malformed {label}: missing {sorted(missing)[0]}")
    extra = present - allowed
    if extra:
        raise ValidationError(f"malformed {label}: unknown field {sorted(extra)[0]}")
    return True


def _require_int(value, label, minimum=None, maximum=None):
    if type(value) is not int:
        raise ValidationError(f"{label} must be an integer")
    if minimum is not None and value < minimum:
        raise ValidationError(f"{label} is below the allowed range")
    if maximum is not None and value > maximum:
        raise ValidationError(f"{label} is above the allowed range")
    return value


def _require_str(value, label, max_bytes=MAX_JSON_STRING_BYTES):
    if not isinstance(value, str):
        raise ValidationError(f"{label} must be a string")
    if len(value.encode("utf-8")) > int(max_bytes):
        raise ValidationError(f"{label} is too large")
    return value


def _packed_json(data):
    raw = canonical_json(data).encode("utf-8")
    if len(raw) > MAX_WIRE_DECOMPRESSED_BYTES:
        raise ValidationError("wire message is too large")
    compressed = zlib.compress(raw, level=9)
    if len(compressed) > MAX_WIRE_COMPRESSED_BYTES:
        raise ValidationError("compressed wire message is too large")
    return WIRE_PACKED_PREFIX + base64.b85encode(compressed).decode("utf-8")


def _safe_zlib_decompress(data):
    decompressor = zlib.decompressobj()
    result = decompressor.decompress(data, MAX_WIRE_DECOMPRESSED_BYTES + 1)
    if decompressor.unconsumed_tail or len(result) > MAX_WIRE_DECOMPRESSED_BYTES:
        raise ValidationError("wire message expands beyond safety limit")
    result += decompressor.flush(MAX_WIRE_DECOMPRESSED_BYTES + 1 - len(result))
    if len(result) > MAX_WIRE_DECOMPRESSED_BYTES:
        raise ValidationError("wire message expands beyond safety limit")
    return result


def _unpacked_json(raw):
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    raw = raw.strip()
    if len(raw.encode("utf-8")) > MAX_WIRE_DECOMPRESSED_BYTES:
        raise ValidationError("wire message is too large")
    if raw.startswith(WIRE_PACKED_PREFIX):
        packed = raw[len(WIRE_PACKED_PREFIX):]
        compressed = base64.b85decode(packed.encode("utf-8"))
        if len(compressed) > MAX_WIRE_COMPRESSED_BYTES:
            raise ValidationError("compressed wire message is too large")
        decompressed = _safe_zlib_decompress(compressed)
        return _json_loads_strict(decompressed.decode("utf-8"))
    return _json_loads_strict(raw)


def pack_wire_message(message):
    """Compress a gossip message into the bounded wire format accepted by peers."""

    if isinstance(message, bytes):
        message = message.decode("utf-8")
    if isinstance(message, str):
        if message.strip().startswith(WIRE_PACKED_PREFIX):
            return message.strip()
        message = _json_loads_strict(message)
    return _packed_json(message)


def unpack_wire_message(raw):
    """Decode a plain or compressed gossip payload into a protocol object."""

    if isinstance(raw, dict):
        return raw
    return _unpacked_json(raw)


def _store_json(data):
    return _packed_json(data)


def _load_json(raw):
    if isinstance(raw, dict):
        return raw
    return _unpacked_json(raw)


def sha3_hex(data):
    """Return the SHA3-256 hex digest used throughout the IND protocol."""

    if isinstance(data, str):
        data = data.encode("utf-8")
    return sha3_256(data).hexdigest()


def b85_sign(private_key_base85, data):
    """Sign canonical protocol bytes with a base85-encoded secp256k1 private key."""

    private_key_decode = base64.b85decode(private_key_base85.strip())
    signing_key = ecdsa.SigningKey.from_string(
        private_key_decode,
        curve=ecdsa.SECP256k1,
        hashfunc=sha3_256,
    )
    signature = signing_key.sign_deterministic(
        data,
        hashfunc=sha3_256,
        sigencode=ecdsa_util.sigencode_string_canonize,
    )
    return base64.b85encode(signature).decode("utf-8")


def b85_verify(public_key_base85, signature_base85, data):
    """Verify a base85-encoded secp256k1 signature without leaking parser errors."""

    try:
        public_key_base85 = public_key_base85.strip()
        verifying_key = _VERIFY_KEY_CACHE.get(public_key_base85)
        if verifying_key is None:
            public_key_decode = base64.b85decode(public_key_base85)
            verifying_key = ecdsa.VerifyingKey.from_string(
                public_key_decode,
                curve=ecdsa.SECP256k1,
                hashfunc=sha3_256,
            )
            if len(_VERIFY_KEY_CACHE) >= MAX_VERIFY_KEY_CACHE:
                _VERIFY_KEY_CACHE.pop(next(iter(_VERIFY_KEY_CACHE)))
            _VERIFY_KEY_CACHE[public_key_base85] = verifying_key
        signature_decode = base64.b85decode(signature_base85.strip())
        if len(signature_decode) != 64:
            return False
        _r, s = ecdsa_util.sigdecode_string(signature_decode, ecdsa.SECP256k1.order)
        if s > ecdsa.SECP256k1.order // 2:
            return False
        return verifying_key.verify(
            signature_decode,
            data,
            hashfunc=sha3_256,
            sigdecode=ecdsa_util.sigdecode_string,
        )
    except Exception:
        return False


def signature_payload(domain, data):
    """Return domain-separated bytes for signing one specific IND object type."""

    domain = _require_str(str(domain), "signature domain", max_bytes=128)
    if isinstance(data, bytes):
        payload = data
    else:
        payload = _canonical_bytes(data)
    return b"IND-SIGNATURE-V1:" + domain.encode("ascii") + b"\n" + payload


def b85_sign_domain(private_key_base85, domain, data):
    """Sign protocol data with an explicit domain separator."""

    return b85_sign(private_key_base85, signature_payload(domain, data))


def b85_verify_domain(public_key_base85, signature_base85, domain, data):
    """Verify a domain-separated IND protocol signature."""

    return b85_verify(public_key_base85, signature_base85, signature_payload(domain, data))


def numerology_signature():
    material = f"IND:{TOTAL_SUPPLY}:{ADDRESS_LENGTH}:{ANGEL_NUMBER}:{MONEY_NUMBER}:{BIRTHDAY_CODE}".encode("ascii")
    return {
        "master_number": MASTER_SUPPLY_NUMBER,
        "angel_number": ANGEL_NUMBER,
        "money_number": MONEY_NUMBER,
        "birthday_number": BIRTHDAY_NUMBER,
        "birthday_code": BIRTHDAY_CODE,
        "address_length": ADDRESS_LENGTH,
        "fixed_supply": TOTAL_SUPPLY,
        "seal": sha3_256(material).hexdigest()[:ADDRESS_TARGET_LENGTH],
    }


def _with_numerology_metadata(metadata, limit, label):
    metadata = copy.deepcopy(metadata or {})
    metadata.setdefault(NUMEROLOGY_METADATA_KEY, numerology_signature())
    _require_metadata(metadata, limit, label)
    return metadata


def _address_payload_from_public_key(public_key_base85, payload_chars=ADDRESS_PAYLOAD_CHARS):
    digest = sha3_256(public_key_base85.strip().encode("utf-8")).digest()
    return base58.b58encode(digest).decode("utf-8")[:payload_chars]


def _fixed_base58(data, length):
    encoded = base58.b58encode(data).decode("utf-8")
    if len(encoded) > length:
        raise ValidationError("address checksum encoding overflow")
    return encoded.rjust(length, "1")


def _address_checksum(version, payload):
    material = f"IND-address:{version}:{payload}".encode("ascii")
    digest = sha3_256(material).digest()[:ADDRESS_CHECKSUM_BYTES]
    return _fixed_base58(digest, ADDRESS_CHECKSUM_CHARS)


def legacy_address_from_public_key(public_key_base85):
    """Derive the pre-checksum IND address for old wallets and token histories."""

    digest = sha3_256(public_key_base85.strip().encode("utf-8")).digest()
    return base58.b58encode(digest).decode("utf-8")[:LEGACY_ADDRESS_LENGTH]


def previous_address_from_public_key(public_key_base85):
    """Derive the old 37-character checked address accepted for existing wallets."""

    payload = _address_payload_from_public_key(public_key_base85, PREVIOUS_ADDRESS_PAYLOAD_CHARS)
    checksum = _address_checksum(ADDRESS_VERSION, payload)
    return f"{ADDRESS_PREFIX}{ADDRESS_VERSION}{payload}{checksum}{ADDRESS_SUFFIX}"


def address_from_public_key(public_key_base85):
    """Derive the checksummed, versioned user-facing IND address from a base85 public key."""

    payload = _address_payload_from_public_key(public_key_base85)
    checksum = _address_checksum(ADDRESS_VERSION, payload)
    return f"{ADDRESS_PREFIX}{ADDRESS_VERSION}{payload}{checksum}{ADDRESS_SUFFIX}"


def is_legacy_address(address):
    if not isinstance(address, str) or len(address) != LEGACY_ADDRESS_LENGTH:
        return False
    return all(char in BASE58_ALPHABET for char in address)


def _is_versioned_address(address, payload_chars):
    expected_length = len(ADDRESS_PREFIX) + len(ADDRESS_VERSION) + payload_chars + ADDRESS_CHECKSUM_CHARS + len(ADDRESS_SUFFIX)
    if not isinstance(address, str) or len(address) != expected_length:
        return False
    if not address.startswith(ADDRESS_PREFIX + ADDRESS_VERSION) or not address.endswith(ADDRESS_SUFFIX):
        return False
    payload_start = len(ADDRESS_PREFIX) + len(ADDRESS_VERSION)
    payload_end = payload_start + payload_chars
    payload = address[payload_start:payload_end]
    checksum = address[payload_end:-len(ADDRESS_SUFFIX)]
    if len(payload) != payload_chars or len(checksum) != ADDRESS_CHECKSUM_CHARS:
        return False
    if not all(char in BASE58_ALPHABET for char in payload + checksum):
        return False
    return checksum == _address_checksum(ADDRESS_VERSION, payload)


def is_current_address(address):
    return _is_versioned_address(address, ADDRESS_PAYLOAD_CHARS)


def is_previous_address(address):
    return _is_versioned_address(address, PREVIOUS_ADDRESS_PAYLOAD_CHARS)


def validate_address(address, label="address", allow_legacy=True):
    """Return a valid IND address or raise ValidationError."""

    if not isinstance(address, str) or address != address.strip():
        raise ValidationError(f"invalid {label}")
    if is_current_address(address):
        return address
    if allow_legacy and is_previous_address(address):
        return address
    if allow_legacy and is_legacy_address(address):
        return address
    raise ValidationError(f"invalid {label}")


def public_key_matches_address(public_key_base85, address):
    try:
        address = validate_address(address)
    except ValidationError:
        return False
    if is_current_address(address):
        return address == address_from_public_key(public_key_base85)
    if is_previous_address(address):
        return address == previous_address_from_public_key(public_key_base85)
    return address == legacy_address_from_public_key(public_key_base85)


def _owner_address_for_public_key(public_key_base85, owner_address, label):
    owner_address = validate_address(owner_address, "owner address")
    if public_key_matches_address(public_key_base85, owner_address):
        return owner_address
    raise ValidationError(f"{label} does not own the token tip")


def _without_signature(data):
    unsigned = copy.deepcopy(data)
    unsigned.pop("signature", None)
    return unsigned


def _require_metadata(metadata, limit, label):
    if not isinstance(metadata, dict):
        raise ValidationError(f"{label} metadata must be an object")
    _validate_json_value(metadata, f"{label} metadata")
    if len(_canonical_bytes(metadata)) > int(limit):
        raise ValidationError(f"{label} metadata is too large")


def _trusted_genesis_keys():
    try:
        from . import settings as ind_settings
        return ind_settings.trusted_genesis_issuer_keys()
    except Exception:
        raw = os.environ.get("IND_TRUSTED_GENESIS_ISSUER_KEYS", "")
        return {key.strip() for key in raw.split(",") if key.strip()}


def _trusted_genesis_manifest_hashes():
    try:
        from . import settings as ind_settings
        return ind_settings.trusted_genesis_manifest_hashes()
    except Exception:
        raw = os.environ.get("IND_TRUSTED_GENESIS_MANIFEST_HASHES", "")
        return {item.strip().lower() for item in raw.split(",") if item.strip()}


def _allow_untrusted_genesis():
    try:
        from . import settings as ind_settings
        return ind_settings.allow_untrusted_genesis()
    except Exception:
        return os.environ.get("IND_ALLOW_UNTRUSTED_GENESIS", "").strip().lower() in {"1", "true", "yes"}


def token_display_id(token):
    """Return the compact denomination/index label shown in wallets."""

    genesis = token["genesis"]
    value = int(genesis.get("value", 1))
    index = int(genesis["index"])
    return f"{value}x{index}"


def _timestamp_day(timestamp):
    return int(timestamp) // 86400


def _last_history_timestamp(token):
    history = token.get("history", [])
    if not history:
        return None
    return int(history[-1]["timestamp"])


def _state_ref_from_state(state):
    return {
        "type": TOKEN_STATE_REF_TYPE,
        "version": TOKEN_VERSION,
        "token_id": state.token_id,
        "display_id": state.display_id,
        "owner_address": state.owner_address,
        "last_transfer_hash": state.last_transfer_hash,
        "sequence": int(state.sequence),
        "value": int(state.value),
    }


def genesis_hash(genesis):
    """Hash a complete signed genesis record."""

    return sha3_hex(_canonical_bytes(genesis))


def transfer_hash(transfer):
    """Hash a complete signed transfer record."""

    return sha3_hex(_canonical_bytes(transfer))


def message_hash(message):
    """Hash a full gossip message for deduplication and storage."""

    return sha3_hex(_canonical_bytes(message))


def _genesis_commitment(index, owner_address, value, nonce, issued_at):
    material = {
        "algorithm": "IND-GENESIS-SUCCESS-v1",
        "index": int(index),
        "owner_address": owner_address,
        "value": int(value),
        "nonce": nonce,
        "issued_at": int(issued_at),
    }
    return sha3_hex(_canonical_bytes(material))


def _unsigned_manifest(manifest):
    unsigned = copy.deepcopy(manifest)
    unsigned.pop("signature", None)
    unsigned.pop("manifest_hash", None)
    return unsigned


def genesis_manifest_hash(manifest):
    """Hash the unsigned launch manifest that defines the lazy genesis supply map."""

    return sha3_hex(_canonical_bytes(_unsigned_manifest(manifest)))


def make_denomination_ranges(denomination_counts, owner_address, start_index=0, nonce_seed_prefix=GENESIS_NONCE_SEED_PREFIX):
    """Build contiguous denomination ranges for a signed lazy-genesis manifest."""

    owner_address = validate_address(str(owner_address).strip(), "owner address")
    ranges = []
    next_index = int(start_index)
    for value, count in denomination_counts:
        value = int(value)
        count = int(count)
        if value <= 0:
            raise ValidationError("denomination value must be positive")
        if count <= 0:
            raise ValidationError("denomination count must be positive")
        ranges.append({
            "start_index": next_index,
            "count": count,
            "value": value,
            "owner_address": owner_address,
            "nonce_seed": sha3_hex(f"{nonce_seed_prefix}:{next_index}:{count}:{value}:{owner_address}"),
        })
        next_index += count
    return ranges


def _validate_manifest_ranges(ranges):
    if not isinstance(ranges, list) or not ranges:
        raise ValidationError("genesis manifest must contain ranges")
    normalized = []
    total_count = 0
    total_value = 0
    for item in ranges:
        _require_exact_fields(item, GENESIS_MANIFEST_RANGE_FIELDS, "genesis manifest range")
        start_index = _require_int(item["start_index"], "genesis manifest range start_index", minimum=0)
        count = _require_int(item["count"], "genesis manifest range count", minimum=1)
        value = _require_int(item["value"], "genesis manifest range value", minimum=1)
        nonce_seed = _require_str(item["nonce_seed"], "genesis manifest range nonce seed")
        if start_index < 0 or count <= 0 or value <= 0:
            raise ValidationError("invalid genesis manifest range values")
        owner_address = validate_address(item["owner_address"], "manifest owner address")
        end_index = start_index + count
        if end_index > TOTAL_SUPPLY:
            raise ValidationError("genesis manifest range outside fixed IND supply")
        normalized.append({
            "start_index": start_index,
            "end_index": end_index,
            "count": count,
            "value": value,
            "owner_address": owner_address,
            "nonce_seed": nonce_seed,
        })
        total_count += count
        total_value += count * value
    normalized.sort(key=lambda item: item["start_index"])
    for previous, current in zip(normalized, normalized[1:]):
        if current["start_index"] < previous["end_index"]:
            raise ValidationError("genesis manifest ranges overlap")
    if total_count > TOTAL_SUPPLY:
        raise ValidationError("genesis manifest exceeds fixed IND token supply")
    return normalized, total_count, total_value


def make_genesis_manifest(ranges, issuer_private_key, issuer_public_key, issued_at=None, metadata=None):
    """Create the issuer-signed supply manifest used to mint lazy genesis tokens."""

    normalized, total_count, total_value = _validate_manifest_ranges(ranges)
    metadata = _with_numerology_metadata(metadata, MAX_GENESIS_METADATA_BYTES, "genesis manifest")
    issued_at = int(issued_at or time.time())
    if issued_at > int(time.time()) + MAX_TRANSFER_FUTURE_SKEW_SECONDS:
        raise ValidationError("genesis manifest issued_at is too far in the future")
    manifest_unsigned = {
        "type": GENESIS_MANIFEST_TYPE,
        "version": TOKEN_VERSION,
        "issuer_public_key": issuer_public_key,
        "issued_at": issued_at,
        "total_token_count": total_count,
        "total_value": total_value,
        "ranges": [
            {
                "start_index": item["start_index"],
                "count": item["count"],
                "value": item["value"],
                "owner_address": item["owner_address"],
                "nonce_seed": item["nonce_seed"],
            }
            for item in normalized
        ],
        "metadata": metadata,
    }
    manifest = copy.deepcopy(manifest_unsigned)
    manifest["signature"] = b85_sign_domain(
        issuer_private_key,
        GENESIS_MANIFEST_SIGNATURE_DOMAIN,
        manifest_unsigned,
    )
    manifest["manifest_hash"] = genesis_manifest_hash(manifest)
    return manifest


def verify_genesis_manifest(manifest, now=None):
    """Validate a signed supply manifest against local trust pins and range totals."""

    _require_exact_fields(
        manifest,
        GENESIS_MANIFEST_FIELDS,
        "genesis manifest",
        optional={"manifest_hash"},
    )
    if manifest["type"] != GENESIS_MANIFEST_TYPE or _require_int(manifest["version"], "genesis manifest version") != TOKEN_VERSION:
        raise ValidationError("unsupported genesis manifest version")
    _require_metadata(manifest["metadata"], MAX_GENESIS_METADATA_BYTES, "genesis manifest")
    issued_at = _require_int(manifest["issued_at"], "genesis manifest issued_at", minimum=0)
    if issued_at > current_time(now) + MAX_TRANSFER_FUTURE_SKEW_SECONDS:
        raise ValidationError("genesis manifest issued_at is too far in the future")
    normalized, total_count, total_value = _validate_manifest_ranges(manifest["ranges"])
    if _require_int(manifest["total_token_count"], "genesis manifest total_token_count", minimum=1) != total_count:
        raise ValidationError("genesis manifest token count mismatch")
    if _require_int(manifest["total_value"], "genesis manifest total_value", minimum=1) != total_value:
        raise ValidationError("genesis manifest value mismatch")
    unsigned = _unsigned_manifest(manifest)
    manifest_hash_value = genesis_manifest_hash(manifest)
    if manifest.get("manifest_hash") and _require_str(manifest["manifest_hash"], "genesis manifest hash") != manifest_hash_value:
        raise ValidationError("genesis manifest hash mismatch")
    trusted_keys = _trusted_genesis_keys()
    trusted_manifest_hashes = _trusted_genesis_manifest_hashes()
    issuer_public_key = _require_str(manifest["issuer_public_key"], "genesis manifest issuer public key")
    if not trusted_keys and not trusted_manifest_hashes and not _allow_untrusted_genesis():
        raise ValidationError("no trusted genesis issuer keys or manifest hashes configured")
    if trusted_keys and issuer_public_key not in trusted_keys:
        raise ValidationError("genesis issuer key is not trusted by this node")
    if trusted_manifest_hashes and manifest_hash_value not in trusted_manifest_hashes:
        raise ValidationError("genesis manifest hash is not trusted by this node")
    if not b85_verify_domain(
        issuer_public_key,
        manifest["signature"],
        GENESIS_MANIFEST_SIGNATURE_DOMAIN,
        unsigned,
    ):
        raise ValidationError("invalid genesis manifest signature")
    return manifest_hash_value, normalized


def _manifest_range_for_index(manifest, index):
    _manifest_hash_value, ranges = verify_genesis_manifest(manifest)
    index = int(index)
    for item in ranges:
        if item["start_index"] <= index < item["end_index"]:
            return item
    raise ValidationError("genesis index is not covered by manifest")


def _lazy_genesis_nonce(manifest_hash_value, range_def, index):
    material = {
        "algorithm": "IND-LAZY-GENESIS-NONCE-v1",
        "manifest_hash": manifest_hash_value,
        "index": int(index),
        "range_start": int(range_def["start_index"]),
        "range_count": int(range_def["count"]),
        "value": int(range_def["value"]),
        "owner_address": range_def["owner_address"],
        "nonce_seed": range_def["nonce_seed"],
    }
    return sha3_hex(_canonical_bytes(material))


def make_lazy_genesis_token(index, manifest, metadata=None):
    """Materialize one token from a signed lazy-genesis manifest."""

    manifest_hash_value, ranges = verify_genesis_manifest(manifest)
    index = int(index)
    range_def = None
    for item in ranges:
        if item["start_index"] <= index < item["end_index"]:
            range_def = item
            break
    if not range_def:
        raise ValidationError("genesis index is not covered by manifest")
    metadata = _with_numerology_metadata(metadata, MAX_GENESIS_METADATA_BYTES, "genesis")
    value = int(range_def["value"])
    owner_address = range_def["owner_address"]
    issued_at = int(manifest["issued_at"])
    nonce = _lazy_genesis_nonce(manifest_hash_value, range_def, index)
    manifest_ref = {
        "type": GENESIS_MANIFEST_REF_TYPE,
        "manifest_hash": manifest_hash_value,
        "manifest": manifest,
    }
    genesis_unsigned = {
        "type": "ind.genesis.v1",
        "version": TOKEN_VERSION,
        "index": index,
        "value": value,
        "owner_address": owner_address,
        "issuer_public_key": manifest["issuer_public_key"],
        "issued_at": issued_at,
        "nonce": nonce,
        "success_commitment": _genesis_commitment(index, owner_address, value, nonce, issued_at),
        "metadata": metadata,
        "manifest_ref": manifest_ref,
    }
    token_id = "ind1_" + sha3_hex(_canonical_bytes(genesis_unsigned))[:56]
    genesis = copy.deepcopy(genesis_unsigned)
    genesis["signature"] = manifest["signature"]
    return {
        "type": TOKEN_TYPE,
        "version": TOKEN_VERSION,
        "token_id": token_id,
        "genesis": genesis,
        "history": [],
    }


def make_genesis_token(index, owner_address, issuer_private_key, issuer_public_key, value=1, nonce=None, metadata=None, issued_at=None):
    """Create a fully materialized genesis token signed directly by the issuer."""

    index = int(index)
    owner_address = validate_address(str(owner_address).strip(), "owner address")
    if index < 0 or index >= TOTAL_SUPPLY:
        raise ValidationError("genesis index outside fixed IND supply")
    if value <= 0:
        raise ValidationError("token value must be positive")
    metadata = _with_numerology_metadata(metadata, MAX_GENESIS_METADATA_BYTES, "genesis")
    issued_at = int(issued_at or time.time())
    if issued_at > int(time.time()) + MAX_TRANSFER_FUTURE_SKEW_SECONDS:
        raise ValidationError("genesis issued_at is too far in the future")
    nonce = nonce or sha3_hex(f"{index}:{owner_address}:{time.time_ns()}")
    genesis_unsigned = {
        "type": "ind.genesis.v1",
        "version": TOKEN_VERSION,
        "index": index,
        "value": int(value),
        "owner_address": owner_address,
        "issuer_public_key": issuer_public_key,
        "issued_at": issued_at,
        "nonce": nonce,
        "success_commitment": _genesis_commitment(index, owner_address, value, nonce, issued_at),
        "metadata": metadata,
    }
    token_id = "ind1_" + sha3_hex(_canonical_bytes(genesis_unsigned))[:56]
    signature = b85_sign_domain(issuer_private_key, GENESIS_SIGNATURE_DOMAIN, genesis_unsigned)
    genesis = copy.deepcopy(genesis_unsigned)
    genesis["signature"] = signature
    return {
        "type": TOKEN_TYPE,
        "version": TOKEN_VERSION,
        "token_id": token_id,
        "genesis": genesis,
        "history": [],
    }


def verify_genesis(genesis, token_id, now=None):
    """Validate a genesis record and prove that it belongs to the supplied token id."""

    _require_exact_fields(genesis, GENESIS_FIELDS, "genesis", optional={"manifest_ref"})
    if genesis["type"] != "ind.genesis.v1" or _require_int(genesis["version"], "genesis version") != TOKEN_VERSION:
        raise ValidationError("unsupported genesis version")
    index = _require_int(genesis["index"], "genesis index", minimum=0, maximum=TOTAL_SUPPLY - 1)
    value = _require_int(genesis["value"], "genesis value", minimum=1)
    if index < 0 or index >= TOTAL_SUPPLY:
        raise ValidationError("genesis index outside fixed IND supply")
    if value <= 0:
        raise ValidationError("token value must be positive")
    owner_address = validate_address(genesis["owner_address"], "genesis owner address")
    _require_metadata(genesis["metadata"], MAX_GENESIS_METADATA_BYTES, "genesis")
    issued_at = _require_int(genesis["issued_at"], "genesis issued_at", minimum=0)
    if issued_at > current_time(now) + MAX_TRANSFER_FUTURE_SKEW_SECONDS:
        raise ValidationError("genesis issued_at is too far in the future")
    expected_commitment = _genesis_commitment(index, owner_address, value, genesis["nonce"], issued_at)
    if genesis["success_commitment"] != expected_commitment:
        raise ValidationError("genesis commitment does not resolve to the IND success state")
    unsigned = _without_signature(genesis)
    expected_token_id = "ind1_" + sha3_hex(_canonical_bytes(unsigned))[:56]
    if token_id != expected_token_id:
        raise ValidationError("token id does not match genesis structure")
    issuer_public_key = genesis["issuer_public_key"]
    if "manifest_ref" in genesis:
        manifest_ref = genesis["manifest_ref"]
        _require_exact_fields(manifest_ref, GENESIS_MANIFEST_REF_FIELDS, "genesis manifest reference")
        if manifest_ref.get("type") != GENESIS_MANIFEST_REF_TYPE:
            raise ValidationError("malformed genesis manifest reference")
        manifest_hash_value, ranges = verify_genesis_manifest(manifest_ref["manifest"], now=now)
        if manifest_ref["manifest_hash"] != manifest_hash_value:
            raise ValidationError("genesis manifest reference hash mismatch")
        range_def = None
        for item in ranges:
            if item["start_index"] <= index < item["end_index"]:
                range_def = item
                break
        if not range_def:
            raise ValidationError("genesis index is not covered by manifest")
        if int(range_def["value"]) != value:
            raise ValidationError("genesis value does not match manifest range")
        if range_def["owner_address"] != owner_address:
            raise ValidationError("genesis owner does not match manifest range")
        if manifest_ref["manifest"]["issuer_public_key"] != issuer_public_key:
            raise ValidationError("genesis issuer does not match manifest")
        if _require_int(manifest_ref["manifest"]["issued_at"], "genesis manifest issued_at") != issued_at:
            raise ValidationError("genesis issued_at does not match manifest")
        expected_nonce = _lazy_genesis_nonce(manifest_hash_value, range_def, index)
        if genesis["nonce"] != expected_nonce:
            raise ValidationError("genesis nonce does not match manifest")
        if genesis["signature"] != manifest_ref["manifest"]["signature"]:
            raise ValidationError("genesis signature does not match manifest signature")
        return
    trusted_keys = _trusted_genesis_keys()
    if not trusted_keys and not _allow_untrusted_genesis():
        raise ValidationError("no trusted genesis issuer keys configured")
    if trusted_keys and issuer_public_key not in trusted_keys:
        raise ValidationError("genesis issuer key is not trusted by this node")
    if not b85_verify_domain(issuer_public_key, genesis["signature"], GENESIS_SIGNATURE_DOMAIN, unsigned):
        raise ValidationError("invalid genesis issuer signature")


def _verify_transfer_signature(transfer):
    sender_public_key = transfer["sender_public_key"]
    sender_address = validate_address(transfer["sender_address"], "sender address")
    if not public_key_matches_address(sender_public_key, sender_address):
        raise ValidationError("sender public key does not match sender address")
    if not b85_verify_domain(
        sender_public_key,
        transfer["signature"],
        TRANSFER_SIGNATURE_DOMAIN,
        _without_signature(transfer),
    ):
        raise ValidationError("invalid transfer signature")


def _env_true(name):
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def current_time(now=None):
    """Normalize protocol wall-clock input so validation paths share one clock hook."""

    return int(time.time() if now is None else now)


def _configured_transparency_verifier():
    try:
        from . import settings as ind_settings
        require_transparency = ind_settings.require_transparency_log()
    except Exception:
        require_transparency = _env_true("IND_REQUIRE_TRANSPARENCY_LOG")
    if not require_transparency:
        return None
    try:
        from . import transparency_client as log_client
    except Exception as exc:
        raise ValidationError("transparency log client is unavailable") from exc
    verifier = log_client.verifier_from_environment(strict_mode=True)
    if verifier is None:
        raise ValidationError("transparency log verification is required but not configured")
    return verifier


def _configured_transparency_submitter():
    if not _env_true("IND_SUBMIT_TO_TRANSPARENCY_LOG"):
        return None
    try:
        from . import transparency_client as log_client
    except Exception as exc:
        raise ValidationError("transparency log client is unavailable") from exc
    return log_client.submitter_from_environment()


def _environment_transparency_verifier():
    try:
        from . import transparency_client as log_client
    except Exception:
        return None
    return log_client.verifier_from_environment()


def verify_token_transparency(token, transparency_verifier, now=None, require_current_root=True):
    """Verify that every transfer in a token history is present in the public log."""

    if transparency_verifier is None:
        raise ValidationError("transparency verifier is required")
    try:
        transparency_verifier.verify_token(token, now=now, require_current_root=require_current_root)
    except Exception as exc:
        raise ValidationError(f"transparency log verification failed: {exc}") from exc
    return True


def verify_token(
    token,
    now=None,
    transparency_verifier=None,
    require_transparency=False,
    require_current_root=True,
):
    """Validate a complete bearer token and return the owner at the current tip."""

    if isinstance(token, str):
        token = _load_json(token)
    _require_exact_fields(token, TOKEN_FIELDS, "token payload")
    if token.get("type") != TOKEN_TYPE:
        raise ValidationError("malformed token payload")
    if _require_int(token.get("version"), "token version") != TOKEN_VERSION:
        raise ValidationError("unsupported token version")
    token_id = _require_str(token.get("token_id"), "token id")
    if not token_id:
        raise ValidationError("missing token id")

    genesis = token.get("genesis")
    verify_genesis(genesis, token_id, now=now)
    owner_address = validate_address(genesis["owner_address"], "genesis owner address")
    issued_at = int(genesis["issued_at"])
    last_hash = genesis_hash(genesis)
    sequence = 0
    previous_timestamp = None
    transfer_days = {}
    max_allowed_timestamp = current_time(now) + MAX_TRANSFER_FUTURE_SKEW_SECONDS

    history = token.get("history", [])
    if not isinstance(history, list):
        raise ValidationError("token history must be a list")

    for transfer in history:
        _require_exact_fields(transfer, TRANSFER_FIELDS, "transfer")
        if transfer["type"] != TRANSFER_TYPE or _require_int(transfer["version"], "transfer version") != TOKEN_VERSION:
            raise ValidationError("unsupported transfer version")
        _require_metadata(transfer["metadata"], MAX_TRANSFER_METADATA_BYTES, "transfer")
        if transfer["token_id"] != token_id:
            raise ValidationError("transfer references a different token")
        sender_address = validate_address(transfer["sender_address"], "sender address")
        recipient_address = validate_address(transfer["recipient_address"], "recipient address")
        transfer_sequence = _require_int(transfer["sequence"], "transfer sequence", minimum=1)
        if transfer_sequence != sequence + 1:
            raise ValidationError("transfer sequence gap")
        if transfer["previous_hash"] != last_hash:
            raise ValidationError("transfer does not extend the current token tip")
        if sender_address != owner_address:
            raise ValidationError("transfer sender is not the current owner")
        transfer_timestamp = _require_int(transfer["timestamp"], "transfer timestamp", minimum=0)
        if transfer_timestamp > max_allowed_timestamp:
            raise ValidationError("transfer timestamp is too far in the future")
        if transfer_timestamp < issued_at:
            raise ValidationError("transfer timestamp predates genesis")
        if previous_timestamp is not None and transfer_timestamp <= previous_timestamp:
            raise ValidationError("transfer timestamps must be strictly increasing")
        transfer_day = _timestamp_day(transfer_timestamp)
        transfer_days[transfer_day] = transfer_days.get(transfer_day, 0) + 1
        if transfer_days[transfer_day] > MAX_TRANSFERS_PER_TOKEN_PER_DAY:
            raise ValidationError("token exceeds daily transfer limit")
        _verify_transfer_signature(transfer)
        owner_address = recipient_address
        last_hash = transfer_hash(transfer)
        sequence = transfer_sequence
        previous_timestamp = transfer_timestamp

    state = TokenState(
        token_id=token_id,
        owner_address=owner_address,
        last_transfer_hash=last_hash,
        sequence=sequence,
        display_id=token_display_id(token),
        value=int(genesis.get("value", 1)),
    )
    if transparency_verifier is None and require_transparency:
        transparency_verifier = _configured_transparency_verifier()
    if transparency_verifier is not None:
        verify_token_transparency(
            token,
            transparency_verifier,
            now=now,
            require_current_root=require_current_root,
        )
    elif require_transparency:
        raise ValidationError("transparency log verification is required but not configured")
    return state


def create_transfer(token, sender_private_key, sender_public_key, recipient_address, metadata=None, timestamp=None):
    """Append a signed transfer from the current owner to a recipient address."""

    recipient_address = validate_address(str(recipient_address).strip(), "recipient address")
    state = verify_token(token)
    sender_address = _owner_address_for_public_key(sender_public_key, state.owner_address, "sender key")
    transfer_timestamp = int(timestamp or time.time())
    previous_timestamp = _last_history_timestamp(token)
    if previous_timestamp is not None:
        transfer_timestamp = max(transfer_timestamp, previous_timestamp + 1)
    transfer_unsigned = {
        "type": TRANSFER_TYPE,
        "version": TOKEN_VERSION,
        "token_id": state.token_id,
        "sequence": state.sequence + 1,
        "previous_hash": state.last_transfer_hash,
        "sender_address": sender_address,
        "sender_public_key": sender_public_key,
        "recipient_address": recipient_address,
        "timestamp": transfer_timestamp,
        "metadata": metadata or {},
    }
    transfer_signed = copy.deepcopy(transfer_unsigned)
    transfer_signed["signature"] = b85_sign_domain(
        sender_private_key,
        TRANSFER_SIGNATURE_DOMAIN,
        transfer_unsigned,
    )
    new_token = copy.deepcopy(token)
    new_token.setdefault("history", []).append(transfer_signed)
    verify_token(new_token)
    return new_token


def create_transfer_announcement(token, now=None):
    """Wrap the latest transfer in the gossip message nodes relay to peers."""

    state = verify_token(token)
    if state.sequence == 0:
        raise ValidationError("genesis token has no transfer to announce")
    return {
        "type": TRANSFER_ANNOUNCEMENT_TYPE,
        "version": TOKEN_VERSION,
        "token": token,
        "announced_at": current_time(now),
    }


def create_receipt(token, recipient_private_key, recipient_public_key, timestamp=None, now=None):
    """Countersign the token tip to show that the recipient has seen the transfer."""

    state = verify_token(token)
    if state.sequence == 0:
        raise ValidationError("genesis ownership does not require a receipt")
    recipient_address = _owner_address_for_public_key(recipient_public_key, state.owner_address, "receipt key")
    tip_timestamp = _last_history_timestamp(token)
    wall_now = current_time(now)
    received_at = int(timestamp if timestamp is not None else wall_now)
    if timestamp is None and tip_timestamp is not None:
        received_at = max(received_at, tip_timestamp)
    if tip_timestamp is not None and received_at < tip_timestamp:
        raise ValidationError("receipt timestamp predates transfer")
    if received_at > wall_now + MAX_TRANSFER_FUTURE_SKEW_SECONDS:
        raise ValidationError("receipt timestamp is too far in the future")
    receipt_unsigned = {
        "type": RECEIPT_TYPE,
        "version": TOKEN_VERSION,
        "token_id": state.token_id,
        "transfer_hash": state.last_transfer_hash,
        "sequence": state.sequence,
        "recipient_address": recipient_address,
        "recipient_public_key": recipient_public_key,
        "received_at": received_at,
    }
    receipt_signed = copy.deepcopy(receipt_unsigned)
    receipt_signed["signature"] = b85_sign_domain(
        recipient_private_key,
        RECEIPT_SIGNATURE_DOMAIN,
        receipt_unsigned,
    )
    return receipt_signed


def create_receipt_announcement(token, recipient_private_key, recipient_public_key, now=None):
    """Build the gossip message that moves a received transfer into local settlement."""

    receipt = create_receipt(token, recipient_private_key, recipient_public_key, now=now)
    return {
        "type": RECEIPT_ANNOUNCEMENT_TYPE,
        "version": TOKEN_VERSION,
        "token": token,
        "receipt": receipt,
        "announced_at": current_time(now),
    }


def verify_receipt_announcement(
    message,
    transparency_verifier=None,
    require_transparency=False,
    now=None,
    require_current_root=True,
):
    """Validate a recipient receipt against the token tip it claims to acknowledge."""

    if isinstance(message, str):
        message = _load_json(message)
    _require_exact_fields(message, RECEIPT_ANNOUNCEMENT_FIELDS, "receipt announcement")
    if message.get("type") != RECEIPT_ANNOUNCEMENT_TYPE:
        raise ValidationError("not a receipt announcement")
    if _require_int(message["version"], "receipt announcement version") != TOKEN_VERSION:
        raise ValidationError("unsupported receipt announcement version")
    token = message.get("token")
    receipt = message.get("receipt")
    state = verify_token(
        token,
        now=now,
        transparency_verifier=transparency_verifier,
        require_transparency=require_transparency,
        require_current_root=require_current_root,
    )
    _require_exact_fields(receipt, RECEIPT_FIELDS, "receipt")
    if receipt.get("type") != RECEIPT_TYPE:
        raise ValidationError("malformed receipt")
    if _require_int(receipt["version"], "receipt version") != TOKEN_VERSION:
        raise ValidationError("unsupported receipt version")
    if receipt["token_id"] != state.token_id:
        raise ValidationError("receipt references a different token")
    if receipt["transfer_hash"] != state.last_transfer_hash:
        raise ValidationError("receipt does not reference the token tip")
    if _require_int(receipt["sequence"], "receipt sequence", minimum=1) != state.sequence:
        raise ValidationError("receipt sequence does not match token tip")
    received_at = _require_int(receipt["received_at"], "receipt received_at", minimum=0)
    tip_timestamp = _last_history_timestamp(token)
    if tip_timestamp is not None and received_at < tip_timestamp:
        raise ValidationError("receipt timestamp predates transfer")
    if received_at > current_time(now) + MAX_TRANSFER_FUTURE_SKEW_SECONDS:
        raise ValidationError("receipt timestamp is too far in the future")
    recipient_address = validate_address(receipt["recipient_address"], "recipient address")
    if recipient_address != state.owner_address:
        raise ValidationError("receipt signer is not the token recipient")
    if not public_key_matches_address(receipt["recipient_public_key"], recipient_address):
        raise ValidationError("receipt public key does not match recipient address")
    if not b85_verify_domain(
        receipt["recipient_public_key"],
        receipt["signature"],
        RECEIPT_SIGNATURE_DOMAIN,
        _without_signature(receipt),
    ):
        raise ValidationError("invalid receipt signature")
    return state


def _last_transfer(token):
    history = token.get("history", [])
    if not history:
        raise ValidationError("token has no transfer")
    return history[-1]


def _conflict_key(transfer):
    return (
        transfer["token_id"],
        int(transfer["sequence"]),
        transfer["previous_hash"],
        transfer["sender_address"],
        transfer["sender_public_key"],
    )


def _find_conflicting_transfer_pair(token_a, token_b):
    state_a = verify_token(token_a)
    state_b = verify_token(token_b)
    if state_a.token_id != state_b.token_id:
        return None
    transfers_a = {}
    for transfer in token_a.get("history", []):
        transfers_a.setdefault(_conflict_key(transfer), []).append(transfer)
    for transfer_b in token_b.get("history", []):
        for transfer_a in transfers_a.get(_conflict_key(transfer_b), []):
            if transfer_hash(transfer_a) != transfer_hash(transfer_b):
                return transfer_a, transfer_b
    return None


def _conflicting_transfers(token_a, token_b):
    return _find_conflicting_transfer_pair(token_a, token_b) is not None


def _conflict_proof_unsigned(token_a, token_b, transfer_a, transfer_b, detected_at):
    hash_a = transfer_hash(transfer_a)
    hash_b = transfer_hash(transfer_b)
    if hash_b < hash_a:
        token_a, token_b = token_b, token_a
        transfer_a, transfer_b = transfer_b, transfer_a
        hash_a, hash_b = hash_b, hash_a
    return (
        {
            "type": CONFLICT_PROOF_TYPE,
            "version": TOKEN_VERSION,
            "token_id": transfer_a["token_id"],
            "previous_hash": transfer_a["previous_hash"],
            "sequence": int(transfer_a["sequence"]),
            "transfer_hash_a": hash_a,
            "transfer_hash_b": hash_b,
            "token_a": token_a,
            "token_b": token_b,
            "detected_at": int(detected_at),
        }
    )


def create_conflict_proof(token_a, token_b, detected_at=None):
    """Create a portable proof that one owner signed two spends from the same state."""

    pair = _find_conflicting_transfer_pair(token_a, token_b)
    if not pair:
        raise ValidationError("tokens do not contain a double-spend conflict")
    proof_unsigned = _conflict_proof_unsigned(
        token_a,
        token_b,
        pair[0],
        pair[1],
        current_time(detected_at),
    )
    proof = copy.deepcopy(proof_unsigned)
    proof["proof_hash"] = sha3_hex(_canonical_bytes(proof_unsigned))
    return proof


def verify_conflict_proof(proof):
    """Verify that a conflict proof really contains two valid conflicting branches."""

    if isinstance(proof, str):
        proof = _load_json(proof)
    _require_exact_fields(proof, CONFLICT_PROOF_FIELDS, "conflict proof")
    if proof.get("type") != CONFLICT_PROOF_TYPE:
        raise ValidationError("not a conflict proof")
    if _require_int(proof["version"], "conflict proof version") != TOKEN_VERSION:
        raise ValidationError("unsupported conflict proof version")
    pair = _find_conflicting_transfer_pair(proof.get("token_a"), proof.get("token_b"))
    if not pair:
        raise ValidationError("conflict proof tokens are not conflicting")
    expected_unsigned = _conflict_proof_unsigned(
        proof["token_a"],
        proof["token_b"],
        pair[0],
        pair[1],
        _require_int(proof["detected_at"], "conflict proof detected_at", minimum=0),
    )
    unsigned = copy.deepcopy(proof)
    proof_hash_value = unsigned.pop("proof_hash", None)
    expected_hash = sha3_hex(_canonical_bytes(unsigned))
    if proof_hash_value != expected_hash:
        raise ValidationError("conflict proof hash mismatch")
    if expected_unsigned != unsigned:
        raise ValidationError("conflict proof conflict fields mismatch")
    return True


def create_transparency_root_announcement(root, observed_at=None):
    """Wrap a signed transparency root for peer gossip."""

    from . import transparency_client as log_client

    message = log_client.make_root_announcement(root, observed_at=observed_at)
    if len(canonical_json(message).encode("utf-8")) > MAX_TRANSPARENCY_ROOT_GOSSIP_BYTES:
        raise ValidationError("transparency root announcement is too large")
    return message


def verify_transparency_root_announcement(message, operator_public_key=None):
    """Verify a peer-gossiped transparency root announcement."""

    from . import transparency_client as log_client

    if isinstance(message, str):
        message = _load_json(message)
    _require_exact_fields(message, TRANSPARENCY_ROOT_ANNOUNCEMENT_FIELDS, "transparency root announcement")
    if len(canonical_json(message).encode("utf-8")) > MAX_TRANSPARENCY_ROOT_GOSSIP_BYTES:
        raise ValidationError("transparency root announcement is too large")
    try:
        return log_client.verify_root_announcement(message, operator_public_key=operator_public_key)
    except Exception as exc:
        raise ValidationError(f"invalid transparency root announcement: {exc}") from exc


def create_transparency_equivocation_proof(root_a, root_b, collision_type=None, detected_at=None):
    """Build a gossip proof that a log operator signed conflicting roots."""

    from . import transparency_client as log_client

    message = log_client.make_equivocation_proof(
        root_a,
        root_b,
        collision_type=collision_type,
        detected_at=detected_at,
    )
    if len(canonical_json(message).encode("utf-8")) > MAX_TRANSPARENCY_EQUIVOCATION_GOSSIP_BYTES:
        raise ValidationError("transparency equivocation proof is too large")
    return message


def verify_transparency_equivocation_proof(message, operator_public_key=None):
    """Verify a self-contained transparency equivocation proof."""

    from . import transparency_client as log_client

    if isinstance(message, str):
        message = _load_json(message)
    _require_exact_fields(message, TRANSPARENCY_EQUIVOCATION_PROOF_FIELDS, "transparency equivocation proof")
    if len(canonical_json(message).encode("utf-8")) > MAX_TRANSPARENCY_EQUIVOCATION_GOSSIP_BYTES:
        raise ValidationError("transparency equivocation proof is too large")
    try:
        return log_client.verify_equivocation_proof(message, operator_public_key=operator_public_key)
    except Exception as exc:
        raise ValidationError(f"invalid transparency equivocation proof: {exc}") from exc


