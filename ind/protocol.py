# Core IND bill protocol validation, transfer construction, and compact checkpoints.

import base64
import copy
import json
import os
import sqlite3
import time
import zlib
from dataclasses import dataclass
from hashlib import sha3_256

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
BILL_VERSION = 2
ADDRESS_VERSION = "1"
ADDRESS_PREFIX = "x"
ADDRESS_SUFFIX = "x"
ADDRESS_TARGET_LENGTH = MASTER_SUPPLY_NUMBER
ADDRESS_CHECKSUM_BYTES = 4
ADDRESS_CHECKSUM_CHARS = 6
ADDRESS_PAYLOAD_CHARS = ADDRESS_TARGET_LENGTH - (
    len(ADDRESS_PREFIX) + len(ADDRESS_VERSION) + ADDRESS_CHECKSUM_CHARS + len(ADDRESS_SUFFIX)
)
ADDRESS_LENGTH = (
    len(ADDRESS_PREFIX)
    + len(ADDRESS_VERSION)
    + ADDRESS_PAYLOAD_CHARS
    + ADDRESS_CHECKSUM_CHARS
    + len(ADDRESS_SUFFIX)
)
PREVIOUS_ADDRESS_PAYLOAD_CHARS = 28
PREVIOUS_ADDRESS_LENGTH = (
    len(ADDRESS_PREFIX)
    + len(ADDRESS_VERSION)
    + PREVIOUS_ADDRESS_PAYLOAD_CHARS
    + ADDRESS_CHECKSUM_CHARS
    + len(ADDRESS_SUFFIX)
)
LEGACY_ADDRESS_LENGTH = 30
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
GENESIS_NONCE_SEED_PREFIX = f"IND-LAZY-GENESIS-v{TOKEN_VERSION}:{MASTER_SUPPLY_NUMBER}:{ANGEL_NUMBER}:{MONEY_NUMBER}:{BIRTHDAY_NUMBER}"
NUMEROLOGY_METADATA_KEY = "ind_alignment"

TOKEN_TYPE = "ind.token.v1"
BILL_TYPE = "ind.bill.v2"
BILL_CHECKPOINT_TYPE = "ind.bill_checkpoint.v2"
CHECKPOINT_ANNOUNCEMENT_TYPE = "ind.checkpoint_announcement.v2"
TRANSFER_TYPE = "ind.transfer.v1"
TRANSFER_ANNOUNCEMENT_TYPE = "ind.transfer_announcement.v1"
TRANSFER_ANNOUNCEMENT_V2_TYPE = "ind.transfer_announcement.v2"
RECEIPT_TYPE = "ind.receipt.v1"
RECEIPT_ANNOUNCEMENT_TYPE = "ind.receipt_announcement.v1"
RECEIPT_ANNOUNCEMENT_V2_TYPE = "ind.receipt_announcement.v2"
CONFLICT_PROOF_TYPE = "ind.conflict_proof.v1"
TRANSPARENCY_ROOT_ANNOUNCEMENT_TYPE = "ind.transparency_root_announcement.v1"
TRANSPARENCY_EQUIVOCATION_PROOF_TYPE = "ind.transparency_equivocation_proof.v1"
TRANSPARENCY_OPERATOR_POLICY_VIOLATION_TYPE = "ind.transparency_operator_policy_violation.v1"
TOKEN_STATE_REF_TYPE = "ind.token_state_ref.v1"
STORED_MESSAGE_REF_TYPE = "ind.stored_message_ref.v1"
GENESIS_MANIFEST_TYPE = "ind.genesis_manifest.v1"
GENESIS_MANIFEST_REF_TYPE = "ind.genesis_manifest_ref.v1"

GENESIS_SIGNATURE_DOMAIN = "IND_GENESIS_V1"
GENESIS_MANIFEST_SIGNATURE_DOMAIN = "IND_GENESIS_MANIFEST_V1"
TRANSFER_SIGNATURE_DOMAIN = "IND_TRANSFER_V1"
RECEIPT_SIGNATURE_DOMAIN = "IND_RECEIPT_V1"

TOKEN_FIELDS = {"type", "version", "token_id", "genesis", "history"}
BILL_FIELDS = {"type", "version", "token_id", "genesis", "checkpoint", "recent_history"}
CHECKPOINT_CORE_FIELDS = {
    "type",
    "version",
    "token_id",
    "genesis_hash",
    "sequence",
    "owner_address",
    "value",
    "display_id",
    "last_transfer_hash",
    "last_transfer_timestamp",
    "last_transfer_day",
    "transfers_in_last_day",
    "previous_checkpoint_hash",
}
CHECKPOINT_FIELDS = CHECKPOINT_CORE_FIELDS | {"checkpoint_hash", "transparency"}
CHECKPOINT_TRANSPARENCY_FIELDS = {"type", "version", "root", "inclusion_proof", "spend_proof"}
CHECKPOINT_ANNOUNCEMENT_FIELDS = {"type", "version", "checkpoint", "bill", "announced_at"}
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
TRANSFER_ANNOUNCEMENT_OPTIONAL_FIELDS = set()
TRANSFER_ANNOUNCEMENT_V2_FIELDS = {"type", "version", "bill", "announced_at"}
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
RECEIPT_ANNOUNCEMENT_V2_FIELDS = {"type", "version", "bill", "receipt", "announced_at"}
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
TRANSPARENCY_OPERATOR_POLICY_VIOLATION_FIELDS = {
    "type",
    "version",
    "violation_type",
    "log_id",
    "root",
    "spend_proof",
    "detected_at",
}

WIRE_PACKED_PREFIX = "indz1:"
DEFAULT_FINALITY_BUFFER_SECONDS = 60
MIN_FINALITY_BUFFER_SECONDS = 0
FINALITY_BUFFER_SECONDS = max(
    MIN_FINALITY_BUFFER_SECONDS,
    _env_int("IND_FINALITY_BUFFER_SECONDS", DEFAULT_FINALITY_BUFFER_SECONDS),
)
MAX_TRANSFERS_PER_BILL_PER_DAY = 10
MAX_TRANSFERS_PER_TOKEN_PER_DAY = MAX_TRANSFERS_PER_BILL_PER_DAY
MAX_BILL_HISTORY_BYTES = _env_int(
    "IND_MAX_BILL_HISTORY_BYTES",
    _env_int("IND_MAX_TOKEN_HISTORY_BYTES", 8 * 1024 * 1024),
)
MAX_TOKEN_HISTORY_BYTES = MAX_BILL_HISTORY_BYTES
MAX_TRANSFER_FUTURE_SKEW_SECONDS = 300
MAX_GENESIS_METADATA_BYTES = 1024
MAX_TRANSFER_METADATA_BYTES = 256
MAX_WIRE_COMPRESSED_BYTES = _env_int("IND_MAX_WIRE_COMPRESSED_BYTES", 16 * 1024 * 1024)
MAX_WIRE_DECOMPRESSED_BYTES = _env_int("IND_MAX_WIRE_DECOMPRESSED_BYTES", 64 * 1024 * 1024)
MAX_TRANSPARENCY_ROOT_GOSSIP_BYTES = _env_int("IND_MAX_TRANSPARENCY_ROOT_GOSSIP_BYTES", 16 * 1024)
MAX_TRANSPARENCY_EQUIVOCATION_GOSSIP_BYTES = _env_int(
    "IND_MAX_TRANSPARENCY_EQUIVOCATION_GOSSIP_BYTES", 32 * 1024
)
MAX_TRANSPARENCY_OPERATOR_POLICY_VIOLATION_GOSSIP_BYTES = _env_int(
    "IND_MAX_TRANSPARENCY_OPERATOR_POLICY_VIOLATION_GOSSIP_BYTES",
    128 * 1024,
)
MAX_VERIFY_KEY_CACHE = _env_int("IND_MAX_VERIFY_KEY_CACHE", 4096)
MAX_JSON_DEPTH = _env_int("IND_MAX_JSON_DEPTH", 64)
MAX_JSON_LIST_ITEMS = _env_int("IND_MAX_JSON_LIST_ITEMS", 100_000)
MAX_JSON_OBJECT_KEYS = _env_int("IND_MAX_JSON_OBJECT_KEYS", 1024)
MAX_JSON_STRING_BYTES = _env_int("IND_MAX_JSON_STRING_BYTES", 64 * 1024)
MAX_JSON_INTEGER_ABS = _env_int("IND_MAX_JSON_INTEGER_ABS", 2**63 - 1)
MAX_PROTOCOL_TIMESTAMP = MAX_JSON_INTEGER_ABS
DEFAULT_LOG_SUBMISSION_VERIFY_TIMEOUT_SECONDS = 30
ALLOW_UNTRUSTED_EMBEDDED_ROOTS_ENV = "IND_ALLOW_UNTRUSTED_EMBEDDED_ROOTS"

DEFAULT_STORE_PATH = "ind_gossip.db"
SQLITE_BUSY_TIMEOUT_MS = 5000
_VERIFY_KEY_CACHE = {}


# Base exception for IND bearer-bill validation failures.
class TokenError(Exception):
    pass


# Raised when a bill, transfer, receipt, or proof is malformed.
class ValidationError(TokenError):
    pass


# Raised when a wire payload exceeds protocol size limits.
class WireSizeError(ValidationError):
    pass


# SQLite connection that always closes when its context manager exits.
class ClosingConnection(sqlite3.Connection):
    def __exit__(self, exc_type, exc_value, traceback):
        result = super().__exit__(exc_type, exc_value, traceback)
        self.close()
        return result


# Tune SQLite for short-lived threaded node connections.
def configure_sqlite_connection(conn):
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute(f"PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS}")
    return conn


# Validated view of the current bill tip used by wallets and nodes.
@dataclass(frozen=True)
class TokenState:
    token_id: str
    owner_address: str
    last_transfer_hash: str
    sequence: int
    display_id: str
    value: int


# Serialize protocol objects in the exact form used for hashes and signatures.
def canonical_json(data):
    _validate_json_value(data, "protocol object")
    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


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


def _require_timestamp(value, label, minimum=0):
    return _require_int(value, label, minimum=minimum, maximum=MAX_PROTOCOL_TIMESTAMP)


def _require_str(value, label, max_bytes=MAX_JSON_STRING_BYTES):
    if not isinstance(value, str):
        raise ValidationError(f"{label} must be a string")
    if len(value.encode("utf-8")) > int(max_bytes):
        raise ValidationError(f"{label} is too large")
    return value


def _packed_json(data):
    raw = canonical_json(data).encode("utf-8")
    if len(raw) > MAX_WIRE_DECOMPRESSED_BYTES:
        raise WireSizeError("wire message is too large")
    compressed = zlib.compress(raw, level=9)
    if len(compressed) > MAX_WIRE_COMPRESSED_BYTES:
        raise WireSizeError("compressed wire message is too large")
    return WIRE_PACKED_PREFIX + base64.b85encode(compressed).decode("utf-8")


def _max_b85_encoded_size(decoded_size):
    full_groups, remainder = divmod(int(decoded_size), 4)
    if not remainder:
        return full_groups * 5
    return full_groups * 5 + remainder + 1


def _safe_zlib_decompress(data):
    try:
        decompressor = zlib.decompressobj()
        result = decompressor.decompress(data, MAX_WIRE_DECOMPRESSED_BYTES + 1)
        if decompressor.unconsumed_tail or len(result) > MAX_WIRE_DECOMPRESSED_BYTES:
            raise WireSizeError("wire message expands beyond safety limit")
        result += decompressor.flush(MAX_WIRE_DECOMPRESSED_BYTES + 1 - len(result))
        if len(result) > MAX_WIRE_DECOMPRESSED_BYTES:
            raise WireSizeError("wire message expands beyond safety limit")
        return result
    except WireSizeError:
        raise
    except zlib.error as exc:
        raise ValidationError("invalid compressed wire payload") from exc


def _unpacked_json(raw):
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValidationError("invalid wire payload encoding") from exc
    raw = raw.strip()
    if len(raw.encode("utf-8")) > MAX_WIRE_DECOMPRESSED_BYTES:
        raise WireSizeError("wire message is too large")
    if raw.startswith(WIRE_PACKED_PREFIX):
        packed = raw[len(WIRE_PACKED_PREFIX) :]
        if len(packed) > _max_b85_encoded_size(MAX_WIRE_COMPRESSED_BYTES):
            raise WireSizeError("compressed wire message is too large")
        try:
            compressed = base64.b85decode(packed.encode("utf-8"))
        except Exception as exc:
            raise ValidationError("invalid packed wire payload") from exc
        if len(compressed) > MAX_WIRE_COMPRESSED_BYTES:
            raise WireSizeError("compressed wire message is too large")
        decompressed = _safe_zlib_decompress(compressed)
        try:
            text = decompressed.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValidationError("invalid compressed wire payload encoding") from exc
        return _json_loads_strict(text)
    return _json_loads_strict(raw)


# Compress a gossip message into the bounded wire format accepted by peers.
def pack_wire_message(message):
    if isinstance(message, bytes):
        message = message.decode("utf-8")
    if isinstance(message, str):
        if message.strip().startswith(WIRE_PACKED_PREFIX):
            return message.strip()
        message = _json_loads_strict(message)
    return _packed_json(message)


# Decode a plain or compressed gossip payload into a protocol object.
def unpack_wire_message(raw):
    if isinstance(raw, dict):
        return raw
    return _unpacked_json(raw)


def _store_json(data):
    return _packed_json(data)


def _load_json(raw):
    if isinstance(raw, dict):
        return raw
    return _unpacked_json(raw)


# Return the SHA3-256 hex digest used throughout the IND protocol.
def sha3_hex(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return sha3_256(data).hexdigest()


# Sign canonical protocol bytes with a base85-encoded secp256k1 private key.
def b85_sign(private_key_base85, data):
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


# Verify a base85-encoded secp256k1 signature without leaking parser errors.
def b85_verify(public_key_base85, signature_base85, data):
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


# Return domain-separated bytes for signing one specific IND object type.
def signature_payload(domain, data):
    domain = _require_str(str(domain), "signature domain", max_bytes=128)
    payload = data if isinstance(data, bytes) else _canonical_bytes(data)
    return b"IND-SIGNATURE-V1:" + domain.encode("ascii") + b"\n" + payload


# Sign protocol data with an explicit domain separator.
def b85_sign_domain(private_key_base85, domain, data):
    return b85_sign(private_key_base85, signature_payload(domain, data))


# Verify a domain-separated IND protocol signature.
def b85_verify_domain(public_key_base85, signature_base85, domain, data):
    return b85_verify(public_key_base85, signature_base85, signature_payload(domain, data))


def numerology_signature():
    material = (
        f"IND:{TOTAL_SUPPLY}:{ADDRESS_LENGTH}:{ANGEL_NUMBER}:{MONEY_NUMBER}:{BIRTHDAY_CODE}".encode(
            "ascii"
        )
    )
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


# Derive the pre-checksum IND address for old wallets and bill histories.
def legacy_address_from_public_key(public_key_base85):
    digest = sha3_256(public_key_base85.strip().encode("utf-8")).digest()
    return base58.b58encode(digest).decode("utf-8")[:LEGACY_ADDRESS_LENGTH]


# Derive the old 37-character checked address accepted for existing wallets.
def previous_address_from_public_key(public_key_base85):
    payload = _address_payload_from_public_key(public_key_base85, PREVIOUS_ADDRESS_PAYLOAD_CHARS)
    checksum = _address_checksum(ADDRESS_VERSION, payload)
    return f"{ADDRESS_PREFIX}{ADDRESS_VERSION}{payload}{checksum}{ADDRESS_SUFFIX}"


# Derive the checksummed, versioned user-facing IND address from a base85 public key.
def address_from_public_key(public_key_base85):
    payload = _address_payload_from_public_key(public_key_base85)
    checksum = _address_checksum(ADDRESS_VERSION, payload)
    return f"{ADDRESS_PREFIX}{ADDRESS_VERSION}{payload}{checksum}{ADDRESS_SUFFIX}"


def is_legacy_address(address):
    if not isinstance(address, str) or len(address) != LEGACY_ADDRESS_LENGTH:
        return False
    return all(char in BASE58_ALPHABET for char in address)


def _is_versioned_address(address, payload_chars):
    expected_length = (
        len(ADDRESS_PREFIX)
        + len(ADDRESS_VERSION)
        + payload_chars
        + ADDRESS_CHECKSUM_CHARS
        + len(ADDRESS_SUFFIX)
    )
    if not isinstance(address, str) or len(address) != expected_length:
        return False
    if not address.startswith(ADDRESS_PREFIX + ADDRESS_VERSION) or not address.endswith(
        ADDRESS_SUFFIX
    ):
        return False
    payload_start = len(ADDRESS_PREFIX) + len(ADDRESS_VERSION)
    payload_end = payload_start + payload_chars
    payload = address[payload_start:payload_end]
    checksum = address[payload_end : -len(ADDRESS_SUFFIX)]
    if len(payload) != payload_chars or len(checksum) != ADDRESS_CHECKSUM_CHARS:
        return False
    if not all(char in BASE58_ALPHABET for char in payload + checksum):
        return False
    return checksum == _address_checksum(ADDRESS_VERSION, payload)


def is_current_address(address):
    return _is_versioned_address(address, ADDRESS_PAYLOAD_CHARS)


def is_previous_address(address):
    return _is_versioned_address(address, PREVIOUS_ADDRESS_PAYLOAD_CHARS)


# Return a valid IND address or raise ValidationError.
def validate_address(address, label="address", allow_legacy=True):
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
    raise ValidationError(f"{label} does not own the bill tip")


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
        return os.environ.get("IND_ALLOW_UNTRUSTED_GENESIS", "").strip().lower() in {
            "1",
            "true",
            "yes",
        }


# Return the compact denomination/index label shown in wallets.
def token_display_id(token):
    genesis = token["genesis"]
    value = int(genesis.get("value", 1))
    index = int(genesis["index"])
    return f"{value}x{index}"


def _timestamp_day(timestamp):
    return int(timestamp) // 86400


def _last_history_timestamp(token):
    history = _bill_history(token)
    if not history:
        checkpoint = token.get("checkpoint") if isinstance(token, dict) else None
        if isinstance(checkpoint, dict) and checkpoint.get("last_transfer_timestamp") is not None:
            return int(checkpoint["last_transfer_timestamp"])
        return None
    return int(history[-1]["timestamp"])


def _bill_history(token):
    if not isinstance(token, dict):
        return []
    if token.get("type") == BILL_TYPE:
        return token.get("recent_history", [])
    return token.get("history", [])


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


def _checkpoint_core(checkpoint):
    return {field: checkpoint[field] for field in sorted(CHECKPOINT_CORE_FIELDS)}


# Hash the compact checkpoint core without embedded proof material.
def checkpoint_hash(checkpoint):
    return sha3_hex(b"IND-BILL-CHECKPOINT-v2:" + _canonical_bytes(_checkpoint_core(checkpoint)))


def _checkpoint_day_count_from_bill(bill, last_transfer):
    last_day = _timestamp_day(last_transfer["timestamp"])
    count = 0
    checkpoint = bill.get("checkpoint") if isinstance(bill, dict) else None
    if isinstance(checkpoint, dict) and int(checkpoint.get("last_transfer_day", -1)) == last_day:
        count += int(checkpoint.get("transfers_in_last_day", 0))
    for transfer in _bill_history(bill):
        if _timestamp_day(transfer["timestamp"]) == last_day:
            count += 1
    return last_day, count


# Create a compact checkpoint for the current settled bill tip.
def create_bill_checkpoint(bill, transparency=None):
    state = verify_bill(
        bill, require_checkpoint_transparency=False, require_recent_transparency=False
    )
    if state.sequence == 0:
        raise ValidationError("genesis bill cannot be checkpointed")
    last_transfer = _last_transfer(bill)
    last_day, transfers_in_last_day = _checkpoint_day_count_from_bill(bill, last_transfer)
    previous_checkpoint = (
        bill.get("checkpoint") if isinstance(bill, dict) and bill.get("type") == BILL_TYPE else None
    )
    checkpoint = {
        "type": BILL_CHECKPOINT_TYPE,
        "version": BILL_VERSION,
        "token_id": state.token_id,
        "genesis_hash": genesis_hash(bill["genesis"]),
        "sequence": int(state.sequence),
        "owner_address": state.owner_address,
        "value": int(state.value),
        "display_id": state.display_id,
        "last_transfer_hash": state.last_transfer_hash,
        "last_transfer_timestamp": int(last_transfer["timestamp"]),
        "last_transfer_day": int(last_day),
        "transfers_in_last_day": int(transfers_in_last_day),
        "previous_checkpoint_hash": (
            previous_checkpoint.get("checkpoint_hash")
            if isinstance(previous_checkpoint, dict)
            else None
        ),
    }
    checkpoint["checkpoint_hash"] = checkpoint_hash(checkpoint)
    if transparency is not None:
        checkpoint["transparency"] = copy.deepcopy(transparency)
    return checkpoint


# Return a v2 compact bill rooted at a transparency-backed checkpoint.
def create_compact_bill(bill, checkpoint):
    verify_checkpoint_for_genesis(checkpoint, bill["genesis"], require_transparency=False)
    return {
        "type": BILL_TYPE,
        "version": BILL_VERSION,
        "token_id": checkpoint["token_id"],
        "genesis": copy.deepcopy(bill["genesis"]),
        "checkpoint": copy.deepcopy(checkpoint),
        "recent_history": [],
    }


# Wrap a compact checkpoint for transparency-log submission.
def create_checkpoint_announcement(
    checkpoint,
    bill=None,
    now=None,
    transparency_verifier=None,
    trusted_operator_public_key=None,
):
    _require_exact_fields(
        checkpoint,
        CHECKPOINT_CORE_FIELDS | {"checkpoint_hash"},
        "bill checkpoint",
        optional={"transparency"},
    )
    if checkpoint["checkpoint_hash"] != checkpoint_hash(checkpoint):
        raise ValidationError("checkpoint hash mismatch")
    if bill is None:
        raise ValidationError("checkpoint announcement requires source bill")
    verify_kwargs = {"require_recent_transparency": False}
    if isinstance(bill, dict) and bill.get("type") == BILL_TYPE:
        verify_kwargs["transparency_verifier"] = transparency_verifier
        verify_kwargs["trusted_operator_public_key"] = trusted_operator_public_key
    verify_bill(bill, **verify_kwargs)
    expected = create_bill_checkpoint(bill)
    for field in CHECKPOINT_CORE_FIELDS | {"checkpoint_hash"}:
        if checkpoint[field] != expected[field]:
            raise ValidationError(f"checkpoint does not match source bill: {field}")
    return {
        "type": CHECKPOINT_ANNOUNCEMENT_TYPE,
        "version": BILL_VERSION,
        "checkpoint": copy.deepcopy(checkpoint),
        "bill": copy.deepcopy(bill),
        "announced_at": current_time(now),
    }


# Hash a complete signed genesis record.
def genesis_hash(genesis):
    return sha3_hex(_canonical_bytes(genesis))


# Hash a complete signed transfer record.
def transfer_hash(transfer):
    return sha3_hex(_canonical_bytes(transfer))


# Hash a full gossip message for deduplication and storage.
def message_hash(message):
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


# Hash the unsigned launch manifest that defines the lazy genesis supply map.
def genesis_manifest_hash(manifest):
    return sha3_hex(_canonical_bytes(_unsigned_manifest(manifest)))


# Build contiguous denomination ranges for a signed lazy-genesis manifest.
def make_denomination_ranges(
    denomination_counts, owner_address, start_index=0, nonce_seed_prefix=GENESIS_NONCE_SEED_PREFIX
):
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
        ranges.append(
            {
                "start_index": next_index,
                "count": count,
                "value": value,
                "owner_address": owner_address,
                "nonce_seed": sha3_hex(
                    f"{nonce_seed_prefix}:{next_index}:{count}:{value}:{owner_address}"
                ),
            }
        )
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
        start_index = _require_int(
            item["start_index"], "genesis manifest range start_index", minimum=0
        )
        count = _require_int(item["count"], "genesis manifest range count", minimum=1)
        value = _require_int(item["value"], "genesis manifest range value", minimum=1)
        nonce_seed = _require_str(item["nonce_seed"], "genesis manifest range nonce seed")
        if start_index < 0 or count <= 0 or value <= 0:
            raise ValidationError("invalid genesis manifest range values")
        owner_address = validate_address(item["owner_address"], "manifest owner address")
        end_index = start_index + count
        if end_index > TOTAL_SUPPLY:
            raise ValidationError("genesis manifest range outside fixed IND supply")
        normalized.append(
            {
                "start_index": start_index,
                "end_index": end_index,
                "count": count,
                "value": value,
                "owner_address": owner_address,
                "nonce_seed": nonce_seed,
            }
        )
        total_count += count
        total_value += count * value
    normalized.sort(key=lambda item: item["start_index"])
    for previous, current in zip(normalized, normalized[1:], strict=False):
        if current["start_index"] < previous["end_index"]:
            raise ValidationError("genesis manifest ranges overlap")
    if total_count > TOTAL_SUPPLY:
        raise ValidationError("genesis manifest exceeds fixed IND bill supply")
    return normalized, total_count, total_value


# Create the issuer-signed supply manifest used to mint lazy genesis bills.
def make_genesis_manifest(
    ranges, issuer_private_key, issuer_public_key, issued_at=None, metadata=None
):
    normalized, total_count, total_value = _validate_manifest_ranges(ranges)
    metadata = _with_numerology_metadata(metadata, MAX_GENESIS_METADATA_BYTES, "genesis manifest")
    issued_at = _require_timestamp(
        int(issued_at if issued_at is not None else time.time()),
        "genesis manifest issued_at",
    )
    if issued_at > current_time() + MAX_TRANSFER_FUTURE_SKEW_SECONDS:
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


# Validate a signed supply manifest against local trust pins and range totals.
def verify_genesis_manifest(manifest, now=None):
    _require_exact_fields(
        manifest,
        GENESIS_MANIFEST_FIELDS,
        "genesis manifest",
        optional={"manifest_hash"},
    )
    if (
        manifest["type"] != GENESIS_MANIFEST_TYPE
        or _require_int(manifest["version"], "genesis manifest version") != TOKEN_VERSION
    ):
        raise ValidationError("unsupported genesis manifest version")
    _require_metadata(manifest["metadata"], MAX_GENESIS_METADATA_BYTES, "genesis manifest")
    issued_at = _require_timestamp(manifest["issued_at"], "genesis manifest issued_at")
    if issued_at > current_time(now) + MAX_TRANSFER_FUTURE_SKEW_SECONDS:
        raise ValidationError("genesis manifest issued_at is too far in the future")
    normalized, total_count, total_value = _validate_manifest_ranges(manifest["ranges"])
    if (
        _require_int(manifest["total_token_count"], "genesis manifest total_token_count", minimum=1)
        != total_count
    ):
        raise ValidationError("genesis manifest bill count mismatch")
    if (
        _require_int(manifest["total_value"], "genesis manifest total_value", minimum=1)
        != total_value
    ):
        raise ValidationError("genesis manifest value mismatch")
    unsigned = _unsigned_manifest(manifest)
    manifest_hash_value = genesis_manifest_hash(manifest)
    if (
        manifest.get("manifest_hash")
        and _require_str(manifest["manifest_hash"], "genesis manifest hash") != manifest_hash_value
    ):
        raise ValidationError("genesis manifest hash mismatch")
    trusted_keys = _trusted_genesis_keys()
    trusted_manifest_hashes = _trusted_genesis_manifest_hashes()
    issuer_public_key = _require_str(
        manifest["issuer_public_key"], "genesis manifest issuer public key"
    )
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


# Materialize one bill from a signed lazy-genesis manifest.
def make_lazy_genesis_token(index, manifest, metadata=None):
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


# Create a fully materialized genesis bill signed directly by the issuer.
def make_genesis_token(
    index,
    owner_address,
    issuer_private_key,
    issuer_public_key,
    value=1,
    nonce=None,
    metadata=None,
    issued_at=None,
):
    index = int(index)
    owner_address = validate_address(str(owner_address).strip(), "owner address")
    if index < 0 or index >= TOTAL_SUPPLY:
        raise ValidationError("genesis index outside fixed IND supply")
    if value <= 0:
        raise ValidationError("bill value must be positive")
    metadata = _with_numerology_metadata(metadata, MAX_GENESIS_METADATA_BYTES, "genesis")
    issued_at = _require_timestamp(
        int(issued_at if issued_at is not None else time.time()),
        "genesis issued_at",
    )
    if issued_at > current_time() + MAX_TRANSFER_FUTURE_SKEW_SECONDS:
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


# Validate a genesis record and prove that it belongs to the supplied bill id.
def verify_genesis(genesis, token_id, now=None):
    _require_exact_fields(genesis, GENESIS_FIELDS, "genesis", optional={"manifest_ref"})
    if (
        genesis["type"] != "ind.genesis.v1"
        or _require_int(genesis["version"], "genesis version") != TOKEN_VERSION
    ):
        raise ValidationError("unsupported genesis version")
    index = _require_int(genesis["index"], "genesis index", minimum=0, maximum=TOTAL_SUPPLY - 1)
    value = _require_int(genesis["value"], "genesis value", minimum=1)
    if index < 0 or index >= TOTAL_SUPPLY:
        raise ValidationError("genesis index outside fixed IND supply")
    if value <= 0:
        raise ValidationError("bill value must be positive")
    owner_address = validate_address(genesis["owner_address"], "genesis owner address")
    _require_metadata(genesis["metadata"], MAX_GENESIS_METADATA_BYTES, "genesis")
    issued_at = _require_timestamp(genesis["issued_at"], "genesis issued_at")
    if issued_at > current_time(now) + MAX_TRANSFER_FUTURE_SKEW_SECONDS:
        raise ValidationError("genesis issued_at is too far in the future")
    expected_commitment = _genesis_commitment(
        index, owner_address, value, genesis["nonce"], issued_at
    )
    if genesis["success_commitment"] != expected_commitment:
        raise ValidationError("genesis commitment does not resolve to the IND success state")
    unsigned = _without_signature(genesis)
    expected_token_id = "ind1_" + sha3_hex(_canonical_bytes(unsigned))[:56]
    if token_id != expected_token_id:
        raise ValidationError("bill id does not match genesis structure")
    issuer_public_key = genesis["issuer_public_key"]
    if "manifest_ref" in genesis:
        manifest_ref = genesis["manifest_ref"]
        _require_exact_fields(
            manifest_ref, GENESIS_MANIFEST_REF_FIELDS, "genesis manifest reference"
        )
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
        if (
            _require_int(manifest_ref["manifest"]["issued_at"], "genesis manifest issued_at")
            != issued_at
        ):
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
    if not b85_verify_domain(
        issuer_public_key, genesis["signature"], GENESIS_SIGNATURE_DOMAIN, unsigned
    ):
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


# Normalize protocol wall-clock input so validation paths share one clock hook.
def current_time(now=None):
    return _require_timestamp(int(time.time() if now is None else now), "current time")


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


def _configured_transparency_operator_public_key():
    try:
        from . import settings as ind_settings

        return ind_settings.transparency_operator_public_key()
    except Exception:
        return os.environ.get("IND_LOG_OPERATOR_PUBLIC_KEY", "").strip()


def _production_mode():
    try:
        from . import settings as ind_settings

        return ind_settings.production_mode()
    except Exception:
        return _env_true("IND_PRODUCTION")


def _embedded_root_operator_key(
    root,
    allow_untrusted_embedded_roots=False,
    trusted_operator_public_key=None,
):
    if allow_untrusted_embedded_roots or _env_true(ALLOW_UNTRUSTED_EMBEDDED_ROOTS_ENV):
        return root.get("operator_public_key")
    if _production_mode():
        raise ValidationError(
            "compact checkpoint requires a mirrored transparency verifier in production"
        )
    if trusted_operator_public_key:
        return trusted_operator_public_key
    operator_public_key = _configured_transparency_operator_public_key()
    if not operator_public_key:
        raise ValidationError(
            "compact checkpoint requires a trusted transparency verifier or pinned operator key"
        )
    return operator_public_key


def _configured_transparency_submitter():
    try:
        from . import settings as ind_settings

        submit_to_transparency = ind_settings.submit_to_transparency_log()
    except Exception:
        submit_to_transparency = _env_true("IND_SUBMIT_TO_TRANSPARENCY_LOG")
    if not submit_to_transparency:
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


# Verify that every transfer in a bill history is present in the public log.
def verify_token_transparency(token, transparency_verifier, now=None, require_current_root=True):
    if transparency_verifier is None:
        raise ValidationError("transparency verifier is required")
    if isinstance(token, dict) and token.get("type") == BILL_TYPE:
        verify_bill(
            token,
            now=now,
            transparency_verifier=transparency_verifier,
            require_transparency=True,
            require_current_root=require_current_root,
        )
        return True
    try:
        transparency_verifier.verify_token(
            token, now=now, require_current_root=require_current_root
        )
    except Exception as exc:
        raise ValidationError(f"transparency log verification failed: {exc}") from exc
    return True


# Validate a complete bearer bill and return the owner at the current tip.
def _verify_full_token(
    token,
    now=None,
    transparency_verifier=None,
    require_transparency=False,
    require_current_root=True,
):
    if isinstance(token, str):
        token = _load_json(token)
    _require_exact_fields(token, TOKEN_FIELDS, "bill payload")
    if token.get("type") != TOKEN_TYPE:
        raise ValidationError("malformed bill payload")
    if _require_int(token.get("version"), "bill version") != TOKEN_VERSION:
        raise ValidationError("unsupported bill version")
    token_id = _require_str(token.get("token_id"), "bill id")
    if not token_id:
        raise ValidationError("missing bill id")

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
        raise ValidationError("bill history must be a list")
    if len(_canonical_bytes(token)) > MAX_BILL_HISTORY_BYTES:
        raise ValidationError("bill history exceeds maximum serialized size")

    for transfer in history:
        # Each transfer must extend the exact current tip and be signed by its owner.
        _require_exact_fields(transfer, TRANSFER_FIELDS, "transfer")
        if (
            transfer["type"] != TRANSFER_TYPE
            or _require_int(transfer["version"], "transfer version") != TOKEN_VERSION
        ):
            raise ValidationError("unsupported transfer version")
        _require_metadata(transfer["metadata"], MAX_TRANSFER_METADATA_BYTES, "transfer")
        if transfer["token_id"] != token_id:
            raise ValidationError("transfer references a different bill")
        sender_address = validate_address(transfer["sender_address"], "sender address")
        recipient_address = validate_address(transfer["recipient_address"], "recipient address")
        transfer_sequence = _require_int(transfer["sequence"], "transfer sequence", minimum=1)
        if transfer_sequence != sequence + 1:
            raise ValidationError("transfer sequence gap")
        if transfer["previous_hash"] != last_hash:
            raise ValidationError("transfer does not extend the current bill tip")
        if sender_address != owner_address:
            raise ValidationError("transfer sender is not the current owner")
        transfer_timestamp = _require_timestamp(transfer["timestamp"], "transfer timestamp")
        if transfer_timestamp > max_allowed_timestamp:
            raise ValidationError("transfer timestamp is too far in the future")
        if transfer_timestamp < issued_at:
            raise ValidationError("transfer timestamp predates genesis")
        if previous_timestamp is not None and transfer_timestamp <= previous_timestamp:
            raise ValidationError("transfer timestamps must be strictly increasing")
        transfer_day = _timestamp_day(transfer_timestamp)
        transfer_days[transfer_day] = transfer_days.get(transfer_day, 0) + 1
        if transfer_days[transfer_day] > MAX_TRANSFERS_PER_BILL_PER_DAY:
            raise ValidationError("bill exceeds daily transfer limit")
        _verify_transfer_signature(transfer)
        owner_address = recipient_address
        last_hash = transfer_hash(transfer)
        sequence = transfer_sequence
        previous_timestamp = transfer_timestamp

    # Transparency verification is intentionally last: structural failures should be local.
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


def _require_hex32(value, label):
    text = _require_str(value, label).lower()
    if len(text) != 64:
        raise ValidationError(f"invalid {label}")
    try:
        bytes.fromhex(text)
    except ValueError as exc:
        raise ValidationError(f"invalid {label}") from exc
    return text


def _verify_checkpoint_transparency(
    checkpoint,
    transparency_verifier=None,
    now=None,
    require_current_root=True,
    allow_untrusted_embedded_roots=False,
    trusted_operator_public_key=None,
):
    transparency = checkpoint.get("transparency")
    if not isinstance(transparency, dict):
        raise ValidationError("compact checkpoint is missing transparency proof")
    _require_exact_fields(
        transparency, CHECKPOINT_TRANSPARENCY_FIELDS, "checkpoint transparency proof"
    )
    if transparency["type"] != "ind.checkpoint_transparency.v2":
        raise ValidationError("malformed checkpoint transparency proof")
    if _require_int(transparency["version"], "checkpoint transparency version") != BILL_VERSION:
        raise ValidationError("unsupported checkpoint transparency version")
    try:
        from . import transparency_client as log_client

        if transparency_verifier is not None:
            transparency_verifier.verify_checkpoint(
                checkpoint,
                now=now,
                require_current_root=require_current_root,
            )
            return True
        root = transparency["root"]
        operator_public_key = _embedded_root_operator_key(
            root,
            allow_untrusted_embedded_roots=allow_untrusted_embedded_roots,
            trusted_operator_public_key=trusted_operator_public_key,
        )
        log_client.verify_inclusion_proof(
            checkpoint["checkpoint_hash"],
            transparency["inclusion_proof"],
            root,
            operator_public_key=operator_public_key,
        )
        log_client.verify_spend_map_proof_for_checkpoint(
            checkpoint,
            transparency["spend_proof"],
            root,
            operator_public_key=operator_public_key,
        )
    except Exception as exc:
        raise ValidationError(f"checkpoint transparency verification failed: {exc}") from exc
    return True


# Validate a compact checkpoint against its genesis and optional proof.
def verify_checkpoint_for_genesis(
    checkpoint,
    genesis,
    now=None,
    require_transparency=True,
    transparency_verifier=None,
    require_current_root=True,
    allow_untrusted_embedded_roots=False,
    trusted_operator_public_key=None,
):
    if isinstance(checkpoint, str):
        checkpoint = _load_json(checkpoint)
    required_fields = (
        CHECKPOINT_FIELDS
        if require_transparency
        else (CHECKPOINT_CORE_FIELDS | {"checkpoint_hash"})
    )
    _require_exact_fields(
        checkpoint,
        required_fields,
        "bill checkpoint",
        optional=set() if require_transparency else {"transparency"},
    )
    if checkpoint["type"] != BILL_CHECKPOINT_TYPE:
        raise ValidationError("malformed bill checkpoint")
    if _require_int(checkpoint["version"], "bill checkpoint version") != BILL_VERSION:
        raise ValidationError("unsupported bill checkpoint version")
    token_id = _require_str(checkpoint["token_id"], "checkpoint bill id")
    verify_genesis(genesis, token_id, now=now)
    if checkpoint["genesis_hash"] != genesis_hash(genesis):
        raise ValidationError("checkpoint genesis hash mismatch")
    if checkpoint["checkpoint_hash"] != checkpoint_hash(checkpoint):
        raise ValidationError("checkpoint hash mismatch")
    _require_int(checkpoint["sequence"], "checkpoint sequence", minimum=1)
    validate_address(checkpoint["owner_address"], "checkpoint owner address")
    checkpoint_value = _require_int(checkpoint["value"], "checkpoint value", minimum=1)
    _require_str(checkpoint["display_id"], "checkpoint display id")
    expected_value = int(genesis.get("value", 1))
    if checkpoint_value != expected_value:
        raise ValidationError("checkpoint value mismatch")
    if checkpoint["display_id"] != token_display_id({"genesis": genesis}):
        raise ValidationError("checkpoint display id mismatch")
    _require_hex32(checkpoint["last_transfer_hash"], "checkpoint last transfer hash")
    last_transfer_timestamp = _require_timestamp(
        checkpoint["last_transfer_timestamp"],
        "checkpoint last transfer timestamp",
    )
    last_transfer_day = _require_int(
        checkpoint["last_transfer_day"], "checkpoint last transfer day", minimum=0
    )
    if last_transfer_day != _timestamp_day(last_transfer_timestamp):
        raise ValidationError("checkpoint last transfer day mismatch")
    _require_int(
        checkpoint["transfers_in_last_day"],
        "checkpoint transfers in last day",
        minimum=1,
        maximum=MAX_TRANSFERS_PER_BILL_PER_DAY,
    )
    previous_checkpoint_hash = checkpoint.get("previous_checkpoint_hash")
    if previous_checkpoint_hash is not None:
        _require_hex32(previous_checkpoint_hash, "previous checkpoint hash")
    if require_transparency:
        _verify_checkpoint_transparency(
            checkpoint,
            transparency_verifier=transparency_verifier,
            now=now,
            require_current_root=require_current_root,
            allow_untrusted_embedded_roots=allow_untrusted_embedded_roots,
            trusted_operator_public_key=trusted_operator_public_key,
        )
    return TokenState(
        token_id=token_id,
        owner_address=checkpoint["owner_address"],
        last_transfer_hash=checkpoint["last_transfer_hash"],
        sequence=int(checkpoint["sequence"]),
        display_id=checkpoint["display_id"],
        value=int(checkpoint["value"]),
    )


# Validate a v2 compact bill from its checkpoint plus recent transfers.
def verify_compact_bill(
    bill,
    now=None,
    transparency_verifier=None,
    require_transparency=False,
    require_current_root=True,
    require_checkpoint_transparency=True,
    require_recent_transparency=None,
    allow_untrusted_embedded_roots=False,
    trusted_operator_public_key=None,
):
    if isinstance(bill, str):
        bill = _load_json(bill)
    _require_exact_fields(bill, BILL_FIELDS, "compact bill payload")
    if bill.get("type") != BILL_TYPE:
        raise ValidationError("malformed compact bill payload")
    if _require_int(bill.get("version"), "compact bill version") != BILL_VERSION:
        raise ValidationError("unsupported compact bill version")
    token_id = _require_str(bill.get("token_id"), "compact bill id")
    if transparency_verifier is None and require_transparency:
        transparency_verifier = _configured_transparency_verifier()
    checkpoint = bill["checkpoint"]
    state = verify_checkpoint_for_genesis(
        checkpoint,
        bill["genesis"],
        now=now,
        require_transparency=require_checkpoint_transparency,
        transparency_verifier=transparency_verifier,
        require_current_root=require_current_root,
        allow_untrusted_embedded_roots=allow_untrusted_embedded_roots,
        trusted_operator_public_key=trusted_operator_public_key,
    )
    if state.token_id != token_id:
        raise ValidationError("compact bill id does not match checkpoint")
    owner_address = state.owner_address
    last_hash = state.last_transfer_hash
    sequence = int(state.sequence)
    issued_at = int(bill["genesis"]["issued_at"])
    previous_timestamp = int(checkpoint["last_transfer_timestamp"])
    transfer_days = {}
    checkpoint_day = int(checkpoint["last_transfer_day"])
    transfer_days[checkpoint_day] = int(checkpoint["transfers_in_last_day"])
    max_allowed_timestamp = current_time(now) + MAX_TRANSFER_FUTURE_SKEW_SECONDS

    history = bill.get("recent_history", [])
    if not isinstance(history, list):
        raise ValidationError("compact bill recent history must be a list")
    if len(_canonical_bytes(bill)) > MAX_BILL_HISTORY_BYTES:
        raise ValidationError("compact bill history exceeds maximum serialized size")

    if require_recent_transparency is None:
        require_recent_transparency = require_transparency or transparency_verifier is not None
    recent_for_transparency = []
    for transfer in history:
        # Recent history resumes from the checkpoint tip, not from genesis.
        _require_exact_fields(transfer, TRANSFER_FIELDS, "transfer")
        if (
            transfer["type"] != TRANSFER_TYPE
            or _require_int(transfer["version"], "transfer version") != TOKEN_VERSION
        ):
            raise ValidationError("unsupported transfer version")
        _require_metadata(transfer["metadata"], MAX_TRANSFER_METADATA_BYTES, "transfer")
        if transfer["token_id"] != token_id:
            raise ValidationError("transfer references a different bill")
        sender_address = validate_address(transfer["sender_address"], "sender address")
        recipient_address = validate_address(transfer["recipient_address"], "recipient address")
        transfer_sequence = _require_int(transfer["sequence"], "transfer sequence", minimum=1)
        if transfer_sequence != sequence + 1:
            raise ValidationError("transfer sequence gap")
        if transfer["previous_hash"] != last_hash:
            raise ValidationError("transfer does not extend the current bill tip")
        if sender_address != owner_address:
            raise ValidationError("transfer sender is not the current owner")
        transfer_timestamp = _require_timestamp(transfer["timestamp"], "transfer timestamp")
        if transfer_timestamp > max_allowed_timestamp:
            raise ValidationError("transfer timestamp is too far in the future")
        if transfer_timestamp < issued_at:
            raise ValidationError("transfer timestamp predates genesis")
        if transfer_timestamp <= previous_timestamp:
            raise ValidationError("transfer timestamps must be strictly increasing")
        transfer_day = _timestamp_day(transfer_timestamp)
        transfer_days[transfer_day] = transfer_days.get(transfer_day, 0) + 1
        if transfer_days[transfer_day] > MAX_TRANSFERS_PER_BILL_PER_DAY:
            raise ValidationError("bill exceeds daily transfer limit")
        _verify_transfer_signature(transfer)
        recent_for_transparency.append(transfer)
        owner_address = recipient_address
        last_hash = transfer_hash(transfer)
        sequence = transfer_sequence
        previous_timestamp = transfer_timestamp

    if require_recent_transparency and recent_for_transparency:
        # Checkpoint proof covers the past; recent transfers still need their own log proofs.
        if transparency_verifier is None and require_transparency:
            transparency_verifier = _configured_transparency_verifier()
        if transparency_verifier is None:
            raise ValidationError(
                "transparency log verification is required for compact recent transfers"
            )
        try:
            for transfer in recent_for_transparency:
                transparency_verifier.verify_transfer(
                    transfer,
                    now=now,
                    require_current_root=require_current_root,
                )
        except Exception as exc:
            raise ValidationError(
                f"compact recent transfer transparency verification failed: {exc}"
            ) from exc

    return TokenState(
        token_id=token_id,
        owner_address=owner_address,
        last_transfer_hash=last_hash,
        sequence=sequence,
        display_id=checkpoint["display_id"],
        value=int(checkpoint["value"]),
    )


# Validate a v1 full-history bill or a v2 compact bill.
def verify_bill(
    bill,
    now=None,
    transparency_verifier=None,
    require_transparency=False,
    require_current_root=True,
    require_checkpoint_transparency=True,
    require_recent_transparency=None,
    allow_untrusted_embedded_roots=False,
    trusted_operator_public_key=None,
):
    if isinstance(bill, str):
        bill = _load_json(bill)
    if isinstance(bill, dict) and bill.get("type") == BILL_TYPE:
        return verify_compact_bill(
            bill,
            now=now,
            transparency_verifier=transparency_verifier,
            require_transparency=require_transparency,
            require_current_root=require_current_root,
            require_checkpoint_transparency=require_checkpoint_transparency,
            require_recent_transparency=require_recent_transparency,
            allow_untrusted_embedded_roots=allow_untrusted_embedded_roots,
            trusted_operator_public_key=trusted_operator_public_key,
        )
    return _verify_full_token(
        bill,
        now=now,
        transparency_verifier=transparency_verifier,
        require_transparency=require_transparency,
        require_current_root=require_current_root,
    )


# Compatibility alias for validating v1 full-history or v2 compact bills.
def verify_token(
    token,
    now=None,
    transparency_verifier=None,
    require_transparency=False,
    require_current_root=True,
    **kwargs,
):
    return verify_bill(
        token,
        now=now,
        transparency_verifier=transparency_verifier,
        require_transparency=require_transparency,
        require_current_root=require_current_root,
        **kwargs,
    )


# Append a signed transfer from the current owner to a recipient address.
def create_transfer(
    token,
    sender_private_key,
    sender_public_key,
    recipient_address,
    metadata=None,
    timestamp=None,
    transparency_verifier=None,
    allow_untrusted_embedded_roots=False,
):
    if isinstance(token, dict) and token.get("type") == BILL_TYPE:
        return create_transfer_v2(
            token,
            sender_private_key,
            sender_public_key,
            recipient_address,
            metadata=metadata,
            timestamp=timestamp,
            transparency_verifier=transparency_verifier,
            allow_untrusted_embedded_roots=allow_untrusted_embedded_roots,
        )
    recipient_address = validate_address(str(recipient_address).strip(), "recipient address")
    state = verify_token(token)
    sender_address = _owner_address_for_public_key(
        sender_public_key, state.owner_address, "sender key"
    )
    transfer_timestamp = _require_timestamp(
        int(timestamp if timestamp is not None else time.time()),
        "transfer timestamp",
    )
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


# Append a signed transfer to a v2 compact bill's recent history.
def create_transfer_v2(
    bill,
    sender_private_key,
    sender_public_key,
    recipient_address,
    metadata=None,
    timestamp=None,
    transparency_verifier=None,
    allow_untrusted_embedded_roots=False,
):
    recipient_address = validate_address(str(recipient_address).strip(), "recipient address")
    state = verify_compact_bill(
        bill,
        require_recent_transparency=False,
        transparency_verifier=transparency_verifier,
        allow_untrusted_embedded_roots=allow_untrusted_embedded_roots,
    )
    sender_address = _owner_address_for_public_key(
        sender_public_key, state.owner_address, "sender key"
    )
    transfer_timestamp = _require_timestamp(
        int(timestamp if timestamp is not None else time.time()),
        "transfer timestamp",
    )
    previous_timestamp = _last_history_timestamp(bill)
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
    new_bill = copy.deepcopy(bill)
    new_bill.setdefault("recent_history", []).append(transfer_signed)
    verify_compact_bill(
        new_bill,
        require_recent_transparency=False,
        transparency_verifier=transparency_verifier,
        allow_untrusted_embedded_roots=allow_untrusted_embedded_roots,
    )
    return new_bill


def _verify_token_for_local_tip_creation(
    token,
    transparency_verifier=None,
    allow_untrusted_embedded_roots=False,
):
    if isinstance(token, dict) and token.get("type") == BILL_TYPE:
        return verify_token(
            token,
            transparency_verifier=transparency_verifier,
            require_recent_transparency=False,
            allow_untrusted_embedded_roots=allow_untrusted_embedded_roots,
        )
    return verify_token(token)


# Wrap the latest transfer in the gossip message nodes relay to peers.
def create_transfer_announcement(
    token,
    now=None,
    transparency_verifier=None,
    allow_untrusted_embedded_roots=False,
):
    state = _verify_token_for_local_tip_creation(
        token,
        transparency_verifier=transparency_verifier,
        allow_untrusted_embedded_roots=allow_untrusted_embedded_roots,
    )
    if state.sequence == 0:
        raise ValidationError("genesis bill has no transfer to announce")
    if isinstance(token, dict) and token.get("type") == BILL_TYPE:
        return {
            "type": TRANSFER_ANNOUNCEMENT_V2_TYPE,
            "version": BILL_VERSION,
            "bill": token,
            "announced_at": current_time(now),
        }
    message = {
        "type": TRANSFER_ANNOUNCEMENT_TYPE,
        "version": TOKEN_VERSION,
        "token": token,
        "announced_at": current_time(now),
    }
    return message


# Countersign the bill tip to show that the recipient has seen the transfer.
def create_receipt(
    token,
    recipient_private_key,
    recipient_public_key,
    timestamp=None,
    now=None,
    transparency_verifier=None,
    allow_untrusted_embedded_roots=False,
):
    state = _verify_token_for_local_tip_creation(
        token,
        transparency_verifier=transparency_verifier,
        allow_untrusted_embedded_roots=allow_untrusted_embedded_roots,
    )
    if state.sequence == 0:
        raise ValidationError("genesis ownership does not require a receipt")
    recipient_address = _owner_address_for_public_key(
        recipient_public_key, state.owner_address, "receipt key"
    )
    tip_timestamp = _last_history_timestamp(token)
    wall_now = current_time(now)
    received_at = _require_timestamp(
        int(timestamp if timestamp is not None else wall_now),
        "receipt timestamp",
    )
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


# Build the gossip message that moves a received transfer into local settlement.
def create_receipt_announcement(
    token,
    recipient_private_key,
    recipient_public_key,
    now=None,
    transparency_verifier=None,
    allow_untrusted_embedded_roots=False,
):
    receipt = create_receipt(
        token,
        recipient_private_key,
        recipient_public_key,
        now=now,
        transparency_verifier=transparency_verifier,
        allow_untrusted_embedded_roots=allow_untrusted_embedded_roots,
    )
    if isinstance(token, dict) and token.get("type") == BILL_TYPE:
        return {
            "type": RECEIPT_ANNOUNCEMENT_V2_TYPE,
            "version": BILL_VERSION,
            "bill": token,
            "receipt": receipt,
            "announced_at": current_time(now),
        }
    return {
        "type": RECEIPT_ANNOUNCEMENT_TYPE,
        "version": TOKEN_VERSION,
        "token": token,
        "receipt": receipt,
        "announced_at": current_time(now),
    }


# Validate a recipient receipt against the bill tip it claims to acknowledge.
def verify_receipt_announcement(
    message,
    transparency_verifier=None,
    require_transparency=False,
    now=None,
    require_current_root=True,
    require_recent_transparency=None,
    allow_untrusted_embedded_roots=False,
):
    if isinstance(message, str):
        message = _load_json(message)
    if message.get("type") == RECEIPT_ANNOUNCEMENT_V2_TYPE:
        _require_exact_fields(message, RECEIPT_ANNOUNCEMENT_V2_FIELDS, "v2 receipt announcement")
        if _require_int(message["version"], "v2 receipt announcement version") != BILL_VERSION:
            raise ValidationError("unsupported v2 receipt announcement version")
        token = message.get("bill")
    else:
        _require_exact_fields(message, RECEIPT_ANNOUNCEMENT_FIELDS, "receipt announcement")
        if message.get("type") != RECEIPT_ANNOUNCEMENT_TYPE:
            raise ValidationError("not a receipt announcement")
        if _require_int(message["version"], "receipt announcement version") != TOKEN_VERSION:
            raise ValidationError("unsupported receipt announcement version")
        token = message.get("token")
    if message.get("type") not in {RECEIPT_ANNOUNCEMENT_TYPE, RECEIPT_ANNOUNCEMENT_V2_TYPE}:
        raise ValidationError("not a receipt announcement")
    receipt = message.get("receipt")
    state = verify_token(
        token,
        now=now,
        transparency_verifier=transparency_verifier,
        require_transparency=require_transparency,
        require_current_root=require_current_root,
        require_recent_transparency=require_recent_transparency,
        allow_untrusted_embedded_roots=allow_untrusted_embedded_roots,
    )
    _require_exact_fields(receipt, RECEIPT_FIELDS, "receipt")
    if receipt.get("type") != RECEIPT_TYPE:
        raise ValidationError("malformed receipt")
    if _require_int(receipt["version"], "receipt version") != TOKEN_VERSION:
        raise ValidationError("unsupported receipt version")
    if receipt["token_id"] != state.token_id:
        raise ValidationError("receipt references a different bill")
    if receipt["transfer_hash"] != state.last_transfer_hash:
        raise ValidationError("receipt does not reference the bill tip")
    if _require_int(receipt["sequence"], "receipt sequence", minimum=1) != state.sequence:
        raise ValidationError("receipt sequence does not match bill tip")
    received_at = _require_timestamp(receipt["received_at"], "receipt received_at")
    tip_timestamp = _last_history_timestamp(token)
    if tip_timestamp is not None and received_at < tip_timestamp:
        raise ValidationError("receipt timestamp predates transfer")
    if received_at > current_time(now) + MAX_TRANSFER_FUTURE_SKEW_SECONDS:
        raise ValidationError("receipt timestamp is too far in the future")
    recipient_address = validate_address(receipt["recipient_address"], "recipient address")
    if recipient_address != state.owner_address:
        raise ValidationError("receipt signer is not the bill recipient")
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
    history = _bill_history(token)
    if not history:
        raise ValidationError("bill has no transfer")
    return history[-1]


def _conflict_key(transfer):
    return (
        transfer["token_id"],
        int(transfer["sequence"]),
        transfer["previous_hash"],
        transfer["sender_address"],
    )


def _find_conflicting_transfer_pair(token_a, token_b):
    state_a = verify_token(token_a)
    state_b = verify_token(token_b)
    if state_a.token_id != state_b.token_id:
        return None
    transfers_a = {}
    for transfer in _bill_history(token_a):
        transfers_a.setdefault(_conflict_key(transfer), []).append(transfer)
    for transfer_b in _bill_history(token_b):
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
    return {
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


# Create a portable proof that one owner signed two spends from the same state.
def create_conflict_proof(token_a, token_b, detected_at=None):
    pair = _find_conflicting_transfer_pair(token_a, token_b)
    if not pair:
        raise ValidationError("bills do not contain a double-spend conflict")
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


# Return the stable identity of a conflict, ignoring when a node observed it.
def conflict_proof_key(proof):
    if isinstance(proof, str):
        proof = _load_json(proof)
    _require_exact_fields(proof, CONFLICT_PROOF_FIELDS, "conflict proof")
    hash_a = str(proof["transfer_hash_a"])
    hash_b = str(proof["transfer_hash_b"])
    if hash_b < hash_a:
        hash_a, hash_b = hash_b, hash_a
    identity = {
        "type": CONFLICT_PROOF_TYPE,
        "version": _require_int(proof["version"], "conflict proof version"),
        "token_id": str(proof["token_id"]),
        "previous_hash": str(proof["previous_hash"]),
        "sequence": _require_int(proof["sequence"], "conflict proof sequence"),
        "transfer_hash_a": hash_a,
        "transfer_hash_b": hash_b,
    }
    return sha3_hex(_canonical_bytes(identity))


# Verify that a conflict proof really contains two valid conflicting branches.
def verify_conflict_proof(proof):
    if isinstance(proof, str):
        proof = _load_json(proof)
    _require_exact_fields(proof, CONFLICT_PROOF_FIELDS, "conflict proof")
    if proof.get("type") != CONFLICT_PROOF_TYPE:
        raise ValidationError("not a conflict proof")
    if _require_int(proof["version"], "conflict proof version") != TOKEN_VERSION:
        raise ValidationError("unsupported conflict proof version")
    pair = _find_conflicting_transfer_pair(proof.get("token_a"), proof.get("token_b"))
    if not pair:
        raise ValidationError("conflict proof bills are not conflicting")
    expected_unsigned = _conflict_proof_unsigned(
        proof["token_a"],
        proof["token_b"],
        pair[0],
        pair[1],
        _require_timestamp(proof["detected_at"], "conflict proof detected_at"),
    )
    unsigned = copy.deepcopy(proof)
    proof_hash_value = unsigned.pop("proof_hash", None)
    expected_hash = sha3_hex(_canonical_bytes(unsigned))
    if proof_hash_value != expected_hash:
        raise ValidationError("conflict proof hash mismatch")
    if expected_unsigned != unsigned:
        raise ValidationError("conflict proof conflict fields mismatch")
    return True


# Wrap a signed transparency root for peer gossip.
def create_transparency_root_announcement(root, observed_at=None):
    from . import transparency_client as log_client

    message = log_client.make_root_announcement(root, observed_at=observed_at)
    if len(canonical_json(message).encode("utf-8")) > MAX_TRANSPARENCY_ROOT_GOSSIP_BYTES:
        raise ValidationError("transparency root announcement is too large")
    return message


# Verify a peer-gossiped transparency root announcement.
def verify_transparency_root_announcement(message, operator_public_key=None):
    from . import transparency_client as log_client

    if isinstance(message, str):
        message = _load_json(message)
    _require_exact_fields(
        message, TRANSPARENCY_ROOT_ANNOUNCEMENT_FIELDS, "transparency root announcement"
    )
    if len(canonical_json(message).encode("utf-8")) > MAX_TRANSPARENCY_ROOT_GOSSIP_BYTES:
        raise ValidationError("transparency root announcement is too large")
    try:
        return log_client.verify_root_announcement(message, operator_public_key=operator_public_key)
    except Exception as exc:
        raise ValidationError(f"invalid transparency root announcement: {exc}") from exc


# Build a gossip proof that a log operator signed conflicting roots.
def create_transparency_equivocation_proof(root_a, root_b, collision_type=None, detected_at=None):
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


# Verify a self-contained transparency equivocation proof.
def verify_transparency_equivocation_proof(message, operator_public_key=None):
    from . import transparency_client as log_client

    if isinstance(message, str):
        message = _load_json(message)
    _require_exact_fields(
        message, TRANSPARENCY_EQUIVOCATION_PROOF_FIELDS, "transparency equivocation proof"
    )
    if len(canonical_json(message).encode("utf-8")) > MAX_TRANSPARENCY_EQUIVOCATION_GOSSIP_BYTES:
        raise ValidationError("transparency equivocation proof is too large")
    try:
        return log_client.verify_equivocation_proof(
            message, operator_public_key=operator_public_key
        )
    except Exception as exc:
        raise ValidationError(f"invalid transparency equivocation proof: {exc}") from exc


# Build gossip evidence that a log operator signed a policy-violating root.
def create_transparency_operator_policy_violation_proof(
    root, spend_proof, violation_type=None, detected_at=None
):
    from . import transparency_client as log_client

    message = log_client.make_operator_policy_violation_proof(
        root,
        spend_proof,
        violation_type=violation_type or "accepted_conflicting_spend",
        detected_at=detected_at,
    )
    if (
        len(canonical_json(message).encode("utf-8"))
        > MAX_TRANSPARENCY_OPERATOR_POLICY_VIOLATION_GOSSIP_BYTES
    ):
        raise ValidationError("transparency operator policy violation proof is too large")
    return message


# Verify self-contained evidence that a transparency operator violated log policy.
def verify_transparency_operator_policy_violation_proof(message, operator_public_key=None):
    from . import transparency_client as log_client

    if isinstance(message, str):
        message = _load_json(message)
    _require_exact_fields(
        message,
        TRANSPARENCY_OPERATOR_POLICY_VIOLATION_FIELDS,
        "transparency operator policy violation proof",
    )
    if (
        len(canonical_json(message).encode("utf-8"))
        > MAX_TRANSPARENCY_OPERATOR_POLICY_VIOLATION_GOSSIP_BYTES
    ):
        raise ValidationError("transparency operator policy violation proof is too large")
    try:
        return log_client.verify_operator_policy_violation_proof(
            message, operator_public_key=operator_public_key
        )
    except Exception as exc:
        raise ValidationError(
            f"invalid transparency operator policy violation proof: {exc}"
        ) from exc
