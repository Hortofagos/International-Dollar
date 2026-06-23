# Shared IND protocol utilities for the active V3 implementation.

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


def _env_int(name, default):
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return int(default)


def _env_true(name):
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


MASTER_SUPPLY_NUMBER = 33
ANGEL_NUMBER = 777
MONEY_NUMBER = 8
BIRTHDAY_NUMBER = 9
BIRTHDAY_CODE = "09.10.2003"
TOTAL_SUPPLY = MASTER_SUPPLY_NUMBER * 1_000_000_000
ALLOWED_BILL_VALUES = (
    1,
    2,
    5,
    10,
    20,
    50,
    100,
    200,
    500,
    1000,
    2000,
    5000,
    10000,
    20000,
    50000,
    100000,
)
ALLOWED_BILL_VALUE_SET = frozenset(ALLOWED_BILL_VALUES)
DENOMINATION_SERIAL_CAPS = {
    1: 6_000_000_000,
    2: 5_500_000_000,
    5: 5_000_000_000,
    10: 4_500_000_000,
    20: 4_000_000_000,
    50: 2_000_000_000,
    100: 1_500_000_000,
    200: 1_000_000_000,
    500: 800_000_000,
    1000: 700_000_000,
    2000: 600_000_000,
    5000: 500_000_000,
    10000: 400_000_000,
    20000: 250_000_000,
    50000: 150_000_000,
    100000: 100_000_000,
}
TOTAL_DENOMINATION_SERIAL_CAPS = sum(DENOMINATION_SERIAL_CAPS.values())
if tuple(DENOMINATION_SERIAL_CAPS) != ALLOWED_BILL_VALUES:
    raise RuntimeError("denomination serial caps must match allowed IND denominations")
if TOTAL_DENOMINATION_SERIAL_CAPS != TOTAL_SUPPLY:
    raise RuntimeError("denomination serial caps must total the fixed IND supply")

TOKEN_VERSION = 3
BILL_VERSION = 3
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
NUMEROLOGY_METADATA_KEY = "ind_alignment"

TOKEN_TYPE = "ind.token.v3"
BILL_TYPE = "ind.bill.v3"
CHECKPOINT_ANNOUNCEMENT_TYPE = "ind.checkpoint_announcement.v3"
TRANSFER_TYPE = "ind.transfer.v3"
TRANSFER_ANNOUNCEMENT_TYPE = "ind.transfer_announcement.v3"
TRANSFER_ANNOUNCEMENT_V3_TYPE = TRANSFER_ANNOUNCEMENT_TYPE
RECEIPT_TYPE = "ind.receipt.v3"
RECEIPT_ANNOUNCEMENT_TYPE = "ind.receipt_announcement.v3"
RECEIPT_ANNOUNCEMENT_V3_TYPE = RECEIPT_ANNOUNCEMENT_TYPE
CONFLICT_PROOF_TYPE = "ind.conflict_proof.v3"
TRANSPARENCY_ROOT_ANNOUNCEMENT_TYPE = "ind.transparency_root_announcement.v3"
TRANSPARENCY_EQUIVOCATION_PROOF_TYPE = "ind.transparency_equivocation_proof.v3"
TRANSPARENCY_OPERATOR_POLICY_VIOLATION_TYPE = "ind.transparency_operator_policy_violation.v3"
TOKEN_STATE_REF_TYPE = "ind.token_state_ref.v3"
STORED_MESSAGE_REF_TYPE = "ind.stored_message_ref.v3"
GENESIS_MANIFEST_TYPE = "ind.genesis_manifest.v3"

TRANSFER_SIGNATURE_DOMAIN = "IND_TRANSFER_V3"

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
MAX_WIRE_COMPRESSED_BYTES = _env_int("IND_MAX_WIRE_COMPRESSED_BYTES", 2 * 1024 * 1024)
MAX_WIRE_DECOMPRESSED_BYTES = _env_int("IND_MAX_WIRE_DECOMPRESSED_BYTES", 8 * 1024 * 1024)
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


class TokenError(Exception):
    pass


class ValidationError(TokenError):
    pass


class WireSizeError(ValidationError):
    pass


class ClosingConnection(sqlite3.Connection):
    def __exit__(self, exc_type, exc_value, traceback):
        result = super().__exit__(exc_type, exc_value, traceback)
        self.close()
        return result


def configure_sqlite_connection(conn):
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute(f"PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS}")
    return conn


@dataclass(frozen=True)
class TokenState:
    token_id: str
    owner_address: str
    last_transfer_hash: str
    sequence: int
    display_id: str
    value: int


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


def _reject_json_float(_value):
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


def validate_bill_value(value, label="bill value"):
    value = _require_int(value, label, minimum=1)
    if value not in ALLOWED_BILL_VALUE_SET:
        raise ValidationError(f"{label} is not an allowed IND denomination")
    return value


def validate_bill_serial(value, serial, label="bill serial"):
    value = validate_bill_value(value, "bill serial value")
    cap = DENOMINATION_SERIAL_CAPS[value]
    return _require_int(serial, label, minimum=1, maximum=cap)


def _require_timestamp(value, label, minimum=0):
    return _require_int(value, label, minimum=minimum, maximum=MAX_PROTOCOL_TIMESTAMP)


def _require_str(value, label, max_bytes=MAX_JSON_STRING_BYTES):
    if not isinstance(value, str):
        raise ValidationError(f"{label} must be a string")
    if len(value.encode("utf-8")) > int(max_bytes):
        raise ValidationError(f"{label} is too large")
    return value


def _require_metadata(metadata, limit, label):
    if not isinstance(metadata, dict):
        raise ValidationError(f"{label} metadata must be an object")
    _validate_json_value(metadata, f"{label} metadata")
    if len(_canonical_bytes(metadata)) > int(limit):
        raise ValidationError(f"{label} metadata is too large")


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


def pack_wire_message(message):
    if isinstance(message, bytes):
        message = message.decode("utf-8")
    if isinstance(message, str):
        if message.strip().startswith(WIRE_PACKED_PREFIX):
            return message.strip()
        message = _json_loads_strict(message)
    return _packed_json(message)


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


def sha3_hex(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return sha3_256(data).hexdigest()


def b85_sign(private_key_base85, data):
    raise ValidationError("legacy base85 signing is disabled; use V3 Ed25519 keys")


def b85_verify(public_key_base85, signature_base85, data):
    return False


def signature_payload(domain, data):
    domain = _require_str(str(domain), "signature domain", max_bytes=128)
    payload = data if isinstance(data, bytes) else _canonical_bytes(data)
    return b"IND-SIGNATURE-V3:" + domain.encode("ascii") + b"\n" + payload


def b85_sign_domain(private_key_base85, domain, data):
    return b85_sign(private_key_base85, signature_payload(domain, data))


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


def legacy_address_from_public_key(public_key_base85):
    digest = sha3_256(public_key_base85.strip().encode("utf-8")).digest()
    return base58.b58encode(digest).decode("utf-8")[:LEGACY_ADDRESS_LENGTH]


def previous_address_from_public_key(public_key_base85):
    payload = _address_payload_from_public_key(public_key_base85, PREVIOUS_ADDRESS_PAYLOAD_CHARS)
    checksum = _address_checksum(ADDRESS_VERSION, payload)
    return f"{ADDRESS_PREFIX}{ADDRESS_VERSION}{payload}{checksum}{ADDRESS_SUFFIX}"


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
        return _env_true("IND_ALLOW_UNTRUSTED_GENESIS")


def token_display_id(token):
    genesis = token["genesis"]
    value = int(genesis.get("value", 1))
    index = int(genesis["index"])
    return f"{value}x{index}"


def _timestamp_day(timestamp):
    return int(timestamp) // 86400


def _bill_history(token):
    if not isinstance(token, dict):
        return []
    if token.get("type") == BILL_TYPE:
        return token.get("recent_history", [])
    return token.get("history", [])


def _last_history_timestamp(token):
    history = _bill_history(token)
    if not history:
        checkpoint = token.get("checkpoint") if isinstance(token, dict) else None
        if isinstance(checkpoint, dict) and checkpoint.get("last_transfer_timestamp") is not None:
            return int(checkpoint["last_transfer_timestamp"])
        return None
    return int(history[-1]["timestamp"])


def _last_transfer(token):
    history = _bill_history(token)
    if not history:
        raise ValidationError("bill has no transfer")
    return history[-1]


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
    return sha3_hex(_canonical_bytes(genesis))


def transfer_hash(transfer):
    return sha3_hex(_canonical_bytes(transfer))


def message_hash(message):
    return sha3_hex(_canonical_bytes(message))


def _unsigned_manifest(manifest):
    unsigned = copy.deepcopy(manifest)
    unsigned.pop("signature", None)
    unsigned.pop("manifest_hash", None)
    return unsigned


def genesis_manifest_hash(manifest):
    return sha3_hex(_canonical_bytes(_unsigned_manifest(manifest)))


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
    return True


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


def _conflict_key(transfer):
    return (
        transfer["token_id"],
        int(transfer["sequence"]),
        transfer["previous_hash"],
        transfer["sender_address"],
    )


def _conflicting_transfers(token_a, token_b):
    transfers_a = {}
    for transfer in _bill_history(token_a):
        transfers_a.setdefault(_conflict_key(transfer), []).append(transfer)
    for transfer_b in _bill_history(token_b):
        for transfer_a in transfers_a.get(_conflict_key(transfer_b), []):
            if transfer_hash(transfer_a) != transfer_hash(transfer_b):
                return True
    return False


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


def create_transparency_root_announcement(root, observed_at=None):
    from . import transparency_client as log_client

    message = log_client.make_root_announcement(root, observed_at=observed_at)
    if len(canonical_json(message).encode("utf-8")) > MAX_TRANSPARENCY_ROOT_GOSSIP_BYTES:
        raise ValidationError("transparency root announcement is too large")
    return message


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
