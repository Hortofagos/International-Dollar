# V3 Ed25519 key text formats and x3 address helpers.

import base64
from hashlib import sha3_256

import base58

from . import crypto_ed25519
from .protocol import (
    ADDRESS_CHECKSUM_BYTES,
    ADDRESS_CHECKSUM_CHARS,
    ADDRESS_PREFIX,
    ADDRESS_SUFFIX,
    ADDRESS_TARGET_LENGTH,
    BASE58_ALPHABET,
    ValidationError,
    _fixed_base58,
)

PRIVATE_KEY_PREFIX = "indsk3:"
PUBLIC_KEY_PREFIX = "indpk3:"
ADDRESS_VERSION = "3"
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


def _b85_encode(raw):
    return base64.b85encode(raw).decode("ascii")


def _b85_decode(text, length, label):
    if not isinstance(text, str) or text != text.strip():
        raise ValidationError(f"invalid {label}")
    try:
        raw = base64.b85decode(text.encode("ascii"))
    except Exception as exc:
        raise ValidationError(f"invalid {label}") from exc
    if len(raw) != int(length):
        raise ValidationError(f"{label} must decode to exactly {int(length)} bytes")
    return raw


# Encode a raw 32-byte Ed25519 private seed as indsk3 text.
def encode_private_key(private_seed):
    crypto_ed25519._require_bytes(
        private_seed,
        crypto_ed25519.PRIVATE_SEED_BYTES,
        "V3 private seed",
    )
    return PRIVATE_KEY_PREFIX + _b85_encode(private_seed)


# Decode indsk3 text to the raw Ed25519 private seed bytes.
def decode_private_key(private_key_text):
    if not isinstance(private_key_text, str) or not private_key_text.startswith(PRIVATE_KEY_PREFIX):
        raise ValidationError("invalid V3 private key")
    return _b85_decode(
        private_key_text[len(PRIVATE_KEY_PREFIX) :],
        crypto_ed25519.PRIVATE_SEED_BYTES,
        "V3 private key",
    )


# Encode a raw 32-byte Ed25519 public key as indpk3 text.
def encode_public_key(public_key_bytes):
    crypto_ed25519._require_bytes(
        public_key_bytes,
        crypto_ed25519.PUBLIC_KEY_BYTES,
        "V3 public key",
    )
    return PUBLIC_KEY_PREFIX + _b85_encode(public_key_bytes)


# Decode indpk3 text to raw Ed25519 public-key bytes.
def decode_public_key(public_key_text):
    if not isinstance(public_key_text, str) or not public_key_text.startswith(PUBLIC_KEY_PREFIX):
        raise ValidationError("invalid V3 public key")
    return _b85_decode(
        public_key_text[len(PUBLIC_KEY_PREFIX) :],
        crypto_ed25519.PUBLIC_KEY_BYTES,
        "V3 public key",
    )


def _public_key_bytes(public_key):
    if isinstance(public_key, bytes):
        return crypto_ed25519._require_bytes(
            public_key,
            crypto_ed25519.PUBLIC_KEY_BYTES,
            "V3 public key",
        )
    return decode_public_key(public_key)


def _address_payload(public_key_bytes):
    digest = sha3_256(b"IND-address-v3:ed25519:" + public_key_bytes).digest()
    return base58.b58encode(digest).decode("ascii")[:ADDRESS_PAYLOAD_CHARS]


def _address_checksum(payload):
    if not isinstance(payload, str) or not all(char in BASE58_ALPHABET for char in payload):
        raise ValidationError("invalid V3 address payload")
    digest = sha3_256(b"IND-address-checksum:v3:" + payload.encode("ascii")).digest()
    return _fixed_base58(digest[:ADDRESS_CHECKSUM_BYTES], ADDRESS_CHECKSUM_CHARS)


# Derive the x3 V3 address for an Ed25519 public key.
def address_from_public_key(public_key):
    payload = _address_payload(_public_key_bytes(public_key))
    return f"{ADDRESS_PREFIX}{ADDRESS_VERSION}{payload}{_address_checksum(payload)}{ADDRESS_SUFFIX}"


def is_address(address):
    if not isinstance(address, str) or len(address) != ADDRESS_LENGTH:
        return False
    if not address.startswith(ADDRESS_PREFIX + ADDRESS_VERSION) or not address.endswith(
        ADDRESS_SUFFIX
    ):
        return False
    payload_start = len(ADDRESS_PREFIX) + len(ADDRESS_VERSION)
    payload_end = payload_start + ADDRESS_PAYLOAD_CHARS
    payload = address[payload_start:payload_end]
    checksum = address[payload_end : -len(ADDRESS_SUFFIX)]
    if len(payload) != ADDRESS_PAYLOAD_CHARS or len(checksum) != ADDRESS_CHECKSUM_CHARS:
        return False
    if not all(char in BASE58_ALPHABET for char in payload + checksum):
        return False
    return checksum == _address_checksum(payload)


# Return a valid x3 address or raise ValidationError.
def validate_address(address, label="V3 address"):
    if not isinstance(address, str) or address != address.strip() or not is_address(address):
        raise ValidationError(f"invalid {label}")
    return address


def public_key_matches_address(public_key, address):
    try:
        return address_from_public_key(public_key) == validate_address(address)
    except ValidationError:
        return False


# Generate or derive one V3 address plus indsk3/indpk3 keypair.
def generate_keypair(private_seed=None):
    private_seed = private_seed or crypto_ed25519.generate_private_seed()
    public_key = crypto_ed25519.public_key_from_private_seed(private_seed)
    private_text = encode_private_key(private_seed)
    public_text = encode_public_key(public_key)
    return address_from_public_key(public_key), private_text, public_text


def sign(private_key_text, message):
    return crypto_ed25519.sign(decode_private_key(private_key_text), message)


def verify(public_key_text, signature, message):
    return crypto_ed25519.verify(decode_public_key(public_key_text), signature, message)
