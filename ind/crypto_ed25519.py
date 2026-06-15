# Ed25519 helpers for IND V3 signing keys.

import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from .protocol import ValidationError

PRIVATE_SEED_BYTES = 32
PUBLIC_KEY_BYTES = 32
SIGNATURE_BYTES = 64
SIGNATURE_ALGORITHM_ID = 1
SIGNATURE_ALGORITHM_NAME = "IND_V3_ED25519_PURE_CONTEXT"


def _require_bytes(value, length, label):
    if not isinstance(value, bytes) or len(value) != int(length):
        raise ValidationError(f"{label} must be exactly {int(length)} bytes")
    return value


# Return one raw 32-byte Ed25519 private seed.
def generate_private_seed():
    return os.urandom(PRIVATE_SEED_BYTES)


# Load a cryptography Ed25519 private key from a raw 32-byte seed.
def private_key_from_seed(private_seed):
    private_seed = _require_bytes(private_seed, PRIVATE_SEED_BYTES, "Ed25519 private seed")
    try:
        return ed25519.Ed25519PrivateKey.from_private_bytes(private_seed)
    except ValueError as exc:
        raise ValidationError("invalid Ed25519 private seed") from exc


# Derive the raw 32-byte Ed25519 public key from a private seed.
def public_key_from_private_seed(private_seed):
    public_key = private_key_from_seed(private_seed).public_key()
    return public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)


# Serialize a cryptography Ed25519 private key to its raw seed bytes.
def private_seed_from_key(private_key):
    if not isinstance(private_key, ed25519.Ed25519PrivateKey):
        raise ValidationError("invalid Ed25519 private key")
    return private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


# Load a cryptography Ed25519 public key from raw bytes.
def public_key_from_bytes(public_key_bytes):
    public_key_bytes = _require_bytes(public_key_bytes, PUBLIC_KEY_BYTES, "Ed25519 public key")
    try:
        return ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
    except ValueError as exc:
        raise ValidationError("invalid Ed25519 public key") from exc


# Sign bytes with Ed25519 and verify before returning the raw signature.
def sign(private_seed, message):
    if not isinstance(message, bytes):
        raise ValidationError("Ed25519 message must be bytes")
    private_key = private_key_from_seed(private_seed)
    signature = private_key.sign(message)
    if len(signature) != SIGNATURE_BYTES:
        raise ValidationError("invalid Ed25519 signature length")
    public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    if not verify(public_key, signature, message):
        raise ValidationError("Ed25519 sign-then-verify failed")
    return signature


# Return True when a raw Ed25519 signature verifies for the supplied bytes.
def verify(public_key_bytes, signature, message):
    if not isinstance(message, bytes):
        raise ValidationError("Ed25519 message must be bytes")
    if not isinstance(signature, bytes) or len(signature) != SIGNATURE_BYTES:
        return False
    try:
        public_key = public_key_from_bytes(public_key_bytes)
        public_key.verify(signature, message)
        return True
    except (InvalidSignature, ValidationError):
        return False
