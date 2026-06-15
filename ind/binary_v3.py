# Canonical binary primitives for IND V3 objects.

from dataclasses import dataclass
from hashlib import sha3_256

from .crypto_ed25519 import SIGNATURE_ALGORITHM_ID as SIGNATURE_ALGORITHM_ID
from .protocol import MAX_PROTOCOL_TIMESTAMP, ValidationError

VERSION = 3
MAX_UVARINT = MAX_PROTOCOL_TIMESTAMP
MAX_BOUNDED_BYTES = 64 * 1024
MAX_SIGNING_PREIMAGE_OBJECT_BYTES = 1024 * 1024
SIGNATURE_PREIMAGE_MAGIC = b"IND-SIGNATURE-V3\x00"


# Raised when V3 canonical binary decoding fails closed.
class BinaryV3Error(ValidationError):
    pass


def _require_uint(value, label, maximum=MAX_UVARINT):
    if type(value) is not int:
        raise BinaryV3Error(f"{label} must be an integer")
    if value < 0:
        raise BinaryV3Error(f"{label} must be non-negative")
    if value > int(maximum):
        raise BinaryV3Error(f"{label} exceeds maximum value")
    return value


# Encode a non-negative integer as minimal unsigned LEB128.
def encode_uvarint(value):
    value = _require_uint(value, "uvarint")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


# Decode one complete unsigned LEB128 integer.
def decode_uvarint(data):
    reader = Reader(data)
    value = reader.read_uvarint("uvarint")
    reader.require_eof()
    return value


# Prefix bytes with their canonical bounded length.
def encode_bytes(data, max_length=MAX_BOUNDED_BYTES):
    if not isinstance(data, bytes):
        raise BinaryV3Error("bounded bytes must be bytes")
    if len(data) > int(max_length):
        raise BinaryV3Error("bounded bytes exceed maximum length")
    return encode_uvarint(len(data)) + data


# Encode text that must stay ASCII on the wire.
def encode_ascii(text, max_length=MAX_BOUNDED_BYTES):
    if not isinstance(text, str):
        raise BinaryV3Error("ASCII field must be a string")
    try:
        raw = text.encode("ascii")
    except UnicodeEncodeError as exc:
        raise BinaryV3Error("ASCII field contains non-ASCII text") from exc
    return encode_bytes(raw, max_length=max_length)


# Require a byte field whose length is fixed by the protocol.
def encode_fixed_bytes(data, length, label="fixed bytes"):
    if not isinstance(data, bytes) or len(data) != int(length):
        raise BinaryV3Error(f"{label} must be exactly {int(length)} bytes")
    return data


# Encode optional 32-byte hashes with a one-byte presence marker.
def encode_nullable_hash(value):
    if value is None:
        return b"\x00"
    return b"\x01" + encode_fixed_bytes(value, 32, "hash")


# Convert canonical lowercase hash text to bytes.
def encode_hash_hex(hex_text):
    if not isinstance(hex_text, str) or len(hex_text) != 64:
        raise BinaryV3Error("hash hex must be 64 characters")
    try:
        return bytes.fromhex(hex_text)
    except ValueError as exc:
        raise BinaryV3Error("invalid hash hex") from exc


# Convert a 32-byte hash back to lowercase hex.
def decode_hash_hex(raw):
    return encode_fixed_bytes(raw, 32, "hash").hex()


# Hash one typed canonical binary object with its domain.
def object_hash(domain, canonical_bytes):
    if not isinstance(domain, str):
        raise BinaryV3Error("object hash domain must be a string")
    if not isinstance(canonical_bytes, bytes):
        raise BinaryV3Error("object hash payload must be bytes")
    return sha3_256(encode_ascii(domain, max_length=128) + encode_bytes(canonical_bytes)).digest()


# Build the exact V3 domain-separated bytes signed by Ed25519 objects.
def signing_preimage(
    network_id,
    object_type,
    object_version,
    signature_algorithm,
    domain,
    canonical_object_without_signature,
):
    _require_uint(network_id, "network id")
    _require_uint(object_version, "object version")
    _require_uint(signature_algorithm, "signature algorithm")
    return b"".join(
        (
            SIGNATURE_PREIMAGE_MAGIC,
            encode_uvarint(network_id),
            encode_ascii(object_type, max_length=64),
            encode_uvarint(object_version),
            encode_uvarint(signature_algorithm),
            encode_ascii(domain, max_length=128),
            encode_bytes(
                canonical_object_without_signature,
                max_length=MAX_SIGNING_PREIMAGE_OBJECT_BYTES,
            ),
        )
    )


@dataclass
class Reader:
    data: bytes
    offset: int = 0

    def __post_init__(self):
        if not isinstance(self.data, bytes):
            raise BinaryV3Error("binary input must be bytes")

    # Return unread byte count without advancing.
    def remaining(self):
        return len(self.data) - self.offset

    # Read an exact byte count and advance the cursor.
    def read(self, length, label="bytes"):
        length = _require_uint(length, "read length", maximum=MAX_BOUNDED_BYTES)
        end = self.offset + length
        if end > len(self.data):
            raise BinaryV3Error(f"truncated {label}")
        chunk = self.data[self.offset : end]
        self.offset = end
        return chunk

    # Decode a minimal unsigned LEB128 integer from the cursor.
    def read_uvarint(self, label="uvarint"):
        start = self.offset
        value = 0
        shift = 0
        while True:
            if self.offset >= len(self.data):
                raise BinaryV3Error(f"truncated {label}")
            byte = self.data[self.offset]
            self.offset += 1
            value |= (byte & 0x7F) << shift
            if value > MAX_UVARINT:
                raise BinaryV3Error(f"{label} exceeds maximum value")
            if not byte & 0x80:
                raw = self.data[start : self.offset]
                if encode_uvarint(value) != raw:
                    raise BinaryV3Error(f"non-minimal {label}")
                return value
            shift += 7
            if shift > 63:
                raise BinaryV3Error(f"{label} is too large")

    # Read a length-prefixed bounded byte field.
    def read_bytes(self, label="bounded bytes", max_length=MAX_BOUNDED_BYTES):
        length = self.read_uvarint(f"{label} length")
        if length > int(max_length):
            raise BinaryV3Error(f"{label} exceeds maximum length")
        return self.read(length, label)

    # Read a bounded byte field and require ASCII text.
    def read_ascii(self, label="ASCII field", max_length=MAX_BOUNDED_BYTES):
        raw = self.read_bytes(label, max_length=max_length)
        try:
            return raw.decode("ascii")
        except UnicodeDecodeError as exc:
            raise BinaryV3Error(f"{label} contains non-ASCII text") from exc

    # Read a byte field whose length is fixed by the caller.
    def read_fixed_bytes(self, length, label="fixed bytes"):
        return self.read(length, label)

    # Read an optional 32-byte hash encoded with a presence marker.
    def read_nullable_hash(self, label="nullable hash"):
        marker = self.read(1, f"{label} marker")
        if marker == b"\x00":
            return None
        if marker == b"\x01":
            return self.read_fixed_bytes(32, label)
        raise BinaryV3Error(f"invalid {label} marker")

    # Require every byte in the envelope to have been consumed.
    def require_eof(self):
        if self.offset != len(self.data):
            raise BinaryV3Error("trailing bytes")
        return True


# Run a reader callback and reject trailing bytes.
def decode_all(data, decoder):
    reader = Reader(data)
    result = decoder(reader)
    reader.require_eof()
    return result
