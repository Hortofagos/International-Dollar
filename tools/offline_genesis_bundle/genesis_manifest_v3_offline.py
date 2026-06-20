#!/usr/bin/env python3
"""Standalone offline IND V3 genesis manifest tool.

This script uses only Python's standard library. It is meant for an air-gapped
Ubuntu machine where project dependencies were never installed.
"""

import argparse
import base64
import json
import secrets
import sys
import time
from hashlib import sha3_256, sha512
from pathlib import Path

GENESIS_MANIFEST_TYPE = "ind.genesis_manifest.v3"
GENESIS_MANIFEST_VERSION = 3
GENESIS_MANIFEST_SIGNATURE_DOMAIN = "IND_GENESIS_MANIFEST_V3"
GENESIS_HASH_ALGORITHM = "IND_GENESIS_REF_SHA3_256_V3"
GENESIS_NONCE_ALGORITHM = "IND_GENESIS_NONCE_SHA3_256_V3"
GENESIS_RANGE_SEED_ALGORITHM = "IND_GENESIS_RANGE_SEED_SHA3_256_V3"
ISSUER_KEY_ID_ALGORITHM = "IND_GENESIS_ISSUER_KEY_ID_SHA3_256_V3"
SIGNATURE_ALGORITHM_ID = 1
SIGNATURE_PREIMAGE_MAGIC = b"IND-SIGNATURE-V3\x00"

MASTER_SUPPLY_NUMBER = 33
TOTAL_SUPPLY = 33_000_000_000
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
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
PRIVATE_KEY_PREFIX = "indsk3:"
PUBLIC_KEY_PREFIX = "indpk3:"
ADDRESS_PREFIX = "x"
ADDRESS_VERSION = "3"
ADDRESS_SUFFIX = "x"
ADDRESS_CHECKSUM_BYTES = 4
ADDRESS_CHECKSUM_CHARS = 6
ADDRESS_TARGET_LENGTH = 33
ADDRESS_PAYLOAD_CHARS = ADDRESS_TARGET_LENGTH - (
    len(ADDRESS_PREFIX) + len(ADDRESS_VERSION) + ADDRESS_CHECKSUM_CHARS + len(ADDRESS_SUFFIX)
)


class ToolError(Exception):
    pass


def canonical_json(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def canonical_bytes(data):
    return canonical_json(data).encode("utf-8")


def sha3_json(data):
    return sha3_256(canonical_bytes(data)).hexdigest()


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path, data):
    Path(path).write_text(
        json.dumps(data, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def require_int(value, label, minimum=None, maximum=None):
    if type(value) is not int:
        raise ToolError(f"{label} must be an integer")
    if minimum is not None and value < int(minimum):
        raise ToolError(f"{label} is below the allowed range")
    if maximum is not None and value > int(maximum):
        raise ToolError(f"{label} is above the allowed range")
    return value


def hex32(value, label):
    if not isinstance(value, str) or len(value) != 64:
        raise ToolError(f"invalid {label}")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise ToolError(f"invalid {label}") from exc
    return value.lower()


def b58encode(data):
    number = int.from_bytes(data, "big")
    chars = ""
    while number:
        number, remainder = divmod(number, 58)
        chars = BASE58_ALPHABET[remainder] + chars
    pad = 0
    for byte in data:
        if byte == 0:
            pad += 1
        else:
            break
    return "1" * pad + (chars or "")


def fixed_base58(data, length):
    encoded = b58encode(data)
    if len(encoded) > int(length):
        raise ToolError("address checksum encoding overflow")
    return encoded.rjust(int(length), "1")


def b85_encode(raw):
    return base64.b85encode(raw).decode("ascii")


def b85_decode(text, length, label):
    if not isinstance(text, str) or text != text.strip():
        raise ToolError(f"invalid {label}")
    try:
        raw = base64.b85decode(text.encode("ascii"))
    except Exception as exc:
        raise ToolError(f"invalid {label}") from exc
    if len(raw) != int(length):
        raise ToolError(f"{label} must decode to exactly {int(length)} bytes")
    return raw


def encode_private_key(seed):
    if not isinstance(seed, bytes) or len(seed) != 32:
        raise ToolError("private seed must be exactly 32 bytes")
    return PRIVATE_KEY_PREFIX + b85_encode(seed)


def decode_private_key(text):
    if not isinstance(text, str) or not text.startswith(PRIVATE_KEY_PREFIX):
        raise ToolError("invalid V3 private key")
    return b85_decode(text[len(PRIVATE_KEY_PREFIX) :], 32, "V3 private key")


def encode_public_key(public_key):
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise ToolError("public key must be exactly 32 bytes")
    return PUBLIC_KEY_PREFIX + b85_encode(public_key)


def decode_public_key(text):
    if not isinstance(text, str) or not text.startswith(PUBLIC_KEY_PREFIX):
        raise ToolError("invalid V3 public key")
    return b85_decode(text[len(PUBLIC_KEY_PREFIX) :], 32, "V3 public key")


# Pure-Python Ed25519 implementation for offline signing.
P = 2**255 - 19
Q = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
I = pow(2, (P - 1) // 4, P)


def xrecover(y):
    xx = (y * y - 1) * pow(D * y * y + 1, P - 2, P)
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = (x * I) % P
    if x % 2 != 0:
        x = P - x
    return x


BY = (4 * pow(5, P - 2, P)) % P
BX = xrecover(BY)
B = (BX, BY)
IDENTITY = (0, 1)


def is_on_curve(point):
    x, y = point
    return (-x * x + y * y - 1 - D * x * x * y * y) % P == 0


def point_add(p1, p2):
    x1, y1 = p1
    x2, y2 = p2
    denom = D * x1 * x2 * y1 * y2
    x3 = (x1 * y2 + x2 * y1) * pow(1 + denom, P - 2, P)
    y3 = (y1 * y2 + x1 * x2) * pow(1 - denom, P - 2, P)
    return x3 % P, y3 % P


def scalar_mult(point, scalar):
    result = IDENTITY
    addend = point
    scalar = int(scalar)
    while scalar > 0:
        if scalar & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        scalar >>= 1
    return result


def encode_point(point):
    x, y = point
    encoded = bytearray(int(y).to_bytes(32, "little"))
    encoded[31] |= (x & 1) << 7
    return bytes(encoded)


def decode_point(data):
    if not isinstance(data, bytes) or len(data) != 32:
        raise ToolError("invalid Ed25519 point")
    y = int.from_bytes(data, "little") & ((1 << 255) - 1)
    sign = data[31] >> 7
    if y >= P:
        raise ToolError("invalid Ed25519 point")
    x = xrecover(y)
    if (x & 1) != sign:
        x = P - x
    point = (x, y)
    if not is_on_curve(point):
        raise ToolError("invalid Ed25519 point")
    return point


def public_key_from_seed(seed):
    digest = sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    return encode_point(scalar_mult(B, scalar))


def sign_ed25519(seed, message):
    digest = sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    prefix = digest[32:]
    public_key = public_key_from_seed(seed)
    r = int.from_bytes(sha512(prefix + message).digest(), "little") % Q
    encoded_r = encode_point(scalar_mult(B, r))
    h = int.from_bytes(sha512(encoded_r + public_key + message).digest(), "little") % Q
    s = (r + h * scalar) % Q
    return encoded_r + int(s).to_bytes(32, "little")


def verify_ed25519(public_key, signature, message):
    if not isinstance(signature, bytes) or len(signature) != 64:
        return False
    try:
        a = decode_point(public_key)
        r = decode_point(signature[:32])
        s = int.from_bytes(signature[32:], "little")
    except ToolError:
        return False
    if s >= Q:
        return False
    h = int.from_bytes(sha512(signature[:32] + public_key + message).digest(), "little") % Q
    return scalar_mult(B, s) == point_add(r, scalar_mult(a, h))


def address_from_public_key(public_key_text):
    public_key = decode_public_key(public_key_text)
    digest = sha3_256(b"IND-address-v3:ed25519:" + public_key).digest()
    payload = b58encode(digest)[:ADDRESS_PAYLOAD_CHARS]
    checksum_digest = sha3_256(b"IND-address-checksum:v3:" + payload.encode("ascii")).digest()
    checksum = fixed_base58(checksum_digest[:ADDRESS_CHECKSUM_BYTES], ADDRESS_CHECKSUM_CHARS)
    return f"{ADDRESS_PREFIX}{ADDRESS_VERSION}{payload}{checksum}{ADDRESS_SUFFIX}"


def validate_address(address, label="address"):
    if not isinstance(address, str) or address != address.strip():
        raise ToolError(f"invalid {label}")
    if len(address) != ADDRESS_TARGET_LENGTH:
        raise ToolError(f"invalid {label}")
    if not address.startswith(ADDRESS_PREFIX + ADDRESS_VERSION) or not address.endswith(ADDRESS_SUFFIX):
        raise ToolError(f"invalid {label}")
    payload_start = len(ADDRESS_PREFIX) + len(ADDRESS_VERSION)
    payload_end = payload_start + ADDRESS_PAYLOAD_CHARS
    payload = address[payload_start:payload_end]
    checksum = address[payload_end : -len(ADDRESS_SUFFIX)]
    if any(char not in BASE58_ALPHABET for char in payload + checksum):
        raise ToolError(f"invalid {label}")
    checksum_digest = sha3_256(b"IND-address-checksum:v3:" + payload.encode("ascii")).digest()
    if checksum != fixed_base58(checksum_digest[:ADDRESS_CHECKSUM_BYTES], ADDRESS_CHECKSUM_CHARS):
        raise ToolError(f"invalid {label}")
    return address


def validate_bill_value(value, label="bill value"):
    value = require_int(value, label, minimum=1)
    if value not in DENOMINATION_SERIAL_CAPS:
        raise ToolError(f"{label} is not an allowed IND denomination")
    return value


def validate_bill_serial(value, serial, label="bill serial"):
    value = validate_bill_value(value, "bill serial value")
    return require_int(serial, label, minimum=1, maximum=DENOMINATION_SERIAL_CAPS[value])


def encode_uvarint(value):
    value = require_int(value, "uvarint", minimum=0)
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def encode_bytes(data):
    return encode_uvarint(len(data)) + data


def encode_ascii(text):
    return encode_bytes(text.encode("ascii"))


def signing_preimage(unsigned_manifest):
    return b"".join(
        (
            SIGNATURE_PREIMAGE_MAGIC,
            encode_uvarint(int(unsigned_manifest["network_id"])),
            encode_ascii(GENESIS_MANIFEST_TYPE),
            encode_uvarint(GENESIS_MANIFEST_VERSION),
            encode_uvarint(SIGNATURE_ALGORITHM_ID),
            encode_ascii(GENESIS_MANIFEST_SIGNATURE_DOMAIN),
            encode_bytes(canonical_bytes(unsigned_manifest)),
        )
    )


def public_key_text_from_private(private_key_text):
    return encode_public_key(public_key_from_seed(decode_private_key(private_key_text)))


def issuer_key_id(issuer_public_key):
    decode_public_key(issuer_public_key)
    return sha3_json(
        {
            "algorithm": ISSUER_KEY_ID_ALGORITHM,
            "issuer_public_key": issuer_public_key,
        }
    )


def unsigned_manifest(manifest):
    result = dict(manifest)
    result.pop("signature", None)
    result.pop("manifest_hash", None)
    return result


def manifest_hash(manifest):
    return sha3_json(unsigned_manifest(manifest))


def normalize_network(value):
    value = str(value or "").strip().lower().replace("_", "-")
    aliases = {
        "main": "mainnet",
        "main-net": "mainnet",
        "mainnet": "mainnet",
        "production": "mainnet",
        "prod": "mainnet",
        "test": "testnet",
        "test-net": "testnet",
        "testnet": "testnet",
        "public-testnet": "testnet",
    }
    return aliases.get(value, value or "mainnet")


def validate_ranges(ranges):
    if not isinstance(ranges, list) or not ranges:
        raise ToolError("genesis manifest must contain ranges")
    normalized = []
    total_count = 0
    total_value = 0
    required = {"value", "start_serial", "count", "owner_address", "nonce_seed"}
    for item in ranges:
        if not isinstance(item, dict) or set(item) != required:
            raise ToolError("malformed genesis manifest range")
        value = validate_bill_value(item["value"], "genesis manifest range value")
        start_serial = validate_bill_serial(
            value, item["start_serial"], "genesis manifest range start_serial"
        )
        count = require_int(item["count"], "genesis manifest range count", minimum=1)
        end_serial = start_serial + count - 1
        validate_bill_serial(value, end_serial, "genesis manifest range end_serial")
        owner_address = validate_address(item["owner_address"], "genesis manifest range owner address")
        nonce_seed = hex32(item["nonce_seed"], "genesis manifest range nonce seed")
        normalized.append(
            {
                "value": value,
                "start_serial": start_serial,
                "end_serial": end_serial,
                "count": count,
                "owner_address": owner_address,
                "nonce_seed": nonce_seed,
            }
        )
        total_count += count
        total_value += count * value
    normalized.sort(key=lambda item: (item["value"], item["start_serial"]))
    for previous, current in zip(normalized, normalized[1:]):
        if previous["value"] == current["value"] and current["start_serial"] <= previous["end_serial"]:
            raise ToolError("genesis manifest ranges overlap")
    if total_count > TOTAL_SUPPLY:
        raise ToolError("genesis manifest exceeds fixed IND bill supply")
    return normalized, total_count, total_value


def manifest_ranges(normalized):
    return [
        {
            "value": item["value"],
            "start_serial": item["start_serial"],
            "count": item["count"],
            "owner_address": item["owner_address"],
            "nonce_seed": item["nonce_seed"],
        }
        for item in normalized
    ]


def full_supply_ranges(owner_address, seed_prefix="IND-MAINNET-GENESIS-V3"):
    owner_address = validate_address(owner_address, "genesis owner address")
    ranges = []
    for value in ALLOWED_BILL_VALUES:
        count = DENOMINATION_SERIAL_CAPS[value]
        ranges.append(
            {
                "value": value,
                "start_serial": 1,
                "count": count,
                "owner_address": owner_address,
                "nonce_seed": sha3_json(
                    {
                        "algorithm": GENESIS_RANGE_SEED_ALGORITHM,
                        "seed_prefix": str(seed_prefix),
                        "value": value,
                        "start_serial": 1,
                        "count": count,
                        "owner_address": owner_address,
                    }
                ),
            }
        )
    return ranges


def numerology_signature():
    material = f"IND:{TOTAL_SUPPLY}:33:777:8:09.10.2003".encode("ascii")
    return {
        "master_number": 33,
        "angel_number": 777,
        "money_number": 8,
        "birthday_number": 9,
        "birthday_code": "09.10.2003",
        "address_length": 33,
        "fixed_supply": TOTAL_SUPPLY,
        "seal": sha3_256(material).hexdigest()[:33],
    }


def make_manifest(ranges, issuer_private_key, issued_at, network="mainnet", network_id=1, metadata=None):
    issuer_public_key = public_key_text_from_private(issuer_private_key)
    normalized, total_count, total_value = validate_ranges(ranges)
    metadata = dict(metadata or {})
    metadata.setdefault("project", "IND")
    metadata.setdefault("purpose", f"{normalize_network(network)} V3 genesis supply manifest")
    metadata.setdefault("ind_alignment", numerology_signature())
    unsigned = {
        "type": GENESIS_MANIFEST_TYPE,
        "version": GENESIS_MANIFEST_VERSION,
        "network": normalize_network(network),
        "network_id": require_int(network_id, "genesis manifest network_id", minimum=0),
        "genesis_algorithm": GENESIS_HASH_ALGORITHM,
        "signature_algorithm": SIGNATURE_ALGORITHM_ID,
        "issuer_public_key": issuer_public_key,
        "issuer_key_id": issuer_key_id(issuer_public_key),
        "issued_at": require_int(issued_at, "genesis manifest issued_at", minimum=0),
        "total_token_count": total_count,
        "total_value": total_value,
        "ranges": manifest_ranges(normalized),
        "metadata": metadata,
    }
    signature = sign_ed25519(decode_private_key(issuer_private_key), signing_preimage(unsigned)).hex()
    manifest = dict(unsigned)
    manifest["signature"] = signature
    manifest["manifest_hash"] = manifest_hash(manifest)
    return manifest


def verify_manifest(manifest, trusted_hashes=None, require_full_supply=False):
    required = {
        "type",
        "version",
        "network",
        "network_id",
        "genesis_algorithm",
        "signature_algorithm",
        "issuer_public_key",
        "issuer_key_id",
        "issued_at",
        "total_token_count",
        "total_value",
        "ranges",
        "metadata",
        "signature",
        "manifest_hash",
    }
    if not isinstance(manifest, dict) or set(manifest) != required:
        raise ToolError("malformed genesis manifest")
    if manifest["type"] != GENESIS_MANIFEST_TYPE or manifest["version"] != GENESIS_MANIFEST_VERSION:
        raise ToolError("unsupported genesis manifest version")
    if manifest["genesis_algorithm"] != GENESIS_HASH_ALGORITHM:
        raise ToolError("unsupported genesis manifest algorithm")
    if manifest["signature_algorithm"] != SIGNATURE_ALGORITHM_ID:
        raise ToolError("unsupported genesis manifest signature algorithm")
    issuer_public_key = manifest["issuer_public_key"]
    public_key = decode_public_key(issuer_public_key)
    if manifest["issuer_key_id"] != issuer_key_id(issuer_public_key):
        raise ToolError("genesis manifest issuer key id mismatch")
    normalized, total_count, total_value = validate_ranges(manifest["ranges"])
    if manifest["total_token_count"] != total_count:
        raise ToolError("genesis manifest bill count mismatch")
    if manifest["total_value"] != total_value:
        raise ToolError("genesis manifest value mismatch")
    if require_full_supply and total_count != TOTAL_SUPPLY:
        raise ToolError("genesis manifest does not cover the fixed IND supply")
    expected_hash = manifest_hash(manifest)
    if hex32(manifest["manifest_hash"], "genesis manifest hash") != expected_hash:
        raise ToolError("genesis manifest hash mismatch")
    if trusted_hashes is not None:
        trusted = {hex32(item, "trusted genesis manifest hash") for item in trusted_hashes}
        if expected_hash not in trusted:
            raise ToolError("genesis manifest hash is not trusted")
    signature = bytes.fromhex(manifest["signature"])
    if not verify_ed25519(public_key, signature, signing_preimage(unsigned_manifest(manifest))):
        raise ToolError("invalid genesis manifest signature")
    return {
        "manifest_hash": expected_hash,
        "issuer_key_id": manifest["issuer_key_id"],
        "ranges": normalized,
        "total_token_count": total_count,
        "total_value": total_value,
    }


def range_for_serial(ranges, value, serial):
    value = validate_bill_value(value, "genesis ref value")
    serial = validate_bill_serial(value, serial, "genesis ref serial")
    for item in ranges:
        if item["value"] == value and item["start_serial"] <= serial <= item["end_serial"]:
            return item
    raise ToolError("genesis serial is not covered by manifest")


def derive_nonce(manifest, value, serial):
    verified = verify_manifest(manifest)
    range_def = range_for_serial(verified["ranges"], value, serial)
    return sha3_json(
        {
            "algorithm": GENESIS_NONCE_ALGORITHM,
            "manifest_hash": verified["manifest_hash"],
            "value": int(value),
            "serial": int(serial),
            "range_start_serial": range_def["start_serial"],
            "range_count": range_def["count"],
            "owner_address": range_def["owner_address"],
            "nonce_seed": range_def["nonce_seed"],
        }
    )


def derive_genesis_hash(manifest, value, serial):
    verified = verify_manifest(manifest)
    range_def = range_for_serial(verified["ranges"], value, serial)
    nonce = derive_nonce(manifest, value, serial)
    return sha3_json(
        {
            "algorithm": GENESIS_HASH_ALGORITHM,
            "network_id": int(manifest["network_id"]),
            "manifest_hash": verified["manifest_hash"],
            "issuer_key_id": verified["issuer_key_id"],
            "value": int(value),
            "serial": int(serial),
            "owner_address": range_def["owner_address"],
            "issued_at": int(manifest["issued_at"]),
            "nonce": nonce,
        }
    )


def derive_genesis_ref(manifest, value, serial):
    verified = verify_manifest(manifest)
    return {
        "type": "ind.genesis_ref.v3",
        "version": GENESIS_MANIFEST_VERSION,
        "network_id": int(manifest["network_id"]),
        "genesis_hash": derive_genesis_hash(manifest, value, serial),
        "manifest_hash": verified["manifest_hash"],
        "issuer_key_id": verified["issuer_key_id"],
        "issue_index": int(serial),
        "issued_at": int(manifest["issued_at"]),
    }


def derive_base_state(manifest, value, serial):
    verified = verify_manifest(manifest)
    range_def = range_for_serial(verified["ranges"], value, serial)
    genesis_hash_value = derive_genesis_hash(manifest, value, serial)
    return {
        "sequence": 0,
        "owner_address": range_def["owner_address"],
        "last_transfer_hash": genesis_hash_value,
        "last_transfer_timestamp": int(manifest["issued_at"]),
        "last_transfer_day": int(manifest["issued_at"]) // 86400,
        "transfers_in_last_day": 0,
        "display_id": f"{int(value)}x{int(serial)}",
        "value": int(value),
    }


def read_text_arg(value, file_value, label):
    if value:
        return value.strip()
    if file_value:
        return Path(file_value).read_text(encoding="utf-8").strip()
    raise ToolError(f"{label} is required")


def cmd_keygen(args):
    seed = bytes.fromhex(args.seed_hex) if args.seed_hex else secrets.token_bytes(32)
    private_key = encode_private_key(seed)
    public_key = public_key_text_from_private(private_key)
    address = address_from_public_key(public_key)
    result = {"address": address, "private_key": private_key, "public_key": public_key}
    if args.out_dir:
        out_dir = Path(args.out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        prefix = args.prefix
        (out_dir / f"{prefix}_private.local.txt").write_text(private_key + "\n", encoding="utf-8")
        (out_dir / f"{prefix}_public.txt").write_text(public_key + "\n", encoding="utf-8")
        (out_dir / f"{prefix}_address.txt").write_text(address + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))


def cmd_create_mainnet(args):
    private_key = read_text_arg(args.issuer_private_key, args.issuer_private_key_file, "issuer private key")
    owner_address = read_text_arg(args.owner_address, args.owner_address_file, "owner address")
    metadata = read_json(args.metadata_file) if args.metadata_file else None
    ranges = full_supply_ranges(owner_address, seed_prefix=args.range_seed_prefix)
    manifest = make_manifest(
        ranges,
        private_key,
        issued_at=args.issued_at,
        network="mainnet",
        network_id=args.network_id,
        metadata=metadata,
    )
    write_json(args.output, manifest)
    print(manifest["manifest_hash"])


def cmd_verify(args):
    manifest = read_json(args.manifest)
    result = verify_manifest(
        manifest,
        trusted_hashes=args.trusted_hash,
        require_full_supply=args.require_full_supply,
    )
    printable = dict(result)
    printable.pop("ranges", None)
    print(json.dumps(printable, indent=2, sort_keys=True))


def cmd_derive_ref(args):
    result = derive_genesis_ref(read_json(args.manifest), args.value, args.serial)
    if args.output:
        write_json(args.output, result)
    print(json.dumps(result, indent=2, sort_keys=True))


def cmd_derive_base_state(args):
    result = derive_base_state(read_json(args.manifest), args.value, args.serial)
    if args.output:
        write_json(args.output, result)
    print(json.dumps(result, indent=2, sort_keys=True))


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    keygen = sub.add_parser("keygen", help="generate one V3 keypair")
    keygen.add_argument("--seed-hex", help="optional deterministic 32-byte seed hex")
    keygen.add_argument("--out-dir", help="write key files into this directory")
    keygen.add_argument("--prefix", default="issuer")
    keygen.set_defaults(func=cmd_keygen)

    create = sub.add_parser("create-mainnet", help="create a full-supply mainnet manifest")
    create.add_argument("--issuer-private-key")
    create.add_argument("--issuer-private-key-file")
    create.add_argument("--owner-address")
    create.add_argument("--owner-address-file")
    create.add_argument("--issued-at", type=int, required=True)
    create.add_argument("--network-id", type=int, default=1)
    create.add_argument("--range-seed-prefix", default="IND-MAINNET-GENESIS-V3")
    create.add_argument("--metadata-file")
    create.add_argument("--output", required=True)
    create.set_defaults(func=cmd_create_mainnet)

    verify = sub.add_parser("verify", help="verify a signed genesis manifest")
    verify.add_argument("manifest")
    verify.add_argument("--trusted-hash", action="append")
    verify.add_argument("--require-full-supply", action="store_true")
    verify.set_defaults(func=cmd_verify)

    derive_ref = sub.add_parser("derive-ref", help="derive one GenesisRefV3")
    derive_ref.add_argument("manifest")
    derive_ref.add_argument("--value", type=int, required=True)
    derive_ref.add_argument("--serial", type=int, required=True)
    derive_ref.add_argument("--output")
    derive_ref.set_defaults(func=cmd_derive_ref)

    derive_state = sub.add_parser("derive-base-state", help="derive one sequence-0 base state")
    derive_state.add_argument("manifest")
    derive_state.add_argument("--value", type=int, required=True)
    derive_state.add_argument("--serial", type=int, required=True)
    derive_state.add_argument("--output")
    derive_state.set_defaults(func=cmd_derive_base_state)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except ToolError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)
