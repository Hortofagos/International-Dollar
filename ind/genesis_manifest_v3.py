"""Native V3 genesis manifest generation and verification."""

import copy
import time
from hashlib import sha3_256

from . import binary_v3, keys_v3
from . import protocol as ind_token
from .crypto_ed25519 import SIGNATURE_ALGORITHM_ID

GENESIS_MANIFEST_TYPE = "ind.genesis_manifest.v3"
GENESIS_MANIFEST_VERSION = 3
GENESIS_MANIFEST_SIGNATURE_DOMAIN = "IND_GENESIS_MANIFEST_V3"
GENESIS_HASH_ALGORITHM = "IND_GENESIS_REF_SHA3_256_V3"
GENESIS_NONCE_ALGORITHM = "IND_GENESIS_NONCE_SHA3_256_V3"
GENESIS_RANGE_SEED_ALGORITHM = "IND_GENESIS_RANGE_SEED_SHA3_256_V3"
ISSUER_KEY_ID_ALGORITHM = "IND_GENESIS_ISSUER_KEY_ID_SHA3_256_V3"

GENESIS_MANIFEST_FIELDS = {
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
GENESIS_MANIFEST_RANGE_FIELDS = {
    "value",
    "start_serial",
    "count",
    "owner_address",
    "nonce_seed",
}


class GenesisManifestV3Error(ind_token.ValidationError):
    pass


def _canonical_bytes(data):
    return ind_token.canonical_json(data).encode("utf-8")


def _sha3_json(data):
    return sha3_256(_canonical_bytes(data)).hexdigest()


def _require_exact_fields(data, required, label):
    if not isinstance(data, dict) or set(data) != set(required):
        raise GenesisManifestV3Error(f"malformed {label}")


def _require_int(value, label, minimum=None, maximum=None):
    if type(value) is not int:
        raise GenesisManifestV3Error(f"{label} must be an integer")
    if minimum is not None and value < int(minimum):
        raise GenesisManifestV3Error(f"{label} is below the allowed range")
    if maximum is not None and value > int(maximum):
        raise GenesisManifestV3Error(f"{label} is above the allowed range")
    return value


def _require_str(value, label):
    if not isinstance(value, str) or value != value.strip() or not value:
        raise GenesisManifestV3Error(f"invalid {label}")
    return value


def _hex32(value, label):
    if not isinstance(value, str) or len(value) != 64:
        raise GenesisManifestV3Error(f"invalid {label}")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise GenesisManifestV3Error(f"invalid {label}") from exc
    return value.lower()


def _signature_bytes(signature_hex):
    if not isinstance(signature_hex, str) or len(signature_hex) != 128:
        raise GenesisManifestV3Error("invalid genesis manifest signature")
    try:
        return bytes.fromhex(signature_hex)
    except ValueError as exc:
        raise GenesisManifestV3Error("invalid genesis manifest signature") from exc


def public_key_from_private_key(private_key_text):
    seed = keys_v3.decode_private_key(private_key_text)
    return keys_v3.encode_public_key(keys_v3.crypto_ed25519.public_key_from_private_seed(seed))


def issuer_key_id(issuer_public_key):
    keys_v3.decode_public_key(issuer_public_key)
    return _sha3_json(
        {
            "algorithm": ISSUER_KEY_ID_ALGORITHM,
            "issuer_public_key": issuer_public_key,
        }
    )


def unsigned_manifest(manifest):
    unsigned = copy.deepcopy(manifest)
    unsigned.pop("signature", None)
    unsigned.pop("manifest_hash", None)
    return unsigned


def manifest_hash(manifest):
    return _sha3_json(unsigned_manifest(manifest))


def _signing_preimage(unsigned):
    return binary_v3.signing_preimage(
        int(unsigned["network_id"]),
        GENESIS_MANIFEST_TYPE,
        GENESIS_MANIFEST_VERSION,
        SIGNATURE_ALGORITHM_ID,
        GENESIS_MANIFEST_SIGNATURE_DOMAIN,
        _canonical_bytes(unsigned),
    )


def _normalize_network(value):
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


def _validate_ranges(ranges):
    if not isinstance(ranges, list) or not ranges:
        raise GenesisManifestV3Error("genesis manifest must contain ranges")
    normalized = []
    total_count = 0
    total_value = 0
    for item in ranges:
        _require_exact_fields(item, GENESIS_MANIFEST_RANGE_FIELDS, "genesis manifest range")
        value = ind_token.validate_bill_value(item["value"], "genesis manifest range value")
        start_serial = ind_token.validate_bill_serial(
            value, item["start_serial"], "genesis manifest range start_serial"
        )
        count = _require_int(item["count"], "genesis manifest range count", minimum=1)
        end_serial = start_serial + count - 1
        ind_token.validate_bill_serial(
            value, end_serial, "genesis manifest range end_serial"
        )
        owner_address = keys_v3.validate_address(
            item["owner_address"], "genesis manifest range owner address"
        )
        nonce_seed = _hex32(item["nonce_seed"], "genesis manifest range nonce seed")
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
    for previous, current in zip(normalized, normalized[1:], strict=False):
        if previous["value"] == current["value"] and current["start_serial"] <= previous["end_serial"]:
            raise GenesisManifestV3Error("genesis manifest ranges overlap")
    if total_count > ind_token.TOTAL_SUPPLY:
        raise GenesisManifestV3Error("genesis manifest exceeds fixed IND bill supply")
    return normalized, total_count, total_value


def _manifest_ranges(normalized):
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
    owner_address = keys_v3.validate_address(owner_address, "genesis owner address")
    return full_supply_ranges_by_denomination(
        {value: owner_address for value in ind_token.ALLOWED_BILL_VALUES},
        seed_prefix=seed_prefix,
    )


def full_supply_ranges_by_denomination(owner_addresses, seed_prefix="IND-MAINNET-GENESIS-V3"):
    if not isinstance(owner_addresses, dict):
        raise GenesisManifestV3Error("denomination owner addresses must be a mapping")
    ranges = []
    for value in ind_token.ALLOWED_BILL_VALUES:
        owner_address = owner_addresses.get(value, owner_addresses.get(str(value)))
        owner_address = keys_v3.validate_address(
            owner_address,
            f"genesis owner address for {value}x",
        )
        count = int(ind_token.DENOMINATION_SERIAL_CAPS[value])
        ranges.append(
            {
                "value": value,
                "start_serial": 1,
                "count": count,
                "owner_address": owner_address,
                "nonce_seed": _sha3_json(
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


def make_manifest(
    ranges,
    issuer_private_key,
    *,
    issued_at=None,
    network="mainnet",
    network_id=1,
    metadata=None,
):
    issuer_public_key = public_key_from_private_key(issuer_private_key)
    normalized, total_count, total_value = _validate_ranges(ranges)
    issued_at = _require_int(
        int(time.time() if issued_at is None else issued_at),
        "genesis manifest issued_at",
        minimum=0,
        maximum=ind_token.MAX_PROTOCOL_TIMESTAMP,
    )
    network = _normalize_network(network)
    metadata = copy.deepcopy(metadata or {})
    metadata.setdefault("project", "IND")
    metadata.setdefault("purpose", f"{network} V3 genesis supply manifest")
    metadata.setdefault(ind_token.NUMEROLOGY_METADATA_KEY, ind_token.numerology_signature())
    ind_token._require_metadata(metadata, ind_token.MAX_GENESIS_METADATA_BYTES, "genesis manifest")
    unsigned = {
        "type": GENESIS_MANIFEST_TYPE,
        "version": GENESIS_MANIFEST_VERSION,
        "network": network,
        "network_id": _require_int(network_id, "genesis manifest network_id", minimum=0),
        "genesis_algorithm": GENESIS_HASH_ALGORITHM,
        "signature_algorithm": SIGNATURE_ALGORITHM_ID,
        "issuer_public_key": issuer_public_key,
        "issuer_key_id": issuer_key_id(issuer_public_key),
        "issued_at": issued_at,
        "total_token_count": total_count,
        "total_value": total_value,
        "ranges": _manifest_ranges(normalized),
        "metadata": metadata,
    }
    signature = keys_v3.sign(issuer_private_key, _signing_preimage(unsigned)).hex()
    manifest = copy.deepcopy(unsigned)
    manifest["signature"] = signature
    manifest["manifest_hash"] = manifest_hash(manifest)
    return manifest


def verify_manifest(
    manifest,
    *,
    trusted_hashes=None,
    require_full_supply=False,
    expected_network=None,
    expected_network_id=None,
):
    _require_exact_fields(manifest, GENESIS_MANIFEST_FIELDS, "genesis manifest")
    if manifest["type"] != GENESIS_MANIFEST_TYPE:
        raise GenesisManifestV3Error("malformed genesis manifest")
    if _require_int(manifest["version"], "genesis manifest version") != GENESIS_MANIFEST_VERSION:
        raise GenesisManifestV3Error("unsupported genesis manifest version")
    if manifest["genesis_algorithm"] != GENESIS_HASH_ALGORITHM:
        raise GenesisManifestV3Error("unsupported genesis manifest algorithm")
    if (
        _require_int(manifest["signature_algorithm"], "genesis manifest signature algorithm")
        != SIGNATURE_ALGORITHM_ID
    ):
        raise GenesisManifestV3Error("unsupported genesis manifest signature algorithm")
    network = _normalize_network(manifest["network"])
    if expected_network is not None and network != _normalize_network(expected_network):
        raise GenesisManifestV3Error("genesis manifest network mismatch")
    network_id = _require_int(manifest["network_id"], "genesis manifest network_id", minimum=0)
    if expected_network_id is not None and network_id != int(expected_network_id):
        raise GenesisManifestV3Error("genesis manifest network id mismatch")
    issuer_public_key = _require_str(manifest["issuer_public_key"], "issuer public key")
    keys_v3.decode_public_key(issuer_public_key)
    if manifest["issuer_key_id"] != issuer_key_id(issuer_public_key):
        raise GenesisManifestV3Error("genesis manifest issuer key id mismatch")
    _require_int(
        manifest["issued_at"],
        "genesis manifest issued_at",
        minimum=0,
        maximum=ind_token.MAX_PROTOCOL_TIMESTAMP,
    )
    ind_token._require_metadata(
        manifest["metadata"], ind_token.MAX_GENESIS_METADATA_BYTES, "genesis manifest"
    )
    normalized, total_count, total_value = _validate_ranges(manifest["ranges"])
    if (
        _require_int(manifest["total_token_count"], "genesis manifest total_token_count", minimum=1)
        != total_count
    ):
        raise GenesisManifestV3Error("genesis manifest bill count mismatch")
    if (
        _require_int(manifest["total_value"], "genesis manifest total_value", minimum=1)
        != total_value
    ):
        raise GenesisManifestV3Error("genesis manifest value mismatch")
    if require_full_supply and total_count != ind_token.TOTAL_SUPPLY:
        raise GenesisManifestV3Error("genesis manifest does not cover the fixed IND supply")
    expected_hash = manifest_hash(manifest)
    if _hex32(manifest["manifest_hash"], "genesis manifest hash") != expected_hash:
        raise GenesisManifestV3Error("genesis manifest hash mismatch")
    if trusted_hashes is not None:
        trusted = {_hex32(item, "trusted genesis manifest hash") for item in trusted_hashes}
        if expected_hash not in trusted:
            raise GenesisManifestV3Error("genesis manifest hash is not trusted by this node")
    signature = _signature_bytes(manifest["signature"])
    if not keys_v3.verify(issuer_public_key, signature, _signing_preimage(unsigned_manifest(manifest))):
        raise GenesisManifestV3Error("invalid genesis manifest signature")
    return {
        "manifest_hash": expected_hash,
        "issuer_key_id": manifest["issuer_key_id"],
        "ranges": normalized,
        "total_token_count": total_count,
        "total_value": total_value,
    }


def _range_for_serial(ranges, value, serial):
    value = ind_token.validate_bill_value(value, "genesis ref value")
    serial = ind_token.validate_bill_serial(value, serial, "genesis ref serial")
    for item in ranges:
        if item["value"] == value and item["start_serial"] <= serial <= item["end_serial"]:
            return item
    raise GenesisManifestV3Error("genesis serial is not covered by manifest")


def derive_nonce(manifest, value, serial):
    verified = verify_manifest(manifest)
    range_def = _range_for_serial(verified["ranges"], value, serial)
    return _sha3_json(
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
    range_def = _range_for_serial(verified["ranges"], value, serial)
    nonce = derive_nonce(manifest, value, serial)
    return _sha3_json(
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
    serial = ind_token.validate_bill_serial(value, serial, "genesis ref serial")
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
    range_def = _range_for_serial(verified["ranges"], value, serial)
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
