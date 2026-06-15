# Signed update and operator-promotion manifests for IND releases.

import json
import os
import time
from pathlib import Path

from . import protocol as ind_token

UPDATE_MANIFEST_TYPE = "ind.update_manifest.v1"
UPDATE_STATUS_TYPE = "ind.update_status.v1"
UPDATE_PROMOTION_TYPE = "ind.operator_update_promotion.v1"
UPDATE_SIGNATURE_DOMAIN = "IND_UPDATE_MANIFEST_V1"
UPDATE_PROMOTION_SIGNATURE_DOMAIN = "IND_OPERATOR_UPDATE_PROMOTION_V1"
UPDATE_SIGNATURE_ALGORITHM = "ECDSA_SECP256K1_SHA3_256_BASE85"
UPDATE_STATE_PATH = Path("files/update_state.json")

RUNTIME_EXCLUDE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    "files",
    "wallet_folder",
    "transaction_folder",
    "ip_folder",
    "full_activation",
}


# Raised when a signed update manifest is malformed or untrusted.
class UpdateManifestError(ValueError):
    pass


def canonical_json(data):
    return ind_token.canonical_json(data)


def canonical_bytes(data):
    return canonical_json(data).encode("utf-8")


def sha3_hex(data):
    return ind_token.sha3_hex(data)


def atomic_write_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(
        json.dumps(data, sort_keys=True, indent=2, ensure_ascii=True) + "\n", encoding="utf-8"
    )
    os.replace(tmp, path)


def _unsigned(record):
    if not isinstance(record, dict):
        raise UpdateManifestError("manifest must be a JSON object")
    unsigned = dict(record)
    unsigned.pop("signature", None)
    return unsigned


def _signature_payload(record, domain):
    return ind_token.signature_payload(domain, _unsigned(record))


# Return a signed copy of an update manifest.
def sign_update_manifest(manifest, private_key, public_key):
    signed = dict(manifest)
    signed["signing_public_key"] = str(public_key).strip()
    signed["signature_algorithm"] = UPDATE_SIGNATURE_ALGORITHM
    signed["signature"] = ind_token.b85_sign(
        private_key, _signature_payload(signed, UPDATE_SIGNATURE_DOMAIN)
    )
    return signed


# Return a signed copy of an operator promotion manifest.
def sign_operator_promotion(promotion, private_key, public_key):
    signed = dict(promotion)
    signed["signing_public_key"] = str(public_key).strip()
    signed["signature_algorithm"] = UPDATE_SIGNATURE_ALGORITHM
    signed["signature"] = ind_token.b85_sign(
        private_key,
        _signature_payload(signed, UPDATE_PROMOTION_SIGNATURE_DOMAIN),
    )
    return signed


def _require_fields(record, fields, label):
    missing = sorted(field for field in fields if field not in record)
    if missing:
        raise UpdateManifestError(f"{label} is missing required fields: {', '.join(missing)}")


def _trusted_keys(keys):
    raw = keys.replace("\n", ",").split(",") if isinstance(keys, str) else list(keys or [])
    return {str(item).strip() for item in raw if str(item).strip()}


def _verify_signature(record, trusted_keys, domain, label):
    public_key = str(record.get("signing_public_key", "")).strip()
    if not public_key:
        raise UpdateManifestError(f"{label} does not name a signing key")
    trusted = _trusted_keys(trusted_keys)
    if not trusted:
        raise UpdateManifestError("no trusted update signing keys are configured")
    if public_key not in trusted:
        raise UpdateManifestError(f"{label} was signed by an untrusted key")
    if str(record.get("signature_algorithm", "")) != UPDATE_SIGNATURE_ALGORITHM:
        raise UpdateManifestError(f"{label} uses an unsupported signature algorithm")
    signature = str(record.get("signature", "")).strip()
    if not signature:
        raise UpdateManifestError(f"{label} has no signature")
    if not ind_token.b85_verify(public_key, signature, _signature_payload(record, domain)):
        raise UpdateManifestError(f"{label} signature is invalid")
    return True


def normalize_artifact(artifact):
    if not isinstance(artifact, dict):
        raise UpdateManifestError("manifest artifacts must be JSON objects")
    _require_fields(artifact, {"platform", "url", "sha3_256", "size_bytes"}, "artifact")
    digest = str(artifact["sha3_256"]).strip().lower()
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise UpdateManifestError("artifact sha3_256 must be a 64-character hex digest")
    size = int(artifact["size_bytes"])
    if size < 0:
        raise UpdateManifestError("artifact size_bytes must be non-negative")
    return {
        **artifact,
        "platform": str(artifact["platform"]).strip(),
        "url": str(artifact["url"]).strip(),
        "sha3_256": digest,
        "size_bytes": size,
    }


# Validate a signed update manifest and return its normalized copy.
def verify_update_manifest(
    manifest,
    trusted_keys,
    *,
    expected_channel=None,
    min_sequence=None,
    allow_rollback=False,
):
    if not isinstance(manifest, dict):
        raise UpdateManifestError("manifest must be a JSON object")
    _require_fields(
        manifest,
        {
            "type",
            "version",
            "channel",
            "release_id",
            "sequence",
            "published_at",
            "min_supported_sequence",
            "requires_restart",
            "artifacts",
            "signing_public_key",
            "signature_algorithm",
            "signature",
        },
        "update manifest",
    )
    if manifest["type"] != UPDATE_MANIFEST_TYPE or int(manifest["version"]) != 1:
        raise UpdateManifestError("unsupported update manifest version")
    channel = str(manifest["channel"]).strip()
    if expected_channel and channel != str(expected_channel).strip():
        raise UpdateManifestError(
            f"manifest channel {channel!r} does not match expected channel {expected_channel!r}"
        )
    artifacts = [normalize_artifact(item) for item in manifest.get("artifacts", [])]
    if not artifacts:
        raise UpdateManifestError("update manifest does not contain any artifacts")
    sequence = int(manifest["sequence"])
    min_supported = int(manifest["min_supported_sequence"])
    if sequence < 0 or min_supported < 0:
        raise UpdateManifestError("manifest sequences must be non-negative")
    if min_sequence is not None and sequence < int(min_sequence) and not allow_rollback:
        raise UpdateManifestError("update manifest sequence is older than the last accepted update")
    normalized = dict(manifest)
    normalized["sequence"] = sequence
    normalized["min_supported_sequence"] = min_supported
    normalized["published_at"] = int(manifest["published_at"])
    normalized["requires_restart"] = bool(manifest["requires_restart"])
    normalized["artifacts"] = artifacts
    _verify_signature(normalized, trusted_keys, UPDATE_SIGNATURE_DOMAIN, "update manifest")
    return normalized


def normalize_update_status(payload):
    if not isinstance(payload, dict):
        raise UpdateManifestError("update status must be a JSON object")
    _require_fields(payload, {"type", "version", "status"}, "update status")
    if payload["type"] != UPDATE_STATUS_TYPE or int(payload["version"]) != 1:
        raise UpdateManifestError("unsupported update status version")
    status = str(payload["status"]).strip()
    if status not in {"disabled", "not_ready"}:
        raise UpdateManifestError("unsupported update status")
    return {**payload, "status": status}


def read_update_state(path=UPDATE_STATE_PATH):
    path = Path(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"last_accepted_sequence": 0, "accepted_releases": []}
    except json.JSONDecodeError as exc:
        raise UpdateManifestError(f"invalid update state JSON in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise UpdateManifestError(f"update state in {path} must be a JSON object")
    data.setdefault("last_accepted_sequence", 0)
    data.setdefault("accepted_releases", [])
    data["last_accepted_sequence"] = int(data.get("last_accepted_sequence") or 0)
    if not isinstance(data["accepted_releases"], list):
        data["accepted_releases"] = []
    return data


def write_update_state(state, path=UPDATE_STATE_PATH):
    atomic_write_json(path, state)
    return state


def record_accepted_update(manifest, path=UPDATE_STATE_PATH):
    state = read_update_state(path)
    sequence = int(manifest["sequence"])
    state["last_accepted_sequence"] = max(int(state.get("last_accepted_sequence", 0)), sequence)
    releases = list(state.get("accepted_releases", []))
    releases.append(
        {
            "release_id": str(manifest.get("release_id", "")),
            "channel": str(manifest.get("channel", "")),
            "sequence": sequence,
            "accepted_at": int(time.time()),
        }
    )
    state["accepted_releases"] = releases[-20:]
    return write_update_state(state, path)


# Build the unsigned promotion record for an already-tested canary release.
def make_operator_promotion(
    canary_manifest, canary_report_hash, *, channel="operator-stable", promoted_at=None
):
    artifact_hashes = [
        str(item.get("sha3_256", "")).lower() for item in canary_manifest.get("artifacts", [])
    ]
    return {
        "type": UPDATE_PROMOTION_TYPE,
        "version": 1,
        "channel": str(channel),
        "canary_channel": str(canary_manifest.get("channel", "")),
        "release_id": str(canary_manifest.get("release_id", "")),
        "sequence": int(canary_manifest.get("sequence", 0)),
        "artifact_hashes": artifact_hashes,
        "canary_report_hash": str(canary_report_hash).strip().lower(),
        "promoted_at": int(promoted_at or time.time()),
    }


# Verify that a promotion exactly names the canary release it promotes.
def verify_operator_promotion(promotion, trusted_keys, canary_manifest):
    if not isinstance(promotion, dict):
        raise UpdateManifestError("operator promotion must be a JSON object")
    _require_fields(
        promotion,
        {
            "type",
            "version",
            "channel",
            "canary_channel",
            "release_id",
            "sequence",
            "artifact_hashes",
            "canary_report_hash",
            "promoted_at",
            "signing_public_key",
            "signature_algorithm",
            "signature",
        },
        "operator promotion",
    )
    if promotion["type"] != UPDATE_PROMOTION_TYPE or int(promotion["version"]) != 1:
        raise UpdateManifestError("unsupported operator promotion version")
    if str(promotion["release_id"]) != str(canary_manifest.get("release_id", "")):
        raise UpdateManifestError("promotion release_id does not match canary manifest")
    if int(promotion["sequence"]) != int(canary_manifest.get("sequence", -1)):
        raise UpdateManifestError("promotion sequence does not match canary manifest")
    if str(promotion["canary_channel"]) != str(canary_manifest.get("channel", "")):
        raise UpdateManifestError("promotion canary channel does not match canary manifest")
    expected_hashes = [
        str(item.get("sha3_256", "")).lower() for item in canary_manifest.get("artifacts", [])
    ]
    if list(promotion.get("artifact_hashes", [])) != expected_hashes:
        raise UpdateManifestError("promotion artifact hashes do not match canary manifest")
    _verify_signature(
        promotion, trusted_keys, UPDATE_PROMOTION_SIGNATURE_DOMAIN, "operator promotion"
    )
    return True
