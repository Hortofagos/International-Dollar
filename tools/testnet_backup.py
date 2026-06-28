#!/usr/bin/env python3
# Create an encrypted off-server backup of public testnet operator state.

import argparse
import base64
import contextlib
import datetime as dt
import hashlib
import io
import json
import os
import secrets
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from ind.io_utils import atomic_write_json

DEFAULT_VPS_HOST = os.environ.get("IND_TESTNET_VPS_HOST", "")
DEFAULT_VPS_USER = os.environ.get("IND_TESTNET_VPS_USER", "")
DEFAULT_SSH_KEY = os.environ.get("IND_TESTNET_SSH_KEY", "")
DEFAULT_BOOTSTRAP_SECRETS = os.environ.get("IND_TESTNET_BOOTSTRAP_SECRETS", "")
DEFAULT_BACKUP_DIR = ROOT_DIR / "files" / "testnet" / "backups"
DEFAULT_KEY_FILE = ROOT_DIR / "files" / "testnet" / "offsite_backup_key.local.json"


def env_list(name):
    return [item.strip() for item in os.environ.get(name, "").split(os.pathsep) if item.strip()]


DEFAULT_REMOTE_PATHS = env_list("IND_TESTNET_BACKUP_REMOTE_PATHS")


# Raised when the encrypted backup cannot be completed.
class BackupError(RuntimeError):
    pass


def read_bootstrap_secrets(path):
    if not path:
        return {}
    path = Path(path)
    if not path.exists() or path.is_dir():
        return {}
    values = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            key, value = line.split(":", 1)
        elif "=" in line:
            key, value = line.split("=", 1)
        else:
            continue
        normalized = " ".join(key.strip().lower().split())
        if normalized and value.strip():
            values[normalized] = value.strip()
    return values


def bootstrap_secret(values, *labels):
    normalized = {" ".join(label.lower().split()) for label in labels}
    for key, value in values.items():
        if key in normalized:
            return value
    for key, value in values.items():
        if any(label in key for label in normalized):
            return value
    return ""


@contextlib.contextmanager
def ssh_environment(key_passphrase=""):
    env = os.environ.copy()
    if not key_passphrase:
        yield env
        return
    with tempfile.TemporaryDirectory(prefix="ind-ssh-askpass-") as temp_dir:
        askpass_path = Path(temp_dir) / "ssh_askpass.cmd"
        askpass_path.write_text(
            "@echo off\r\n"
            'powershell -NoProfile -ExecutionPolicy Bypass -Command "[Console]::Out.Write($env:IND_SSH_KEY_PASSPHRASE)"\r\n',
            encoding="utf-8",
        )
        env["SSH_ASKPASS"] = str(askpass_path)
        env["SSH_ASKPASS_REQUIRE"] = "force"
        env.setdefault("DISPLAY", "localhost:0")
        env["IND_SSH_KEY_PASSPHRASE"] = key_passphrase
        yield env


def b64encode(data):
    return base64.b64encode(data).decode("ascii")


def b64decode(text):
    return base64.b64decode(text.encode("ascii"))


def load_or_create_backup_key(path):
    path = Path(path)
    if path.exists():
        return load_backup_key(path)
    key = secrets.token_bytes(32)
    atomic_write_json(
        path,
        {
            "type": "ind.testnet_offsite_backup_key.v3",
            "version": 1,
            "algorithm": "AES-256-GCM",
            "created_at": int(dt.datetime.now(dt.UTC).timestamp()),
            "key_b64": b64encode(key),
        },
    )
    return key


def load_backup_key(path):
    path = Path(path)
    if not path.exists():
        raise BackupError(f"backup key does not exist: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    key = b64decode(payload["key_b64"])
    if len(key) != 32:
        raise BackupError(f"backup key at {path} is not 32 bytes")
    return key


def tar_paths(paths):
    relative = []
    for raw_path in paths:
        clean = str(raw_path).strip()
        if not clean:
            continue
        if not clean.startswith("/"):
            raise BackupError(f"remote backup path must be absolute: {clean}")
        parts = Path(clean).parts
        if any(part == ".." for part in parts):
            raise BackupError(f"unsafe remote backup path: {clean}")
        relative.append(clean.lstrip("/"))
    if not relative:
        raise BackupError("no remote paths configured for backup")
    return relative


def quote_sh(value):
    return "'" + str(value).replace("'", "'\"'\"'") + "'"


def fetch_remote_tar(args, sudo_password, key_passphrase):
    relative_paths = tar_paths(args.remote_path)
    tar_args = " ".join(quote_sh(path) for path in relative_paths)
    remote_command = (
        "sudo -S -p '' tar --ignore-failed-read --warning=no-file-changed "
        f"-C / -czf - {tar_args}"
    )
    command = [
        "ssh",
        "-i",
        str(args.ssh_key),
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        f"ConnectTimeout={int(args.ssh_timeout_seconds)}",
        f"{args.vps_user}@{args.vps_host}",
        remote_command,
    ]
    with ssh_environment(key_passphrase) as ssh_env:
        process = subprocess.run(
            command,
            input=(sudo_password + "\n").encode("utf-8"),
            capture_output=True,
            timeout=int(args.remote_timeout_seconds),
            env=ssh_env,
            check=False,
        )
    if process.returncode != 0:
        stderr = process.stderr.decode("utf-8", errors="replace").strip()
        raise BackupError(stderr or f"remote tar failed with exit code {process.returncode}")
    if not process.stdout:
        raise BackupError("remote tar returned an empty backup stream")
    return process.stdout, relative_paths, process.stderr.decode("utf-8", errors="replace").strip()


def encrypt_backup(tar_bytes, key, metadata):
    nonce = secrets.token_bytes(12)
    aad = backup_authenticated_metadata(metadata)
    ciphertext = AESGCM(key).encrypt(nonce, tar_bytes, aad)
    verified = AESGCM(key).decrypt(nonce, ciphertext, aad)
    if verified != tar_bytes:
        raise BackupError("backup encryption verification failed")
    return nonce, ciphertext


def backup_authenticated_metadata(metadata):
    return json.dumps(metadata, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def encrypted_backup_metadata(payload):
    if not isinstance(payload, dict):
        raise BackupError("encrypted backup must be a JSON object")
    required = {
        "type",
        "version",
        "algorithm",
        "tar_format",
        "tar_sha3_256",
        "tar_size_bytes",
        "included_paths",
        "nonce_b64",
        "ciphertext_b64",
    }
    missing = sorted(field for field in required if field not in payload)
    if missing:
        raise BackupError(f"encrypted backup is missing fields: {', '.join(missing)}")
    if payload["type"] != "ind.testnet_offsite_backup.v3" or int(payload["version"]) != 1:
        raise BackupError("unsupported encrypted backup version")
    if payload["algorithm"] != "AES-256-GCM" or payload["tar_format"] != "tar.gz":
        raise BackupError("unsupported encrypted backup format")
    return {
        key: value for key, value in payload.items() if key not in {"nonce_b64", "ciphertext_b64"}
    }


def decrypt_backup(payload, key):
    metadata = encrypted_backup_metadata(payload)
    try:
        nonce = b64decode(payload["nonce_b64"])
        ciphertext = b64decode(payload["ciphertext_b64"])
    except Exception as exc:
        raise BackupError("encrypted backup has invalid base64 fields") from exc
    try:
        tar_bytes = AESGCM(key).decrypt(nonce, ciphertext, backup_authenticated_metadata(metadata))
    except Exception as exc:
        raise BackupError("encrypted backup authentication failed") from exc
    if hashlib.sha3_256(tar_bytes).hexdigest() != str(metadata["tar_sha3_256"]).lower():
        raise BackupError("decrypted backup tar hash mismatch")
    if len(tar_bytes) != int(metadata["tar_size_bytes"]):
        raise BackupError("decrypted backup tar size mismatch")
    return tar_bytes, metadata


def _safe_tar_member_name(name):
    normalized = str(name).replace("\\", "/").strip("/")
    path = PurePosixPath(normalized)
    if not normalized or path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise BackupError(f"unsafe backup tar member path: {name}")
    return normalized


def inspect_backup_tar(tar_bytes):
    entries = []
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as archive:
        for member in archive.getmembers():
            safe_name = _safe_tar_member_name(member.name)
            if member.isdev() or member.isfifo():
                raise BackupError(f"unsupported special tar member: {safe_name}")
            link_name = (
                _safe_tar_member_name(member.linkname) if member.issym() or member.islnk() else ""
            )
            entries.append(
                {
                    "name": safe_name,
                    "type": "dir" if member.isdir() else "file" if member.isfile() else "link",
                    "size": int(member.size),
                    "link_name": link_name,
                }
            )
    if not entries:
        raise BackupError("backup tar contains no entries")
    return entries


def extract_backup_tar(tar_bytes, output_dir):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    root = output_dir.resolve()
    extracted = []
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as archive:
        for member in archive.getmembers():
            safe_name = _safe_tar_member_name(member.name)
            if member.isdev() or member.isfifo() or member.issym() or member.islnk():
                raise BackupError(f"refusing to extract unsafe tar member: {safe_name}")
            target = (root / safe_name).resolve()
            if target != root and root not in target.parents:
                raise BackupError(f"backup tar member escapes restore directory: {safe_name}")
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                extracted.append(safe_name)
                continue
            if member.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                source = archive.extractfile(member)
                if source is None:
                    raise BackupError(f"could not read backup tar member: {safe_name}")
                with source, target.open("wb") as handle:
                    handle.write(source.read())
                extracted.append(safe_name)
                continue
            raise BackupError(f"unsupported tar member type: {safe_name}")
    return extracted


def load_encrypted_backup(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise BackupError(f"encrypted backup is not valid JSON: {exc}") from exc


def verify_backup_file(backup_path, key_file):
    payload = load_encrypted_backup(backup_path)
    tar_bytes, metadata = decrypt_backup(payload, load_backup_key(key_file))
    entries = inspect_backup_tar(tar_bytes)
    return {
        "ok": True,
        "backup_path": str(backup_path),
        "source_host": metadata.get("source_host", ""),
        "tar_size_bytes": int(metadata["tar_size_bytes"]),
        "tar_sha3_256": metadata["tar_sha3_256"],
        "included_path_count": len(metadata.get("included_paths") or []),
        "tar_entry_count": len(entries),
    }


def extract_backup_file(backup_path, key_file, restore_dir):
    payload = load_encrypted_backup(backup_path)
    tar_bytes, metadata = decrypt_backup(payload, load_backup_key(key_file))
    entries = inspect_backup_tar(tar_bytes)
    extracted = extract_backup_tar(tar_bytes, restore_dir)
    return {
        "ok": True,
        "backup_path": str(backup_path),
        "restore_dir": str(restore_dir),
        "source_host": metadata.get("source_host", ""),
        "tar_entry_count": len(entries),
        "extracted_entry_count": len(extracted),
    }


def create_backup(args):
    required = {
        "--vps-host": args.vps_host,
        "--vps-user": args.vps_user,
        "--ssh-key": args.ssh_key,
        "--ssh-bootstrap-secrets-file": args.ssh_bootstrap_secrets_file,
    }
    missing = [name for name, value in required.items() if not str(value or "").strip()]
    if missing:
        raise BackupError(
            "remote backup config is incomplete; set env defaults or pass "
            + ", ".join(sorted(missing))
        )
    values = read_bootstrap_secrets(args.ssh_bootstrap_secrets_file)
    key_passphrase = bootstrap_secret(values, "private key passphrase")
    sudo_password = bootstrap_secret(
        values, f"temporary sudo password for {args.vps_user}", "sudo password"
    )
    if not sudo_password:
        raise BackupError("sudo password is required to read protected operator files")

    tar_bytes, included_paths, remote_stderr = fetch_remote_tar(args, sudo_password, key_passphrase)
    key = load_or_create_backup_key(args.key_file)
    now = dt.datetime.now(dt.UTC)
    stamp = now.strftime("%Y%m%d-%H%M%S")
    backup_dir = Path(args.backup_dir)
    backup_dir.mkdir(parents=True, exist_ok=True)
    backup_path = backup_dir / f"ind-testnet-offsite-{stamp}.tar.gz.aesgcm.json"
    manifest_path = backup_path.with_suffix(backup_path.suffix + ".manifest.json")

    metadata = {
        "type": "ind.testnet_offsite_backup.v3",
        "version": 1,
        "created_at": int(now.timestamp()),
        "created_at_iso": now.isoformat(),
        "source_host": args.vps_host,
        "source_user": args.vps_user,
        "algorithm": "AES-256-GCM",
        "tar_format": "tar.gz",
        "tar_sha3_256": hashlib.sha3_256(tar_bytes).hexdigest(),
        "tar_size_bytes": len(tar_bytes),
        "included_paths": included_paths,
    }
    nonce, ciphertext = encrypt_backup(tar_bytes, key, metadata)
    encrypted_payload = {
        **metadata,
        "nonce_b64": b64encode(nonce),
        "ciphertext_b64": b64encode(ciphertext),
    }
    atomic_write_json(backup_path, encrypted_payload)
    manifest = {
        **metadata,
        "backup_path": str(backup_path),
        "backup_size_bytes": backup_path.stat().st_size,
        "key_file": str(args.key_file),
        "remote_tar_warnings": remote_stderr,
    }
    atomic_write_json(manifest_path, manifest)
    return {
        "ok": True,
        "backup_path": str(backup_path),
        "manifest_path": str(manifest_path),
        "tar_size_bytes": len(tar_bytes),
        "backup_size_bytes": backup_path.stat().st_size,
        "included_path_count": len(included_paths),
    }


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Create an encrypted off-server backup of the public testnet operator state"
    )
    parser.add_argument("--vps-host", default=DEFAULT_VPS_HOST)
    parser.add_argument("--vps-user", default=DEFAULT_VPS_USER)
    parser.add_argument("--ssh-key", type=Path, default=DEFAULT_SSH_KEY)
    parser.add_argument(
        "--ssh-bootstrap-secrets-file", type=Path, default=DEFAULT_BOOTSTRAP_SECRETS
    )
    parser.add_argument("--ssh-timeout-seconds", type=int, default=10)
    parser.add_argument("--remote-timeout-seconds", type=int, default=180)
    parser.add_argument("--backup-dir", type=Path, default=DEFAULT_BACKUP_DIR)
    parser.add_argument("--key-file", type=Path, default=DEFAULT_KEY_FILE)
    parser.add_argument("--remote-path", action="append", default=list(DEFAULT_REMOTE_PATHS))
    parser.add_argument(
        "--verify-backup",
        type=Path,
        help="decrypt and verify an existing encrypted backup instead of creating one",
    )
    parser.add_argument(
        "--extract-backup",
        type=Path,
        help="decrypt and extract an existing encrypted backup into --restore-dir",
    )
    parser.add_argument(
        "--restore-dir",
        type=Path,
        help="directory for a local restore drill when --extract-backup is used",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    try:
        if args.verify_backup:
            result = verify_backup_file(args.verify_backup, args.key_file)
        elif args.extract_backup:
            if not args.restore_dir:
                raise BackupError("--extract-backup requires --restore-dir")
            result = extract_backup_file(args.extract_backup, args.key_file, args.restore_dir)
        else:
            result = create_backup(args)
    except BackupError as exc:
        print(
            json.dumps({"ok": False, "error": str(exc)}, sort_keys=True, indent=2), file=sys.stderr
        )
        return 1
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
