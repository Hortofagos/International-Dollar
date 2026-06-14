#!/usr/bin/env python3
"""Run an operator smoke test against the public IND testnet."""

import argparse
import base64
import contextlib
import json
import os
import secrets as secretlib
import shlex
import subprocess
import sys
import time
import tempfile
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from ind import address_generation
from ind import runtime as runtime_json
from ind import sender_node
from ind import settings as ind_settings
from ind import token as ind_token
from ind import wallet_decryption
from ind import wallet_encryption
from ind import wallet_services

from tools import testnet_faucet
from tools import testnet_peers
from tools import testnet_report


DEFAULT_VPS_HOST = os.environ.get("IND_TESTNET_VPS_HOST", "")
DEFAULT_VPS_USER = os.environ.get("IND_TESTNET_VPS_USER", "")
DEFAULT_REMOTE_PATH = os.environ.get("IND_TESTNET_REMOTE_PATH", "")
DEFAULT_REMOTE_RUNTIME_CWD = os.environ.get("IND_TESTNET_REMOTE_RUNTIME_CWD", "")
DEFAULT_REMOTE_PYTHON = os.environ.get("IND_TESTNET_REMOTE_PYTHON", "")
DEFAULT_REMOTE_STORE = os.environ.get("IND_TESTNET_REMOTE_STORE", "")
DEFAULT_REMOTE_RUN_AS_USER = os.environ.get("IND_TESTNET_REMOTE_RUN_AS_USER", "")
DEFAULT_REMOTE_LEGACY_WALLET = os.environ.get("IND_TESTNET_REMOTE_LEGACY_WALLET", "")
DEFAULT_REMOTE_LOG_OPERATOR_URL = "http://127.0.0.1:8890"
DEFAULT_REMOTE_LOG_MIRROR = os.environ.get("IND_TESTNET_REMOTE_LOG_MIRROR", "")
DEFAULT_REMOTE_LOG_OBSERVED_ROOTS = os.environ.get("IND_TESTNET_REMOTE_LOG_OBSERVED_ROOTS", "")
DEFAULT_SSH_KEY = os.environ.get("IND_TESTNET_SSH_KEY", "")
DEFAULT_BOOTSTRAP_SECRETS = os.environ.get("IND_TESTNET_BOOTSTRAP_SECRETS", "")
DEFAULT_PEER = "testnet-seed.international-dollar.com"
DEFAULT_LOCAL_METADATA = ROOT_DIR / "files" / "testnet" / "local_clean_wallet.local.json"
DEFAULT_LOCAL_PASSPHRASE = ROOT_DIR / "files" / "testnet" / "local_clean_wallet_passphrase.local.txt"
DEFAULT_REMOTE_METADATA = ROOT_DIR / "files" / "testnet" / "vps_testnet_wallet.local.json"
DEFAULT_REMOTE_PASSPHRASE = ROOT_DIR / "files" / "testnet" / "vps_testnet_wallet_passphrase.local.txt"
DEFAULT_SUMMARY = ROOT_DIR / "files" / "testnet" / "latest_smoke_summary.local.json"


class SmokeError(RuntimeError):
    """Raised when the smoke test cannot continue safely."""


@contextlib.contextmanager
def temporary_env(updates):
    previous = {key: os.environ.get(key) for key in updates}
    try:
        for key, value in updates.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = str(value)
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def read_json(path, default=None):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return dict(default or {})


def write_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, sort_keys=True, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def read_secret_text(path, label):
    path = Path(path)
    if not path.exists():
        raise SmokeError(f"{label} file not found: {path}")
    value = path.read_text(encoding="utf-8").strip()
    if not value:
        raise SmokeError(f"{label} file is empty: {path}")
    return value


def write_secret_text(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(str(value).strip() + "\n", encoding="utf-8")
    os.replace(tmp, path)


def read_or_create_secret_text(path, label, generate=False):
    path = Path(path)
    if path.exists():
        return read_secret_text(path, label)
    if not generate:
        raise SmokeError(f"{label} file not found: {path}")
    value = secretlib.token_urlsafe(48)
    write_secret_text(path, value)
    return value


def read_bootstrap_secrets(path):
    if not path:
        return {}
    path = Path(path)
    if not path.exists() or path.is_dir():
        return {}
    secrets = {}
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
        key = " ".join(key.strip().lower().split())
        value = value.strip()
        if key and value:
            secrets[key] = value
    return secrets


def bootstrap_secret(secrets, *labels):
    normalized = {" ".join(label.lower().split()) for label in labels}
    for key, value in secrets.items():
        if key in normalized:
            return value
    for key, value in secrets.items():
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


def manifest_hash(manifest_path):
    manifest = read_json(manifest_path)
    if not manifest:
        raise SmokeError(f"manifest not found or empty: {manifest_path}")
    return ind_token.genesis_manifest_hash(manifest)


def testnet_env(manifest_path, peer=DEFAULT_PEER, store_path=None):
    env = {
        "IND_NETWORK": "testnet",
        "IND_TRUSTED_GENESIS_MANIFEST_HASHES": manifest_hash(manifest_path),
        "IND_PEER_PING_SERVERS": peer,
    }
    if store_path:
        env["IND_STORE_PATH"] = store_path
    return env


def require_remote_config(args, *, require_log=False):
    required = {
        "--vps-host": args.vps_host,
        "--vps-user": args.vps_user,
        "--ssh-key": args.ssh_key,
        "--remote-path": args.remote_path,
        "--remote-runtime-cwd": args.remote_runtime_cwd,
        "--remote-python": args.remote_python,
        "--remote-store-path": args.remote_store_path,
    }
    if getattr(args, "migrate_remote_legacy_wallet", False):
        required["--remote-legacy-wallet-file"] = getattr(args, "remote_legacy_wallet_file", "")
    if require_log:
        required["--remote-log-mirror"] = args.remote_log_mirror
        required["--remote-log-observed-roots-db"] = args.remote_log_observed_roots_db
    missing = [name for name, value in required.items() if not str(value or "").strip()]
    if missing:
        raise SmokeError(
            "remote testnet config is incomplete; set env defaults or pass "
            + ", ".join(sorted(missing))
        )


def validate_wallet_lines(address, lines):
    if len(lines) < 3:
        raise SmokeError(f"wallet {address} did not unlock to address/private/public lines")
    wallet_address = lines[0].strip()
    private_key = lines[1].strip()
    public_key = lines[2].strip()
    if wallet_address != address:
        raise SmokeError(f"wallet metadata address {address} does not match unlocked wallet {wallet_address}")
    if not private_key or not public_key:
        raise SmokeError(f"wallet {address} unlocked without signing keys")
    if not ind_token.public_key_matches_address(public_key, address):
        raise SmokeError(f"wallet {address} public key does not match address")
    return [line if line.endswith("\n") else line + "\n" for line in lines]


def unlock_local_wallet(address, passphrase):
    wallet_decryption.clear_plaintext_wallet_files(clear_memory=True)
    if not wallet_decryption.wallet_decrypt(passphrase, address):
        raise SmokeError(f"encrypted local wallet {address} did not unlock")
    path = runtime_json.decrypted_wallet_path(address)
    return validate_wallet_lines(address, runtime_json.read_decrypted_wallet_lines(path))


def create_local_wallet(passphrase, metadata_path):
    address, private_key, public_key = address_generation.generate_keypair()
    runtime_json.write_wallet_generation(address, private_key, public_key)
    wallet_encryption.wallet_encrypt(passphrase)
    lines = unlock_local_wallet(address, passphrase)
    write_json(
        metadata_path,
        {
            "network": "testnet",
            "purpose": "testnet smoke recipient",
            "address": address,
            "public_key": public_key,
            "encrypted_wallet_path": str(runtime_json.encrypted_wallet_path(address)),
            "created_at": int(time.time()),
        },
    )
    return address, lines


def prepare_local_wallet(args):
    passphrase = read_secret_text(args.local_wallet_passphrase_file, "local wallet passphrase")
    metadata = read_json(args.local_wallet_metadata_file)
    address = args.local_wallet_address or str(metadata.get("address", "")).strip()
    if not address and args.create_local_wallet:
        return create_local_wallet(passphrase, args.local_wallet_metadata_file)
    if not address:
        raise SmokeError("local wallet address is required; pass --local-wallet-address or --create-local-wallet")
    ind_token.validate_address(address, "local wallet address")
    return address, unlock_local_wallet(address, passphrase)


REMOTE_SCRIPT = r"""
import json
import os
import sys
import time
from pathlib import Path

payload = json.loads(sys.stdin.read() or "{}")
os.environ["IND_NETWORK"] = "testnet"
if payload.get("manifest_hash"):
    os.environ["IND_TRUSTED_GENESIS_MANIFEST_HASHES"] = payload["manifest_hash"]
if payload.get("store_path"):
    os.environ["IND_STORE_PATH"] = payload["store_path"]
if payload.get("peer"):
    os.environ["IND_PEER_PING_SERVERS"] = payload["peer"]

from ind import address_generation
from ind import runtime as runtime_json
from ind import sender_node
from ind import settings as ind_settings
from ind import token as ind_token
from ind import wallet_decryption
from ind import wallet_encryption
from ind import wallet_services


def emit(data):
    print(json.dumps(data, sort_keys=True))


def fail(message):
    emit({"ok": False, "error": message})
    raise SystemExit(2)


def validate_lines(address, lines):
    if len(lines) < 3:
        fail("wallet did not unlock to address/private/public lines")
    if lines[0].strip() != address:
        fail("wallet metadata address does not match unlocked wallet")
    if not ind_token.public_key_matches_address(lines[2].strip(), address):
        fail("wallet public key does not match address")
    return [line if line.endswith("\n") else line + "\n" for line in lines]


def unlock(address, passphrase):
    wallet_decryption.clear_plaintext_wallet_files(clear_memory=True)
    if not wallet_decryption.wallet_decrypt(passphrase, address):
        fail("encrypted remote wallet did not unlock")
    path = runtime_json.decrypted_wallet_path(address)
    return validate_lines(address, runtime_json.read_decrypted_wallet_lines(path))


def create_wallet(passphrase):
    address, private_key, public_key = address_generation.generate_keypair()
    runtime_json.write_wallet_generation(address, private_key, public_key)
    wallet_encryption.wallet_encrypt(passphrase)
    return address, public_key


def encrypted_wallet_exists(address):
    return any(
        runtime_json.wallet_address_from_name(path.name) == address
        for path in runtime_json.iter_encrypted_wallet_files()
    )


def load_legacy_wallet(path):
    text = Path(path).read_text(encoding="utf-8").strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = None
    if isinstance(data, dict):
        address = str(data.get("address") or data.get("wallet_address") or "").strip()
        private_key = str(data.get("private_key") or data.get("private") or "").strip()
        public_key = str(data.get("public_key") or data.get("public") or "").strip()
        bills = data.get("bills") or data.get("tokens") or []
        if isinstance(bills, str):
            bills = [line for line in bills.splitlines() if line.strip()]
        return address, private_key, public_key, [str(line).rstrip("\n") for line in bills]
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) < 3:
        fail("legacy wallet does not contain address/private/public key lines")
    return lines[0], lines[1], lines[2], lines[4:]


def record_summary(record):
    return {
        "display_id": record["display_id"],
        "token_id": record["token_id"],
        "owner_address": record["owner_address"],
        "sequence": int(record["sequence"]),
        "status": record["status"],
    }


def process_local_wallet_messages(address, lines, finality_buffer_seconds):
    store = ind_token.INDLocalStore()
    private_key = lines[1].strip()
    public_key = lines[2].strip()
    receipt_count = 0
    for message in list(store.messages_for_recipient(address)):
        try:
            result = store.ingest_message(message)
            if result.get("conflict_proof"):
                continue
            if message.get("type") in {ind_token.TRANSFER_ANNOUNCEMENT_TYPE, ind_token.TRANSFER_ANNOUNCEMENT_V2_TYPE}:
                bill = message["bill"] if message.get("type") == ind_token.TRANSFER_ANNOUNCEMENT_V2_TYPE else message["token"]
                state = ind_token.verify_token(bill)
                if state.owner_address == address:
                    receipt = ind_token.create_receipt_announcement(bill, private_key, public_key)
                    store.ingest_message(receipt)
                    runtime_json.write_transaction_message(receipt)
                    receipt_count += 1
        except Exception:
            continue
    finalized = store.finalize_pending(buffer_seconds=int(finality_buffer_seconds))
    wallet_ids = {line.split()[0].lstrip("-") for line in runtime_json.wallet_bill_lines(lines) if line.split()}
    updated_wallet = list(lines)
    for record in store.token_records_for_owner(address, settled_only=True):
        if record["display_id"] not in wallet_ids:
            updated_wallet.append(record["display_id"] + " " + str(record["sequence"]) + " " + str(int(time.time())) + "\n")
            wallet_ids.add(record["display_id"])
    runtime_json.write_decrypted_wallet_lines(runtime_json.decrypted_wallet_path(address), updated_wallet)
    return finalized, receipt_count


action = payload.get("action")
address = str(payload.get("address") or "").strip()
passphrase = str(payload.get("passphrase") or "")
if not passphrase:
    fail("remote wallet passphrase was not provided")

if action == "migrate_legacy_wallet":
    legacy_path = Path(str(payload.get("legacy_wallet_path") or ""))
    remove_legacy = bool(payload.get("remove_legacy", True))
    if not legacy_path.exists():
        if address and encrypted_wallet_exists(address):
            lines = unlock(address, passphrase)
            emit({
                "ok": True,
                "action": action,
                "address": address,
                "public_key": lines[2].strip(),
                "created": False,
                "migrated": False,
                "legacy_removed": True,
                "encrypted_wallet_path": str(runtime_json.encrypted_wallet_path(address)),
            })
            raise SystemExit(0)
        fail("legacy wallet file not found and no encrypted wallet was available")
    legacy_address, private_key, public_key, bills = load_legacy_wallet(legacy_path)
    if address and legacy_address != address:
        fail("legacy wallet address does not match the requested remote wallet address")
    address = legacy_address
    ind_token.validate_address(address, "legacy remote wallet address")
    if not private_key or not public_key:
        fail("legacy wallet is missing signing keys")
    if not ind_token.public_key_matches_address(public_key, address):
        fail("legacy wallet public key does not match address")
    runtime_json.write_wallet_generation(address, private_key, public_key, bills=bills)
    wallet_encryption.wallet_encrypt(passphrase)
    lines = unlock(address, passphrase)
    runtime_json.clear_wallet_generation()
    legacy_removed = False
    if remove_legacy:
        try:
            legacy_path.unlink()
            legacy_removed = True
        except FileNotFoundError:
            legacy_removed = True
    emit({
        "ok": True,
        "action": action,
        "address": address,
        "public_key": lines[2].strip(),
        "created": True,
        "migrated": True,
        "legacy_removed": legacy_removed,
        "encrypted_wallet_path": str(runtime_json.encrypted_wallet_path(address)),
    })
elif action == "prepare_wallet":
    created = False
    public_key = ""
    if not address:
        if not payload.get("create"):
            fail("remote wallet address is required unless create=true")
        address, public_key = create_wallet(passphrase)
        created = True
    ind_token.validate_address(address, "remote wallet address")
    lines = unlock(address, passphrase)
    emit({
        "ok": True,
        "action": action,
        "address": address,
        "public_key": public_key or lines[2].strip(),
        "created": created,
        "encrypted_wallet_path": str(runtime_json.encrypted_wallet_path(address)),
    })
elif action == "receive":
    lines = unlock(address, passphrase)
    if payload.get("remote_store_only"):
        finalized, receipt_count = process_local_wallet_messages(
            address,
            lines,
            payload.get("finality_buffer_seconds", ind_settings.finality_buffer_seconds()),
        )
    else:
        sender_node.receive_bills()
        if not payload.get("skip_peer_gossip"):
            sender_node.send_bills()
        store = ind_token.INDLocalStore()
        finalized = store.finalize_pending(buffer_seconds=int(payload.get("finality_buffer_seconds", ind_settings.finality_buffer_seconds())))
        receipt_count = None
    store = ind_token.INDLocalStore()
    records = [record_summary(item) for item in wallet_services.spendable_wallet_records(address, store=store)]
    pending = [record_summary(item) for item in wallet_services.pending_wallet_records(address, store=store)]
    emit({"ok": True, "action": action, "address": address, "finalized": finalized, "receipt_count": receipt_count, "spendable": records, "pending": pending})
elif action == "spend":
    lines = unlock(address, passphrase)
    recipient = ind_token.validate_address(payload.get("recipient_address"), "recipient address")
    expected_display_id = str(payload.get("expected_display_id") or "").strip()
    store = ind_token.INDLocalStore()
    store.finalize_pending(buffer_seconds=int(payload.get("finality_buffer_seconds", ind_settings.finality_buffer_seconds())))
    records = wallet_services.spendable_wallet_records(address, store=store)
    if expected_display_id:
        records = [item for item in records if item["display_id"] == expected_display_id]
    if not records:
        fail("remote wallet has no matching settled bill to spend")
    record = records[0]
    wallet_line = f"{record['display_id']} {record['sequence']} {int(time.time())}\n"
    state = wallet_services.spend_wallet_bill(lines, wallet_line, recipient, store=store)
    if not state:
        fail("remote spend was refused by local store confidence checks")
    if not payload.get("skip_peer_gossip"):
        sender_node.send_bills()
    emit({"ok": True, "action": action, "display_id": state.display_id, "token_id": state.token_id, "recipient_address": recipient, "sequence": state.sequence})
elif action == "finalize":
    store = ind_token.INDLocalStore()
    finalized = store.finalize_pending(buffer_seconds=int(payload.get("finality_buffer_seconds", ind_settings.finality_buffer_seconds())))
    refs = [str(item).strip() for item in payload.get("refs", []) if str(item).strip()]
    statuses = []
    for ref in refs:
        bill = store.get_compact_bill(ref) or store.get_token(ref) or store.get_compact_bill_by_display_id(ref) or store.get_token_by_display_id(ref)
        if not bill:
            statuses.append({"ref": ref, "status": "unknown"})
            continue
        try:
            state = ind_token.verify_token(bill)
            confidence = store.token_confidence(state.token_id, expected_owner=state.owner_address, min_settled_seconds=0)
            statuses.append({"ref": ref, "display_id": state.display_id, "owner_address": state.owner_address, "sequence": state.sequence, "status": confidence.get("level", "unknown")})
        except ind_token.ValidationError:
            statuses.append({"ref": ref, "status": "invalid"})
    emit({"ok": True, "action": action, "finalized": finalized, "statuses": statuses})
else:
    fail("unsupported remote action")
"""


def run_ssh_python(args, payload):
    script = base64.b64encode(REMOTE_SCRIPT.encode("utf-8")).decode("ascii")
    bootstrap = f"import base64; exec(base64.b64decode({script!r}).decode('utf-8'))"
    remote_env = {
        "IND_NETWORK": "testnet",
        "IND_STORE_PATH": args.remote_store_path,
        "IND_TRUSTED_GENESIS_MANIFEST_HASHES": payload["manifest_hash"],
        "IND_PEER_PING_SERVERS": args.peers_env,
        "PYTHONPATH": args.remote_path,
    }
    if args.remote_submit_to_transparency_log:
        remote_env["IND_SUBMIT_TO_TRANSPARENCY_LOG"] = "1"
        remote_env["IND_LOG_OPERATOR_URL"] = args.remote_log_operator_url
        remote_env["IND_LOG_MIRROR_URLS"] = args.remote_log_mirror
        remote_env["IND_LOG_UNSAFE_SINGLE_MIRROR"] = "1"
        remote_env["IND_LOG_MIN_MIRRORS"] = "1"
        remote_env["IND_LOG_CONSISTENCY_CHECK_INTERVAL_SECONDS"] = "0"
        remote_env["IND_LOG_OBSERVED_ROOTS_DB"] = args.remote_log_observed_roots_db
        remote_env["IND_LOG_SUBMISSION_VERIFY_TIMEOUT_SECONDS"] = str(
            args.remote_log_submission_verify_timeout_seconds
        )
        if args.remote_log_operator_public_key:
            remote_env["IND_LOG_OPERATOR_PUBLIC_KEY"] = args.remote_log_operator_public_key
    env_prefix = " ".join(f"{key}={shlex.quote(str(value))}" for key, value in remote_env.items())
    inner_command = (
        f"cd {shlex.quote(args.remote_runtime_cwd)} && "
        f"if [ -x {shlex.quote(args.remote_python)} ]; then PY={shlex.quote(args.remote_python)}; "
        "else PY=python3; fi; "
        f"{env_prefix} \"$PY\" -c {shlex.quote(bootstrap)}"
    )
    stdin_text = json.dumps(payload)
    if args.remote_run_as_user:
        if not args.remote_sudo_password:
            raise SmokeError("remote sudo password is required when --remote-run-as-user is set")
        remote_command = f"sudo -S -p '' -u {shlex.quote(args.remote_run_as_user)} sh -c {shlex.quote(inner_command)}"
        stdin_text = args.remote_sudo_password + "\n" + stdin_text
    else:
        remote_command = inner_command
    command = [
        "ssh",
        "-i",
        str(args.ssh_key),
        "-o",
        "BatchMode=no" if args.ssh_key_passphrase else "BatchMode=yes",
        "-o",
        "PasswordAuthentication=no",
        "-o",
        "KbdInteractiveAuthentication=no",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        f"ConnectTimeout={int(args.ssh_timeout_seconds)}",
        f"{args.vps_user}@{args.vps_host}",
        remote_command,
    ]
    with ssh_environment(args.ssh_key_passphrase) as ssh_env:
        process = subprocess.run(
            command,
            input=stdin_text,
            text=True,
            capture_output=True,
            timeout=args.ssh_timeout_seconds + args.remote_action_timeout_seconds,
            check=False,
            env=ssh_env,
        )
    if process.returncode != 0:
        detail = (process.stderr or process.stdout or "").strip()
        raise SmokeError(f"remote action {payload.get('action')} failed over SSH: {detail}")
    try:
        result = json.loads((process.stdout or "").strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError) as exc:
        raise SmokeError(f"remote action {payload.get('action')} returned non-JSON output") from exc
    if not result.get("ok"):
        raise SmokeError(f"remote action {payload.get('action')} refused: {result.get('error', 'unknown error')}")
    return result


def remote_payload(args, action, passphrase, **extra):
    payload = {
        "action": action,
        "address": args.remote_wallet_address,
        "passphrase": passphrase,
        "manifest_hash": manifest_hash(args.manifest),
        "store_path": args.remote_store_path,
        "peer": args.peers_env,
        "finality_buffer_seconds": args.finality_buffer_seconds,
        "remote_store_only": args.remote_store_only,
        "skip_peer_gossip": args.remote_skip_peer_gossip,
    }
    payload.update(extra)
    return payload


def write_remote_wallet_metadata(path, result):
    write_json(
        path,
        {
            "network": "testnet",
            "purpose": "public testnet VPS smoke wallet",
            "address": result["address"],
            "public_key": result.get("public_key", ""),
            "encrypted_wallet_path": result.get("encrypted_wallet_path", ""),
            "updated_at": int(time.time()),
        },
    )


def prepare_remote_wallet(args, passphrase):
    metadata = read_json(args.remote_wallet_metadata_file)
    if not args.remote_wallet_address:
        args.remote_wallet_address = str(metadata.get("address", "")).strip()
    if args.migrate_remote_legacy_wallet:
        result = run_ssh_python(
            args,
            remote_payload(
                args,
                "migrate_legacy_wallet",
                passphrase,
                legacy_wallet_path=args.remote_legacy_wallet_file,
                remove_legacy=not args.keep_remote_legacy_wallet,
            ),
        )
    else:
        result = run_ssh_python(
            args,
            remote_payload(args, "prepare_wallet", passphrase, create=args.create_remote_wallet),
        )
    args.remote_wallet_address = result["address"]
    write_remote_wallet_metadata(args.remote_wallet_metadata_file, result)
    return result


def wait_for_finality(args, label):
    if args.no_wait or args.finality_buffer_seconds <= 0:
        return
    print(f"waiting {args.finality_buffer_seconds}s for {label} finality...", flush=True)
    time.sleep(args.finality_buffer_seconds)


def parse_peer_messages(raw):
    if not raw or raw == "n":
        return []
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if isinstance(decoded, list):
        return [item for item in decoded if isinstance(item, dict)]
    if isinstance(decoded, dict):
        return [decoded]
    return []


def receive_locally(local_address, local_lines, args):
    store = ind_token.INDLocalStore()
    private_key = local_lines[1].strip()
    public_key = local_lines[2].strip()
    messages = list(store.messages_for_recipient(local_address))
    receipt_broadcast_results = []
    for peer in args.peers:
        messages.extend(parse_peer_messages(sender_node.connect("r", local_address, [peer])))
    receipt_count = 0
    for message in messages:
        try:
            result = store.ingest_message(message)
            if result.get("conflict_proof"):
                continue
            if message.get("type") in {ind_token.TRANSFER_ANNOUNCEMENT_TYPE, ind_token.TRANSFER_ANNOUNCEMENT_V2_TYPE}:
                bill = message["bill"] if message.get("type") == ind_token.TRANSFER_ANNOUNCEMENT_V2_TYPE else message["token"]
                state = ind_token.verify_token(bill)
                if state.owner_address == local_address:
                    receipt = ind_token.create_receipt_announcement(bill, private_key, public_key)
                    store.ingest_message(receipt)
                    runtime_json.write_transaction_message(receipt)
                    receipt_broadcast_results.extend(
                        testnet_peers.broadcast_message_to_peers(receipt, args.peers)
                    )
                    receipt_count += 1
        except Exception:
            continue
    finalized = store.finalize_pending(buffer_seconds=args.finality_buffer_seconds)
    spendable = wallet_services.spendable_wallet_records(local_address, store=store)
    pending = wallet_services.pending_wallet_records(local_address, store=store)
    return {
        "address": local_address,
        "finalized": finalized,
        "receipt_count": receipt_count,
        "receipt_broadcast_results": receipt_broadcast_results,
        "spendable": [
            {
                "display_id": item["display_id"],
                "token_id": item["token_id"],
                "sequence": int(item["sequence"]),
                "status": item["status"],
            }
            for item in spendable
        ],
        "pending": [
            {
                "display_id": item["display_id"],
                "token_id": item["token_id"],
                "sequence": int(item["sequence"]),
                "status": item["status"],
            }
            for item in pending
        ],
    }


def wait_for_peer_owner(display_id, expected_owner, args):
    deadline = time.monotonic() + max(0, int(args.remote_visibility_timeout_seconds))
    last_records = {}
    while True:
        matched = {}
        for peer in args.peers:
            records = testnet_report.query_peer_status([display_id], peer=peer)
            last_records[peer] = records
            for record in records:
                if record.get("owner_address") == expected_owner:
                    matched[peer] = record
        if len(matched) == len(args.peers):
            return matched
        if time.monotonic() >= deadline:
            break
        time.sleep(3)
    raise SmokeError(
        f"peer did not report {display_id} at expected owner {expected_owner}; last status: {last_records}"
    )


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Perform faucet issue -> VPS receipt -> finality -> VPS spend -> "
            "local receipt -> finality -> final status check on public testnet."
        )
    )
    parser.add_argument("--manifest", default=str(testnet_faucet.DEFAULT_MANIFEST))
    parser.add_argument(
        "--peer",
        action="append",
        help="seed/node to use; repeatable and comma-separated; default uses testnet/testnet.json",
    )
    parser.add_argument("--faucet-private-key-file", default=str(ROOT_DIR / "files" / "testnet" / "faucet_private_key.local.json"))
    parser.add_argument("--faucet-public-key-file", default=str(ROOT_DIR / "files" / "testnet" / "faucet_public_key.local.json"))
    parser.add_argument("--resume-display-id", help="resume an already issued bill instead of minting a new faucet bill")
    parser.add_argument("--local-wallet-address")
    parser.add_argument("--local-wallet-metadata-file", default=str(DEFAULT_LOCAL_METADATA))
    parser.add_argument("--local-wallet-passphrase-file", default=str(DEFAULT_LOCAL_PASSPHRASE))
    parser.add_argument("--create-local-wallet", action="store_true")
    parser.add_argument("--remote-wallet-address", help="encrypted testnet wallet address on the VPS")
    parser.add_argument("--remote-wallet-metadata-file", default=str(DEFAULT_REMOTE_METADATA))
    parser.add_argument("--remote-wallet-passphrase-file", default=str(DEFAULT_REMOTE_PASSPHRASE))
    parser.add_argument("--generate-remote-wallet-passphrase-if-missing", action="store_true")
    parser.add_argument("--create-remote-wallet", action="store_true")
    parser.add_argument("--migrate-remote-legacy-wallet", action="store_true")
    parser.add_argument("--remote-legacy-wallet-file", default=DEFAULT_REMOTE_LEGACY_WALLET)
    parser.add_argument("--keep-remote-legacy-wallet", action="store_true")
    parser.add_argument("--prepare-remote-wallet-only", action="store_true")
    parser.add_argument("--vps-host", default=DEFAULT_VPS_HOST)
    parser.add_argument("--vps-user", default=DEFAULT_VPS_USER)
    parser.add_argument("--ssh-key", default=str(DEFAULT_SSH_KEY))
    parser.add_argument("--ssh-bootstrap-secrets-file", default=str(DEFAULT_BOOTSTRAP_SECRETS))
    parser.add_argument("--ssh-timeout-seconds", type=int, default=10)
    parser.add_argument("--remote-action-timeout-seconds", type=int, default=90)
    parser.add_argument("--remote-path", default=DEFAULT_REMOTE_PATH)
    parser.add_argument("--remote-runtime-cwd", default=DEFAULT_REMOTE_RUNTIME_CWD)
    parser.add_argument("--remote-python", default=DEFAULT_REMOTE_PYTHON)
    parser.add_argument("--remote-store-path", default=DEFAULT_REMOTE_STORE)
    parser.add_argument("--remote-run-as-user", default=DEFAULT_REMOTE_RUN_AS_USER)
    parser.add_argument("--no-remote-sudo", action="store_true")
    parser.add_argument("--remote-submit-to-transparency-log", action="store_true")
    parser.add_argument("--remote-log-operator-url", default=DEFAULT_REMOTE_LOG_OPERATOR_URL)
    parser.add_argument("--remote-log-mirror", default=DEFAULT_REMOTE_LOG_MIRROR)
    parser.add_argument("--remote-log-operator-public-key", default="")
    parser.add_argument("--remote-log-observed-roots-db", default=DEFAULT_REMOTE_LOG_OBSERVED_ROOTS)
    parser.add_argument("--remote-log-submission-verify-timeout-seconds", type=int, default=30)
    parser.add_argument("--remote-store-only", action="store_true")
    parser.add_argument("--remote-skip-peer-gossip", action="store_true")
    parser.add_argument("--remote-visibility-timeout-seconds", type=int, default=60)
    parser.add_argument("--finality-buffer-seconds", type=int, default=ind_settings.finality_buffer_seconds())
    parser.add_argument("--no-wait", action="store_true", help="skip sleep delays; useful only for local/dev tests")
    parser.add_argument("--summary-file", default=str(DEFAULT_SUMMARY))
    parser.add_argument("--no-summary-file", action="store_true")
    return parser.parse_args()


def main():
    os.environ.setdefault("IND_NETWORK", "testnet")
    args = parse_args()
    args.peers = testnet_peers.parse_peer_args(args.peer)
    if not args.peers:
        args.peers = [DEFAULT_PEER]
    args.peer = args.peers[0]
    args.peers_env = testnet_peers.peers_env_value(args.peers)
    args.remote_wallet_metadata_file = Path(args.remote_wallet_metadata_file)
    if args.no_remote_sudo:
        args.remote_run_as_user = ""
    require_remote_config(args, require_log=args.remote_submit_to_transparency_log)
    args.ssh_key = Path(args.ssh_key)
    bootstrap_secrets = read_bootstrap_secrets(args.ssh_bootstrap_secrets_file)
    args.ssh_key_passphrase = bootstrap_secret(bootstrap_secrets, "private key passphrase")
    args.remote_sudo_password = bootstrap_secret(
        bootstrap_secrets,
        f"temporary sudo password for {args.vps_user}",
        "sudo password",
    )
    if not args.remote_wallet_address:
        metadata = read_json(args.remote_wallet_metadata_file)
        args.remote_wallet_address = str(metadata.get("address", "")).strip()
    if not args.remote_wallet_address and not (args.create_remote_wallet or args.migrate_remote_legacy_wallet):
        raise SystemExit(
            "remote wallet address is required unless --create-remote-wallet or --migrate-remote-legacy-wallet is set"
        )
    remote_passphrase = read_or_create_secret_text(
        args.remote_wallet_passphrase_file,
        "remote wallet passphrase",
        generate=(
            args.generate_remote_wallet_passphrase_if_missing
            or args.create_remote_wallet
            or args.migrate_remote_legacy_wallet
        ),
    )

    with temporary_env(testnet_env(args.manifest, peer=args.peers_env)):
        runtime_json.ensure_runtime_files()
        remote_prepare = prepare_remote_wallet(args, remote_passphrase)
        if args.prepare_remote_wallet_only:
            print(json.dumps({"ok": True, "remote_wallet": remote_prepare}, sort_keys=True, indent=2))
            return

        local_address, local_lines = prepare_local_wallet(args)

        if args.resume_display_id:
            faucet_issue = {
                "accepted": True,
                "network": "testnet",
                "display_id": args.resume_display_id,
                "recipient_address": remote_prepare["address"],
                "resumed": True,
            }
        else:
            faucet_issue = testnet_faucet.issue_testnet_bill(
                remote_prepare["address"],
                manifest_path=args.manifest,
                faucet_private_key_file=args.faucet_private_key_file,
                faucet_public_key_file=args.faucet_public_key_file,
                broadcast=True,
                peers=args.peers,
            )
            if args.remote_store_only:
                wait_for_peer_owner(faucet_issue["display_id"], remote_prepare["address"], args)

        remote_receipt = run_ssh_python(args, remote_payload(args, "receive", remote_passphrase))
        wait_for_finality(args, "VPS receipt")
        remote_settled = run_ssh_python(args, remote_payload(args, "receive", remote_passphrase))

        remote_spend = run_ssh_python(
            args,
            remote_payload(
                args,
                "spend",
                remote_passphrase,
                recipient_address=local_address,
                expected_display_id=faucet_issue["display_id"],
            ),
        )

        local_receipt = receive_locally(local_address, local_lines, args)
        wait_for_finality(args, "local receipt")
        local_settled = receive_locally(local_address, local_lines, args)

        remote_final = run_ssh_python(
            args,
            remote_payload(args, "finalize", remote_passphrase, refs=[faucet_issue["display_id"]]),
        )
        peer_status = {
            peer: testnet_report.query_peer_status([faucet_issue["display_id"]], peer=peer)
            for peer in args.peers
        }

        summary = {
            "ok": True,
            "network": "testnet",
            "created_at": int(time.time()),
            "peers": args.peers,
            "faucet_issue": faucet_issue,
            "remote_wallet": {
                "address": remote_prepare["address"],
                "created": bool(remote_prepare.get("created")),
            },
            "local_wallet": {
                "address": local_address,
            },
            "remote_receipt": remote_receipt,
            "remote_settled": remote_settled,
            "remote_spend": remote_spend,
            "local_receipt": local_receipt,
            "local_settled": local_settled,
            "remote_final": remote_final,
            "peer_status": peer_status,
        }
        if not args.no_summary_file:
            write_json(args.summary_file, summary)
        print(json.dumps(summary, sort_keys=True, indent=2))


if __name__ == "__main__":
    try:
        main()
    finally:
        wallet_decryption.clear_plaintext_wallet_files(clear_memory=True)
