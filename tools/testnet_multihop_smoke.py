#!/usr/bin/env python3
"""Run multi-wallet public-testnet transfer smoke checks for existing bills."""

import argparse
import base64
import contextlib
import json
import os
import shlex
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from ind import runtime as runtime_json
from ind import sender_node
from ind import settings as ind_settings
from ind import token as ind_token
from ind import wallet_decryption
from ind import wallet_services
from tools import testnet_report
from tools import testnet_peers
from tools.testnet_smoke import (
    DEFAULT_PEER,
    DEFAULT_REMOTE_LOG_MIRROR,
    DEFAULT_REMOTE_LOG_OBSERVED_ROOTS,
    DEFAULT_REMOTE_LOG_OPERATOR_URL,
    DEFAULT_REMOTE_PATH,
    DEFAULT_REMOTE_PYTHON,
    DEFAULT_REMOTE_RUN_AS_USER,
    DEFAULT_REMOTE_RUNTIME_CWD,
    DEFAULT_REMOTE_STORE,
    DEFAULT_REMOTE_METADATA,
    DEFAULT_REMOTE_PASSPHRASE,
    DEFAULT_SSH_KEY,
    DEFAULT_BOOTSTRAP_SECRETS,
    DEFAULT_VPS_HOST,
    DEFAULT_VPS_USER,
    SmokeError,
    bootstrap_secret,
    manifest_hash,
    read_bootstrap_secrets,
    read_secret_text,
    require_remote_config,
    ssh_environment,
    temporary_env,
    testnet_env,
    unlock_local_wallet,
)
from tools.testnet_faucet import DEFAULT_MANIFEST


DEFAULT_LOCAL_CLEAN_METADATA = ROOT_DIR / "files" / "testnet" / "local_clean_wallet.local.json"
DEFAULT_LOCAL_CLEAN_PASSPHRASE = ROOT_DIR / "files" / "testnet" / "local_clean_wallet_passphrase.local.txt"
DEFAULT_LOCAL_SECOND_METADATA = ROOT_DIR / "files" / "testnet" / "local_second_wallet.local.json"
DEFAULT_LOCAL_SECOND_PASSPHRASE = ROOT_DIR / "files" / "testnet" / "local_second_wallet_passphrase.local.txt"
DEFAULT_SUMMARY = ROOT_DIR / "files" / "testnet" / "multihop_1x5_1x6_1x7_summary.local.json"


REMOTE_SCRIPT = r"""
import json
import os
import sys
import time
import urllib.parse
import urllib.request

payload = json.loads(sys.stdin.read() or "{}")
os.environ["IND_NETWORK"] = "testnet"
if payload.get("manifest_hash"):
    os.environ["IND_TRUSTED_GENESIS_MANIFEST_HASHES"] = payload["manifest_hash"]
if payload.get("store_path"):
    os.environ["IND_STORE_PATH"] = payload["store_path"]
if payload.get("peer"):
    os.environ["IND_PEER_PING_SERVERS"] = payload["peer"]

from ind import runtime as runtime_json
from ind import sender_node
from ind import token as ind_token
from ind import wallet_decryption
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
    return validate_lines(address, runtime_json.read_decrypted_wallet_lines(runtime_json.decrypted_wallet_path(address)))


def message_bill(message):
    if message.get("type") == ind_token.TRANSFER_ANNOUNCEMENT_V2_TYPE:
        return message["bill"]
    if message.get("type") == ind_token.TRANSFER_ANNOUNCEMENT_TYPE:
        return message["token"]
    if message.get("type") == ind_token.RECEIPT_ANNOUNCEMENT_V2_TYPE:
        return message["bill"]
    if message.get("type") == ind_token.RECEIPT_ANNOUNCEMENT_TYPE:
        return message["token"]
    return None


def transfer_hash_from_message(message):
    bill = message_bill(message)
    if not bill:
        return ""
    return ind_token.transfer_hash(ind_token._last_transfer(bill))


def state_summary_from_bill(bill):
    state = ind_token.verify_token(bill)
    return {
        "display_id": state.display_id,
        "token_id": state.token_id,
        "owner_address": state.owner_address,
        "sequence": int(state.sequence),
        "transfer_hash": state.last_transfer_hash,
    }


def record_summary(record):
    return {
        "display_id": record["display_id"],
        "token_id": record["token_id"],
        "owner_address": record["owner_address"],
        "sequence": int(record["sequence"]),
        "status": record["status"],
    }


def wallet_status(address, finality_buffer_seconds):
    store = ind_token.INDLocalStore()
    finalized = store.finalize_pending(buffer_seconds=int(finality_buffer_seconds))
    return {
        "finalized": finalized,
        "spendable": [record_summary(item) for item in wallet_services.spendable_wallet_records(address, store=store)],
        "pending": [record_summary(item) for item in wallet_services.pending_wallet_records(address, store=store)],
    }


def broadcast(message, peer):
    if not peer:
        return "skipped"
    return sender_node.connect("b", ind_token.pack_wire_message(message), [peer])


def operator_get(path, params=None):
    params = params or {}
    query = urllib.parse.urlencode(params)
    url = "http://127.0.0.1:8890" + path + (("?" + query) if query else "")
    request = urllib.request.Request(url, headers={"User-Agent": "International-Dollar-testnet-multihop/1"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


action = payload.get("action")
address = str(payload.get("address") or "").strip()
passphrase = str(payload.get("passphrase") or "")
finality_buffer_seconds = int(payload.get("finality_buffer_seconds", 60))
peer = str(payload.get("peer") or "")

if action in {"prepare_wallet", "spend", "ingest_message", "wallet_status", "duplicate_spend_possible"}:
    if not address or not passphrase:
        fail("remote wallet address/passphrase is required")
    lines = unlock(address, passphrase)

if action == "prepare_wallet":
    emit({
        "ok": True,
        "action": action,
        "address": address,
        "public_key": lines[2].strip(),
        "status": wallet_status(address, finality_buffer_seconds),
    })
elif action == "wallet_status":
    emit({"ok": True, "action": action, "address": address, "status": wallet_status(address, finality_buffer_seconds)})
elif action == "duplicate_spend_possible":
    display_id = str(payload.get("display_id") or "").strip()
    store = ind_token.INDLocalStore()
    store.finalize_pending(buffer_seconds=finality_buffer_seconds)
    records = wallet_services.spendable_wallet_records(address, store=store)
    matches = [item for item in records if item["display_id"] == display_id]
    emit({"ok": True, "action": action, "display_id": display_id, "possible": bool(matches), "matches": [record_summary(item) for item in matches]})
elif action == "ingest_message":
    message = payload.get("message")
    if not isinstance(message, dict):
        fail("message must be a JSON object")
    store = ind_token.INDLocalStore()
    result = store.ingest_message(message)
    receipt = None
    receipt_result = None
    bill = message_bill(message)
    state_summary = state_summary_from_bill(bill) if bill else {}
    if message.get("type") in {ind_token.TRANSFER_ANNOUNCEMENT_TYPE, ind_token.TRANSFER_ANNOUNCEMENT_V2_TYPE}:
        state = ind_token.verify_token(bill)
        if state.owner_address == address:
            receipt = ind_token.create_receipt_announcement(bill, lines[1].strip(), lines[2].strip())
            receipt_result = store.ingest_message(receipt)
            runtime_json.write_transaction_message(receipt)
            if not payload.get("skip_broadcast"):
                broadcast(receipt, peer)
    finalized = store.finalize_pending(buffer_seconds=finality_buffer_seconds)
    emit({
        "ok": True,
        "action": action,
        "accepted": bool(result.get("accepted")),
        "status": result.get("status", ""),
        "message_type": message.get("type", ""),
        "state": state_summary,
        "transfer_hash": transfer_hash_from_message(message),
        "receipt": receipt,
        "receipt_accepted": bool(receipt_result.get("accepted")) if isinstance(receipt_result, dict) else None,
        "receipt_status": receipt_result.get("status", "") if isinstance(receipt_result, dict) else "",
        "finalized": finalized,
        "wallet_status": wallet_status(address, finality_buffer_seconds),
    })
elif action == "spend":
    display_id = str(payload.get("display_id") or "").strip()
    recipient = ind_token.validate_address(payload.get("recipient_address"), "recipient address")
    store = ind_token.INDLocalStore()
    store.finalize_pending(buffer_seconds=finality_buffer_seconds)
    bill = store.get_compact_bill_by_display_id(display_id) or store.get_token_by_display_id(display_id)
    if not bill:
        fail("remote wallet has no matching bill")
    if not wallet_services.bill_is_spendable(store, bill, address):
        fail("remote wallet does not consider the bill spendable")
    transferred = ind_token.create_transfer(
        bill,
        lines[1].strip(),
        lines[2].strip(),
        recipient,
        metadata={"network": "testnet", "source": "testnet-multihop-smoke"},
    )
    announcement = ind_token.create_transfer_announcement(transferred)
    result = store.ingest_message(announcement)
    runtime_json.write_transaction_message(announcement)
    broadcast_result = "skipped" if payload.get("skip_broadcast") else broadcast(announcement, peer)
    emit({
        "ok": True,
        "action": action,
        "accepted": bool(result.get("accepted")),
        "status": result.get("status", ""),
        "display_id": display_id,
        "recipient_address": recipient,
        "announcement": announcement,
        "state": state_summary_from_bill(transferred),
        "transfer_hash": transfer_hash_from_message(announcement),
        "broadcast_result": broadcast_result,
        "wallet_status": wallet_status(address, finality_buffer_seconds),
    })
elif action == "operator_root":
    emit({"ok": True, "action": action, "root": operator_get("/v1/root")})
elif action == "operator_proof":
    entry_hash = str(payload.get("entry_hash") or "").strip()
    tree_size = int(payload.get("tree_size") or 0)
    if not entry_hash or tree_size <= 0:
        fail("entry_hash and tree_size are required")
    emit({"ok": True, "action": action, "proof": operator_get("/v1/proof", {"entry_hash": entry_hash, "tree_size": tree_size})})
else:
    fail("unsupported remote action")
"""


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


def fetch_json(url, timeout=30):
    request = urllib.request.Request(url, headers={"User-Agent": "International-Dollar-testnet-multihop/1"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def run_ssh_python(args, payload):
    script = base64.b64encode(REMOTE_SCRIPT.encode("utf-8")).decode("ascii")
    bootstrap = f"import base64; exec(base64.b64decode({script!r}).decode('utf-8'))"
    remote_env = {
        "IND_NETWORK": "testnet",
        "IND_STORE_PATH": args.remote_store_path,
        "IND_TRUSTED_GENESIS_MANIFEST_HASHES": payload["manifest_hash"],
        "IND_PEER_PING_SERVERS": args.peers_env,
        "PYTHONPATH": args.remote_path,
        "IND_SUBMIT_TO_TRANSPARENCY_LOG": "1",
        "IND_LOG_OPERATOR_URL": args.remote_log_operator_url,
        "IND_LOG_MIRROR_URLS": args.remote_log_mirror,
        "IND_LOG_UNSAFE_SINGLE_MIRROR": "1",
        "IND_LOG_MIN_MIRRORS": "1",
        "IND_LOG_CONSISTENCY_CHECK_INTERVAL_SECONDS": "0",
        "IND_LOG_OBSERVED_ROOTS_DB": args.remote_log_observed_roots_db,
        "IND_LOG_SUBMISSION_VERIFY_TIMEOUT_SECONDS": str(args.remote_log_submission_verify_timeout_seconds),
    }
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


def remote_payload(args, action, **extra):
    payload = {
        "action": action,
        "address": args.remote_wallet_address,
        "passphrase": args.remote_wallet_passphrase,
        "manifest_hash": manifest_hash(args.manifest),
        "store_path": args.remote_store_path,
        "peer": args.peers_env,
        "finality_buffer_seconds": args.finality_buffer_seconds,
    }
    payload.update(extra)
    return payload


def load_local_wallet(label, metadata_path, passphrase_path):
    metadata = read_json(metadata_path)
    address = str(metadata.get("address", "")).strip()
    if not address:
        raise SmokeError(f"{label} wallet metadata is missing an address: {metadata_path}")
    passphrase = read_secret_text(passphrase_path, f"{label} wallet passphrase")
    lines = unlock_local_wallet(address, passphrase)
    return {
        "label": label,
        "address": address,
        "private_key": lines[1].strip(),
        "public_key": lines[2].strip(),
        "metadata_path": str(metadata_path),
    }


def message_bill(message):
    if message.get("type") == ind_token.TRANSFER_ANNOUNCEMENT_V2_TYPE:
        return message["bill"]
    if message.get("type") == ind_token.TRANSFER_ANNOUNCEMENT_TYPE:
        return message["token"]
    if message.get("type") == ind_token.RECEIPT_ANNOUNCEMENT_V2_TYPE:
        return message["bill"]
    if message.get("type") == ind_token.RECEIPT_ANNOUNCEMENT_TYPE:
        return message["token"]
    return None


def transfer_hash_from_message(message):
    bill = message_bill(message)
    if not bill:
        return ""
    return ind_token.transfer_hash(ind_token._last_transfer(bill))


def state_summary_from_bill(bill):
    state = ind_token.verify_token(bill)
    return {
        "display_id": state.display_id,
        "token_id": state.token_id,
        "owner_address": state.owner_address,
        "sequence": int(state.sequence),
        "transfer_hash": state.last_transfer_hash,
    }


def record_summary(record):
    return {
        "display_id": record["display_id"],
        "token_id": record["token_id"],
        "owner_address": record["owner_address"],
        "sequence": int(record["sequence"]),
        "status": record["status"],
    }


def wallet_status(address, finality_buffer_seconds):
    store = ind_token.INDLocalStore()
    finalized = store.finalize_pending(buffer_seconds=int(finality_buffer_seconds))
    return {
        "finalized": finalized,
        "spendable": [record_summary(item) for item in wallet_services.spendable_wallet_records(address, store=store)],
        "pending": [record_summary(item) for item in wallet_services.pending_wallet_records(address, store=store)],
    }


def status_for_refs(refs, peer):
    return testnet_report.query_peer_status(refs, peer=peer)


def status_for_all_peers(refs, peers):
    return {peer: status_for_refs(refs, peer) for peer in peers}


def local_ref_status(refs):
    return testnet_report.local_status(refs, finalize=True)


def broadcast_message(message, peers):
    return testnet_peers.broadcast_message_to_peers(message, peers)


def artifact_path(display_id, hop, name):
    safe_display = str(display_id).replace("/", "_")
    return ROOT_DIR / "files" / "testnet" / f"multihop_{safe_display}_{hop}_{name}.local.json"


def save_artifact(path, payload, artifacts):
    write_json(path, payload)
    artifacts.append(str(path.relative_to(ROOT_DIR)))
    return str(path)


def display_path(path):
    path = Path(path)
    if not path.is_absolute():
        path = ROOT_DIR / path
    try:
        return str(path.resolve().relative_to(ROOT_DIR.resolve()))
    except ValueError:
        return str(path)


def spendable_possible(address, display_id):
    store = ind_token.INDLocalStore()
    records = wallet_services.spendable_wallet_records(address, store=store)
    return [record_summary(item) for item in records if item["display_id"] == display_id]


def local_spend(args, display_id, sender, recipient, hop, hop_label, artifacts):
    store = ind_token.INDLocalStore()
    store.finalize_pending(buffer_seconds=args.finality_buffer_seconds)
    bill = store.get_compact_bill_by_display_id(display_id) or store.get_token_by_display_id(display_id)
    if not bill:
        raise SmokeError(f"local store does not know {display_id}")
    if not wallet_services.bill_is_spendable(store, bill, sender["address"]):
        raise SmokeError(f"{sender['label']} does not consider {display_id} spendable")
    transferred = ind_token.create_transfer(
        bill,
        sender["private_key"],
        sender["public_key"],
        recipient["address"],
        metadata={"network": "testnet", "source": "testnet-multihop-smoke", "hop": hop_label},
    )
    announcement = ind_token.create_transfer_announcement(transferred)
    ingest = store.ingest_message(announcement)
    announcement_path = artifact_path(display_id, hop, f"{sender['label']}_to_{recipient['label']}_transfer")
    save_artifact(announcement_path, announcement, artifacts)
    broadcast_result = broadcast_message(announcement, args.peers)
    remote_ingest = run_ssh_python(args, remote_payload(args, "ingest_message", message=announcement))

    receipt = ind_token.create_receipt_announcement(transferred, recipient["private_key"], recipient["public_key"])
    receipt_ingest = store.ingest_message(receipt)
    receipt_path = artifact_path(display_id, hop, f"{recipient['label']}_receipt")
    save_artifact(receipt_path, receipt, artifacts)
    receipt_broadcast_result = broadcast_message(receipt, args.peers)
    remote_receipt_ingest = run_ssh_python(args, remote_payload(args, "ingest_message", message=receipt))

    return {
        "display_id": display_id,
        "hop": hop_label,
        "sender": sender["label"],
        "sender_address": sender["address"],
        "recipient": recipient["label"],
        "recipient_address": recipient["address"],
        "announcement_artifact": str(announcement_path.relative_to(ROOT_DIR)),
        "receipt_artifact": str(receipt_path.relative_to(ROOT_DIR)),
        "transfer_hash": transfer_hash_from_message(announcement),
        "state": state_summary_from_bill(transferred),
        "local_ingest": {"accepted": bool(ingest.get("accepted")), "status": ingest.get("status", "")},
        "remote_ingest": {
            "accepted": bool(remote_ingest.get("accepted")),
            "status": remote_ingest.get("status", ""),
            "transfer_hash": remote_ingest.get("transfer_hash", ""),
        },
        "local_receipt_ingest": {"accepted": bool(receipt_ingest.get("accepted")), "status": receipt_ingest.get("status", "")},
        "remote_receipt_ingest": {
            "accepted": bool(remote_receipt_ingest.get("accepted")),
            "status": remote_receipt_ingest.get("status", ""),
        },
        "broadcast_result": broadcast_result,
        "receipt_broadcast_result": receipt_broadcast_result,
        "duplicate_after": {
            "sender_spendable_matches": spendable_possible(sender["address"], display_id),
        },
    }


def local_to_remote_spend(args, display_id, sender, hop, artifacts):
    remote_recipient = {"label": "vps", "address": args.remote_wallet_address}
    store = ind_token.INDLocalStore()
    store.finalize_pending(buffer_seconds=args.finality_buffer_seconds)
    bill = store.get_compact_bill_by_display_id(display_id) or store.get_token_by_display_id(display_id)
    if not bill:
        raise SmokeError(f"local store does not know {display_id}")
    if not wallet_services.bill_is_spendable(store, bill, sender["address"]):
        raise SmokeError(f"{sender['label']} does not consider {display_id} spendable")
    transferred = ind_token.create_transfer(
        bill,
        sender["private_key"],
        sender["public_key"],
        args.remote_wallet_address,
        metadata={"network": "testnet", "source": "testnet-multihop-smoke", "hop": "local_second_to_vps"},
    )
    announcement = ind_token.create_transfer_announcement(transferred)
    ingest = store.ingest_message(announcement)
    announcement_path = artifact_path(display_id, hop, f"{sender['label']}_to_vps_transfer")
    save_artifact(announcement_path, announcement, artifacts)
    broadcast_result = broadcast_message(announcement, args.peers)
    remote_ingest = run_ssh_python(args, remote_payload(args, "ingest_message", message=announcement))
    receipt = remote_ingest.get("receipt")
    receipt_ingest = None
    receipt_path = None
    if isinstance(receipt, dict):
        receipt_ingest = store.ingest_message(receipt)
        receipt_path = artifact_path(display_id, hop, "vps_receipt")
        save_artifact(receipt_path, receipt, artifacts)
        broadcast_message(receipt, args.peers)
    return {
        "display_id": display_id,
        "hop": "local_second_to_vps",
        "sender": sender["label"],
        "sender_address": sender["address"],
        "recipient": remote_recipient["label"],
        "recipient_address": remote_recipient["address"],
        "announcement_artifact": str(announcement_path.relative_to(ROOT_DIR)),
        "receipt_artifact": str(receipt_path.relative_to(ROOT_DIR)) if receipt_path else "",
        "transfer_hash": transfer_hash_from_message(announcement),
        "state": state_summary_from_bill(transferred),
        "local_ingest": {"accepted": bool(ingest.get("accepted")), "status": ingest.get("status", "")},
        "remote_ingest": {
            "accepted": bool(remote_ingest.get("accepted")),
            "status": remote_ingest.get("status", ""),
            "receipt_accepted": remote_ingest.get("receipt_accepted"),
            "receipt_status": remote_ingest.get("receipt_status", ""),
        },
        "local_receipt_ingest": {
            "accepted": bool(receipt_ingest.get("accepted")) if isinstance(receipt_ingest, dict) else False,
            "status": receipt_ingest.get("status", "") if isinstance(receipt_ingest, dict) else "",
        },
        "broadcast_result": broadcast_result,
        "duplicate_after": {
            "sender_spendable_matches": spendable_possible(sender["address"], display_id),
        },
    }


def remote_to_local_spend(args, display_id, recipient, hop, artifacts):
    remote_spend = run_ssh_python(
        args,
        remote_payload(args, "spend", display_id=display_id, recipient_address=recipient["address"]),
    )
    announcement = remote_spend["announcement"]
    announcement_path = artifact_path(display_id, hop, f"vps_to_{recipient['label']}_transfer")
    save_artifact(announcement_path, announcement, artifacts)
    store = ind_token.INDLocalStore()
    ingest = store.ingest_message(announcement)
    bill = message_bill(announcement)
    receipt = ind_token.create_receipt_announcement(bill, recipient["private_key"], recipient["public_key"])
    receipt_ingest = store.ingest_message(receipt)
    receipt_path = artifact_path(display_id, hop, f"{recipient['label']}_receipt")
    save_artifact(receipt_path, receipt, artifacts)
    receipt_broadcast_result = broadcast_message(receipt, args.peers)
    remote_receipt_ingest = run_ssh_python(args, remote_payload(args, "ingest_message", message=receipt))
    duplicate_remote = run_ssh_python(args, remote_payload(args, "duplicate_spend_possible", display_id=display_id))
    return {
        "display_id": display_id,
        "hop": "vps_to_local_clean",
        "sender": "vps",
        "sender_address": args.remote_wallet_address,
        "recipient": recipient["label"],
        "recipient_address": recipient["address"],
        "announcement_artifact": str(announcement_path.relative_to(ROOT_DIR)),
        "receipt_artifact": str(receipt_path.relative_to(ROOT_DIR)),
        "transfer_hash": transfer_hash_from_message(announcement),
        "state": remote_spend.get("state", {}),
        "remote_spend": {
            "accepted": bool(remote_spend.get("accepted")),
            "status": remote_spend.get("status", ""),
            "broadcast_result": remote_spend.get("broadcast_result", ""),
        },
        "local_ingest": {"accepted": bool(ingest.get("accepted")), "status": ingest.get("status", "")},
        "local_receipt_ingest": {"accepted": bool(receipt_ingest.get("accepted")), "status": receipt_ingest.get("status", "")},
        "remote_receipt_ingest": {
            "accepted": bool(remote_receipt_ingest.get("accepted")),
            "status": remote_receipt_ingest.get("status", ""),
        },
        "receipt_broadcast_result": receipt_broadcast_result,
        "duplicate_after": {
            "remote_spend_possible": bool(duplicate_remote.get("possible")),
            "remote_matches": duplicate_remote.get("matches", []),
        },
    }


def wait_for_finality(args, label):
    if args.finality_buffer_seconds <= 0:
        return
    print(f"waiting {args.finality_buffer_seconds}s for {label} finality...", flush=True)
    time.sleep(args.finality_buffer_seconds + args.finality_slack_seconds)


def finalize_everywhere(args, refs):
    local = {
        "local_clean": wallet_status(args.local_clean["address"], args.finality_buffer_seconds),
        "local_second": wallet_status(args.local_second["address"], args.finality_buffer_seconds),
        "refs": local_ref_status(refs),
    }
    remote = run_ssh_python(args, remote_payload(args, "wallet_status"))
    peer = status_for_all_peers(refs, args.peers)
    return {"local": local, "remote": remote, "peer": peer}


def wait_for_public_mirrors(args, target_tree_size):
    deadline = time.monotonic() + args.mirror_wait_seconds
    last = {}
    while True:
        main = fetch_json(args.main_latest_url)
        second = fetch_json(args.second_latest_url)
        comparable = {
            key: main.get(key) == second.get(key)
            for key in ("log_id", "tree_size", "root_hash", "spend_map_root", "spend_map_size")
        }
        ok = (
            int(main.get("tree_size", 0)) >= int(target_tree_size)
            and int(second.get("tree_size", 0)) >= int(target_tree_size)
            and all(comparable.values())
        )
        last = {"main": main, "second": second, "comparable": comparable, "ok": ok}
        if ok or time.monotonic() >= deadline:
            return last
        time.sleep(args.mirror_poll_seconds)


def verify_operator_proofs(args, transfer_hashes, tree_size):
    results = []
    for entry_hash in transfer_hashes:
        result = run_ssh_python(
            args,
            remote_payload(args, "operator_proof", entry_hash=entry_hash, tree_size=tree_size),
        )
        proof = result["proof"]
        results.append(
            {
                "entry_hash": entry_hash,
                "leaf_index": int(proof["leaf_index"]),
                "tree_size": int(proof["tree_size"]),
                "present": proof.get("entry_hash") == entry_hash,
            }
        )
    return results


def parse_args():
    parser = argparse.ArgumentParser(description="Move existing public-testnet bills through local and VPS wallets.")
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    parser.add_argument(
        "--peer",
        action="append",
        help="seed/node to use; repeatable and comma-separated; default uses testnet/testnet.json",
    )
    parser.add_argument("--bill", dest="bills", action="append", default=["1x5", "1x6", "1x7"])
    parser.add_argument("--local-clean-wallet-metadata-file", default=str(DEFAULT_LOCAL_CLEAN_METADATA))
    parser.add_argument("--local-clean-wallet-passphrase-file", default=str(DEFAULT_LOCAL_CLEAN_PASSPHRASE))
    parser.add_argument("--local-second-wallet-metadata-file", default=str(DEFAULT_LOCAL_SECOND_METADATA))
    parser.add_argument("--local-second-wallet-passphrase-file", default=str(DEFAULT_LOCAL_SECOND_PASSPHRASE))
    parser.add_argument("--remote-wallet-address")
    parser.add_argument("--remote-wallet-metadata-file", default=str(DEFAULT_REMOTE_METADATA))
    parser.add_argument("--remote-wallet-passphrase-file", default=str(DEFAULT_REMOTE_PASSPHRASE))
    parser.add_argument("--vps-host", default=DEFAULT_VPS_HOST)
    parser.add_argument("--vps-user", default=DEFAULT_VPS_USER)
    parser.add_argument("--ssh-key", default=str(DEFAULT_SSH_KEY))
    parser.add_argument("--ssh-bootstrap-secrets-file", default=str(DEFAULT_BOOTSTRAP_SECRETS))
    parser.add_argument("--ssh-timeout-seconds", type=int, default=10)
    parser.add_argument("--remote-action-timeout-seconds", type=int, default=120)
    parser.add_argument("--remote-path", default=DEFAULT_REMOTE_PATH)
    parser.add_argument("--remote-runtime-cwd", default=DEFAULT_REMOTE_RUNTIME_CWD)
    parser.add_argument("--remote-python", default=DEFAULT_REMOTE_PYTHON)
    parser.add_argument("--remote-store-path", default=DEFAULT_REMOTE_STORE)
    parser.add_argument("--remote-run-as-user", default=DEFAULT_REMOTE_RUN_AS_USER)
    parser.add_argument("--no-remote-sudo", action="store_true")
    parser.add_argument("--remote-log-operator-url", default=DEFAULT_REMOTE_LOG_OPERATOR_URL)
    parser.add_argument("--remote-log-mirror", default=DEFAULT_REMOTE_LOG_MIRROR)
    parser.add_argument("--remote-log-operator-public-key", default="")
    parser.add_argument("--remote-log-observed-roots-db", default=DEFAULT_REMOTE_LOG_OBSERVED_ROOTS)
    parser.add_argument("--remote-log-submission-verify-timeout-seconds", type=int, default=5)
    parser.add_argument("--finality-buffer-seconds", type=int, default=ind_settings.finality_buffer_seconds())
    parser.add_argument("--finality-slack-seconds", type=int, default=2)
    parser.add_argument("--mirror-wait-seconds", type=int, default=240)
    parser.add_argument("--mirror-poll-seconds", type=int, default=10)
    parser.add_argument("--main-latest-url", default="https://international-dollar.com/transparency/latest.json")
    parser.add_argument("--second-latest-url", default="https://seed.internetofthebots.com/transparency/latest.json")
    parser.add_argument("--summary-file", default=str(DEFAULT_SUMMARY))
    return parser.parse_args()


def main():
    os.environ.setdefault("IND_NETWORK", "testnet")
    args = parse_args()
    args.peers = testnet_peers.parse_peer_args(args.peer)
    if not args.peers:
        args.peers = [DEFAULT_PEER]
    args.peer = args.peers[0]
    args.peers_env = testnet_peers.peers_env_value(args.peers)
    args.manifest = Path(args.manifest)
    if args.no_remote_sudo:
        args.remote_run_as_user = ""
    require_remote_config(args, require_log=True)
    args.ssh_key = Path(args.ssh_key)
    bootstrap_secrets = read_bootstrap_secrets(args.ssh_bootstrap_secrets_file)
    args.ssh_key_passphrase = bootstrap_secret(bootstrap_secrets, "private key passphrase")
    args.remote_sudo_password = bootstrap_secret(
        bootstrap_secrets,
        f"temporary sudo password for {args.vps_user}",
        "sudo password",
    )
    remote_metadata = read_json(args.remote_wallet_metadata_file)
    args.remote_wallet_address = args.remote_wallet_address or str(remote_metadata.get("address", "")).strip()
    if not args.remote_wallet_address:
        raise SmokeError("remote wallet address is required")
    args.remote_wallet_passphrase = read_secret_text(args.remote_wallet_passphrase_file, "remote wallet passphrase")

    artifacts = []
    transfer_hashes = []
    phase_results = {}

    with temporary_env(testnet_env(args.manifest, peer=args.peers_env)):
        runtime_json.ensure_runtime_files()
        args.local_clean = load_local_wallet(
            "local_clean",
            Path(args.local_clean_wallet_metadata_file),
            Path(args.local_clean_wallet_passphrase_file),
        )
        args.local_second = load_local_wallet(
            "local_second",
            Path(args.local_second_wallet_metadata_file),
            Path(args.local_second_wallet_passphrase_file),
        )
        remote_prepare = run_ssh_python(args, remote_payload(args, "prepare_wallet"))
        before_root = run_ssh_python(args, remote_payload(args, "operator_root"))["root"]
        initial_status = {
            "local": local_ref_status(args.bills),
            "peer": status_for_all_peers(args.bills, args.peers),
            "remote_wallet": remote_prepare,
            "operator_root": before_root,
        }

        phase1 = []
        for display_id in args.bills:
            item = local_spend(
                args,
                display_id,
                args.local_clean,
                args.local_second,
                "01",
                "local_clean_to_local_second",
                artifacts,
            )
            phase1.append(item)
            transfer_hashes.append(item["transfer_hash"])
        wait_for_finality(args, "local_clean -> local_second")
        phase_results["after_local_clean_to_local_second"] = finalize_everywhere(args, args.bills)

        phase2 = []
        for display_id in args.bills:
            item = local_to_remote_spend(args, display_id, args.local_second, "02", artifacts)
            phase2.append(item)
            transfer_hashes.append(item["transfer_hash"])
        wait_for_finality(args, "local_second -> VPS")
        phase_results["after_local_second_to_vps"] = finalize_everywhere(args, args.bills)

        phase3 = []
        for display_id in args.bills:
            item = remote_to_local_spend(args, display_id, args.local_clean, "03", artifacts)
            phase3.append(item)
            transfer_hashes.append(item["transfer_hash"])
        wait_for_finality(args, "VPS -> local_clean")
        final_status = finalize_everywhere(args, args.bills)

        after_root = run_ssh_python(args, remote_payload(args, "operator_root"))["root"]
        target_tree_size = int(before_root["tree_size"]) + len(transfer_hashes)
        mirror = wait_for_public_mirrors(args, target_tree_size)
        proof_tree_size = int(after_root["tree_size"])
        proof_results = verify_operator_proofs(args, transfer_hashes, proof_tree_size)

        summary = {
            "ok": True,
            "network": "testnet",
            "created_at": int(time.time()),
            "bills": args.bills,
            "peers": args.peers,
            "wallets": {
                "local_clean": {
                    "address": args.local_clean["address"],
                    "metadata_path": display_path(args.local_clean_wallet_metadata_file),
                },
                "local_second": {
                    "address": args.local_second["address"],
                    "metadata_path": display_path(args.local_second_wallet_metadata_file),
                },
                "vps": {
                    "address": args.remote_wallet_address,
                    "metadata_path": display_path(args.remote_wallet_metadata_file),
                },
            },
            "initial_status": initial_status,
            "phases": {
                "local_clean_to_local_second": phase1,
                "local_second_to_vps": phase2,
                "vps_to_local_clean": phase3,
            },
            "phase_status": phase_results,
            "final_status": final_status,
            "transparency": {
                "operator_tree_size_before": int(before_root["tree_size"]),
                "operator_root_hash_before": before_root["root_hash"],
                "operator_tree_size_after": int(after_root["tree_size"]),
                "operator_root_hash_after": after_root["root_hash"],
                "expected_min_tree_size_after": target_tree_size,
                "transfer_hashes": transfer_hashes,
                "operator_inclusion_proofs": proof_results,
                "public_mirror": {
                    "ok": bool(mirror.get("ok")),
                    "main": {
                        "tree_size": int(mirror["main"].get("tree_size", 0)),
                        "root_hash": mirror["main"].get("root_hash", ""),
                        "timestamp": int(mirror["main"].get("timestamp", 0)),
                        "spend_map_root": mirror["main"].get("spend_map_root", ""),
                    },
                    "second": {
                        "tree_size": int(mirror["second"].get("tree_size", 0)),
                        "root_hash": mirror["second"].get("root_hash", ""),
                        "timestamp": int(mirror["second"].get("timestamp", 0)),
                        "spend_map_root": mirror["second"].get("spend_map_root", ""),
                    },
                    "comparable_fields_equal": mirror.get("comparable", {}),
                },
            },
            "artifacts": artifacts,
        }
        write_json(args.summary_file, summary)
        print(json.dumps(summary, sort_keys=True, indent=2))


if __name__ == "__main__":
    try:
        main()
    finally:
        wallet_decryption.clear_plaintext_wallet_files(clear_memory=True)
