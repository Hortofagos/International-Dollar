#!/usr/bin/env python3
"""Issue public-operator-backed V3 bills on the VPS nodes and exercise wallet hops."""

import argparse
import base64
import json
import os
import subprocess
import sys
import time
import traceback
from hashlib import sha3_256
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

os.environ["IND_NETWORK"] = "testnet"
os.environ["IND_NODE_PORT"] = "18888"
os.environ.setdefault("IND_REQUIRE_TRANSPARENCY_LOG", "0")
os.environ.setdefault("IND_SUBMIT_TO_TRANSPARENCY_LOG", "0")

from ind import protocol_v3
from ind import runtime as runtime_json
from ind import wallet_services
from ind.store import INDLocalStore
from tools import testnet_peers
from tools.testnet_backup import bootstrap_secret, read_bootstrap_secrets, ssh_environment
from tools.v3_public_wallet_e2e import (
    ACCEPTED_FINAL_STATUSES,
    DEFAULT_PEERS,
    _broadcast_message,
    _message_hash,
    _query_public_status,
    _run_hop,
    _run_negative_cases,
    _safe_path,
    _status_snapshot,
    _wallet_report,
)

DEFAULT_NODE_CONFIG = ROOT_DIR / "files" / "testnet" / "v3_vps_public_wallet_e2e.local.json"
NODE_CONFIG_ENV = "IND_V3_VPS_E2E_NODE_CONFIG"
OPERATOR_ROOT_WAIT_ATTEMPTS = 90
OPERATOR_ROOT_WAIT_INTERVAL_SECONDS = 2
REQUIRED_NODE_FIELDS = {
    "name",
    "host",
    "user",
    "key",
    "service",
    "db",
    "private_key_file",
    "public_key_file",
    "mirror_dir",
}


def _progress(message):
    print(f"[v3-vps-e2e] {message}", file=sys.stderr, flush=True)


REMOTE_ISSUE_PROGRAM = r"""
import base64
import json
import os
import re
import sys
import time
from hashlib import sha3_256

sys.path.insert(0, "/opt/international-dollar")
os.environ["IND_NETWORK"] = "testnet"
os.environ["IND_NODE_PORT"] = "18888"

from ind import archive_segment_v3
from ind import crypto_ed25519
from ind import genesis_manifest_v3
from ind import keys_v3
from ind import proof_bundle_v3
from ind import protocol_v3
from ind import spend_map_v3
from ind import token as ind_token
from ind import transparency_client as log_client
from ind import transparency_server as log_server
from ind import wallet_services

payload = json.loads(base64.b64decode("__PAYLOAD_B64__").decode("utf-8"))
operator_private, operator_public = log_server.load_or_create_operator_keys(
    payload["private_key_file"],
    payload["public_key_file"],
)
log = log_server.TransparencyLog(payload["db"], operator_private, operator_public)


def _sha3_text(text):
    return sha3_256(str(text).encode("ascii")).hexdigest()


def _nested_strings(value):
    if isinstance(value, dict):
        for item in value.values():
            yield from _nested_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _nested_strings(item)
    elif isinstance(value, str):
        yield value


def _load_private_key_text(path):
    text = open(path, encoding="utf-8").read()
    stripped = text.strip()
    if stripped.startswith(keys_v3.PRIVATE_KEY_PREFIX):
        return stripped
    try:
        data = json.loads(text)
    except Exception:
        data = None
    if data is not None:
        for item in _nested_strings(data):
            item = item.strip()
            if item.startswith(keys_v3.PRIVATE_KEY_PREFIX):
                return item
    match = re.search(r"indsk3:[!-~]+", text)
    if match:
        return match.group(0)
    raise RuntimeError(f"V3 private key not found in {path}")


def _archive_resolver(segment):
    return lambda value: segment if value == segment["segment_hash"] else None


def _load_trusted_genesis_context():
    manifest_file = payload.get("genesis_manifest_file")
    owner_private_key_file = payload.get("genesis_owner_private_key_file")
    if not manifest_file and not owner_private_key_file:
        return None
    if not manifest_file or not owner_private_key_file:
        raise RuntimeError(
            "genesis_manifest_file and genesis_owner_private_key_file must be set together"
        )
    manifest = json.load(open(manifest_file, encoding="utf-8"))
    owner_private_key = _load_private_key_text(owner_private_key_file)
    owner_seed = keys_v3.decode_private_key(owner_private_key)
    owner_public_key = keys_v3.encode_public_key(
        crypto_ed25519.public_key_from_private_seed(owner_seed)
    )
    owner_address = keys_v3.address_from_public_key(owner_public_key)
    genesis_manifest_v3.verify_manifest(
        manifest,
        expected_network="testnet",
        expected_network_id=protocol_v3.DEFAULT_NETWORK_ID,
    )
    return {
        "manifest": manifest,
        "owner_address": owner_address,
        "owner_private_key": owner_private_key,
        "owner_public_key": owner_public_key,
    }


def _deindex_invalid_historical_claims():
    invalid = []
    checked = 0
    with log._connect() as conn:
        rows = conn.execute(
            '''
            SELECT spend_claims.rowid AS rowid, spend_claims.*, log_entries.transfer_json
            FROM spend_claims
            LEFT JOIN log_entries ON spend_claims.transfer_hash = log_entries.entry_hash
            WHERE transfer_leaf_index IS NOT NULL
            ORDER BY spend_claims.rowid ASC
            '''
        ).fetchall()
        for row in rows:
            checked += 1
            claim = {
                "type": "ind.transparency_spend_claim.v3",
                "version": log_client.LOG_VERSION,
                "log_id": log.log_id,
                "spend_key": row["spend_key"],
                "token_id": row["token_id"],
                "previous_hash": row["previous_hash"],
                "sequence": int(row["sequence"]),
                "sender_address": row["sender_address"],
                "sender_public_key": row["sender_public_key"],
                "transfer_hash": row["transfer_hash"],
                "transfer_leaf_index": int(row["transfer_leaf_index"]),
                "accepted_at": int(row["first_seen"]),
            }
            if row["transfer_json"]:
                claim["transfer"] = json.loads(row["transfer_json"])
            try:
                log_client._normalize_spend_claim(claim)
            except Exception as exc:
                invalid.append(
                    {
                        "rowid": int(row["rowid"]),
                        "transfer_hash": row["transfer_hash"],
                        "leaf": int(row["transfer_leaf_index"]),
                        "error": str(exc),
                    }
                )
                conn.execute(
                    '''
                    UPDATE spend_claims
                    SET transfer_leaf_index = NULL
                    WHERE spend_key = ? AND transfer_hash = ?
                    ''',
                    (row["spend_key"], row["transfer_hash"]),
                )
        if invalid:
            conn.execute("DELETE FROM spend_map_nodes_v3")
            conn.execute("DELETE FROM spend_map_claims_v3")
            conn.execute("DELETE FROM spend_map_meta_v3")
    return {"checked": checked, "deindexed": invalid, "deindexed_count": len(invalid)}


historical_claim_cleanup = _deindex_invalid_historical_claims()
trusted_genesis = _load_trusted_genesis_context()

issued = []
base_time = int(time.time()) - 20
for index, spec in enumerate(payload["bills"], start=1):
    display_id = str(spec["display_id"])
    value = int(spec["value"])
    recipient_address = str(spec["recipient_address"])
    issued_at = base_time + index * 3
    parsed = protocol_v3.parse_display_id(display_id)
    if trusted_genesis is not None:
        manifest = trusted_genesis["manifest"]
        genesis_ref = genesis_manifest_v3.derive_genesis_ref(
            manifest,
            value,
            int(parsed["serial"]),
        )
        base_state = genesis_manifest_v3.derive_base_state(
            manifest,
            value,
            int(parsed["serial"]),
        )
        if base_state["display_id"] != display_id:
            raise RuntimeError("genesis manifest derived an unexpected display id")
        if base_state["owner_address"] != trusted_genesis["owner_address"]:
            raise RuntimeError("genesis owner private key does not match manifest owner")
        issuer = (
            trusted_genesis["owner_address"],
            trusted_genesis["owner_private_key"],
            trusted_genesis["owner_public_key"],
        )
        token_id = _sha3_text(f"IND:testnet:token:v3:{genesis_ref['genesis_hash']}")
        issued_at = max(issued_at, int(base_state["last_transfer_timestamp"]) + 1)
        genesis_mode = "trusted_manifest"
    else:
        issuer = wallet_services.generate_wallet_v3(os.urandom(32))
        genesis_hash = _sha3_text(
            f"{payload['run_id']}:{payload['node']}:{display_id}:genesis:{time.time_ns()}"
        )
        token_id = _sha3_text(
            f"{payload['run_id']}:{payload['node']}:{display_id}:token:{time.time_ns()}"
        )
        genesis_ref = {
            "type": protocol_v3.GENESIS_REF_TYPE,
            "version": protocol_v3.VERSION,
            "network_id": int(protocol_v3.DEFAULT_NETWORK_ID),
            "genesis_hash": genesis_hash,
            "manifest_hash": None,
            "issuer_key_id": None,
            "issue_index": int(parsed["serial"]),
            "issued_at": issued_at,
        }
        base_state = {
            "sequence": 0,
            "owner_address": issuer[0],
            "last_transfer_hash": genesis_hash,
            "last_transfer_timestamp": issued_at,
            "last_transfer_day": issued_at // 86400,
            "transfers_in_last_day": 0,
            "display_id": display_id,
            "value": value,
        }
        genesis_mode = "synthetic_untrusted"
    transfer = protocol_v3.create_transfer_from_state(
        token_id,
        base_state,
        issuer[1],
        issuer[2],
        recipient_address,
        metadata={
            "source": "v3-vps-public-wallet-e2e",
            "run_id": payload["run_id"],
            "node": payload["node"],
            "label": str(spec.get("label", "")),
        },
        timestamp=issued_at + 1,
        network_id=protocol_v3.DEFAULT_NETWORK_ID,
    )
    archive_segment = archive_segment_v3.make_archive_segment(
        token_id,
        genesis_ref,
        base_state,
        [transfer],
        network_id=protocol_v3.DEFAULT_NETWORK_ID,
    )
    checkpoint_core = archive_segment_v3.verify_archive_segment(archive_segment)
    transfer_hash = protocol_v3.transfer_hash(transfer)
    transfer_append = log.append_entry_hash(
        transfer_hash,
        submitted_at=issued_at + 2,
        transfer=transfer,
    )
    claim = protocol_v3.spend_claim_for_transfer(
        transfer,
        log.log_id,
        transfer_append["leaf_index"],
        issued_at + 2,
    )
    with log._connect() as conn:
        log._record_spend_claim(
            conn,
            claim,
            transfer_hash,
            transfer_append["leaf_index"],
            issued_at + 2,
        )
    checkpoint_append = log.append_entry_hash(
        checkpoint_core["checkpoint_hash"],
        submitted_at=issued_at + 3,
        entry_kind="checkpoint",
        entry=checkpoint_core,
    )
    root = log.publish_root(issued_at + 4)
    inclusion = log.inclusion_proof(checkpoint_append["entry_hash"], int(root["tree_size"]))
    with log._connect() as conn:
        claims = log._spend_claim_records(conn, tree_size=int(root["tree_size"]))
    compressed = spend_map_v3.build_compressed_spend_map_proof(
        claims,
        protocol_v3.spend_key_for_transfer(transfer),
        int(root["tree_size"]),
        network_id=protocol_v3.DEFAULT_NETWORK_ID,
    )
    source_evidence = proof_bundle_v3.make_archive_segment_evidence(
        archive_segment,
        network_id=protocol_v3.DEFAULT_NETWORK_ID,
        include_segment=False,
    )
    proof_bundle = proof_bundle_v3.make_proof_bundle(
        checkpoint_core,
        root,
        inclusion,
        compressed,
        source_evidence,
        network_id=protocol_v3.DEFAULT_NETWORK_ID,
        created_at=issued_at + 5,
    )
    bill = protocol_v3.create_bill_from_checkpoint_core(
        genesis_ref,
        checkpoint_core,
        proof_bundle,
        trusted_operator_public_key=operator_public,
        archive_segment_resolver=_archive_resolver(archive_segment),
    )
    issued.append(
        {
            "label": str(spec.get("label", "")),
            "display_id": display_id,
            "value": value,
            "token_id": token_id,
            "owner_address": recipient_address,
            "sequence": int(checkpoint_core["sequence"]),
            "operator_log_id": log.log_id,
            "operator_public_key": operator_public,
            "root_id": log_client.signed_root_id(root),
            "proof_bundle_hash": proof_bundle["proof_bundle_hash"],
            "archive_segment_hash": archive_segment["segment_hash"],
            "checkpoint_hash": checkpoint_core["checkpoint_hash"],
            "transfer_hash": transfer_hash,
            "genesis_mode": genesis_mode,
            "genesis_manifest_hash": genesis_ref.get("manifest_hash"),
            "transfer_append": {
                "accepted": bool(transfer_append.get("accepted")),
                "entry_hash": transfer_append.get("entry_hash"),
                "leaf_index": int(transfer_append.get("leaf_index")),
                "tree_size": int(transfer_append.get("tree_size")),
            },
            "checkpoint_append": {
                "accepted": bool(checkpoint_append.get("accepted")),
                "entry_hash": checkpoint_append.get("entry_hash"),
                "leaf_index": int(checkpoint_append.get("leaf_index")),
                "tree_size": int(checkpoint_append.get("tree_size")),
            },
            "bill": bill,
            "proof_bundle": proof_bundle,
            "archive_segment": archive_segment,
            "transfer_message_hash": None,
        }
    )

print("BEGIN_IND_ISSUE_JSON")
print(
    json.dumps(
        {
            "node": payload["node"],
            "historical_claim_cleanup": historical_claim_cleanup,
            "issued": issued,
        },
        sort_keys=True,
    )
)
print("END_IND_ISSUE_JSON")
"""


def _python():
    candidate = ROOT_DIR / ".venv" / "Scripts" / "python.exe"
    return str(candidate if candidate.exists() else sys.executable)


def _config_bool(value):
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _expand_local_path(value):
    if not value:
        return ""
    return Path(os.path.expandvars(os.path.expanduser(str(value))))


def _normalize_node_config(name, item):
    if not isinstance(item, dict):
        raise RuntimeError(f"node config {name!r} must be an object")
    node = dict(item)
    node.setdefault("name", name)
    missing = [field for field in sorted(REQUIRED_NODE_FIELDS) if not str(node.get(field) or "")]
    if missing:
        raise RuntimeError(f"node config {node['name']!r} is missing: {', '.join(missing)}")
    node["key"] = _expand_local_path(node["key"])
    node["bootstrap"] = _expand_local_path(node.get("bootstrap"))
    node["needs_askpass"] = _config_bool(node.get("needs_askpass"))
    node["needs_sudo_password"] = _config_bool(node.get("needs_sudo_password"))
    return node


def load_node_config(path=None):
    config_path = Path(path or os.environ.get(NODE_CONFIG_ENV) or DEFAULT_NODE_CONFIG)
    if not config_path.exists():
        raise RuntimeError(
            "VPS node config is required. Create an ignored local JSON file at "
            f"{DEFAULT_NODE_CONFIG} or pass --node-config /path/to/config. "
            "The file should contain primary/iotb node objects with host, user, key, "
            "service, db, private_key_file, public_key_file, and mirror_dir."
        )
    data = json.loads(config_path.read_text(encoding="utf-8"))
    raw_nodes = data.get("nodes") if isinstance(data, dict) else None
    if raw_nodes is None:
        raw_nodes = data
    if isinstance(raw_nodes, list):
        nodes = {
            str(item.get("name") or "").strip(): _normalize_node_config(
                str(item.get("name") or "").strip(), item
            )
            for item in raw_nodes
            if isinstance(item, dict)
        }
    elif isinstance(raw_nodes, dict):
        nodes = {
            str(name).strip(): _normalize_node_config(str(name).strip(), item)
            for name, item in raw_nodes.items()
        }
    else:
        raise RuntimeError("node config must contain a nodes object or list")
    if "primary" not in nodes:
        raise RuntimeError("node config must include a primary node")
    return nodes


def _ssh_base(node, batch=True):
    return [
        "ssh",
        "-i",
        str(node["key"]),
        "-o",
        f"BatchMode={'yes' if batch else 'no'}",
        "-o",
        "ConnectTimeout=12",
        "-o",
        "StrictHostKeyChecking=accept-new",
        f"{node['user']}@{node['host']}",
    ]


def _node_secret_values(node):
    secrets = read_bootstrap_secrets(node.get("bootstrap"))
    return {
        "key_passphrase": bootstrap_secret(
            secrets,
            str(node.get("key_passphrase_label") or "private key passphrase"),
            "private key passphrase",
        ),
        "sudo_password": bootstrap_secret(
            secrets,
            str(node.get("sudo_password_label") or f"temporary sudo password for {node['user']}"),
            "sudo password",
        ),
    }


def _run_ssh(node, remote_command, *, stdin_text=None, timeout=120):
    cmd = _ssh_base(node, batch=not node.get("needs_askpass"))
    cmd.append(remote_command)
    env = None
    context = None
    if node.get("needs_askpass"):
        values = _node_secret_values(node)
        context = ssh_environment(values["key_passphrase"])
        env = context.__enter__()
        if stdin_text is None and node.get("needs_sudo_password"):
            stdin_text = values["sudo_password"] + "\n"
    try:
        proc = subprocess.run(
            cmd,
            input=stdin_text,
            text=True,
            capture_output=True,
            timeout=timeout,
            env=env,
        )
    finally:
        if context is not None:
            context.__exit__(None, None, None)
    if proc.returncode != 0:
        raise RuntimeError(
            f"ssh command failed on {node['name']} with {proc.returncode}: {proc.stderr.strip()}"
        )
    return proc.stdout, proc.stderr


def _remote_issue_command(node, payload):
    payload = dict(payload)
    payload.update(
        {
            "node": node["name"],
            "db": node["db"],
            "private_key_file": node["private_key_file"],
            "public_key_file": node["public_key_file"],
            "genesis_manifest_file": node.get("genesis_manifest_file"),
            "genesis_owner_private_key_file": node.get("genesis_owner_private_key_file"),
        }
    )
    encoded = base64.b64encode(json.dumps(payload, sort_keys=True).encode("utf-8")).decode(
        "ascii"
    )
    program = REMOTE_ISSUE_PROGRAM.replace("__PAYLOAD_B64__", encoded)
    sudo_prelude = "sudo -S -p '' -v" if node.get("needs_sudo_password") else "sudo -n true"
    backup_label = (
        str(payload.get("run_id", "run")).replace(" ", "_").replace("/", "_").replace("\\", "_")
        + "_"
        + node["name"]
        + "_operator_issue"
    )
    db_basename = Path(node["db"]).name
    return (
        "set -eu\n"
        f"{sudo_prelude}\n"
        f"backup_dir=$HOME/ind-code-backups/{backup_label}\n"
        "mkdir -p \"$backup_dir\"\n"
        f"sudo -n cp -a {node['db']} \"$backup_dir/{db_basename}.before-issue\"\n"
        f"if [ -f {node['db']}-wal ]; then sudo -n cp -a {node['db']}-wal \"$backup_dir/{db_basename}-wal.before-issue\"; fi\n"
        f"if [ -f {node['db']}-shm ]; then sudo -n cp -a {node['db']}-shm \"$backup_dir/{db_basename}-shm.before-issue\"; fi\n"
        "sudo -n chown -R $(id -u):$(id -g) \"$backup_dir\"\n"
        f"trap 'sudo -n systemctl start {node['service']} >/dev/null 2>&1 || true' EXIT\n"
        f"sudo -n systemctl stop {node['service']}\n"
        "sudo -n env IND_NETWORK=testnet IND_NODE_PORT=18888 "
        "PYTHONPATH=/opt/international-dollar "
        "/opt/international-dollar/.venv/bin/python - <<'PY'\n"
        f"{program}\n"
        "PY\n"
        f"sudo -n systemctl start {node['service']}\n"
        "trap - EXIT\n"
    )


def _parse_remote_issue(stdout):
    start = stdout.find("BEGIN_IND_ISSUE_JSON")
    end = stdout.find("END_IND_ISSUE_JSON")
    if start < 0 or end < 0 or end <= start:
        raise RuntimeError("remote issue output did not include JSON markers")
    body = stdout[start + len("BEGIN_IND_ISSUE_JSON") : end].strip()
    return json.loads(body)


def _issue_remote(node, run_id, bill_specs):
    command = _remote_issue_command(node, {"run_id": run_id, "bills": bill_specs})
    stdout, stderr = _run_ssh(node, command, timeout=180)
    result = _parse_remote_issue(stdout)
    backup_label = (
        str(run_id).replace(" ", "_").replace("/", "_").replace("\\", "_")
        + "_"
        + node["name"]
        + "_operator_issue"
    )
    return {
        "node": node["name"],
        "stderr": stderr.strip(),
        "backup_dir": f"$HOME/ind-code-backups/{backup_label}",
        "historical_claim_cleanup": result.get("historical_claim_cleanup", {}),
        "issued": result["issued"],
    }


def _publish_latest_root_mirror(node, run_id, exact_roots=None):
    mirror_dir = node["mirror_dir"]
    exact_roots = list(exact_roots or [])
    encoded_roots = base64.b64encode(
        json.dumps(exact_roots, sort_keys=True).encode("utf-8")
    ).decode("ascii")
    backup_label = (
        str(run_id).replace(" ", "_").replace("/", "_").replace("\\", "_")
        + "_"
        + node["name"]
        + "_mirror_publish"
    )
    sudo_prelude = "sudo -S -p '' -v" if node.get("needs_sudo_password") else "sudo -n true"
    command = (
        "set -eu\n"
        f"{sudo_prelude}\n"
        f"backup_dir=$HOME/ind-code-backups/{backup_label}\n"
        "mkdir -p \"$backup_dir\"\n"
        f"if [ -f {mirror_dir}/latest.json ]; then sudo -n cp -a {mirror_dir}/latest.json \"$backup_dir/latest.json.before-publish\"; fi\n"
        f"if [ -f {mirror_dir}/manifest.json ]; then sudo -n cp -a {mirror_dir}/manifest.json \"$backup_dir/manifest.json.before-publish\"; fi\n"
        "sudo -n chown -R $(id -u):$(id -g) \"$backup_dir\"\n"
        "cd /opt/international-dollar\n"
        "sudo -n env PYTHONPATH=/opt/international-dollar "
        "/opt/international-dollar/.venv/bin/python - <<'PY'\n"
        "import json\n"
        "import base64\n"
        "import time\n"
        "from operator_tools.root_streamer import OperatorRootSource, StaticRootMirrorWriter, verify_roots\n"
        f"exact_roots = json.loads(base64.b64decode('{encoded_roots}').decode('utf-8'))\n"
        "writer = StaticRootMirrorWriter("
        f"'{mirror_dir}'"
        ")\n"
        "published_exact = []\n"
        "for exact_root in verify_roots(exact_roots):\n"
        "    writer.publish_root(exact_root, force_historical=True)\n"
        "    published_exact.append({'tree_size': int(exact_root['tree_size']), 'timestamp': int(exact_root['timestamp'])})\n"
        "source = OperatorRootSource('http://127.0.0.1:8890', timeout=10)\n"
        "roots = []\n"
        "last_error = ''\n"
        f"for _attempt in range({OPERATOR_ROOT_WAIT_ATTEMPTS}):\n"
        "    try:\n"
        "        roots = verify_roots(source.roots(limit=1))\n"
        "        if roots:\n"
        "            break\n"
        "        last_error = 'no roots returned'\n"
        "    except Exception as exc:\n"
        "        last_error = f'{type(exc).__name__}: {exc}'\n"
        f"    time.sleep({OPERATOR_ROOT_WAIT_INTERVAL_SECONDS})\n"
        "if not roots:\n"
        "    raise SystemExit(f'operator root unavailable after restart: {last_error}')\n"
        "root = sorted(roots, key=lambda item: (int(item['timestamp']), int(item['tree_size'])))[-1]\n"
        "changed = writer.publish_root(root)\n"
        f"latest = json.loads(open('{mirror_dir}/latest.json', encoding='utf-8').read())\n"
        "print('BEGIN_IND_MIRROR_JSON')\n"
        "print(json.dumps({'changed': bool(changed), 'tree_size': int(root['tree_size']), 'timestamp': int(root['timestamp']), 'latest_tree_size': int(latest['tree_size']), 'latest_timestamp': int(latest['timestamp']), 'published_exact': published_exact}, sort_keys=True))\n"
        "print('END_IND_MIRROR_JSON')\n"
        "PY\n"
    )
    stdout, stderr = _run_ssh(node, command, timeout=180)
    start = stdout.find("BEGIN_IND_MIRROR_JSON")
    end = stdout.find("END_IND_MIRROR_JSON")
    if start < 0 or end < 0 or end <= start:
        raise RuntimeError("mirror publish output did not include JSON markers")
    body = stdout[start + len("BEGIN_IND_MIRROR_JSON") : end].strip()
    result = json.loads(body)
    result.update(
        {
            "node": node["name"],
            "backup_dir": f"$HOME/ind-code-backups/{backup_label}",
            "stderr": stderr.strip(),
        }
    )
    return result


def _new_display_ids(run_id):
    serial_base = int(time.time())
    run_offset = int(sha3_256(run_id.encode("ascii")).hexdigest()[:5], 16) % 1000
    serial = serial_base + run_offset
    return {
        "main": protocol_v3.canonical_display_id(1, serial),
        "negative": protocol_v3.canonical_display_id(2, serial + 1),
        "aux": protocol_v3.canonical_display_id(5, serial + 2),
    }


def _issue_record_for_bill(issue_record):
    return {
        key: issue_record[key]
        for key in (
            "label",
            "display_id",
            "value",
            "token_id",
            "owner_address",
            "sequence",
            "operator_log_id",
            "operator_public_key",
            "root_id",
            "proof_bundle_hash",
            "archive_segment_hash",
            "checkpoint_hash",
            "transfer_hash",
            "transfer_message_hash",
            "transfer_append",
            "checkpoint_append",
        )
    }


def _bill_info(issue_record):
    return {
        "label": issue_record["label"],
        "display_id": issue_record["display_id"],
        "token_id": issue_record["token_id"],
        "operator_public_key": issue_record["operator_public_key"],
        "operator_log_id": issue_record["operator_log_id"],
        "archive_segment": issue_record["archive_segment"],
        "archive_segment_hash": issue_record["archive_segment_hash"],
        "proof_bundle": issue_record["proof_bundle"],
        "proof_bundle_hash": issue_record["proof_bundle_hash"],
        "bill": issue_record["bill"],
        "checkpoint_hash": issue_record["checkpoint_hash"],
        "initial_owner": issue_record["owner_address"],
    }


def _write_memory_wallets(wallets):
    for wallet in wallets:
        runtime_json.write_decrypted_wallet(
            wallet[0],
            "\n".join([wallet[0], wallet[1], wallet[2]]) + "\n",
        )


def _clear_memory_wallets(wallets):
    for wallet in wallets:
        runtime_json.clear_decrypted_wallet(wallet[0])


def _receive_issued_bill(store, issue_record, recipient_wallet, peers, *, broadcast_evidence=True):
    archive_announcement = protocol_v3.create_archive_segment_announcement(
        issue_record["archive_segment"]
    )
    local_archive = store.ingest_message(archive_announcement)
    store.store_proof_bundle_v3(
        issue_record["proof_bundle"],
        trusted_operator_public_key=issue_record["operator_public_key"],
    )
    bill_hash = store.store_bill_v3(
        issue_record["bill"],
        proof_bundle=issue_record["proof_bundle"],
        status="settled",
        trusted_operator_public_key=issue_record["operator_public_key"],
    )
    state = protocol_v3.verify_bill(
        issue_record["bill"],
        proof_bundle=issue_record["proof_bundle"],
        proof_bundle_resolver=store.proof_bundle_resolver_v3,
        trusted_operator_public_key=issue_record["operator_public_key"],
        archive_segment_resolver=store.archive_segment_resolver_v3,
    )
    if state.owner_address != recipient_wallet[0]:
        raise RuntimeError(f"issued bill owner mismatch for {issue_record['display_id']}")
    proof_announcement = protocol_v3.create_proof_bundle_announcement(
        issue_record["proof_bundle"]
    )
    if broadcast_evidence:
        archive_broadcast = _broadcast_message(
            archive_announcement,
            peers,
            f"issue_{issue_record['label']}_archive_segment",
            timeout=12,
        )
        proof_broadcast = _broadcast_message(
            proof_announcement,
            peers,
            f"issue_{issue_record['label']}_proof_bundle",
            timeout=12,
        )
    else:
        archive_broadcast = {
            "label": f"issue_{issue_record['label']}_archive_segment",
            "message_type": archive_announcement.get("type", ""),
            "message_hash": _message_hash(archive_announcement),
            "skipped": True,
        }
        proof_broadcast = {
            "label": f"issue_{issue_record['label']}_proof_bundle",
            "message_type": proof_announcement.get("type", ""),
            "message_hash": _message_hash(proof_announcement),
            "skipped": True,
        }
    return {
        "display_id": issue_record["display_id"],
        "token_id": issue_record["token_id"],
        "recipient_address": recipient_wallet[0],
        "sequence": int(state.sequence),
        "owner_address": state.owner_address,
        "bill_hash": bill_hash,
        "local_archive_result": {
            "accepted": bool(local_archive.get("accepted")),
            "status": local_archive.get("status"),
        },
        "archive_message_hash": _message_hash(archive_announcement),
        "archive_broadcast": archive_broadcast,
        "proof_message_hash": _message_hash(proof_announcement),
        "proof_broadcast": proof_broadcast,
        "status_after_finalize": _status_snapshot(
            store,
            issue_record["token_id"],
            issue_record["display_id"],
            expected_owner=recipient_wallet[0],
        ),
    }


def _report_ok(report):
    if report.get("failures"):
        return False
    for item in report.get("issued_receives", []):
        if not item["local_archive_result"].get("accepted"):
            return False
        row = (item["status_after_finalize"].get("row") or {})
        if row.get("status") not in ACCEPTED_FINAL_STATUSES:
            return False
        if row.get("owner_address") != item.get("recipient_address"):
            return False
    if not report.get("hops"):
        return False
    for hop in report["hops"]:
        if hop["owner_after_spend"] != hop["recipient_address"]:
            return False
        if not hop["verify"].get("verified"):
            return False
        if not hop["transfer_broadcast"].get("all_ok"):
            return False
        row = (hop["status_after_finalize"].get("row") or {})
        if row.get("status") not in ACCEPTED_FINAL_STATUSES:
            return False
    negatives = report.get("negative_cases") or {}
    if not negatives.get("wrong_spend_with_non_owner_wallet", {}).get("rejected"):
        return False
    conflict = negatives.get("double_spend", {})
    if not conflict.get("conflict_local", {}).get("accepted"):
        return False
    if not conflict.get("conflict_broadcast", {}).get("all_ok"):
        return False
    return bool(negatives.get("stale_branch_clone_probe", {}).get("did_not_corrupt_latest_tip"))


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--peer", action="append", help="seed/node; repeatable and comma-separated")
    parser.add_argument(
        "--node-config",
        type=Path,
        default=os.environ.get(NODE_CONFIG_ENV),
        help=f"local VPS node config JSON; defaults to {NODE_CONFIG_ENV} or {DEFAULT_NODE_CONFIG}",
    )
    parser.add_argument("--hops", type=int, default=4)
    parser.add_argument("--run-id", default=time.strftime("%Y%m%d_%H%M%S"))
    parser.add_argument("--report-path", type=Path)
    parser.add_argument("--skip-iotb-issue", action="store_true")
    parser.add_argument(
        "--allow-synthetic-genesis-issue",
        action="store_true",
        help=(
            "allow remote issue probes without genesis_manifest_file and "
            "genesis_owner_private_key_file; unsafe outside local sandboxes"
        ),
    )
    parser.add_argument("--skip-issue-evidence-broadcast", action="store_true")
    parser.add_argument("--wait-final-status-seconds", type=int, default=65)
    return parser.parse_args(argv)


def _has_trusted_genesis_context(node):
    return bool(node.get("genesis_manifest_file") and node.get("genesis_owner_private_key_file"))


def main(argv=None):
    args = parse_args(argv)
    nodes = load_node_config(args.node_config)
    primary_node = nodes["primary"]
    iotb_node = nodes.get("iotb")
    if not args.skip_iotb_issue and iotb_node is None:
        raise RuntimeError("node config must include an iotb node unless --skip-iotb-issue is set")
    peers = testnet_peers.parse_peer_args(args.peer or DEFAULT_PEERS, default_to_config=False)
    if not peers:
        peers = list(DEFAULT_PEERS)
    report_path = args.report_path or (
        ROOT_DIR / "files" / "testnet" / f"{args.run_id}_v3_vps_public_wallet_e2e.json"
    )
    report_path.parent.mkdir(parents=True, exist_ok=True)
    store_path = report_path.with_suffix(".sqlite3")
    os.environ["IND_STORE_PATH"] = str(store_path)
    runtime_json.ensure_runtime_files()

    wallet_a = wallet_services.generate_wallet_v3(os.urandom(32))
    wallet_b = wallet_services.generate_wallet_v3(os.urandom(32))
    wallets = {"A": wallet_a, "B": wallet_b}
    display_ids = _new_display_ids(args.run_id)
    primary_specs = [
        {
            "label": "main",
            "display_id": display_ids["main"],
            "value": 1,
            "recipient_address": wallet_a[0],
        },
        {
            "label": "negative",
            "display_id": display_ids["negative"],
            "value": 2,
            "recipient_address": wallet_a[0],
        },
    ]
    iotb_specs = [
        {
            "label": "aux_iotb",
            "display_id": display_ids["aux"],
            "value": 5,
            "recipient_address": wallet_a[0],
        }
    ]
    store = INDLocalStore(db_path=store_path, require_transparency=False)
    report = {
        "type": "ind.v3_vps_public_wallet_e2e.v3",
        "run_id": args.run_id,
        "network": "testnet",
        "node_port": os.environ["IND_NODE_PORT"],
        "commands": [
            "$env:IND_NETWORK='testnet'; $env:IND_NODE_PORT='18888'; .\\.venv\\Scripts\\python.exe tools\\v3_testnet_smoke.py --run-pytest",
            "$env:IND_NETWORK='testnet'; $env:IND_NODE_PORT='18888'; .\\.venv\\Scripts\\python.exe tools\\v3_vps_public_wallet_e2e.py --node-config <local>",
        ],
        "peers": peers,
        "store_path": _safe_path(store_path),
        "wallets": {"A": _wallet_report(wallet_a), "B": _wallet_report(wallet_b)},
        "remote_issues": [],
        "mirror_publishes": [],
        "issued_bills": [],
        "issued_receives": [],
        "hops": [],
        "negative_cases": {},
        "skipped_remote_issues": [],
        "failures": [],
    }

    try:
        _progress("issuing primary-backed bills")
        primary_issue = _issue_remote(primary_node, args.run_id, primary_specs)
        _progress(f"primary issued {len(primary_issue['issued'])} bills")
        _progress("publishing primary latest root to static mirror")
        report["mirror_publishes"].append(
            _publish_latest_root_mirror(
                primary_node,
                args.run_id,
                [item["proof_bundle"]["signed_root"] for item in primary_issue["issued"]],
            )
        )
        report["remote_issues"].append(
            {
                "node": primary_issue["node"],
                "stderr": primary_issue["stderr"],
                "backup_dir": primary_issue["backup_dir"],
                "historical_claim_cleanup": primary_issue["historical_claim_cleanup"],
                "issued": [_issue_record_for_bill(item) for item in primary_issue["issued"]],
            }
        )
        issues = list(primary_issue["issued"])
        if not args.skip_iotb_issue and not args.allow_synthetic_genesis_issue and not _has_trusted_genesis_context(iotb_node):
            report["skipped_remote_issues"].append(
                {
                    "node": iotb_node["name"],
                    "reason": (
                        "trusted genesis context is not configured; synthetic "
                        "operator-issued genesis probes are disabled by default"
                    ),
                }
            )
            _progress("skipping iotb-backed issue: trusted genesis context is not configured")
        elif not args.skip_iotb_issue:
            _progress("issuing iotb-backed bills")
            iotb_issue = _issue_remote(iotb_node, args.run_id, iotb_specs)
            _progress(f"iotb issued {len(iotb_issue['issued'])} bills")
            _progress("publishing iotb latest root to static mirror")
            report["mirror_publishes"].append(
                _publish_latest_root_mirror(
                    iotb_node,
                    args.run_id,
                    [item["proof_bundle"]["signed_root"] for item in iotb_issue["issued"]],
                )
            )
            report["remote_issues"].append(
                {
                    "node": iotb_issue["node"],
                    "stderr": iotb_issue["stderr"],
                    "backup_dir": iotb_issue["backup_dir"],
                    "historical_claim_cleanup": iotb_issue["historical_claim_cleanup"],
                    "issued": [_issue_record_for_bill(item) for item in iotb_issue["issued"]],
                }
            )
            issues.extend(iotb_issue["issued"])
        report["issued_bills"] = [_issue_record_for_bill(item) for item in issues]

        issue_by_label = {item["label"]: item for item in issues}
        for item in issues:
            _progress(f"importing issued bill {item['label']} {item['display_id']}")
            report["issued_receives"].append(
                _receive_issued_bill(
                    store,
                    item,
                    wallet_a,
                    peers,
                    broadcast_evidence=not args.skip_issue_evidence_broadcast,
                )
            )

        main_bill = _bill_info(issue_by_label["main"])
        negative_bill = _bill_info(issue_by_label["negative"])
        report["initial_main_status"] = _status_snapshot(
            store,
            main_bill["token_id"],
            main_bill["display_id"],
            expected_owner=wallet_a[0],
        )

        path = [("A", "B"), ("B", "A"), ("A", "B"), ("B", "A")]
        _write_memory_wallets([wallet_a, wallet_b])
        for index, (sender_name, recipient_name) in enumerate(
            path[: max(0, args.hops)],
            start=1,
        ):
            _progress(f"hop {index}: {sender_name}->{recipient_name}")
            report["hops"].append(
                _run_hop(
                    store,
                    main_bill,
                    wallets,
                    sender_name,
                    recipient_name,
                    peers,
                    index,
                )
            )
        report["negative_cases"] = _run_negative_cases(
            store,
            negative_bill,
            wallets,
            peers,
            args.run_id,
        )
        _progress("negative cases completed")
    except Exception as exc:  # noqa: BLE001 - reports must preserve failures.
        report["failures"].append(
            {
                "error": str(exc),
                "type": type(exc).__name__,
                "traceback": traceback.format_exc(),
            }
        )
    finally:
        _clear_memory_wallets([wallet_a, wallet_b])

    refs = [item["display_id"] for item in report.get("issued_bills", [])]
    if report.get("hops"):
        refs.append(report["hops"][-1]["display_id"])
    if refs:
        _progress("querying public status after run")
        report["public_status_after_run"] = _query_public_status(peers, sorted(set(refs)))
    if args.wait_final_status_seconds > 0 and refs:
        _progress(f"waiting {args.wait_final_status_seconds}s before final public status")
        time.sleep(int(args.wait_final_status_seconds))
        _progress("querying public status after finality wait")
        report["public_status_after_finality_wait"] = _query_public_status(
            peers,
            sorted(set(refs)),
            timeout_seconds=30,
        )
    report["final_main_status"] = (
        _status_snapshot(
            store,
            report["hops"][-1]["token_id"],
            report["hops"][-1]["display_id"],
        )
        if report.get("hops")
        else {}
    )
    report["ok"] = _report_ok(report)
    report_path.write_text(
        json.dumps(report, sort_keys=True, indent=2, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, sort_keys=True, indent=2, ensure_ascii=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
