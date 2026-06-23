#!/usr/bin/env python3
"""Live public-testnet probe for strict multi-operator append fanout."""

import argparse
import json
import os
import sys
import time
import traceback
from hashlib import sha3_256
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from tools import render_operator_env


def _apply_operator_env(operator_set_path, observed_roots_path=None):
    operator_set = render_operator_env.load_operator_set(operator_set_path)
    for key, value in render_operator_env.env_from_operator_set(operator_set).items():
        os.environ[key] = str(value)
    os.environ["IND_NETWORK"] = "testnet"
    os.environ["IND_NODE_PORT"] = "18888"
    if observed_roots_path:
        os.environ["IND_LOG_OBSERVED_ROOTS_DB"] = str(observed_roots_path)
    return operator_set


def _operator_by_log_id(operator_set, log_client):
    result = {}
    for item in operator_set["operators"]:
        log_id = log_client.log_id_from_public_key(item["public_key"])
        result[log_id] = item
    return result


def _wallet_lines(wallet):
    return [wallet[0], wallet[1], wallet[2]]


def _new_display_id(run_id):
    run_offset = int(sha3_256(str(run_id).encode("ascii")).hexdigest()[:5], 16) % 1000
    return f"1x{int(time.time()) + run_offset}"


def _response_ok(result, transfer_hash, spend_key):
    response = result.get("response") if isinstance(result, dict) else None
    if not result.get("accepted") or not isinstance(response, dict):
        return False
    return (
        str(response.get("entry_hash", "")).lower() == transfer_hash
        and str(response.get("spend_key", "")) == spend_key
        and int(response.get("tree_size", 0)) >= int(response.get("leaf_index", -1)) + 1
    )


def _verify_operator_inclusion(log_client, operator, transfer_hash, minimum_tree_size, timeout):
    client = log_client.HTTPTransparencyOperator(
        operator["url"],
        timeout=12,
        operator_public_key=operator["public_key"],
    )
    deadline = time.monotonic() + max(1, int(timeout))
    last_error = ""
    while True:
        try:
            root = client.latest_root()
            log_client.verify_signed_root(root, operator_public_key=operator["public_key"])
            if int(root["tree_size"]) < int(minimum_tree_size):
                last_error = (
                    f"root tree_size {int(root['tree_size'])} is below append "
                    f"tree_size {int(minimum_tree_size)}"
                )
            else:
                proof = client.inclusion_proof(transfer_hash, int(root["tree_size"]))
                log_client.verify_inclusion_proof(
                    transfer_hash,
                    proof,
                    root,
                    operator_public_key=operator["public_key"],
                )
                return {
                    "ok": True,
                    "tree_size": int(root["tree_size"]),
                    "timestamp": int(root["timestamp"]),
                    "root_hash": root["root_hash"],
                }
        except Exception as exc:  # noqa: BLE001 - surfaced in JSON for operators.
            last_error = f"{type(exc).__name__}: {exc}"
        if time.monotonic() >= deadline:
            return {"ok": False, "error": last_error}
        time.sleep(2)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--operator-set", type=Path, default=render_operator_env.DEFAULT_OPERATOR_SET)
    parser.add_argument(
        "--node-config",
        type=Path,
        help="local VPS node config JSON; defaults to v3_vps_public_wallet_e2e.local.json",
    )
    parser.add_argument("--run-id", default=time.strftime("fanout_%Y%m%d_%H%M%S"))
    parser.add_argument("--report-path", type=Path)
    parser.add_argument("--peer", action="append", help="seed/node; repeatable and comma-separated")
    parser.add_argument("--wait-root-seconds", type=int, default=95)
    parser.add_argument(
        "--refresh-iotb-primary-mirror",
        action="store_true",
        help="best-effort refresh of the IOTB-hosted Primary mirror after issuing a bill",
    )
    parser.add_argument("--json", action="store_true")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    report_path = args.report_path or (
        ROOT_DIR / "files" / "testnet" / f"{args.run_id}_v3_operator_fanout_probe.json"
    )
    report_path.parent.mkdir(parents=True, exist_ok=True)
    observed_roots_path = report_path.with_suffix(".observed_roots.sqlite3")
    operator_set = _apply_operator_env(args.operator_set, observed_roots_path)

    from ind import protocol_v3
    from ind import runtime as runtime_json
    from ind import transparency_client as log_client
    from ind import wallet_services
    from ind.store import INDLocalStore
    from tools import testnet_peers
    from tools.v3_public_wallet_e2e import _broadcast_message, _query_public_status
    from tools.v3_vps_public_wallet_e2e import (
        _issue_remote,
        _publish_latest_root_mirror,
        _run_ssh,
        _safe_path,
        load_node_config,
    )

    nodes = load_node_config(args.node_config)
    primary_node = nodes["primary"]
    peers = testnet_peers.parse_peer_args(args.peer, default_to_config=False)
    if not peers:
        peers = ["167.233.115.216", "91.99.175.174", "51.83.199.25", "108.61.23.82"]
    store_path = report_path.with_suffix(".sqlite3")
    os.environ["IND_STORE_PATH"] = str(store_path)
    runtime_json.ensure_runtime_files()

    wallet_a = wallet_services.generate_wallet_v3(os.urandom(32))
    wallet_b = wallet_services.generate_wallet_v3(os.urandom(32))
    display_id = _new_display_id(args.run_id)
    report = {
        "type": "ind.v3_operator_fanout_probe.v1",
        "run_id": args.run_id,
        "network": "testnet",
        "operator_count": len(operator_set["operators"]),
        "operator_names": [item["name"] for item in operator_set["operators"]],
        "peers": peers,
        "store_path": _safe_path(store_path),
        "observed_roots_path": _safe_path(observed_roots_path),
        "wallets": {"sender": {"address": wallet_a[0]}, "recipient": {"address": wallet_b[0]}},
        "issued": {},
        "mirror_publish": {},
        "mirror_refresh": {},
        "append_results": [],
        "inclusion_checks": [],
        "broadcast": {},
        "public_status": {},
        "failures": [],
        "ok": False,
    }

    try:
        store = INDLocalStore(db_path=store_path, require_transparency=False)
        issue = _issue_remote(
            primary_node,
            args.run_id,
            [
                {
                    "label": "fanout",
                    "display_id": display_id,
                    "value": 1,
                    "recipient_address": wallet_a[0],
                }
            ],
        )
        issued = issue["issued"][0]
        report["issued"] = {
            "display_id": issued["display_id"],
            "token_id": issued["token_id"],
            "operator_log_id": issued["operator_log_id"],
            "transfer_append": issued["transfer_append"],
            "checkpoint_append": issued["checkpoint_append"],
            "backup_dir": issue["backup_dir"],
        }
        report["mirror_publish"] = _publish_latest_root_mirror(
            primary_node,
            args.run_id,
            [issued["proof_bundle"]["signed_root"]],
        )
        if args.refresh_iotb_primary_mirror and "iotb" in nodes:
            try:
                _run_ssh(
                    nodes["iotb"],
                    "sudo -n systemctl start ind-transparency-mirror.service || true",
                    timeout=45,
                )
                report["mirror_refresh"] = {"node": "iotb", "ok": True}
            except Exception as exc:  # noqa: BLE001 - best-effort mirror refresh.
                report["mirror_refresh"] = {"node": "iotb", "ok": False, "error": str(exc)}

        store.store_archive_segment_v3(issued["archive_segment"])
        store.store_proof_bundle_v3(
            issued["proof_bundle"],
            trusted_operator_public_key=issued["operator_public_key"],
        )
        store.store_bill_v3(
            issued["bill"],
            proof_bundle=issued["proof_bundle"],
            status="settled",
            trusted_operator_public_key=issued["operator_public_key"],
        )

        spend_state = wallet_services.spend_wallet_bill_v3(
            _wallet_lines(wallet_a),
            issued["bill"],
            wallet_b[0],
            store=store,
            proof_bundle=issued["proof_bundle"],
            trusted_operator_public_key=issued["operator_public_key"],
            timestamp=int(time.time()),
        )
        if spend_state is None:
            raise RuntimeError("wallet spend returned None")
        transferred_bill = store.get_bill_v3_by_token_id(issued["token_id"])
        announcement = protocol_v3.create_transfer_announcement(
            transferred_bill,
            proof_bundle=issued["proof_bundle"],
            archive_segments=[issued["archive_segment"]],
        )
        transfer = transferred_bill["recent_transfers"][-1]
        transfer_hash = protocol_v3.transfer_hash(transfer)
        spend_key = protocol_v3.spend_key_for_transfer(transfer)
        report["transfer"] = {
            "transfer_hash": transfer_hash,
            "spend_key": spend_key,
            "sequence": int(transfer["sequence"]),
            "recipient_address": wallet_b[0],
        }

        submitter = log_client.submitter_from_environment()
        if submitter is None or not hasattr(submitter, "submit_transfer_announcement_to_all"):
            raise RuntimeError("multi-operator submitter is not configured")
        expected_count = len(operator_set["operators"])
        results = submitter.submit_transfer_announcement_to_all(announcement)
        report["append_results"] = results
        accepted = [item for item in results if _response_ok(item, transfer_hash, spend_key)]
        if len(accepted) != expected_count:
            raise RuntimeError(
                f"expected {expected_count} operator append acceptances, got {len(accepted)}"
            )

        by_log_id = _operator_by_log_id(operator_set, log_client)
        inclusion_checks = []
        for result in accepted:
            log_id = result["log_id"]
            operator = by_log_id.get(log_id)
            if operator is None:
                inclusion_checks.append(
                    {"log_id": log_id, "ok": False, "error": "operator not in operator set"}
                )
                continue
            check = _verify_operator_inclusion(
                log_client,
                operator,
                transfer_hash,
                int(result["response"]["tree_size"]),
                args.wait_root_seconds,
            )
            check.update({"operator": operator["name"], "log_id": log_id})
            inclusion_checks.append(check)
        report["inclusion_checks"] = inclusion_checks
        if not all(item.get("ok") for item in inclusion_checks):
            raise RuntimeError("one or more operator inclusion checks failed")

        report["broadcast"] = _broadcast_message(
            announcement,
            peers,
            "operator_fanout_transfer",
            timeout=60,
            retry_limit=4,
        )
        report["public_status"] = _query_public_status(
            peers,
            [issued["display_id"], issued["token_id"]],
            timeout_seconds=30,
        )
        report["ok"] = bool(report["broadcast"].get("all_ok")) and all(
            item.get("ok") for item in inclusion_checks
        )
    except Exception as exc:  # noqa: BLE001 - report probes must preserve failures.
        report["failures"].append(
            {
                "error": str(exc),
                "type": type(exc).__name__,
                "traceback": traceback.format_exc(),
            }
        )
    finally:
        runtime_json.clear_decrypted_wallet(wallet_a[0])
        runtime_json.clear_decrypted_wallet(wallet_b[0])

    report_path.write_text(
        json.dumps(report, sort_keys=True, indent=2, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, sort_keys=True, indent=2, ensure_ascii=True))
    return 0 if report.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
