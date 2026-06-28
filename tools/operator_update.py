#!/usr/bin/env python3
# Operator staged update rollout helper for signed IND update manifests.

import argparse
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from ind import auto_update, update_manifest
from ind.io_utils import atomic_write_json


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path, data):
    atomic_write_json(path, data)


def read_key_file(path, field):
    text = Path(path).read_text(encoding="utf-8").strip()
    if str(path).lower().endswith(".json"):
        return str(json.loads(text).get(field, "")).strip()
    return text


def safe_update_info(info):
    return {
        "available": bool(info.available),
        "update_type": info.update_type,
        "source": info.source,
        "status": info.status,
        "channel": info.channel,
        "release_id": info.release_id,
        "sequence": int(info.sequence),
        "dirty": bool(info.dirty),
        "error": info.error,
        "requires_restart": bool(info.requires_restart),
    }


def safe_install_result(result):
    return {
        "success": bool(result.success),
        "update_type": result.update_type,
        "release_id": result.release_id,
        "sequence": int(result.sequence),
        "changed_files": list(result.changed_files),
        "dependencies_updated": bool(result.dependencies_updated),
        "dependencies_skipped": bool(result.dependencies_skipped),
        "error": result.error,
    }


def run_command(command, timeout=120):
    process = subprocess.run(
        command,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    return {
        "command": command,
        "returncode": int(process.returncode),
        "stdout": (process.stdout or "").strip(),
        "stderr": (process.stderr or "").strip(),
        "ok": process.returncode == 0,
    }


def encrypted_backup(paths, output_path, passphrase_env):
    paths = [Path(path) for path in paths]
    if not paths:
        return None
    passphrase = os.environ.get(passphrase_env, "")
    if not passphrase:
        raise RuntimeError(f"{passphrase_env} must be set to create an encrypted operator backup")
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ind-operator-backup-") as temp_dir:
        tar_path = Path(temp_dir) / "operator-state.tar.gz"
        with tarfile.open(tar_path, "w:gz") as archive:
            for path in paths:
                if path.exists():
                    archive.add(path, arcname=path.name)
        command = [
            "openssl",
            "enc",
            "-aes-256-cbc",
            "-pbkdf2",
            "-salt",
            "-in",
            str(tar_path),
            "-out",
            str(output_path),
            "-pass",
            f"env:{passphrase_env}",
        ]
        result = run_command(command, timeout=300)
        if not result["ok"]:
            raise RuntimeError(result["stderr"] or result["stdout"] or "encrypted backup failed")
    return {"path": str(output_path), "created_at": int(time.time())}


def restart_units(units):
    results = []
    if not units:
        return results
    systemctl = shutil.which("systemctl")
    if not systemctl:
        raise RuntimeError("systemctl is not available")
    for unit in units:
        results.append(run_command([systemctl, "restart", unit], timeout=120))
        if not results[-1]["ok"]:
            raise RuntimeError(
                f"failed to restart {unit}: {results[-1]['stderr'] or results[-1]['stdout']}"
            )
    return results


def run_check_commands(commands):
    results = []
    for command in commands:
        result = run_command(command, timeout=300)
        results.append(result)
        if not result["ok"]:
            raise RuntimeError(f"check command failed: {' '.join(command)}")
    return results


def command_check(args):
    info = auto_update.check_for_updates(args.repo, manual=True)
    print(json.dumps(safe_update_info(info), sort_keys=True, indent=2))
    return 1 if info.error else 0


def command_install_canary(args):
    info = auto_update.check_for_updates(args.repo, manual=True)
    if info.error:
        raise RuntimeError(info.error)
    if not info.available:
        print(
            json.dumps(
                {"ok": True, "installed": False, "update": safe_update_info(info)},
                sort_keys=True,
                indent=2,
            )
        )
        return 0
    if info.channel != "operator-canary":
        raise RuntimeError(
            f"install-canary requires an operator-canary manifest, got {info.channel!r}"
        )
    backup = (
        encrypted_backup(args.backup_path, args.backup_output, args.backup_passphrase_env)
        if args.backup_path
        else None
    )
    result = auto_update.install_update(args.repo, info)
    if not result.success:
        raise RuntimeError(result.error or "canary install failed")
    restart_results = restart_units(args.restart_unit)
    check_results = run_check_commands(args.check_command)
    payload = {
        "ok": True,
        "installed": True,
        "backup": backup,
        "update": safe_update_info(info),
        "install": safe_install_result(result),
        "restarts": restart_results,
        "checks": check_results,
    }
    if args.report_file:
        write_json(args.report_file, payload)
    print(json.dumps(payload, sort_keys=True, indent=2))
    return 0


def command_promote(args):
    canary_manifest = read_json(args.canary_manifest)
    report = read_json(args.canary_report)
    report_hash = update_manifest.sha3_hex(update_manifest.canonical_bytes(report))
    promotion = update_manifest.make_operator_promotion(
        canary_manifest,
        report_hash,
        channel=args.channel,
        promoted_at=args.promoted_at,
    )
    signed = update_manifest.sign_operator_promotion(
        promotion,
        read_key_file(args.signing_private_key_file, "private_key"),
        read_key_file(args.signing_public_key_file, "public_key"),
    )
    if args.output:
        write_json(args.output, signed)
    print(json.dumps(signed, sort_keys=True, indent=2))
    return 0


def promotion_matches_update(promotion, manifest):
    if str(promotion.get("release_id", "")) != str(manifest.get("release_id", "")):
        raise RuntimeError("promotion release_id does not match install manifest")
    if int(promotion.get("sequence", -1)) != int(manifest.get("sequence", -2)):
        raise RuntimeError("promotion sequence does not match install manifest")
    promoted_hashes = list(promotion.get("artifact_hashes", []))
    manifest_hashes = [
        str(item.get("sha3_256", "")).lower() for item in manifest.get("artifacts", [])
    ]
    if promoted_hashes != manifest_hashes:
        raise RuntimeError("promotion artifact hashes do not match install manifest")
    return True


def command_install_promoted(args):
    promotion = read_json(args.promotion)
    canary_manifest = read_json(args.canary_manifest)
    trusted = os.environ.get("IND_UPDATE_SIGNING_KEYS", "")
    if args.trusted_signing_key:
        trusted = ",".join([trusted, *args.trusted_signing_key]).strip(",")
    update_manifest.verify_operator_promotion(promotion, trusted, canary_manifest)
    info = auto_update.check_for_updates(args.repo, manual=True)
    if info.error:
        raise RuntimeError(info.error)
    if not info.available:
        print(
            json.dumps(
                {"ok": True, "installed": False, "update": safe_update_info(info)},
                sort_keys=True,
                indent=2,
            )
        )
        return 0
    if info.channel != str(promotion.get("channel", "")):
        raise RuntimeError(
            f"promotion channel {promotion.get('channel')!r} does not match update channel {info.channel!r}"
        )
    promotion_matches_update(promotion, info.manifest or {})
    backup = (
        encrypted_backup(args.backup_path, args.backup_output, args.backup_passphrase_env)
        if args.backup_path
        else None
    )
    result = auto_update.install_update(args.repo, info)
    if not result.success:
        raise RuntimeError(result.error or "promoted install failed")
    restart_results = restart_units(args.restart_unit)
    check_results = run_check_commands(args.check_command)
    payload = {
        "ok": True,
        "installed": True,
        "backup": backup,
        "promotion": {
            "release_id": promotion.get("release_id", ""),
            "sequence": int(promotion.get("sequence", 0)),
            "channel": promotion.get("channel", ""),
        },
        "update": safe_update_info(info),
        "install": safe_install_result(result),
        "restarts": restart_results,
        "checks": check_results,
    }
    if args.report_file:
        write_json(args.report_file, payload)
    print(json.dumps(payload, sort_keys=True, indent=2))
    return 0


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Staged signed update rollout helper for IND operators"
    )
    parser.add_argument("--repo", default=str(ROOT_DIR), help="IND checkout/install root")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("check", help="check the configured signed update endpoint").set_defaults(
        func=command_check
    )

    canary = sub.add_parser(
        "install-canary", help="install an operator-canary release and run checks"
    )
    canary.add_argument("--backup-path", action="append", default=[])
    canary.add_argument("--backup-output", default="files/operator_update_backup.tar.gz.enc")
    canary.add_argument("--backup-passphrase-env", default="IND_OPERATOR_BACKUP_PASSPHRASE")
    canary.add_argument("--restart-unit", action="append", default=[])
    canary.add_argument("--check-command", nargs="+", action="append", default=[])
    canary.add_argument("--report-file", default="")
    canary.set_defaults(func=command_install_canary)

    promote = sub.add_parser("promote", help="sign a promotion for a canary release")
    promote.add_argument("--canary-manifest", required=True)
    promote.add_argument("--canary-report", required=True)
    promote.add_argument("--signing-private-key-file", required=True)
    promote.add_argument("--signing-public-key-file", required=True)
    promote.add_argument("--channel", default="operator-stable")
    promote.add_argument("--promoted-at", type=int)
    promote.add_argument("--output", default="")
    promote.set_defaults(func=command_promote)

    promoted = sub.add_parser(
        "install-promoted", help="install a release only after a signed promotion"
    )
    promoted.add_argument("--promotion", required=True)
    promoted.add_argument("--canary-manifest", required=True)
    promoted.add_argument("--trusted-signing-key", action="append", default=[])
    promoted.add_argument("--backup-path", action="append", default=[])
    promoted.add_argument("--backup-output", default="files/operator_update_backup.tar.gz.enc")
    promoted.add_argument("--backup-passphrase-env", default="IND_OPERATOR_BACKUP_PASSPHRASE")
    promoted.add_argument("--restart-unit", action="append", default=[])
    promoted.add_argument("--check-command", nargs="+", action="append", default=[])
    promoted.add_argument("--report-file", default="")
    promoted.set_defaults(func=command_install_promoted)
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    try:
        return args.func(args)
    except Exception as exc:  # noqa: BLE001 - operator CLI should return clean JSON.
        print(
            json.dumps({"ok": False, "error": str(exc)}, sort_keys=True, indent=2), file=sys.stderr
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
