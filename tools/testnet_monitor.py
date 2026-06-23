#!/usr/bin/env python3
# Write a machine-readable health snapshot for the public IND testnet node.

import argparse
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))


DEFAULT_STATUS_FILE = os.environ.get(
    "IND_TESTNET_MONITOR_STATUS_FILE", "files/testnet/monitor_status.json"
)
DEFAULT_OPERATOR_ROOT_URL = "http://127.0.0.1:8890/v3/root"
DEFAULT_STATIC_ROOT = os.environ.get("IND_TESTNET_MONITOR_STATIC_ROOT", "")
DEFAULT_ARCHIVE_MANIFEST = os.environ.get("IND_TESTNET_MONITOR_ARCHIVE_MANIFEST", "")
DEFAULT_PEER_DIR = os.environ.get("IND_TESTNET_MONITOR_PEER_DIR", "ip_folder")
DEFAULT_CERT_FILE = os.environ.get("IND_TESTNET_MONITOR_CERT_FILE", "")
USER_AGENT = "International-Dollar-testnet-monitor/1"

DEFAULT_MIRROR_ROOT_URLS = [
    item.strip()
    for item in os.environ.get("IND_TESTNET_MONITOR_MIRROR_ROOT_URLS", "").split(",")
    if item.strip()
]

DEFAULT_SYSTEMD_UNITS = [
    item.strip()
    for item in os.environ.get("IND_TESTNET_MONITOR_SYSTEMD_UNITS", "").split(",")
    if item.strip()
]

DEFAULT_DISK_PATHS = [
    item.strip()
    for item in os.environ.get("IND_TESTNET_MONITOR_DISK_PATHS", ".").split(os.pathsep)
    if item.strip()
]


def run_command(args, timeout=10):
    try:
        process = subprocess.run(
            args,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        return {
            "returncode": int(process.returncode),
            "stdout": process.stdout.strip(),
            "stderr": process.stderr.strip(),
        }
    except FileNotFoundError:
        return {"returncode": 127, "stdout": "", "stderr": f"{args[0]} not found"}
    except subprocess.TimeoutExpired:
        return {"returncode": 124, "stdout": "", "stderr": "command timed out"}


def atomic_write_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(
        json.dumps(data, sort_keys=True, indent=2, ensure_ascii=True) + "\n", encoding="utf-8"
    )
    os.replace(tmp, path)


def load_json_file(path):
    if not path:
        return None, "path is not configured"
    path = Path(path)
    if not path.exists():
        return None, f"{path} does not exist"
    if path.is_dir():
        return None, f"{path} is a directory"
    try:
        return json.loads(path.read_text(encoding="utf-8")), ""
    except json.JSONDecodeError as exc:
        return None, f"{path} is not valid JSON: {exc}"


def fetch_json(url, timeout=10):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def add_issue(report, level, code, message):
    report["issues"].append({"level": level, "code": code, "message": message})


def normalize_root_url(url):
    url = str(url).strip()
    if url.endswith(".json"):
        return url
    return url.rstrip("/") + "/latest.json"


def root_status(root, now, freshness_warn_seconds):
    timestamp = int(root.get("timestamp", 0))
    return {
        "ok": now - timestamp <= freshness_warn_seconds,
        "tree_size": int(root.get("tree_size", 0)),
        "timestamp": timestamp,
        "age_seconds": now - timestamp,
        "root_hash": root.get("root_hash", ""),
        "log_id": root.get("log_id", ""),
    }


def service_status(unit):
    active = run_command(["systemctl", "is-active", unit])
    enabled = run_command(["systemctl", "is-enabled", unit])
    active_state = active["stdout"] or active["stderr"] or "unknown"
    enabled_state = enabled["stdout"] or enabled["stderr"] or "unknown"
    return {
        "active_state": active_state,
        "enabled_state": enabled_state,
        "ok": active["returncode"] == 0 and active_state == "active",
    }


def collect_systemd(report, units):
    services = {}
    for unit in units:
        status = service_status(unit)
        services[unit] = status
        if not status["ok"]:
            add_issue(
                report, "error", "systemd_unit_inactive", f"{unit} is {status['active_state']}"
            )
    report["systemd_units"] = services


def collect_disk(report, paths, warn_percent):
    disks = {}
    for raw_path in paths:
        path = Path(raw_path)
        if not path.exists():
            disks[raw_path] = {"ok": False, "error": "path does not exist"}
            add_issue(report, "warning", "disk_path_missing", f"{raw_path} does not exist")
            continue
        usage = shutil.disk_usage(str(path))
        used_percent = round(((usage.total - usage.free) / usage.total) * 100, 2)
        disks[raw_path] = {
            "ok": used_percent < warn_percent,
            "total_bytes": usage.total,
            "used_bytes": usage.total - usage.free,
            "free_bytes": usage.free,
            "used_percent": used_percent,
        }
        if used_percent >= warn_percent:
            add_issue(report, "warning", "disk_usage_high", f"{raw_path} is {used_percent}% full")
    report["disk"] = disks


def collect_mirror_roots(
    report,
    transparency,
    operator_root,
    mirror_root_urls,
    freshness_warn_seconds,
):
    if not mirror_root_urls:
        return
    now = int(report["timestamp"])
    operator_tree_size = int(operator_root.get("tree_size", 0)) if operator_root else None
    operator_root_hash = str(operator_root.get("root_hash", "")) if operator_root else ""
    mirrors = []
    for raw_url in mirror_root_urls:
        url = normalize_root_url(raw_url)
        try:
            root = fetch_json(url)
            status = root_status(root, now, freshness_warn_seconds)
            status["url"] = url
            if not status["ok"]:
                add_issue(
                    report,
                    "error",
                    "mirror_root_stale",
                    f"{url} root is {status['age_seconds']}s old",
                )
            if operator_tree_size is not None:
                if status["tree_size"] < operator_tree_size:
                    status["ok"] = False
                    add_issue(
                        report,
                        "error",
                        "mirror_root_behind_operator",
                        f"{url} tree_size {status['tree_size']} is behind operator tree_size {operator_tree_size}",
                    )
                elif status["tree_size"] == operator_tree_size and (
                    operator_root_hash and status["root_hash"] != operator_root_hash
                ):
                    status["ok"] = False
                    add_issue(
                        report,
                        "error",
                        "mirror_root_hash_mismatch",
                        f"{url} root hash does not match the operator at tree_size {operator_tree_size}",
                    )
            mirrors.append(status)
        except Exception as exc:  # noqa: BLE001 - this is a monitor probe.
            mirrors.append({"ok": False, "url": url, "error": str(exc)})
            add_issue(report, "error", "mirror_root_unavailable", f"{url} unavailable: {exc}")
    transparency["mirror_roots"] = mirrors


def collect_transparency(
    report,
    operator_root_url,
    static_root_path,
    archive_manifest_path,
    freshness_warn_seconds,
    mirror_root_urls=(),
):
    transparency = {}
    now = int(report["timestamp"])
    operator_root = None

    try:
        root = fetch_json(operator_root_url)
        operator_root = root
        transparency["operator_root"] = root_status(root, now, freshness_warn_seconds)
        if not transparency["operator_root"]["ok"]:
            add_issue(
                report,
                "warning",
                "operator_root_stale",
                f"operator root is {transparency['operator_root']['age_seconds']}s old",
            )
    except Exception as exc:  # noqa: BLE001 - this is an operator health probe.
        transparency["operator_root"] = {"ok": False, "error": str(exc)}
        add_issue(report, "error", "operator_root_unavailable", f"operator root unavailable: {exc}")

    collect_mirror_roots(
        report,
        transparency,
        operator_root,
        mirror_root_urls,
        freshness_warn_seconds,
    )

    static_root, static_error = load_json_file(static_root_path)
    if static_root:
        transparency["static_root"] = root_status(static_root, now, freshness_warn_seconds)
        if not transparency["static_root"]["ok"]:
            add_issue(
                report,
                "warning",
                "static_root_stale",
                f"static root is {transparency['static_root']['age_seconds']}s old",
            )
    else:
        transparency["static_root"] = {"ok": False, "error": static_error}
        add_issue(report, "error", "static_root_missing", static_error)

    archive, archive_error = load_json_file(archive_manifest_path)
    if archive:
        archived_count = int(archive.get("archived_entry_count", 0))
        signed_tree_size = int(archive.get("signed_root_tree_size", 0))
        transparency["hash_log_archive"] = {
            "ok": archived_count == signed_tree_size,
            "archive_id": archive.get("archive_id", ""),
            "archived_entry_count": archived_count,
            "signed_root_tree_size": signed_tree_size,
            "signed_root_timestamp": int(archive.get("signed_root_timestamp", 0)),
            "manifest_timestamp": int(archive.get("manifest_timestamp", 0)),
            "segment_count": len(archive.get("segments", [])),
        }
        latest_size = max(
            int(transparency.get("operator_root", {}).get("tree_size", 0)),
            int(transparency.get("static_root", {}).get("tree_size", 0)),
        )
        if archived_count != signed_tree_size:
            add_issue(
                report,
                "error",
                "archive_manifest_inconsistent",
                "archive entry count does not match signed root",
            )
        elif latest_size and archived_count < latest_size:
            add_issue(
                report,
                "warning",
                "archive_behind_latest_root",
                f"archive covers {archived_count}/{latest_size} entries",
            )
    else:
        transparency["hash_log_archive"] = {"ok": False, "error": archive_error}
        add_issue(report, "error", "archive_manifest_missing", archive_error)

    report["transparency"] = transparency


def collect_peers(report, peer_dir):
    path = Path(peer_dir)
    if not path.exists():
        report["peers"] = {
            "ok": False,
            "directory": str(path),
            "count": 0,
            "error": "directory does not exist",
        }
        add_issue(report, "warning", "peer_directory_missing", f"{path} does not exist")
        return
    peers = set()
    for file_path in path.rglob("*"):
        if not file_path.is_file():
            continue
        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for match in re.finditer(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b", text):
            peers.add(match.group(0))
    report["peers"] = {"ok": True, "directory": str(path), "count": len(peers)}


def collect_cert(report, cert_file, warn_days):
    if not cert_file:
        report["certificate"] = {
            "ok": True,
            "skipped": True,
            "reason": "certificate file is not configured",
        }
        return
    cert_path = Path(cert_file)
    if not cert_path.exists():
        report["certificate"] = {
            "ok": False,
            "path": str(cert_path),
            "error": "certificate file does not exist",
        }
        add_issue(report, "error", "certificate_missing", f"{cert_path} does not exist")
        return
    result = run_command(["openssl", "x509", "-enddate", "-noout", "-in", str(cert_path)])
    if result["returncode"] != 0:
        report["certificate"] = {
            "ok": False,
            "path": str(cert_path),
            "error": result["stderr"] or result["stdout"],
        }
        add_issue(report, "error", "certificate_unreadable", "certificate expiry could not be read")
        return
    raw = result["stdout"].removeprefix("notAfter=").strip()
    try:
        expires = dt.datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.UTC)
        now = dt.datetime.now(dt.UTC)
        seconds_remaining = int((expires - now).total_seconds())
    except ValueError:
        report["certificate"] = {
            "ok": False,
            "path": str(cert_path),
            "not_after": raw,
            "error": "unparsed expiry",
        }
        add_issue(
            report,
            "warning",
            "certificate_expiry_unparsed",
            "certificate expiry could not be parsed",
        )
        return
    warn_seconds = int(warn_days) * 24 * 60 * 60
    report["certificate"] = {
        "ok": seconds_remaining > warn_seconds,
        "path": str(cert_path),
        "not_after": raw,
        "seconds_remaining": seconds_remaining,
        "days_remaining": round(seconds_remaining / 86400, 2),
    }
    if seconds_remaining <= warn_seconds:
        add_issue(
            report,
            "warning",
            "certificate_expiring",
            f"certificate expires in {round(seconds_remaining / 86400, 2)} days",
        )


def parse_fail2ban_status(text):
    parsed = {}
    for label in ("Currently failed", "Total failed", "Currently banned", "Total banned"):
        match = re.search(rf"{re.escape(label)}:\s*(\d+)", text)
        if match:
            parsed[label.lower().replace(" ", "_")] = int(match.group(1))
    return parsed


def collect_fail2ban(report):
    status = run_command(["fail2ban-client", "status", "sshd"])
    if status["returncode"] != 0:
        report["fail2ban"] = {"ok": False, "error": status["stderr"] or status["stdout"]}
        add_issue(
            report, "warning", "fail2ban_status_unavailable", "fail2ban sshd status unavailable"
        )
        return
    parsed = parse_fail2ban_status(status["stdout"])
    report["fail2ban"] = {"ok": True, **parsed}


def collect_nginx(report):
    status = run_command(["nginx", "-t"])
    report["nginx_config"] = {"ok": status["returncode"] == 0}
    if status["returncode"] != 0:
        report["nginx_config"]["error"] = status["stderr"] or status["stdout"]
        add_issue(report, "error", "nginx_config_invalid", "nginx -t failed")


def collect_convergence(report, peers, refs, ref_files, finality_buffer_seconds):
    if not refs and not ref_files:
        return
    from tools import testnet_convergence_monitor

    all_refs = list(refs or [])
    for path in ref_files or []:
        all_refs.extend(testnet_convergence_monitor.refs_from_file(path))
    convergence = testnet_convergence_monitor.build_report(
        peers,
        all_refs,
        finality_buffer_seconds=finality_buffer_seconds,
        queried_at=int(report["timestamp"]),
    )
    report["convergence"] = convergence
    if not convergence["ok"]:
        add_issue(
            report,
            "error",
            "seed_convergence_failed",
            "seed bill status differs across configured peers",
        )


def build_report(args):
    report = {
        "type": "ind.testnet_monitor_status.v3",
        "version": 1,
        "timestamp": int(time.time()),
        "ok": True,
        "issues": [],
    }
    collect_systemd(report, args.systemd_unit)
    collect_disk(report, args.disk_path, args.disk_warn_percent)
    collect_transparency(
        report,
        args.operator_root_url,
        args.static_root,
        args.archive_manifest,
        args.root_freshness_warn_seconds,
        args.mirror_root_url,
    )
    collect_peers(report, args.peer_dir)
    collect_cert(report, args.cert_file, args.cert_warn_days)
    collect_fail2ban(report)
    collect_nginx(report)
    collect_convergence(
        report,
        args.convergence_peer,
        args.convergence_ref,
        args.convergence_ref_file,
        args.convergence_finality_buffer_seconds,
    )
    report["ok"] = not any(issue["level"] == "error" for issue in report["issues"])
    return report


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Write a JSON health snapshot for the public IND testnet node"
    )
    parser.add_argument("--status-file", default=DEFAULT_STATUS_FILE)
    parser.add_argument("--operator-root-url", default=DEFAULT_OPERATOR_ROOT_URL)
    parser.add_argument("--static-root", default=DEFAULT_STATIC_ROOT)
    parser.add_argument(
        "--mirror-root-url",
        action="append",
        default=list(DEFAULT_MIRROR_ROOT_URLS),
        help="public root mirror base URL or latest.json URL required for strict verification",
    )
    parser.add_argument("--archive-manifest", default=DEFAULT_ARCHIVE_MANIFEST)
    parser.add_argument("--peer-dir", default=DEFAULT_PEER_DIR)
    parser.add_argument("--cert-file", default=DEFAULT_CERT_FILE)
    parser.add_argument("--systemd-unit", action="append", default=list(DEFAULT_SYSTEMD_UNITS))
    parser.add_argument("--disk-path", action="append", default=list(DEFAULT_DISK_PATHS))
    parser.add_argument("--disk-warn-percent", type=float, default=85.0)
    parser.add_argument("--cert-warn-days", type=int, default=21)
    parser.add_argument("--root-freshness-warn-seconds", type=int, default=180)
    parser.add_argument(
        "--convergence-peer", action="append", help="seed/node for convergence checks"
    )
    parser.add_argument(
        "--convergence-ref", action="append", default=[], help="canary bill display ID or bill ID"
    )
    parser.add_argument(
        "--convergence-ref-file",
        action="append",
        default=[],
        help="JSON/text file containing canary refs",
    )
    parser.add_argument("--convergence-finality-buffer-seconds", type=int, default=60)
    parser.add_argument(
        "--retry-count",
        type=int,
        default=1,
        help="retry a failing monitor snapshot this many times before writing the final status",
    )
    parser.add_argument(
        "--retry-delay-seconds",
        type=float,
        default=20,
        help="delay between retry attempts when the monitor snapshot is not ok",
    )
    parser.add_argument("--json", action="store_true", help="print the status JSON to stdout")
    parser.add_argument(
        "--strict", action="store_true", help="exit non-zero when an error-level issue is present"
    )
    return parser.parse_args(argv)


def build_report_with_retries(args):
    retry_count = max(1, int(args.retry_count))
    retry_delay = max(0.0, float(args.retry_delay_seconds))
    report = None
    for attempt in range(1, retry_count + 1):
        report = build_report(args)
        report["attempt"] = attempt
        report["max_attempts"] = retry_count
        if report["ok"] or attempt == retry_count:
            return report
        if retry_delay:
            time.sleep(retry_delay)
    return report


def main(argv=None):
    args = parse_args(argv)
    report = build_report_with_retries(args)
    atomic_write_json(args.status_file, report)
    if args.json:
        print(json.dumps(report, sort_keys=True, indent=2, ensure_ascii=True))
    if args.strict and not report["ok"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
