#!/usr/bin/env python3
"""Render or install a headless public-testnet seed/mirror/auditor service."""

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from ind.io_utils import atomic_write_text
from tools import render_operator_env, testnet_peers

DEFAULT_REPO_DIR = "/opt/international-dollar"
DEFAULT_RUNTIME_DIR = "/var/lib/ind-node"
DEFAULT_WEB_ROOT = "/var/www/ind-testnet-mirror"
DEFAULT_NODE_USER = "ind-node"
DEFAULT_NODE_UNIT = "ind-testnet-seed-node.service"
DEFAULT_NODE_ENV = "/etc/ind-testnet-node.env"
DEFAULT_OPERATOR_ENV = "/etc/ind-testnet-operator-set.env"
DEFAULT_START_PRE = "/usr/local/bin/ind-testnet-node-start-pre"
DEFAULT_VERIFY_SCRIPT = "/usr/local/bin/ind-testnet-seed-local-verify"
DEFAULT_NGINX_SITE = "/etc/nginx/sites-available/ind-testnet-mirror"
DEFAULT_NGINX_ENABLED = "/etc/nginx/sites-enabled/ind-testnet-mirror"
DEFAULT_NODE_PORT = 18888


@dataclass(frozen=True)
class GeneratedFile:
    path: str
    text: str
    mode: int = 0o644


@dataclass(frozen=True)
class MirrorTarget:
    name: str
    source_url: str
    public_mirror_urls: tuple[str, ...]
    target_subdir: str = ""

    @property
    def workdir_suffix(self):
        return f"/{self.target_subdir.strip('/')}" if self.target_subdir else ""


DEFAULT_MIRRORS = (
    MirrorTarget(
        name="primary",
        source_url="https://international-dollar.com/transparency",
        public_mirror_urls=(
            "https://international-dollar.com/transparency",
            "https://testnet-seed.internetofthebots.com/transparency",
        ),
    ),
    MirrorTarget(
        name="iotb",
        source_url="https://international-dollar.com/iotb-operator/transparency",
        public_mirror_urls=(
            "https://international-dollar.com/iotb-operator/transparency",
            "https://testnet-seed.international-dollar.com/iotb-operator/transparency",
        ),
        target_subdir="iotb-operator",
    ),
)


def mirror_targets_from_operator_set(operator_set_path):
    try:
        operator_set = render_operator_env.load_operator_set(operator_set_path)
    except Exception:
        return list(DEFAULT_MIRRORS)
    mirrors = []
    for operator in operator_set["operators"]:
        mirror_urls = tuple(operator.get("mirrors") or ())
        if not mirror_urls:
            continue
        name = str(operator["name"])
        target_subdir = "" if name == "primary" else name
        if name == "iotb":
            target_subdir = "iotb-operator"
        mirrors.append(
            MirrorTarget(
                name=name,
                source_url=mirror_urls[0],
                public_mirror_urls=mirror_urls,
                target_subdir=target_subdir,
            )
        )
    return mirrors or list(DEFAULT_MIRRORS)


def _dedupe(items):
    seen = set()
    result = []
    for item in items:
        value = str(item).strip()
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _host_key(value):
    value = str(value).strip().lower().strip("[]")
    if not value:
        return ""
    if ":" in value and value.count(":") == 1:
        value = value.rsplit(":", 1)[0]
    return value


def filter_self_peers(peers, public_hosts):
    self_hosts = {_host_key(host) for host in public_hosts if _host_key(host)}
    if not self_hosts:
        return _dedupe(peers)
    return [peer for peer in _dedupe(peers) if _host_key(peer) not in self_hosts]


def _env_line(key, value):
    return f"{key}={str(value)}\n"


def render_node_env(repo_dir, peers, node_port=DEFAULT_NODE_PORT):
    return "".join(
        [
            _env_line("IND_NETWORK", "testnet"),
            _env_line("IND_NODE_PORT", int(node_port)),
            _env_line("IND_NODE_CAPACITY_PROFILE", "operator"),
            _env_line("IND_IGNORE_RUNTIME_KILL_FLAG", "1"),
            _env_line("IND_PEER_PING_SERVERS", testnet_peers.peers_env_value(peers)),
            _env_line("PYTHONPATH", repo_dir),
            _env_line("PYTHONUNBUFFERED", "1"),
        ]
    )


def render_start_pre(runtime_dir, repo_dir, node_user=DEFAULT_NODE_USER):
    return f"""#!/bin/sh
set -eu
cd {runtime_dir}
export IND_NETWORK=testnet
export PYTHONPATH={repo_dir}
if [ "$(id -u)" = "0" ]; then
    install -d -m 750 -o {node_user} -g {node_user} {runtime_dir}
    chown -R {node_user}:{node_user} {runtime_dir}
    find {runtime_dir} -type d -exec chmod 750 {{}} +
    find {runtime_dir} -type f -exec chmod u+rw,go-rwx {{}} +
fi
{repo_dir}/.venv/bin/python - <<'PY'
from ind import runtime
runtime.ensure_runtime_files()
runtime.set_kill_node(False)
PY
if [ "$(id -u)" = "0" ]; then
    chown -R {node_user}:{node_user} {runtime_dir}
    find {runtime_dir} -type d -exec chmod 750 {{}} +
    find {runtime_dir} -type f -exec chmod u+rw,go-rwx {{}} +
fi
"""


def render_seed_service(args):
    return f"""[Unit]
Description=IND public testnet gossip seed node
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User={args.node_user}
Group={args.node_user}
WorkingDirectory={args.runtime_dir}
EnvironmentFile={args.node_env}
EnvironmentFile={args.operator_env}
ExecStartPre={args.start_pre}
ExecStart={args.repo_dir}/.venv/bin/python {args.repo_dir}/node_client.py
Restart=always
RestartSec=5
TimeoutStopSec=30
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths={args.runtime_dir}

[Install]
WantedBy=multi-user.target
"""


def render_mirror_service(args, mirror):
    workdir = args.web_root + mirror.workdir_suffix
    return f"""[Unit]
Description=Mirror IND testnet {mirror.name} transparency roots to this seed
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
User={args.node_user}
Group={args.node_user}
WorkingDirectory={args.runtime_dir}
Environment=PYTHONPATH={args.repo_dir}
ExecStart={args.repo_dir}/.venv/bin/python {args.repo_dir}/tools/publish_testnet_static_mirror.py --source-url {mirror.source_url} --keep-workdir {workdir} --local-only --allow-missing-archive
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths={args.web_root} {args.runtime_dir}
"""


def render_timer(description, on_boot_seconds, on_unit_active_seconds):
    return f"""[Unit]
Description={description}

[Timer]
OnBootSec={int(on_boot_seconds)}s
OnUnitActiveSec={int(on_unit_active_seconds)}s
AccuracySec=10s
Persistent=true

[Install]
WantedBy=timers.target
"""


def _mirror_static_paths(args, mirror):
    prefix = args.web_root + mirror.workdir_suffix + "/transparency"
    return prefix + "/latest.json", prefix + "/archive/manifest.json"


def _monitor_args(args, mirror, convergence_peers, mirror_names):
    static_root, archive_manifest = _mirror_static_paths(args, mirror)
    command = [
        f"{args.repo_dir}/.venv/bin/python",
        f"{args.repo_dir}/tools/testnet_monitor.py",
        "--json",
        "--retry-count",
        str(args.monitor_retry_count),
        "--retry-delay-seconds",
        str(args.monitor_retry_delay_seconds),
        "--status-file",
        f"{args.runtime_dir}/monitor_{mirror.name}.json",
        "--operator-root-url",
        mirror.source_url.rstrip("/") + "/latest.json",
        "--static-root",
        static_root,
        "--archive-manifest",
        archive_manifest,
    ]
    for url in mirror.public_mirror_urls:
        command.extend(["--mirror-root-url", url])
    for unit in [args.node_unit, *[f"ind-testnet-{name}-mirror.timer" for name in mirror_names]]:
        command.extend(["--systemd-unit", unit])
    for path in [args.runtime_dir, args.web_root]:
        command.extend(["--disk-path", path])
    for peer in convergence_peers:
        command.extend(["--convergence-peer", peer])
    for ref in args.canary_ref:
        command.extend(["--convergence-ref", ref])
    return command


def _systemd_word(value):
    value = str(value)
    if re.fullmatch(r"[A-Za-z0-9_@%+=:,./~?-]+", value):
        return value
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _systemd_exec(command):
    return " ".join(_systemd_word(item) for item in command)


def render_monitor_service(args, mirror, convergence_peers, mirror_names):
    return f"""[Unit]
Description=Monitor IND testnet {mirror.name} mirror on this seed
Wants=network-online.target
After=network-online.target ind-testnet-{mirror.name}-mirror.service

[Service]
Type=oneshot
WorkingDirectory={args.runtime_dir}
Environment=IND_NETWORK=testnet
Environment=PYTHONPATH={args.repo_dir}
ExecStart={_systemd_exec(_monitor_args(args, mirror, convergence_peers, mirror_names))}
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths={args.runtime_dir}
"""


def render_nginx_site(web_root):
    return f"""server {{
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    root {web_root};
    autoindex off;
    server_tokens off;

    location ^~ /operator-api/ {{
        return 404;
    }}

    location / {{
        try_files $uri =404;
    }}
}}
"""


def render_local_verify(args, mirrors=None):
    mirrors = mirrors or mirror_targets_from_operator_set(args.operator_set)
    mirror_checks = "".join(
        f"curl -fsS http://127.0.0.1{mirror.workdir_suffix}/transparency/latest.json >/dev/null\n"
        for mirror in mirrors
    ).rstrip()
    return f"""#!/bin/sh
set -eu
systemctl is-active --quiet {args.node_unit}
ss -ltn | grep -E ':{int(args.node_port)}[[:space:]]' >/dev/null
operator_api_status="$(curl -sS -o /dev/null -w '%{{http_code}}' http://127.0.0.1/operator-api/ || true)"
test "$operator_api_status" = "404"
{mirror_checks}
"""


def render_operator_env_file(operator_set):
    data = render_operator_env.load_operator_set(operator_set)
    env = render_operator_env.env_from_operator_set(data)
    return render_operator_env.render_env(env, "systemd-envfile")


def generated_files(args):
    peers = testnet_peers.parse_peer_args(args.peer)
    convergence_seed = args.convergence_peer or peers
    convergence_peers = filter_self_peers(convergence_seed, args.public_host)
    mirrors = mirror_targets_from_operator_set(args.operator_set)
    mirror_names = [mirror.name for mirror in mirrors]
    files = [
        GeneratedFile(
            args.start_pre,
            render_start_pre(args.runtime_dir, args.repo_dir, args.node_user),
            0o755,
        ),
        GeneratedFile(args.verify_script, render_local_verify(args, mirrors), 0o755),
        GeneratedFile(args.node_env, render_node_env(args.repo_dir, peers, args.node_port), 0o640),
        GeneratedFile(args.operator_env, render_operator_env_file(args.operator_set), 0o640),
        GeneratedFile(
            f"{args.systemd_dir}/{args.node_unit}",
            render_seed_service(args),
        ),
    ]
    for index, mirror in enumerate(mirrors):
        files.extend(
            [
                GeneratedFile(
                    f"{args.systemd_dir}/ind-testnet-{mirror.name}-mirror.service",
                    render_mirror_service(args, mirror),
                ),
                GeneratedFile(
                    f"{args.systemd_dir}/ind-testnet-{mirror.name}-mirror.timer",
                    render_timer(
                        f"Refresh IND testnet {mirror.name} transparency mirror",
                        args.mirror_boot_seconds + index * 5,
                        args.mirror_refresh_seconds,
                    ),
                ),
                GeneratedFile(
                    f"{args.systemd_dir}/ind-testnet-{mirror.name}-monitor.service",
                    render_monitor_service(args, mirror, convergence_peers, mirror_names),
                ),
                GeneratedFile(
                    f"{args.systemd_dir}/ind-testnet-{mirror.name}-monitor.timer",
                    render_timer(
                        f"Run IND testnet {mirror.name} mirror monitor",
                        args.monitor_boot_seconds + index * 5,
                        args.monitor_refresh_seconds,
                    ),
                ),
            ]
        )
    if not args.no_nginx:
        files.append(GeneratedFile(args.nginx_site, render_nginx_site(args.web_root)))
    return files


def _atomic_write(path, text, mode):
    path = Path(path)
    atomic_write_text(path, text)
    path.chmod(mode)


def _run(command):
    subprocess.run(command, check=True)


def install_generated_files(args, files):
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise PermissionError("--install must be run as root on the VPS")
    user_exists = subprocess.run(
        ["id", "-u", args.node_user],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if user_exists.returncode != 0:
        _run(
            [
                "useradd",
                "--system",
                "--home-dir",
                args.runtime_dir,
                "--shell",
                "/usr/sbin/nologin",
                args.node_user,
            ]
        )
    _run(["install", "-d", "-m", "750", "-o", args.node_user, "-g", args.node_user, args.runtime_dir])
    _run(["install", "-d", "-m", "755", "-o", args.node_user, "-g", args.node_user, args.web_root])
    mirrors = mirror_targets_from_operator_set(args.operator_set)
    for mirror in mirrors:
        _run(
            [
                "install",
                "-d",
                "-m",
                "755",
                "-o",
                args.node_user,
                "-g",
                args.node_user,
                args.web_root + mirror.workdir_suffix,
            ]
        )
    for item in files:
        _atomic_write(item.path, item.text, item.mode)
    if not args.no_nginx:
        enabled = Path(args.nginx_enabled)
        enabled.parent.mkdir(parents=True, exist_ok=True)
        default_site = enabled.parent / "default"
        if not args.keep_nginx_default and (default_site.exists() or default_site.is_symlink()):
            default_site.unlink()
        if enabled.exists() or enabled.is_symlink():
            enabled.unlink()
        enabled.symlink_to(args.nginx_site)
        _run(["nginx", "-t"])
        _run(["systemctl", "reload-or-restart", "nginx"])
    _run(["systemctl", "daemon-reload"])
    if not args.no_enable:
        units = [
            args.node_unit,
            *[f"ind-testnet-{mirror.name}-mirror.timer" for mirror in mirrors],
            *[f"ind-testnet-{mirror.name}-monitor.timer" for mirror in mirrors],
        ]
        _run(["systemctl", "enable", "--now", *units])
    return {"installed": [item.path for item in files], "enabled": not args.no_enable}


def render_all(files):
    chunks = []
    for item in files:
        chunks.append(f"# --- {item.path} mode={oct(item.mode)} ---\n{item.text}")
        if not item.text.endswith("\n"):
            chunks.append("\n")
    return "\n".join(chunks)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--install", action="store_true", help="write files and enable services")
    parser.add_argument("--no-enable", action="store_true", help="install files without enabling units")
    parser.add_argument("--repo-dir", default=DEFAULT_REPO_DIR)
    parser.add_argument("--runtime-dir", default=DEFAULT_RUNTIME_DIR)
    parser.add_argument("--web-root", default=DEFAULT_WEB_ROOT)
    parser.add_argument("--node-user", default=DEFAULT_NODE_USER)
    parser.add_argument("--node-unit", default=DEFAULT_NODE_UNIT)
    parser.add_argument("--node-port", type=int, default=DEFAULT_NODE_PORT)
    parser.add_argument("--node-env", default=DEFAULT_NODE_ENV)
    parser.add_argument("--operator-env", default=DEFAULT_OPERATOR_ENV)
    parser.add_argument("--operator-set", default=str(render_operator_env.DEFAULT_OPERATOR_SET))
    parser.add_argument("--start-pre", default=DEFAULT_START_PRE)
    parser.add_argument("--verify-script", default=DEFAULT_VERIFY_SCRIPT)
    parser.add_argument("--systemd-dir", default="/etc/systemd/system")
    parser.add_argument("--nginx-site", default=DEFAULT_NGINX_SITE)
    parser.add_argument("--nginx-enabled", default=DEFAULT_NGINX_ENABLED)
    parser.add_argument("--no-nginx", action="store_true")
    parser.add_argument("--keep-nginx-default", action="store_true")
    parser.add_argument("--peer", action="append", help="explicit peer; repeatable/comma-separated")
    parser.add_argument("--public-host", action="append", default=[], help="this VPS public IP/DNS")
    parser.add_argument(
        "--convergence-peer",
        action="append",
        help="peer for on-box monitor convergence; defaults to explicit/default peers",
    )
    parser.add_argument("--canary-ref", action="append", default=[])
    parser.add_argument("--mirror-boot-seconds", type=int, default=30)
    parser.add_argument("--mirror-refresh-seconds", type=int, default=60)
    parser.add_argument("--monitor-boot-seconds", type=int, default=90)
    parser.add_argument("--monitor-refresh-seconds", type=int, default=120)
    parser.add_argument("--monitor-retry-count", type=int, default=3)
    parser.add_argument("--monitor-retry-delay-seconds", type=float, default=20)
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    files = generated_files(args)
    if args.install:
        print(json.dumps(install_generated_files(args, files), sort_keys=True, indent=2))
    else:
        print(render_all(files), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
