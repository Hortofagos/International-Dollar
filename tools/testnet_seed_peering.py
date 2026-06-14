#!/usr/bin/env python3
"""Render or install durable testnet seed peering systemd drop-ins."""

import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from tools import testnet_peers


DEFAULT_UNIT = "ind-testnet-seed-node.service"


def render_dropin(peers):
    value = testnet_peers.peers_env_value(peers)
    return (
        "# Managed by tools/testnet_seed_peering.py\n"
        "[Service]\n"
        f'Environment="IND_PEER_PING_SERVERS={value}"\n'
    )


def install_dropin(unit, peers, dropin_root="/etc/systemd/system", reload_daemon=True):
    unit = str(unit).strip()
    if not unit.endswith(".service"):
        raise ValueError("unit must be a .service name")
    target_dir = Path(dropin_root) / f"{unit}.d"
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / "10-explicit-testnet-peers.conf"
    text = render_dropin(peers)
    tmp = target.with_name(target.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, target)
    if reload_daemon:
        subprocess.run(["systemctl", "daemon-reload"], check=True)
    return target


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Configure explicit IND testnet seed peering")
    parser.add_argument("--peer", action="append", help="seed hostname; repeatable/comma-separated; default testnet/testnet.json")
    parser.add_argument("--unit", default=DEFAULT_UNIT)
    parser.add_argument("--dropin-root", default="/etc/systemd/system")
    parser.add_argument("--install", action="store_true", help="write the systemd drop-in")
    parser.add_argument("--no-daemon-reload", action="store_true")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    peers = testnet_peers.parse_peer_args(args.peer)
    if args.install:
        target = install_dropin(args.unit, peers, args.dropin_root, reload_daemon=not args.no_daemon_reload)
        print(str(target))
    else:
        print(render_dropin(peers), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
