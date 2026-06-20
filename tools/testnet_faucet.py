#!/usr/bin/env python3
"""Disabled legacy public-testnet faucet.

The old faucet materialized lazy-genesis bills through the retired JSON bill
protocol. Native V3 testnet funding should use stored BillV3/proof-bundle flows
instead.
"""

import argparse
import contextlib
import json
import os
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from ind import protocol_policy
from ind import token as ind_token

DEFAULT_MANIFEST = ROOT_DIR / "testnet" / "genesis_manifest.json"
DEFAULT_STATE_PATH = ROOT_DIR / "files" / "testnet" / "testnet_faucet_state.json"


@contextlib.contextmanager
def testnet_network():
    previous = os.environ.get("IND_NETWORK")
    os.environ["IND_NETWORK"] = "testnet"
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop("IND_NETWORK", None)
        else:
            os.environ["IND_NETWORK"] = previous


def read_json(path, default=None):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {} if default is None else dict(default)


def write_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(path.name + ".tmp")
    tmp_path.write_text(
        json.dumps(data, sort_keys=True, indent=2, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    os.replace(tmp_path, path)


def read_key(path, field):
    text = Path(path).read_text(encoding="utf-8").strip()
    if str(path).lower().endswith(".json"):
        data = json.loads(text)
        return str(data.get(field, "")).strip()
    return text


def manifest_ranges(manifest):
    return sorted(manifest["ranges"], key=lambda item: int(item["start_index"]))


def pick_index(manifest, state, explicit_index=None):
    if explicit_index is not None:
        index = int(explicit_index)
    else:
        ranges = manifest_ranges(manifest)
        index = int(state.get("next_index", ranges[0]["start_index"]))
    for item in manifest_ranges(manifest):
        start = int(item["start_index"])
        end = start + int(item["count"])
        if index < start and explicit_index is None:
            index = start
        if start <= index < end:
            return index
    raise SystemExit("no remaining testnet faucet indexes in the configured manifest ranges")


def ensure_manifest_trusted_for_process(manifest):
    manifest_hash = ind_token.genesis_manifest_hash(manifest)
    env_value = os.environ.get("IND_TRUSTED_GENESIS_MANIFEST_HASHES", "").strip()
    if not env_value:
        os.environ["IND_TRUSTED_GENESIS_MANIFEST_HASHES"] = manifest_hash
    return manifest_hash


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--recipient-address")
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    parser.add_argument("--faucet-private-key-file")
    parser.add_argument("--faucet-public-key-file")
    parser.add_argument("--index", type=int)
    parser.add_argument("--state-file", default=str(DEFAULT_STATE_PATH))
    parser.add_argument("--peer", action="append")
    parser.add_argument("--no-broadcast", action="store_true")
    return parser.parse_args(argv)


def issue_testnet_bill(*_args, **_kwargs):
    raise RuntimeError(
        protocol_policy.legacy_disabled_message(
            "legacy testnet faucet; use native V3 funding tooling"
        )
    )


def main(argv=None):
    parse_args(argv)
    raise SystemExit(
        protocol_policy.legacy_disabled_message(
            "legacy testnet faucet; use native V3 funding tooling"
        )
    )


if __name__ == "__main__":
    main(sys.argv[1:])
