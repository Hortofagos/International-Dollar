#!/usr/bin/env python3
"""Issue one public-testnet IND token by transferring it from the faucet wallet."""

import argparse
import json
import os
import sys
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

os.environ.setdefault("IND_NETWORK", "testnet")

import ind_token
from ind import runtime as runtime_json
from ind import sender_node


DEFAULT_MANIFEST = ROOT_DIR / "testnet" / "genesis_manifest.json"
DEFAULT_STATE_PATH = ROOT_DIR / "files" / "testnet" / "testnet_faucet_state.json"


def read_json(path, default=None):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {} if default is None else dict(default)


def write_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(path.name + ".tmp")
    tmp_path.write_text(json.dumps(data, sort_keys=True, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
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


def parse_args():
    parser = argparse.ArgumentParser(description="Transfer one real IND token on the public testnet.")
    parser.add_argument("--recipient-address", required=True, help="recipient wallet address")
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST), help="public testnet genesis manifest")
    parser.add_argument("--faucet-private-key-file", required=True, help="JSON/text file with the faucet private key")
    parser.add_argument("--faucet-public-key-file", required=True, help="JSON/text file with the faucet public key")
    parser.add_argument("--index", type=int, help="specific manifest index to issue; default uses the next local index")
    parser.add_argument("--state-file", default=str(DEFAULT_STATE_PATH), help="local next-index state file")
    parser.add_argument("--no-broadcast", action="store_true", help="queue the transfer without immediately gossiping it")
    return parser.parse_args()


def main():
    args = parse_args()
    runtime_json.ensure_runtime_files()
    manifest = read_json(args.manifest)
    manifest_hash = ensure_manifest_trusted_for_process(manifest)
    faucet_private = read_key(args.faucet_private_key_file, "private_key")
    faucet_public = read_key(args.faucet_public_key_file, "public_key")
    faucet_address = ind_token.address_from_public_key(faucet_public)
    recipient_address = ind_token.validate_address(args.recipient_address, "recipient address")

    owner_addresses = {item["owner_address"] for item in manifest_ranges(manifest)}
    if owner_addresses != {faucet_address}:
        raise SystemExit("faucet public key does not match the owner address in every manifest range")

    state = read_json(args.state_file, default={"next_index": manifest["ranges"][0]["start_index"]})
    index = pick_index(manifest, state, explicit_index=args.index)
    token = ind_token.make_lazy_genesis_token(
        index,
        manifest,
        metadata={"network": "testnet", "source": "public-testnet-faucet-v1"},
    )
    transferred = ind_token.create_transfer(
        token,
        faucet_private,
        faucet_public,
        recipient_address,
        metadata={"network": "testnet", "source": "public-testnet-faucet-v1"},
    )
    announcement = ind_token.create_transfer_announcement(transferred)
    store = ind_token.INDLocalStore()
    store.ingest_message(announcement)
    runtime_json.write_transaction_message(announcement)
    if args.index is None:
        state["next_index"] = index + 1
        state["updated_at"] = int(time.time())
        write_json(args.state_file, state)
    if not args.no_broadcast:
        sender_node.send_bills()

    transfer_state = ind_token.verify_token(transferred)
    print(
        json.dumps(
            {
                "accepted": True,
                "network": "testnet",
                "manifest_hash": manifest_hash,
                "display_id": transfer_state.display_id,
                "token_id": transfer_state.token_id,
                "recipient_address": recipient_address,
                "sequence": transfer_state.sequence,
                "broadcast": not args.no_broadcast,
            },
            sort_keys=True,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
