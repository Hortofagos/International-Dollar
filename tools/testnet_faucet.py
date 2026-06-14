#!/usr/bin/env python3
"""Issue one public-testnet IND bill by transferring it from the faucet wallet."""

import argparse
import contextlib
import json
import os
import sys
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import ind_token
from ind import runtime as runtime_json
from ind import sender_node
from tools import testnet_peers


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
    parser = argparse.ArgumentParser(description="Transfer one real IND bill on the public testnet.")
    parser.add_argument("--recipient-address", required=True, help="recipient wallet address")
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST), help="public testnet genesis manifest")
    parser.add_argument("--faucet-private-key-file", required=True, help="JSON/text file with the faucet private key")
    parser.add_argument("--faucet-public-key-file", required=True, help="JSON/text file with the faucet public key")
    parser.add_argument("--index", type=int, help="specific manifest index to issue; default uses the next local index")
    parser.add_argument("--state-file", default=str(DEFAULT_STATE_PATH), help="local next-index state file")
    parser.add_argument(
        "--peer",
        action="append",
        help="seed/node to broadcast to; repeatable and comma-separated; default uses testnet/testnet.json",
    )
    parser.add_argument("--no-broadcast", action="store_true", help="queue the transfer without immediately gossiping it")
    return parser.parse_args()


def issue_testnet_bill(
    recipient_address,
    manifest_path=DEFAULT_MANIFEST,
    faucet_private_key_file=None,
    faucet_public_key_file=None,
    index=None,
    state_file=DEFAULT_STATE_PATH,
    broadcast=True,
    peers=None,
):
    """Issue one lazy-genesis testnet bill and return a safe public summary."""

    if faucet_private_key_file is None or faucet_public_key_file is None:
        raise ValueError("faucet private/public key files are required")
    with testnet_network():
        runtime_json.ensure_runtime_files()
        manifest = read_json(manifest_path)
        manifest_hash = ensure_manifest_trusted_for_process(manifest)
        faucet_private = read_key(faucet_private_key_file, "private_key")
        faucet_public = read_key(faucet_public_key_file, "public_key")
        faucet_address = ind_token.address_from_public_key(faucet_public)
        recipient_address = ind_token.validate_address(recipient_address, "recipient address")

        owner_addresses = {item["owner_address"] for item in manifest_ranges(manifest)}
        if owner_addresses != {faucet_address}:
            raise SystemExit("faucet public key does not match the owner address in every manifest range")

        state = read_json(state_file, default={"next_index": manifest["ranges"][0]["start_index"]})
        issue_index = pick_index(manifest, state, explicit_index=index)
        bill = ind_token.make_lazy_genesis_token(
            issue_index,
            manifest,
            metadata={"network": "testnet", "source": "public-testnet-faucet-v1"},
        )
        transferred = ind_token.create_transfer(
            bill,
            faucet_private,
            faucet_public,
            recipient_address,
            metadata={"network": "testnet", "source": "public-testnet-faucet-v1"},
        )
        announcement = ind_token.create_transfer_announcement(transferred)
        store = ind_token.INDLocalStore()
        store.ingest_message(announcement)
        broadcast_results = []
        selected_peers = testnet_peers.parse_peer_args(peers)
        if not broadcast:
            runtime_json.write_transaction_message(announcement)
        if index is None:
            state["next_index"] = issue_index + 1
            state["updated_at"] = int(time.time())
            write_json(state_file, state)
        if broadcast:
            if selected_peers:
                broadcast_results = testnet_peers.broadcast_message_to_peers(announcement, selected_peers)
            else:
                runtime_json.write_transaction_message(announcement)
                sender_node.send_bills()

        transfer_state = ind_token.verify_token(transferred)
        return {
            "accepted": True,
            "network": "testnet",
            "manifest_hash": manifest_hash,
            "display_id": transfer_state.display_id,
            "token_id": transfer_state.token_id,
            "recipient_address": recipient_address,
            "sequence": transfer_state.sequence,
            "broadcast": bool(broadcast),
            "peers": selected_peers,
            "broadcast_results": broadcast_results,
        }


def main():
    args = parse_args()
    result = issue_testnet_bill(
        args.recipient_address,
        manifest_path=args.manifest,
        faucet_private_key_file=args.faucet_private_key_file,
        faucet_public_key_file=args.faucet_public_key_file,
        index=args.index,
        state_file=args.state_file,
        broadcast=not args.no_broadcast,
        peers=args.peer,
    )
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
