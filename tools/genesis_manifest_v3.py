#!/usr/bin/env python3
"""Create and verify native IND V3 genesis manifests."""

import argparse
import json
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from ind import genesis_manifest_v3, keys_v3


def _load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _write_json(path, data):
    Path(path).write_text(
        json.dumps(data, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def _read_text_arg(value, file_value, label):
    if value:
        return value.strip()
    if file_value:
        return Path(file_value).read_text(encoding="utf-8").strip()
    raise SystemExit(f"{label} is required")


def cmd_keygen(args):
    seed = bytes.fromhex(args.seed_hex) if args.seed_hex else None
    address, private_key, public_key = keys_v3.generate_keypair(seed)
    result = {
        "address": address,
        "private_key": private_key,
        "public_key": public_key,
    }
    if args.out_dir:
        out_dir = Path(args.out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        prefix = args.prefix
        (out_dir / f"{prefix}_private.local.txt").write_text(private_key + "\n", encoding="utf-8")
        (out_dir / f"{prefix}_public.txt").write_text(public_key + "\n", encoding="utf-8")
        (out_dir / f"{prefix}_address.txt").write_text(address + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))


def cmd_create_mainnet(args):
    private_key = _read_text_arg(
        args.issuer_private_key,
        args.issuer_private_key_file,
        "issuer private key",
    )
    owner_address = _read_text_arg(args.owner_address, args.owner_address_file, "owner address")
    metadata = _load_json(args.metadata_file) if args.metadata_file else None
    ranges = genesis_manifest_v3.full_supply_ranges(
        owner_address,
        seed_prefix=args.range_seed_prefix,
    )
    manifest = genesis_manifest_v3.make_manifest(
        ranges,
        private_key,
        issued_at=args.issued_at,
        network="mainnet",
        network_id=args.network_id,
        metadata=metadata,
    )
    _write_json(args.output, manifest)
    print(manifest["manifest_hash"])


def cmd_verify(args):
    manifest = _load_json(args.manifest)
    trusted_hashes = args.trusted_hash or None
    result = genesis_manifest_v3.verify_manifest(
        manifest,
        trusted_hashes=trusted_hashes,
        require_full_supply=args.require_full_supply,
        expected_network=args.expected_network,
        expected_network_id=args.expected_network_id,
    )
    print(json.dumps(result, indent=2, sort_keys=True))


def cmd_derive_ref(args):
    manifest = _load_json(args.manifest)
    ref = genesis_manifest_v3.derive_genesis_ref(manifest, args.value, args.serial)
    if args.output:
        _write_json(args.output, ref)
    print(json.dumps(ref, indent=2, sort_keys=True))


def cmd_derive_base_state(args):
    manifest = _load_json(args.manifest)
    state = genesis_manifest_v3.derive_base_state(manifest, args.value, args.serial)
    if args.output:
        _write_json(args.output, state)
    print(json.dumps(state, indent=2, sort_keys=True))


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    keygen = sub.add_parser("keygen", help="generate one V3 keypair")
    keygen.add_argument("--seed-hex", help="optional deterministic 32-byte seed hex")
    keygen.add_argument("--out-dir", help="write key files into this directory")
    keygen.add_argument("--prefix", default="issuer", help="output filename prefix")
    keygen.set_defaults(func=cmd_keygen)

    create = sub.add_parser("create-mainnet", help="create a full-supply mainnet manifest")
    create.add_argument("--issuer-private-key")
    create.add_argument("--issuer-private-key-file")
    create.add_argument("--owner-address")
    create.add_argument("--owner-address-file")
    create.add_argument("--issued-at", type=int, required=True)
    create.add_argument("--network-id", type=int, default=1)
    create.add_argument("--range-seed-prefix", default="IND-MAINNET-GENESIS-V3")
    create.add_argument("--metadata-file")
    create.add_argument("--output", required=True)
    create.set_defaults(func=cmd_create_mainnet)

    verify = sub.add_parser("verify", help="verify a signed genesis manifest")
    verify.add_argument("manifest")
    verify.add_argument("--trusted-hash", action="append")
    verify.add_argument("--require-full-supply", action="store_true")
    verify.add_argument("--expected-network", default="mainnet")
    verify.add_argument("--expected-network-id", type=int, default=1)
    verify.set_defaults(func=cmd_verify)

    derive_ref = sub.add_parser("derive-ref", help="derive one GenesisRefV3 from a manifest")
    derive_ref.add_argument("manifest")
    derive_ref.add_argument("--value", type=int, required=True)
    derive_ref.add_argument("--serial", type=int, required=True)
    derive_ref.add_argument("--output")
    derive_ref.set_defaults(func=cmd_derive_ref)

    derive_state = sub.add_parser(
        "derive-base-state",
        help="derive the sequence-0 base state for one manifest bill",
    )
    derive_state.add_argument("manifest")
    derive_state.add_argument("--value", type=int, required=True)
    derive_state.add_argument("--serial", type=int, required=True)
    derive_state.add_argument("--output")
    derive_state.set_defaults(func=cmd_derive_base_state)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main(sys.argv[1:])
