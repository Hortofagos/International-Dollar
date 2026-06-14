#!/usr/bin/env python3
import argparse
import base64
import json
import sys
import time
from hashlib import sha3_256
from pathlib import Path

import ecdsa

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import ind_token


NODE_PREFIX = b"IND-MERKLE-NODE-v1"
PEAK_PREFIX = b"IND-MERKLE-PEAK-v1"
DEFAULT_OUTPUT_DIR = ROOT_DIR / "genesis"
DEFAULT_SHARD_SIZE = 100_000
HUGE_COUNT = 1_000_000
ESTIMATED_TOKEN_BYTES = 700


class MerkleAccumulator:
    def __init__(self):
        self.peaks = []
        self.count = 0

    @staticmethod
    def _hash(prefix, left, right):
        return sha3_256(prefix + left + right).digest()

    def add(self, leaf):
        node = leaf
        level = 0
        while True:
            if level == len(self.peaks):
                self.peaks.append(None)
            if self.peaks[level] is None:
                self.peaks[level] = node
                break
            node = self._hash(NODE_PREFIX, self.peaks[level], node)
            self.peaks[level] = None
            level += 1
        self.count += 1

    def root_hex(self):
        nodes = [node for node in self.peaks if node is not None]
        if not nodes:
            return ""
        root = nodes[0]
        for node in nodes[1:]:
            root = self._hash(PEAK_PREFIX, root, node)
        return root.hex()


def canonical_manifest(data):
    return json.dumps(data, sort_keys=True, indent=2, ensure_ascii=True)


def read_text(path):
    return Path(path).read_text(encoding="utf-8").strip()


def write_json(path, data):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(data, sort_keys=True, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def write_text(path, text):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(text, encoding="utf-8")


def read_key_file(path, field):
    text = read_text(path)
    if str(path).endswith(".json"):
        data = json.loads(text)
        return str(data.get(field, "")).strip()
    return text


def load_issuer_keys(args):
    private_key = args.issuer_private_key or (read_key_file(args.issuer_private_key_file, "private_key") if args.issuer_private_key_file else "")
    public_key = args.issuer_public_key or (read_key_file(args.issuer_public_key_file, "public_key") if args.issuer_public_key_file else "")
    if private_key and public_key:
        return private_key, public_key
    if not args.generate_local_issuer_keypair:
        raise SystemExit("issuer keys required: pass --issuer-private-key-file and --issuer-public-key-file, or use --generate-local-issuer-keypair for test data")

    signing_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1, hashfunc=sha3_256)
    verify_key = signing_key.get_verifying_key()
    private_key = base64.b85encode(signing_key.to_string()).decode("utf-8")
    public_key = base64.b85encode(verify_key.to_string()).decode("utf-8")
    write_json(Path(args.output_dir) / "issuer_private_key.local.json", {"private_key": private_key})
    write_json(Path(args.output_dir) / "issuer_public_key.local.json", {"public_key": public_key})
    return private_key, public_key


def estimate_bytes(count):
    return count * ESTIMATED_TOKEN_BYTES


def format_bytes(value):
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    number = float(value)
    for unit in units:
        if number < 1024 or unit == units[-1]:
            return f"{number:.2f} {unit}"
        number /= 1024
    return f"{number:.2f} PB"


def shard_path(output_dir, shard_index):
    return Path(output_dir) / "shards" / f"genesis_{shard_index:08d}.ndjson"


def open_shard(output_dir, shard_index):
    path = shard_path(output_dir, shard_index)
    path.parent.mkdir(parents=True, exist_ok=True)
    return path.open("w", encoding="utf-8"), path


def parse_denomination_plan(raw):
    plan = []
    for item in raw.split(","):
        if not item.strip():
            continue
        value_text, count_text = item.split(":", 1)
        plan.append((int(value_text), int(count_text)))
    if not plan:
        raise SystemExit("--denominations must contain value:count entries")
    return plan


def parse_args():
    parser = argparse.ArgumentParser(description="Generate IND genesis bill shards or a lazy signed supply manifest.")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    parser.add_argument("--start-index", type=int, default=0)
    parser.add_argument("--count", type=int)
    parser.add_argument("--value", type=int, default=1)
    parser.add_argument("--denominations", help="comma-separated lazy supply plan, for example 1:11000000000,2:11000000000,8:11000000000")
    parser.add_argument("--owner-address", required=True)
    parser.add_argument("--issuer-private-key")
    parser.add_argument("--issuer-public-key")
    parser.add_argument("--issuer-private-key-file")
    parser.add_argument("--issuer-public-key-file")
    parser.add_argument("--generate-local-issuer-keypair", action="store_true")
    parser.add_argument("--shard-size", type=int, default=DEFAULT_SHARD_SIZE)
    parser.add_argument("--write", action="store_true", help="write shards and manifest; default is a dry-run estimate")
    parser.add_argument("--allow-huge", action="store_true", help="allow writing more than one million genesis records")
    parser.add_argument("--lazy-manifest", action="store_true", help="write only a signed supply manifest; bills are minted on demand")
    parser.add_argument("--metadata-project", default="IND")
    parser.add_argument("--created-at", type=int, help="fixed manifest/bill metadata timestamp for reproducible generation")
    return parser.parse_args()


def planned_count(args):
    if args.denominations:
        return sum(count for _value, count in parse_denomination_plan(args.denominations))
    if args.count is None:
        raise SystemExit("--count is required unless --denominations is provided")
    return args.count


def validate_args(args):
    count = planned_count(args)
    if count <= 0:
        raise SystemExit("--count must be positive")
    if args.start_index < 0:
        raise SystemExit("--start-index must be non-negative")
    if args.value <= 0:
        raise SystemExit("--value must be positive")
    if args.shard_size <= 0:
        raise SystemExit("--shard-size must be positive")
    end_index = args.start_index + count
    if end_index > ind_token.TOTAL_SUPPLY:
        raise SystemExit(f"requested range ends at {end_index}, above TOTAL_SUPPLY={ind_token.TOTAL_SUPPLY}")
    if args.denominations and not args.lazy_manifest:
        raise SystemExit("--denominations currently requires --lazy-manifest")
    if args.write and not args.lazy_manifest and count > HUGE_COUNT and not args.allow_huge:
        raise SystemExit("refusing huge write; pass --allow-huge if you really intend to generate this many records")


def supply_ranges(args):
    if args.denominations:
        plan = parse_denomination_plan(args.denominations)
    else:
        plan = [(args.value, args.count)]
    return ind_token.make_denomination_ranges(plan, args.owner_address, start_index=args.start_index)


def dry_run(args):
    count = planned_count(args)
    end_index = args.start_index + count
    print("IND genesis dry run")
    print(f"range: [{args.start_index}, {end_index})")
    print(f"count: {count:,}")
    if args.denominations:
        total_value = sum(value * range_count for value, range_count in parse_denomination_plan(args.denominations))
        print(f"denomination plan: {args.denominations}")
        print(f"total face value: {total_value:,}")
    else:
        print(f"value per bill: {args.value:,}")
    print(f"max protocol supply: {ind_token.TOTAL_SUPPLY:,}")
    print(f"rough shard payload estimate: {format_bytes(estimate_bytes(count))}")
    if args.lazy_manifest:
        ranges = supply_ranges(args)
        manifest_unsigned = {
            "type": ind_token.GENESIS_MANIFEST_TYPE,
            "version": ind_token.TOKEN_VERSION,
            "ranges": ranges,
        }
        print(f"lazy manifest rough estimate: {format_bytes(len(ind_token.canonical_json(manifest_unsigned).encode('utf-8')) + 1000)}")
    print("no files written; pass --write to generate the manifest or shards")


def generate_lazy_manifest(args):
    issuer_private_key, issuer_public_key = load_issuer_keys(args)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    created_at = int(args.created_at or time.time())
    metadata = {
        "project": args.metadata_project,
        "generated_at": created_at,
        "mode": "lazy",
    }
    manifest = ind_token.make_genesis_manifest(
        supply_ranges(args),
        issuer_private_key,
        issuer_public_key,
        issued_at=created_at,
        metadata=metadata,
    )
    compact_size = len(ind_token.canonical_json(manifest).encode("utf-8"))
    write_text(output_dir / "manifest.json", canonical_manifest(manifest) + "\n")
    print(canonical_manifest({
        "manifest_path": "manifest.json",
        "manifest_hash": ind_token.genesis_manifest_hash(manifest),
        "manifest_bytes": compact_size,
        "total_token_count": manifest["total_token_count"],
        "total_value": manifest["total_value"],
        "materialized_payload_estimate": format_bytes(estimate_bytes(manifest["total_token_count"])),
        "lazy_savings_estimate": format_bytes(max(0, estimate_bytes(manifest["total_token_count"]) - compact_size)),
    }))


def generate(args):
    issuer_private_key, issuer_public_key = load_issuer_keys(args)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    accumulator = MerkleAccumulator()
    created_at = int(args.created_at or time.time())
    shard_index = 0
    shard_count = 0
    current_shard, current_path = open_shard(output_dir, shard_index)
    shards = []
    start_time = time.time()

    try:
        for offset in range(args.count):
            index = args.start_index + offset
            nonce = ind_token.sha3_hex(f"IND-GENESIS-v1:{index}:{args.owner_address}:{args.value}")
            metadata = {
                "project": args.metadata_project,
                "generated_at": created_at,
            }
            bill = ind_token.make_genesis_token(
                index,
                args.owner_address,
                issuer_private_key,
                issuer_public_key,
                value=args.value,
                nonce=nonce,
                metadata=metadata,
                issued_at=created_at,
            )
            leaf_hash = bytes.fromhex(ind_token.genesis_hash(bill["genesis"]))
            accumulator.add(leaf_hash)
            current_shard.write(ind_token.canonical_json(bill) + "\n")
            shard_count += 1

            if shard_count == args.shard_size and offset != args.count - 1:
                current_shard.close()
                shards.append({
                    "path": str(current_path.relative_to(output_dir)),
                    "records": shard_count,
                })
                shard_index += 1
                shard_count = 0
                current_shard, current_path = open_shard(output_dir, shard_index)
    finally:
        current_shard.close()

    shards.append({
        "path": str(current_path.relative_to(output_dir)),
        "records": shard_count,
    })
    manifest = {
        "type": "ind.genesis_manifest.v1",
        "version": ind_token.TOKEN_VERSION,
        "total_supply": ind_token.TOTAL_SUPPLY,
        "start_index": args.start_index,
        "end_index_exclusive": args.start_index + args.count,
        "count": args.count,
        "value": args.value,
        "owner_address": args.owner_address,
        "issuer_public_key": issuer_public_key,
        "created_at": created_at,
        "leaf_hash": "sha3_256(canonical_json(genesis_with_signature))",
        "merkle_algorithm": "append-only peaks: NODE=sha3_256(IND-MERKLE-NODE-v1||left||right), ROOT folds peaks with IND-MERKLE-PEAK-v1",
        "merkle_root": accumulator.root_hex(),
        "shards": shards,
        "elapsed_seconds": round(time.time() - start_time, 3),
    }
    write_text(output_dir / "manifest.json", canonical_manifest(manifest) + "\n")
    print(canonical_manifest(manifest))


def main():
    args = parse_args()
    validate_args(args)
    if not args.write:
        dry_run(args)
        return
    if args.lazy_manifest:
        generate_lazy_manifest(args)
        return
    generate(args)


if __name__ == "__main__":
    main()
