#!/usr/bin/env python3
import argparse
import json
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import ind_token


def parse_args():
    parser = argparse.ArgumentParser(description="Mint one IND lazy-genesis token from a signed supply manifest.")
    parser.add_argument("--manifest", required=True, help="path to signed genesis manifest JSON")
    parser.add_argument("--index", type=int, required=True, help="token index to mint")
    parser.add_argument("--output", help="output token JSON path; defaults to stdout")
    return parser.parse_args()


def main():
    args = parse_args()
    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    token = ind_token.make_lazy_genesis_token(args.index, manifest)
    payload = ind_token.canonical_json(token) + "\n"
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(payload, encoding="utf-8")
    else:
        print(payload, end="")


if __name__ == "__main__":
    main()
