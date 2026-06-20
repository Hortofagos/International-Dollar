#!/usr/bin/env python3
"""Legacy lazy-token minter removed from the active V3 toolchain."""

import argparse
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from ind import protocol_policy


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    _args, _unknown = parser.parse_known_args(argv)
    return _args


def main(argv=None):
    parse_args(argv)
    raise SystemExit(
        protocol_policy.legacy_disabled_message(
            "legacy lazy-token minter; use native V3 genesis/proof-bundle tooling"
        )
    )


if __name__ == "__main__":
    main(sys.argv[1:])
