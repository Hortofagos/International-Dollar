#!/usr/bin/env python3
"""Retired multi-hop testnet smoke script."""

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from ind import protocol_policy


def main():
    raise SystemExit(
        protocol_policy.legacy_disabled_message(
            "legacy multi-hop smoke; use tools/v3_testnet_smoke.py"
        )
    )


if __name__ == "__main__":
    main()
