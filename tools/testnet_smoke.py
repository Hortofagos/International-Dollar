#!/usr/bin/env python3
"""Retired faucet-backed testnet smoke script.

Use ``tools/v3_testnet_smoke.py`` for active V3 readiness checks.
"""

import contextlib
import os
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from ind import address_generation, keys_v3, protocol_policy  # noqa: F401


class SmokeError(RuntimeError):
    pass


@contextlib.contextmanager
def temporary_env(updates):
    previous = {key: os.environ.get(key) for key in updates}
    try:
        for key, value in updates.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = str(value)
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def validate_wallet_lines(address, lines):
    if len(lines) < 3:
        raise SmokeError(f"wallet {address} did not unlock to address/private/public lines")
    wallet_address = lines[0].strip()
    private_key = lines[1].strip()
    public_key = lines[2].strip()
    if wallet_address != address:
        raise SmokeError(
            f"wallet metadata address {address} does not match unlocked wallet {wallet_address}"
        )
    if not private_key or not public_key:
        raise SmokeError(f"wallet {address} unlocked without signing keys")
    if not keys_v3.public_key_matches_address(public_key, address):
        raise SmokeError(f"wallet {address} public key does not match address")
    return [line if line.endswith("\n") else line + "\n" for line in lines]


def main():
    raise SystemExit(
        protocol_policy.legacy_disabled_message(
            "legacy testnet smoke; use tools/v3_testnet_smoke.py"
        )
    )


if __name__ == "__main__":
    main()
