"""Clear cached bill index lines from an encrypted IND wallet.

This preserves the wallet address and signing keys, then removes the visual
bill/history lines so a migrated wallet can resync bill records from peers.
Dry-run is the default; pass --execute to write the updated encrypted wallet.
"""

import argparse
import getpass
import shutil
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from ind import runtime as runtime_json
from ind import wallet_decryption, wallet_encryption


def _encrypted_wallets():
    return [
        path
        for path in runtime_json.iter_encrypted_wallet_files()
        if path.name.startswith(runtime_json.WALLET_ENCRYPTED_PREFIX)
    ]


def _resolve_address(address):
    address = str(address or "").strip()
    if address:
        return address
    wallets = _encrypted_wallets()
    if len(wallets) == 1:
        return runtime_json.wallet_address_from_name(wallets[0].name)
    if not wallets:
        raise ValueError("no encrypted wallets found in wallet_folder")
    choices = "\n".join(
        f"  {runtime_json.wallet_address_from_name(path.name)}" for path in wallets
    )
    raise ValueError("multiple encrypted wallets found; pass --address:\n" + choices)


def _encrypted_wallet_path(address):
    path = runtime_json.encrypted_wallet_path(address)
    if not path.exists():
        raise FileNotFoundError(path)
    return path


def _backup_wallet(path):
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    backup_path = path.with_name(f"{path.name}.bill-cache-backup-{timestamp}")
    shutil.copy2(path, backup_path)
    return backup_path


def _split_wallet_payload(lines):
    key_lines = list(lines[:3])
    if len(key_lines) < 3 or any(not str(line).strip() for line in key_lines):
        raise ValueError("unlocked wallet payload is missing address/private/public key lines")
    return key_lines, list(runtime_json.wallet_bill_lines(lines))


def clear_wallet_bill_cache(address, passphrase, *, execute=False):
    address = _resolve_address(address)
    encrypted_path = _encrypted_wallet_path(address)
    if not wallet_decryption.wallet_decrypt(passphrase, address):
        raise ValueError("wallet unlock failed")
    try:
        wallet_path = runtime_json.decrypted_wallet_path(address)
        lines = runtime_json.read_decrypted_wallet_lines(wallet_path)
        if not lines or lines[0].strip() != address:
            raise ValueError("unlocked wallet address mismatch")
        key_lines, bill_lines = _split_wallet_payload(lines)
        if not execute:
            return {
                "address": address,
                "bill_lines": len(bill_lines),
                "backup_path": None,
                "updated": False,
            }
        backup_path = _backup_wallet(encrypted_path)
        payload = "".join(
            line if str(line).endswith("\n") else str(line) + "\n" for line in key_lines
        )
        runtime_json.write_decrypted_wallet(address, payload)
        wallet_encryption.wallet_reencrypt_unlocked(address, payload)
        return {
            "address": address,
            "bill_lines": len(bill_lines),
            "backup_path": str(backup_path),
            "updated": True,
        }
    finally:
        runtime_json.clear_decrypted_wallet(address)
        wallet_decryption.clear_plaintext_wallet_files(clear_memory=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--address", help="wallet address to repair")
    parser.add_argument(
        "--execute",
        action="store_true",
        help="write the cleaned encrypted wallet; default is dry-run",
    )
    parser.add_argument(
        "--passphrase-env",
        help="read the wallet passphrase from this environment variable",
    )
    args = parser.parse_args(argv)
    passphrase = None
    if args.passphrase_env:
        import os

        passphrase = os.environ.get(args.passphrase_env)
    if passphrase is None:
        passphrase = getpass.getpass("Wallet password: ")
    result = clear_wallet_bill_cache(args.address, passphrase, execute=args.execute)
    action = "updated" if result["updated"] else "dry-run"
    print(
        f"{action}: wallet {result['address']} has {result['bill_lines']} cached bill lines"
    )
    if result["backup_path"]:
        print(f"backup: {result['backup_path']}")


if __name__ == "__main__":
    main()
