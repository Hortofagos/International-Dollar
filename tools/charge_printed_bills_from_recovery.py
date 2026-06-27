"""Queue printed-bill charges from a recovered paper-wallet address file.

Dry-run is the default. Pass --execute to sign transfers and update the
encrypted wallet.
"""

import argparse
import contextlib
import csv
import getpass
import os
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from ind import keys_v3
from ind import runtime as runtime_json
from ind import sender_node, settings as ind_settings, wallet_decryption, wallet_encryption
from ind import wallet_services


def _read_charge_map(path):
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(path)
    mapping = {}
    if path.suffix.lower() == ".csv":
        with path.open(newline="", encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                display_id = str(row.get("serial") or row.get("display_id") or "").strip()
                address = str(row.get("charge_address") or row.get("address") or "").strip()
                if display_id and address:
                    mapping[display_id] = keys_v3.validate_address(address, "charge address")
    else:
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.replace(",", " ").split()
            if len(parts) < 2:
                raise ValueError(f"invalid charge-map line: {raw_line!r}")
            mapping[parts[0]] = keys_v3.validate_address(parts[1], "charge address")
    if not mapping:
        raise ValueError("charge map is empty")
    return mapping


def _store_paths():
    paths = []
    with contextlib.suppress(Exception):
        paths.append(ind_settings.default_store_path())
    paths.extend(getattr(ind_settings, "DEFAULT_STORE_PATHS", {}).values())
    unique = []
    seen = set()
    for path in paths:
        text = str(path).strip()
        if text and text not in seen:
            unique.append(text)
            seen.add(text)
    return unique


def _wallet_store_for_address(address):
    fallback = None
    for store_path in _store_paths():
        store = sender_node.wallet_sync_store(db_path=store_path)
        if fallback is None:
            fallback = store
        with contextlib.suppress(Exception):
            store.finalize_pending(buffer_seconds=ind_settings.finality_buffer_seconds())
        spendable = wallet_services.spendable_wallet_records(address, store=store, limit=1)
        pending = wallet_services.pending_wallet_records(address, store=store, limit=1)
        if spendable or pending:
            return store
    return fallback or sender_node.wallet_sync_store()


def _wallet_addresses():
    return [
        runtime_json.wallet_address_from_name(path.name)
        for path in runtime_json.iter_encrypted_wallet_files()
    ]


def _select_wallet_address(configured_address=None):
    if configured_address:
        return keys_v3.validate_address(configured_address, "wallet address")
    addresses = _wallet_addresses()
    if not addresses:
        raise ValueError("no encrypted wallet found")
    if len(addresses) > 1:
        raise ValueError(
            "multiple encrypted wallets found; pass --wallet-address with the one to charge"
        )
    return addresses[0]


def _unlock_wallet(address, passphrase=None, passphrase_env=None):
    if passphrase is None and passphrase_env:
        passphrase = os.environ.get(passphrase_env)
    if passphrase is None:
        passphrase = getpass.getpass(f"Wallet passphrase for {address}: ")
    if not wallet_decryption.wallet_decrypt(passphrase, address):
        raise ValueError("wallet unlock failed")
    wallet_path = runtime_json.decrypted_wallet_path(address)
    wallet_lines = runtime_json.read_decrypted_wallet_lines(wallet_path)
    if not wallet_lines or wallet_lines[0].strip() != address:
        raise ValueError("unlocked wallet address mismatch")
    return wallet_path, wallet_lines


def _wallet_bill_map(wallet_lines):
    bills = {}
    for line in runtime_json.wallet_bill_lines(wallet_lines):
        display_id = wallet_services.wallet_line_display_id(line)
        if display_id and not str(line).lstrip().startswith("-"):
            bills[display_id] = line
    return bills


def _limited_items(mapping, limit):
    items = list(mapping.items())
    if limit is not None:
        return items[: int(limit)]
    return items


def charge_from_recovery(
    mapping,
    wallet_lines,
    store,
    *,
    execute=False,
    limit=None,
    progress=None,
    progress_every=25,
):
    wallet_bills = _wallet_bill_map(wallet_lines)
    selected = _limited_items(mapping, limit)
    updated = list(wallet_lines)
    sent = []
    errors = []
    spendable_records = wallet_services.spendable_wallet_records(
        wallet_lines[0].strip(), store=store, limit=None
    )
    spendable_ids = {record.get("display_id") for record in spendable_records}
    missing = [display_id for display_id, _address in selected if display_id not in wallet_bills]
    not_ready = [
        display_id
        for display_id, _address in selected
        if display_id in wallet_bills and display_id not in spendable_ids
    ]
    ready = [
        display_id
        for display_id, _address in selected
        if display_id in wallet_bills and display_id in spendable_ids
    ]
    if callable(progress):
        progress(
            "preflight "
            f"selected={len(selected)} ready={len(ready)} "
            f"missing={len(missing)} not_ready={len(not_ready)}"
        )

    if not execute:
        return {
            "sent": sent,
            "errors": errors,
            "missing": missing,
            "not_ready": not_ready,
            "ready": ready,
        }
    if missing or not_ready:
        errors.extend(f"{display_id}: missing from unlocked wallet" for display_id in missing)
        errors.extend(f"{display_id}: not settled/spendable" for display_id in not_ready)
        return {
            "sent": sent,
            "errors": errors,
            "missing": missing,
            "not_ready": not_ready,
            "updated_wallet": updated,
        }

    total = len(selected)
    for index, (display_id, charge_address) in enumerate(selected, start=1):
        if callable(progress) and (
            index == 1 or index == total or index % max(1, int(progress_every)) == 0
        ):
            progress(f"signing {index}/{total}: {display_id}")
        wallet_line = wallet_bills.get(display_id)
        try:
            state = wallet_services.spend_wallet_bill(
                wallet_lines,
                wallet_line,
                charge_address,
                store=store,
            )
            if not state:
                raise RuntimeError("bill is not spendable or is not settled")
            replacement = f"-{display_id} {state.sequence} {int(time.time())}\n"
            for index, existing in enumerate(updated):
                if existing == wallet_line:
                    updated[index] = replacement
                    break
            sent.append(display_id)
        except Exception as exc:
            errors.append(f"{display_id}: {exc}")
    return {"sent": sent, "errors": errors, "missing": missing, "updated_wallet": updated}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mapping", required=True, help="CSV or text serial-to-address recovery file")
    parser.add_argument("--wallet-address", help="wallet address to unlock when multiple wallets exist")
    parser.add_argument("--limit", type=int, help="only process the first N mapping entries")
    parser.add_argument("--execute", action="store_true", help="sign transfers and update the wallet")
    parser.add_argument(
        "--passphrase-env",
        help="read the wallet passphrase from this environment variable instead of prompting",
    )
    args = parser.parse_args(argv)

    mapping = _read_charge_map(args.mapping)
    print(f"loaded_mapping={len(mapping)}", flush=True)
    address = _select_wallet_address(args.wallet_address)
    print(f"wallet_address={address}", flush=True)
    wallet_path, wallet_lines = _unlock_wallet(address, passphrase_env=args.passphrase_env)
    print(f"wallet_unlocked_lines={len(wallet_lines)}", flush=True)
    store = _wallet_store_for_address(address)
    print(f"store={store.db_path}", flush=True)
    result = charge_from_recovery(
        mapping,
        wallet_lines,
        store,
        execute=args.execute,
        limit=args.limit,
        progress=lambda message: print(message, flush=True),
    )

    if args.execute:
        if result["sent"]:
            print("persisting_wallet_state=true", flush=True)
            runtime_json.write_decrypted_wallet_lines(wallet_path, result["updated_wallet"])
            payload = runtime_json.read_decrypted_wallet_payload(wallet_path)
            wallet_encryption.wallet_reencrypt_unlocked(address, payload)
        print(f"queued={len(result['sent'])}")
    else:
        print(f"ready={len(result['ready'])}")
    print(f"missing_wallet_lines={len(result['missing'])}")
    print(f"not_ready={len(result.get('not_ready', []))}")
    print(f"errors={len(result['errors'])}")
    for error in result["errors"][:20]:
        print(error)
    if len(result["errors"]) > 20:
        print(f"... {len(result['errors']) - 20} more errors")
    return 1 if result["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
