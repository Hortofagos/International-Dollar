"""Testable wallet actions shared by the desktop UI and scripts."""

from . import runtime as runtime_json
from . import token as ind_token


def _wallet_address(wallet_lines):
    return str(wallet_lines[0]).strip() if wallet_lines else ""


def _wallet_keys(wallet_lines):
    if len(wallet_lines) < 3:
        raise ind_token.ValidationError("wallet is missing signing keys")
    return wallet_lines[1].strip(), wallet_lines[2].strip()


def _display_id_from_wallet_line(wallet_bill_line):
    parts = str(wallet_bill_line).split()
    if not parts or parts[0].startswith("-"):
        return None
    return parts[0]


def token_is_spendable(store, token, wallet_address, min_settled_seconds=0):
    """Return True only when the local store considers a token spendable."""

    state = ind_token.verify_token(token)
    if wallet_address and state.owner_address != wallet_address:
        return False
    confidence = store.token_confidence(
        state.token_id,
        expected_owner=state.owner_address,
        min_settled_seconds=min_settled_seconds,
    )
    return bool(confidence.get("accepted"))


def spendable_wallet_records(wallet_address, store=None, limit=1000):
    """List locally settled, conflict-free token records for one wallet address."""

    store = store or ind_token.INDLocalStore()
    records = []
    for record in store.token_records_for_owner(wallet_address, settled_only=True, limit=limit):
        confidence = store.token_confidence(
            record["token_id"],
            expected_owner=wallet_address,
            min_settled_seconds=0,
        )
        if confidence.get("accepted"):
            records.append(record)
    return records


def pending_wallet_records(wallet_address, store=None, limit=1000):
    """List locally known incoming tokens that are visible but not spendable yet."""

    store = store or ind_token.INDLocalStore()
    records = []
    for record in store.token_records_for_owner(wallet_address, settled_only=False, limit=limit):
        if record.get("status") not in {"unreceipted", "pending"}:
            continue
        confidence = store.token_confidence(
            record["token_id"],
            expected_owner=wallet_address,
            min_settled_seconds=0,
        )
        if confidence.get("level") in {"unreceipted", "pending"}:
            records.append(record)
    return records


def spend_wallet_bill(wallet_lines, wallet_bill_line, recipient_address, store=None):
    """Spend one locally stored wallet bill and queue its transfer announcement."""

    store = store or ind_token.INDLocalStore()
    wallet_address = _wallet_address(wallet_lines)
    display_id = _display_id_from_wallet_line(wallet_bill_line)
    if not display_id:
        return None
    token = store.get_token_by_display_id(display_id)
    if not token:
        return None
    if not token_is_spendable(store, token, wallet_address):
        return None
    private_key, public_key = _wallet_keys(wallet_lines)
    transferred_token = ind_token.create_transfer(
        token,
        private_key,
        public_key,
        recipient_address,
    )
    announcement = ind_token.create_transfer_announcement(transferred_token)
    store.ingest_message(announcement)
    runtime_json.write_transaction_message(announcement)
    return ind_token.verify_token(transferred_token)


def claim_bill_payload(bill_payload, wallet_lines, wallet_address):
    """Convert a scanned token/announcement/paper-wallet payload into a queued claim message."""

    try:
        message = ind_token.unpack_wire_message(bill_payload)
        if message.get("type") == ind_token.TOKEN_TYPE:
            receipt = ind_token.create_receipt_announcement(
                message,
                wallet_lines[1].strip(),
                wallet_lines[2].strip(),
            )
        elif message.get("type") == ind_token.TRANSFER_ANNOUNCEMENT_TYPE:
            receipt = ind_token.create_receipt_announcement(
                message["token"],
                wallet_lines[1].strip(),
                wallet_lines[2].strip(),
            )
        else:
            return False
        runtime_json.write_transaction_message(receipt)
        return True
    except Exception:
        split = str(bill_payload).splitlines()
        if len(split) < 3:
            return False
        display_id = split[0]
        private_key = split[1]
        public_key = split[2]
        store = ind_token.INDLocalStore()
        token = store.get_token_by_display_id(display_id)
        if not token:
            return False
        state = ind_token.verify_token(token)
        if public_key and not ind_token.public_key_matches_address(public_key, state.owner_address):
            return False
        confidence = store.token_confidence(state.token_id, expected_owner=state.owner_address, min_settled_seconds=0)
        if not confidence.get("accepted"):
            return False
        transferred_token = ind_token.create_transfer(
            token,
            private_key,
            public_key,
            wallet_address,
        )
        announcement = ind_token.create_transfer_announcement(transferred_token)
        runtime_json.write_transaction_message(announcement)
        return True
