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


def bill_is_spendable(store, bill, wallet_address, min_settled_seconds=0):
    """Return True only when the local store considers a bill spendable."""

    state = ind_token.verify_token(bill)
    if wallet_address and state.owner_address != wallet_address:
        return False
    confidence = store.token_confidence(
        state.token_id,
        expected_owner=state.owner_address,
        min_settled_seconds=min_settled_seconds,
    )
    return bool(confidence.get("accepted"))


token_is_spendable = bill_is_spendable


def spendable_wallet_records(wallet_address, store=None, limit=1000):
    """List locally settled spendable bill records for one wallet address."""

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
    """List locally known incoming bills that are visible but not spendable yet."""

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
    bill = store.get_compact_bill_by_display_id(display_id) or store.get_token_by_display_id(display_id)
    if not bill:
        return None
    if not bill_is_spendable(store, bill, wallet_address):
        return None
    private_key, public_key = _wallet_keys(wallet_lines)
    transferred_bill = ind_token.create_transfer(
        bill,
        private_key,
        public_key,
        recipient_address,
    )
    announcement = ind_token.create_transfer_announcement(transferred_bill)
    store.ingest_message(announcement)
    runtime_json.write_transaction_message(announcement)
    return ind_token.verify_token(transferred_bill)


def compact_wallet_bill(wallet_lines, wallet_bill_line, store=None):
    """Force a compact checkpoint for one locally settled wallet bill."""

    store = store or ind_token.INDLocalStore()
    wallet_address = _wallet_address(wallet_lines)
    display_id = _display_id_from_wallet_line(wallet_bill_line)
    if not display_id:
        return None
    bill = store.get_compact_bill_by_display_id(display_id) or store.get_token_by_display_id(display_id)
    if not bill:
        return None
    if not bill_is_spendable(store, bill, wallet_address):
        return None
    compact_bill = store.compact_bill_now(display_id=display_id)
    return ind_token.verify_bill(compact_bill)


def _claim_wire_message(message, wallet_lines):
    private_key, public_key = _wallet_keys(wallet_lines)
    if message.get("type") == ind_token.TOKEN_TYPE:
        bill = message
    elif message.get("type") == ind_token.TRANSFER_ANNOUNCEMENT_TYPE:
        bill = message.get("token")
    elif message.get("type") == ind_token.TRANSFER_ANNOUNCEMENT_V2_TYPE:
        bill = message.get("bill")
    else:
        return False

    try:
        receipt = ind_token.create_receipt_announcement(bill, private_key, public_key)
    except (KeyError, TypeError, ind_token.ValidationError):
        return False
    runtime_json.write_transaction_message(receipt)
    return True


def _claim_paper_wallet_payload(bill_payload, wallet_address):
    split = str(bill_payload).splitlines()
    if len(split) < 3:
        return False

    display_id = split[0]
    private_key = split[1]
    public_key = split[2]
    store = ind_token.INDLocalStore()
    bill = store.get_compact_bill_by_display_id(display_id) or store.get_token_by_display_id(display_id)
    if not bill:
        return False

    try:
        state = ind_token.verify_token(bill)
        if public_key and not ind_token.public_key_matches_address(public_key, state.owner_address):
            return False
        confidence = store.token_confidence(
            state.token_id,
            expected_owner=state.owner_address,
            min_settled_seconds=0,
        )
        if not confidence.get("accepted"):
            return False
        transferred_bill = ind_token.create_transfer(
            bill,
            private_key,
            public_key,
            wallet_address,
        )
        announcement = ind_token.create_transfer_announcement(transferred_bill)
    except (KeyError, TypeError, ind_token.ValidationError):
        return False

    runtime_json.write_transaction_message(announcement)
    return True


def claim_bill_payload(bill_payload, wallet_lines, wallet_address):
    """Convert a scanned bill, announcement, or paper-wallet payload into a queued claim message."""

    try:
        message = ind_token.unpack_wire_message(bill_payload)
    except ind_token.ValidationError:
        return _claim_paper_wallet_payload(bill_payload, wallet_address)
    return _claim_wire_message(message, wallet_lines)
