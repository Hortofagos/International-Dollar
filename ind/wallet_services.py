"""Testable wallet actions shared by the desktop UI and scripts."""

from . import runtime as runtime_json
from . import token as ind_token


def spend_wallet_bill(wallet_lines, wallet_bill_line, recipient_address, store=None):
    """Spend one locally stored wallet bill and queue its transfer announcement."""

    store = store or ind_token.INDLocalStore()
    display_id = wallet_bill_line.split()[0].lstrip("-")
    token = store.get_token_by_display_id(display_id)
    if not token:
        return None
    transferred_token = ind_token.create_transfer(
        token,
        wallet_lines[1].strip(),
        wallet_lines[2].strip(),
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
        transferred_token = ind_token.create_transfer(
            token,
            private_key,
            public_key,
            wallet_address,
        )
        announcement = ind_token.create_transfer_announcement(transferred_token)
        runtime_json.write_transaction_message(announcement)
        return True
