# Testable wallet actions shared by the desktop UI and scripts.

from . import keys_v3, protocol_policy, protocol_v3
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


# Return True only when the local store considers a bill spendable.
def bill_is_spendable(store, bill, wallet_address, min_settled_seconds=0):
    if isinstance(bill, dict) and bill.get("type") == protocol_v3.BILL_TYPE:
        return bill_is_spendable_v3(store, bill, wallet_address)
    raise ind_token.ValidationError(
        protocol_policy.legacy_disabled_message("legacy wallet spendability")
    )


token_is_spendable = bill_is_spendable


# List locally settled spendable bill records for one wallet address.
def spendable_wallet_records(wallet_address, store=None, limit=1000):
    store = store or ind_token.INDLocalStore()
    if keys_v3.is_address(wallet_address):
        return store.bill_v3_records_for_owner(
            wallet_address,
            statuses=("settled", "verified"),
            limit=limit,
        )
    return []


# List locally known incoming bills that are visible but not spendable yet.
def pending_wallet_records(wallet_address, store=None, limit=1000):
    store = store or ind_token.INDLocalStore()
    if keys_v3.is_address(wallet_address):
        return store.bill_v3_records_for_owner(
            wallet_address,
            statuses=("unreceipted", "pending"),
            limit=limit,
        )
    return []


# Spend one locally stored wallet bill and queue its transfer announcement.
def spend_wallet_bill(wallet_lines, wallet_bill_line, recipient_address, store=None):
    store = store or ind_token.INDLocalStore()
    wallet_address = _wallet_address(wallet_lines)
    display_id = _display_id_from_wallet_line(wallet_bill_line)
    if not display_id:
        return None
    bill_v3 = store.get_bill_v3_by_display_id(display_id)
    if bill_v3:
        return spend_wallet_bill_v3(
            wallet_lines,
            bill_v3,
            recipient_address,
            store=store,
        )
    raise ind_token.ValidationError(protocol_policy.legacy_disabled_message("legacy wallet spend"))


# Return a V3 wallet tuple: address, private key, public key.
def generate_wallet_v3(seed=None):
    return keys_v3.generate_keypair(seed)


# Return True when a BillV3 verifies and is owned by the wallet address.
def bill_is_spendable_v3(
    store,
    bill,
    wallet_address,
    proof_bundle=None,
    trusted_operator_public_key=None,
):
    state = protocol_v3.verify_bill(
        bill,
        proof_bundle=proof_bundle,
        proof_bundle_resolver=getattr(store, "proof_bundle_resolver_v3", None),
        transparency_verifier=getattr(store, "transparency_verifier", None),
        trusted_operator_public_key=trusted_operator_public_key,
        archive_segment_resolver=getattr(store, "archive_segment_resolver_v3", None),
    )
    if wallet_address and state.owner_address != wallet_address:
        return False
    confidence = store.bill_v3_confidence(
        state.token_id,
        expected_owner=state.owner_address,
        min_settled_seconds=0,
    )
    return bool(confidence.get("accepted"))


# Spend one stored BillV3 and persist the new BillV3 tip.
def spend_wallet_bill_v3(
    wallet_lines,
    wallet_bill_line,
    recipient_address,
    store=None,
    proof_bundle=None,
    trusted_operator_public_key=None,
    timestamp=None,
):
    store = store or ind_token.INDLocalStore()
    wallet_address = _wallet_address(wallet_lines)
    if wallet_address:
        keys_v3.validate_address(wallet_address, "wallet V3 address")
    if isinstance(wallet_bill_line, dict):
        bill = wallet_bill_line
    else:
        display_id = _display_id_from_wallet_line(wallet_bill_line)
        if not display_id:
            return None
        bill = store.get_bill_v3_by_display_id(display_id)
    if not bill:
        return None
    if not bill_is_spendable_v3(
        store,
        bill,
        wallet_address,
        proof_bundle=proof_bundle,
        trusted_operator_public_key=trusted_operator_public_key,
    ):
        return None
    private_key, public_key = _wallet_keys(wallet_lines)
    transferred_bill = protocol_v3.create_transfer(
        bill,
        private_key,
        public_key,
        recipient_address,
        proof_bundle=proof_bundle,
        proof_bundle_resolver=store.proof_bundle_resolver_v3,
        trusted_operator_public_key=trusted_operator_public_key,
        archive_segment_resolver=store.archive_segment_resolver_v3,
        timestamp=timestamp,
    )
    if proof_bundle is None:
        proof_bundle = store.get_proof_bundle_v3(
            transferred_bill["proof_bundle_ref"]["proof_bundle_hash"]
        )
    announcement = protocol_v3.create_transfer_announcement(
        transferred_bill,
        proof_bundle=proof_bundle,
    )
    store.store_bill_v3(
        transferred_bill,
        proof_bundle=proof_bundle,
        status="unreceipted",
        trusted_operator_public_key=trusted_operator_public_key,
    )
    runtime_json.write_transaction_message(announcement)
    return protocol_v3.verify_bill(
        transferred_bill,
        proof_bundle=proof_bundle,
        proof_bundle_resolver=store.proof_bundle_resolver_v3,
        trusted_operator_public_key=trusted_operator_public_key,
        archive_segment_resolver=store.archive_segment_resolver_v3,
    )


# Force a compact checkpoint for one locally settled wallet bill.
def compact_wallet_bill(wallet_lines, wallet_bill_line, store=None):
    raise ind_token.ValidationError(
        protocol_policy.legacy_disabled_message("legacy compact checkpoint")
    )


def _claim_wire_message(message, wallet_lines):
    private_key, public_key = _wallet_keys(wallet_lines)
    if message.get("type") == protocol_v3.TRANSFER_ANNOUNCEMENT_TYPE:
        store = ind_token.INDLocalStore()
        try:
            bill, _proof_bundle, _segments = protocol_v3.decode_transfer_announcement(message)
            receipt = protocol_v3.create_receipt_announcement(
                bill,
                private_key,
                public_key,
                proof_bundle_resolver=store.proof_bundle_resolver_v3,
                transparency_verifier=getattr(store, "transparency_verifier", None),
                archive_segment_resolver=store.archive_segment_resolver_v3,
            )
        except (KeyError, TypeError, ind_token.ValidationError, protocol_v3.ProtocolV3Error):
            return False
        runtime_json.write_transaction_message(receipt)
        return True
    return False


def _claim_paper_wallet_payload(bill_payload, wallet_address):
    return False


# Convert a scanned bill, announcement, or paper-wallet payload into a queued claim message.
def claim_bill_payload(bill_payload, wallet_lines, wallet_address):
    try:
        message = ind_token.unpack_wire_message(bill_payload)
    except ind_token.ValidationError:
        return _claim_paper_wallet_payload(bill_payload, wallet_address)
    return _claim_wire_message(message, wallet_lines)
