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
    return wallet_line_display_id(wallet_bill_line)


def wallet_line_display_id(wallet_bill_line):
    parts = str(wallet_bill_line).split()
    if not parts:
        return None
    display_id = parts[0].lstrip("-")
    try:
        protocol_v3.parse_display_id(display_id, "wallet bill display id")
    except ind_token.ValidationError:
        return None
    return display_id


def wallet_line_is_sent(wallet_bill_line):
    parts = str(wallet_bill_line).split()
    return bool(parts and parts[0].startswith("-") and wallet_line_display_id(wallet_bill_line))


def wallet_sent_display_ids(wallet_lines):
    return set(wallet_sent_sequences(wallet_lines))


def wallet_sent_sequences(wallet_lines):
    sent_sequences = {}
    for line in runtime_json.wallet_bill_lines(wallet_lines):
        if wallet_line_is_sent(line):
            display_id = wallet_line_display_id(line)
            parts = str(line).split()
            try:
                sequence = int(parts[1])
            except (IndexError, TypeError, ValueError):
                sequence = None
            if display_id not in sent_sequences or sequence is None:
                sent_sequences[display_id] = sequence
            elif sent_sequences[display_id] is not None:
                sent_sequences[display_id] = max(sent_sequences[display_id], sequence)
    return sent_sequences


def filter_locally_sent_records(records, wallet_lines):
    sent_sequences = wallet_sent_sequences(wallet_lines)
    if not sent_sequences:
        return list(records)
    visible = []
    for record in records:
        display_id = str(record.get("display_id", "")).strip()
        if display_id not in sent_sequences:
            visible.append(record)
            continue
        sent_sequence = sent_sequences[display_id]
        if sent_sequence is None:
            continue
        try:
            record_sequence = int(record.get("sequence"))
        except (TypeError, ValueError):
            continue
        if record_sequence > sent_sequence:
            visible.append(record)
    return visible


def wallet_display_label(display_id):
    text = str(display_id).strip()
    sign = ""
    if text.startswith("-"):
        sign = "-"
        text = text[1:]
    try:
        protocol_v3.parse_display_id(text)
        return sign + text
    except ind_token.ValidationError:
        return sign + text


def wallet_display_value(display_id):
    text = str(display_id).strip()
    if text.startswith("-"):
        text = text[1:]
    try:
        return int(protocol_v3.parse_display_id(text)["value"])
    except ind_token.ValidationError:
        return 0


def wallet_owned_line_value(wallet_bill_line):
    parts = str(wallet_bill_line).split()
    if not parts or parts[0].startswith("-"):
        return 0
    return wallet_display_value(parts[0])


# Return True only when the local store considers a bill spendable.
def bill_is_spendable(store, bill, wallet_address, min_settled_seconds=0):
    if isinstance(bill, dict) and bill.get("type") == protocol_v3.BILL_TYPE:
        return bill_is_spendable_v3(store, bill, wallet_address)
    raise ind_token.ValidationError(
        protocol_policy.non_v3_disabled_message("non-V3 wallet spendability")
    )


token_is_spendable = bill_is_spendable


# List locally settled spendable bill records for one wallet address.
def spendable_wallet_records(wallet_address, store=None, limit=None):
    store = store or ind_token.INDLocalStore()
    if keys_v3.is_address(wallet_address):
        return store.bill_v3_records_for_owner(
            wallet_address,
            statuses=("settled", "verified"),
            limit=limit,
        )
    return []


# List locally known incoming bills that are visible but not spendable yet.
def pending_wallet_records(wallet_address, store=None, limit=None):
    store = store or ind_token.INDLocalStore()
    if keys_v3.is_address(wallet_address):
        return store.bill_v3_records_for_owner(
            wallet_address,
            statuses=("pending",),
            limit=limit,
        )
    return []


def validate_wallet_address(address, label="wallet V3 address"):
    return keys_v3.validate_address(str(address).strip(), label)


def validate_recipient_address(recipient_address):
    return validate_wallet_address(recipient_address, "recipient address")


def _trusted_operator_key_for_bill(
    store,
    bill,
    proof_bundle=None,
    trusted_operator_public_key=None,
):
    if trusted_operator_public_key:
        return trusted_operator_public_key
    if proof_bundle is not None:
        trusted_key_getter = getattr(store, "_trusted_operator_key_from_proof_bundle_v3", None)
        if callable(trusted_key_getter):
            trusted_key = trusted_key_getter(proof_bundle)
            if trusted_key:
                return trusted_key
    trusted_key_getter = getattr(store, "_trusted_operator_key_from_bill_v3", None)
    if callable(trusted_key_getter):
        trusted_key = trusted_key_getter(bill)
        if trusted_key:
            return trusted_key
    return None


def _archive_segments_for_proof_bundle(store, proof_bundle):
    hash_getter = getattr(store, "_archive_segment_hashes_for_proof_bundle_v3", None)
    segment_getter = getattr(store, "get_archive_segment_v3", None)
    if not callable(hash_getter) or not callable(segment_getter):
        return []
    try:
        segment_hashes = sorted(hash_getter(proof_bundle))
    except Exception:
        return []
    segments = []
    for segment_hash in segment_hashes:
        try:
            segment = segment_getter(segment_hash)
        except Exception:
            segment = None
        if segment is not None:
            segments.append(segment)
    return segments


# Spend one locally stored wallet bill and queue its transfer announcement.
def spend_wallet_bill(wallet_lines, wallet_bill_line, recipient_address, store=None):
    store = store or ind_token.INDLocalStore()
    display_id = _display_id_from_wallet_line(wallet_bill_line)
    if not display_id:
        return None
    wallet_address = _wallet_address(wallet_lines)
    spendable_lookup = getattr(store, "get_spendable_bill_v3_by_display_id", None)
    if callable(spendable_lookup) and wallet_address:
        bill_v3 = spendable_lookup(display_id, wallet_address)
    else:
        bill_v3 = store.get_bill_v3_by_display_id(display_id)
    if bill_v3:
        return spend_wallet_bill_v3(
            wallet_lines,
            bill_v3,
            recipient_address,
            store=store,
        )
    raise ind_token.ValidationError(protocol_policy.non_v3_disabled_message("non-V3 wallet spend"))


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
    trusted_operator_public_key = _trusted_operator_key_for_bill(
        store,
        bill,
        proof_bundle=proof_bundle,
        trusted_operator_public_key=trusted_operator_public_key,
    )
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
        spendable_lookup = getattr(store, "get_spendable_bill_v3_by_display_id", None)
        if callable(spendable_lookup) and wallet_address:
            bill = spendable_lookup(display_id, wallet_address)
        else:
            bill = store.get_bill_v3_by_display_id(display_id)
    if not bill:
        return None
    trusted_operator_public_key = _trusted_operator_key_for_bill(
        store,
        bill,
        proof_bundle=proof_bundle,
        trusted_operator_public_key=trusted_operator_public_key,
    )
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
    archive_segments = _archive_segments_for_proof_bundle(store, proof_bundle)
    announcement = protocol_v3.create_transfer_announcement(
        transferred_bill,
        proof_bundle=proof_bundle,
        archive_segments=archive_segments,
    )
    store.store_bill_v3(
        transferred_bill,
        proof_bundle=proof_bundle,
        status="verified",
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
    store = store or ind_token.INDLocalStore()
    display_id = _display_id_from_wallet_line(wallet_bill_line)
    if not display_id:
        return None
    compact_bill = store.compact_bill_now(display_id=display_id)
    wallet_address = _wallet_address(wallet_lines)
    if wallet_address:
        proof_bundle = store.get_proof_bundle_v3(
            compact_bill["proof_bundle_ref"]["proof_bundle_hash"]
        )
        trusted_operator_public_key = _trusted_operator_key_for_bill(
            store,
            compact_bill,
            proof_bundle=proof_bundle,
        )
        state = protocol_v3.verify_bill(
            compact_bill,
            proof_bundle=proof_bundle,
            proof_bundle_resolver=store.proof_bundle_resolver_v3,
            transparency_verifier=getattr(store, "transparency_verifier", None),
            trusted_operator_public_key=trusted_operator_public_key,
            archive_segment_resolver=store.archive_segment_resolver_v3,
        )
        if state.owner_address != wallet_address:
            return None
    return compact_bill


def claim_store():
    from . import sender_node

    return sender_node.wallet_sync_store()


def _claim_wire_message(message, wallet_lines):
    wallet_address = wallet_lines[0].strip() if wallet_lines else ""
    if message.get("type") == protocol_v3.TRANSFER_ANNOUNCEMENT_TYPE:
        store = claim_store()
        try:
            bill, proof_bundle, archive_segments = protocol_v3.decode_transfer_announcement(message)
            for segment in archive_segments:
                store.store_archive_segment_v3(segment)
            trusted_operator_public_key = None
            trusted_key_getter = getattr(store, "_trusted_operator_key_from_proof_bundle_v3", None)
            if callable(trusted_key_getter):
                trusted_operator_public_key = trusted_key_getter(proof_bundle)
            if proof_bundle is not None:
                store.store_proof_bundle_v3(
                    proof_bundle,
                    trusted_operator_public_key=trusted_operator_public_key,
                    transparency_verifier=getattr(store, "transparency_verifier", None),
                )
            state = protocol_v3.verify_bill(
                bill,
                proof_bundle=proof_bundle,
                proof_bundle_resolver=store.proof_bundle_resolver_v3,
                transparency_verifier=getattr(store, "transparency_verifier", None),
                trusted_operator_public_key=trusted_operator_public_key,
                archive_segment_resolver=store.archive_segment_resolver_v3,
            )
            if wallet_address and state.owner_address != wallet_address:
                return False
            store.store_bill_v3(
                bill,
                proof_bundle=proof_bundle,
                status="verified",
                trusted_operator_public_key=trusted_operator_public_key,
            )
        except (KeyError, TypeError, ind_token.ValidationError, protocol_v3.ProtocolV3Error):
            return False
        return True
    return False


PAPER_WALLET_KEY_CHECK_MESSAGE = b"IND paper wallet key check v1"


def _paper_wallet_payload_parts(bill_payload):
    lines = [line.strip() for line in str(bill_payload).splitlines()]
    if len(lines) < 3:
        raise ind_token.ValidationError(
            "paper wallet payload must include bill id, private key, and public key"
        )
    display_id, private_key, public_key = lines[:3]
    sequence = lines[3] if len(lines) > 3 else ""
    protocol_v3.parse_display_id(display_id, "paper wallet bill display id")
    keys_v3.decode_private_key(private_key)
    keys_v3.decode_public_key(public_key)
    signature = keys_v3.sign(private_key, PAPER_WALLET_KEY_CHECK_MESSAGE)
    if not keys_v3.verify(public_key, signature, PAPER_WALLET_KEY_CHECK_MESSAGE):
        raise ind_token.ValidationError("paper wallet private key does not match public key")
    return display_id, private_key, public_key, sequence


def _claim_paper_wallet_payload(bill_payload, wallet_address):
    try:
        recipient_address = validate_recipient_address(wallet_address)
        display_id, private_key, public_key, _sequence = _paper_wallet_payload_parts(bill_payload)
        paper_wallet_address = keys_v3.address_from_public_key(public_key)
        store = claim_store()
        bill = store.get_spendable_bill_v3_by_display_id(display_id, paper_wallet_address)
        if not bill:
            raise ind_token.ValidationError(
                f"{display_id} is not spendable for the scanned paper wallet on this network. "
                "Charge the printed PDF first, wait for the send to queue, then sync before claiming."
            )
        paper_wallet_lines = [
            paper_wallet_address + "\n",
            private_key + "\n",
            public_key + "\n",
        ]
        return bool(
            spend_wallet_bill_v3(
                paper_wallet_lines,
                bill,
                recipient_address,
                store=store,
            )
        )
    except (KeyError, TypeError, protocol_v3.ProtocolV3Error) as exc:
        raise ind_token.ValidationError(f"paper wallet claim failed: {exc}") from exc


# Convert a scanned bill, announcement, or paper-wallet payload into a queued claim message.
def claim_bill_payload(bill_payload, wallet_lines, wallet_address):
    try:
        message = ind_token.unpack_wire_message(bill_payload)
    except ind_token.ValidationError:
        return _claim_paper_wallet_payload(bill_payload, wallet_address)
    return _claim_wire_message(message, wallet_lines)
