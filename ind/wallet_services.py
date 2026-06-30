# Testable wallet actions shared by the desktop UI and scripts.

import os
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import keys_v3, protocol_policy, protocol_v3
from . import runtime as runtime_json
from . import token as ind_token

WALLET_SIGN_WORKERS_ENV = "IND_WALLET_SIGN_WORKERS"
WALLET_SIGN_DEFAULT_MAX_WORKERS = 4


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


# Extract and validate the display id from one wallet bill line.
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


# Return whether a wallet line marks a local bill as already sent.
def wallet_line_is_sent(wallet_bill_line):
    parts = str(wallet_bill_line).split()
    return bool(parts and parts[0].startswith("-") and wallet_line_display_id(wallet_bill_line))


def wallet_sent_display_ids(wallet_lines):
    return set(wallet_sent_sequences(wallet_lines))


# Track the latest locally sent sequence per display id so stale rows stay hidden.
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


# Filter store rows so wallet history does not show locally superseded bill tips.
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


# Return the display label the UI should show for a wallet bill id.
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


# Parse the denomination value from a wallet display id.
def wallet_display_value(display_id):
    text = str(display_id).strip()
    if text.startswith("-"):
        text = text[1:]
    try:
        return int(protocol_v3.parse_display_id(text)["value"])
    except ind_token.ValidationError:
        return 0


# Return the best timestamp available for the latest transfer in a bill record.
def latest_bill_transfer_timestamp(record=None, bill=None, fallback=None):
    if not isinstance(bill, dict):
        blob = dict(record or {}).get("bill_blob")
        if blob is not None:
            try:
                bill = protocol_v3.decode_bill(bytes(blob))
            except Exception:
                bill = None
    if isinstance(bill, dict):
        transfers = bill.get("recent_transfers")
        if isinstance(transfers, list) and transfers:
            try:
                return int(transfers[-1]["timestamp"])
            except (KeyError, TypeError, ValueError):
                pass
        checkpoint = bill.get("checkpoint_core")
        if isinstance(checkpoint, dict):
            try:
                return int(checkpoint["last_transfer_timestamp"])
            except (KeyError, TypeError, ValueError):
                pass
    if fallback is not None:
        try:
            return int(fallback)
        except (TypeError, ValueError):
            return None
    return None


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


def _spendable_v3_statuses(store):
    statuses = getattr(store, "spendable_bill_v3_statuses", None)
    if callable(statuses):
        return tuple(statuses())
    return ("settled", "verified")


# List locally settled spendable bill records for one wallet address.
def spendable_wallet_records(wallet_address, store=None, limit=None, offset=0):
    store = store or ind_token.INDLocalStore()
    if keys_v3.is_address(wallet_address):
        statuses = _spendable_v3_statuses(store)
        if offset:
            return store.bill_v3_records_for_owner(
                wallet_address,
                statuses=statuses,
                limit=limit,
                offset=offset,
            )
        return store.bill_v3_records_for_owner(
            wallet_address,
            statuses=statuses,
            limit=limit,
        )
    return []


def spendable_wallet_display_ids(wallet_address, display_ids, store=None):
    store = store or ind_token.INDLocalStore()
    display_ids = [str(display_id).strip() for display_id in display_ids if str(display_id).strip()]
    if not display_ids or not keys_v3.is_address(wallet_address):
        return set()
    display_id_lookup = getattr(store, "spendable_bill_v3_display_ids", None)
    if callable(display_id_lookup):
        return set(display_id_lookup(wallet_address, display_ids))
    spendable_lookup = getattr(store, "get_spendable_bill_v3_by_display_id", None)
    if callable(spendable_lookup):
        return {
            display_id
            for display_id in display_ids
            if spendable_lookup(display_id, wallet_address)
        }
    selected_ids = set(display_ids)
    return {
        str(record.get("display_id") or "").strip()
        for record in spendable_wallet_records(wallet_address, store=store, limit=None)
        if str(record.get("display_id") or "").strip() in selected_ids
    }


# List locally known incoming bills that are visible but not spendable yet.
def pending_wallet_records(wallet_address, store=None, limit=None, offset=0):
    store = store or ind_token.INDLocalStore()
    if keys_v3.is_address(wallet_address):
        statuses = ["pending"]
        if "verified" not in _spendable_v3_statuses(store):
            statuses.append("verified")
        statuses = tuple(statuses)
        if offset:
            return store.bill_v3_records_for_owner(
                wallet_address,
                statuses=statuses,
                limit=limit,
                offset=offset,
            )
        return store.bill_v3_records_for_owner(
            wallet_address,
            statuses=statuses,
            limit=limit,
        )
    return []


def wallet_metadata_records(wallet_address, store=None, statuses=None, limit=None, offset=0):
    if not keys_v3.is_address(wallet_address):
        return []
    store = store or ind_token.INDLocalStore()
    metadata_reader = getattr(store, "bill_v3_metadata_records_for_owner", None)
    if callable(metadata_reader):
        if offset:
            return metadata_reader(wallet_address, statuses=statuses, limit=limit, offset=offset)
        return metadata_reader(wallet_address, statuses=statuses, limit=limit)
    counter = getattr(store, "bill_v3_count_records_for_owner", None)
    if callable(counter) and limit is None and not offset:
        return counter(wallet_address, statuses=statuses)
    if offset:
        return store.bill_v3_records_for_owner(
            wallet_address,
            statuses=statuses,
            limit=limit,
            offset=offset,
        )
    return store.bill_v3_records_for_owner(wallet_address, statuses=statuses, limit=limit)


def wallet_count_records(wallet_address, store=None, statuses=None):
    return wallet_metadata_records(wallet_address, store=store, statuses=statuses, limit=None)


def spendable_wallet_metadata_records(
    wallet_address,
    store=None,
    wallet_lines=None,
    limit=None,
    offset=0,
):
    store = store or ind_token.INDLocalStore()
    records = wallet_metadata_records(
        wallet_address,
        store=store,
        statuses=_spendable_v3_statuses(store),
        limit=limit,
        offset=offset,
    )
    return filter_locally_sent_records(records, wallet_lines or [])


def bill_finality_progress(store=None, bill=None, record=None, status=None):
    store = store or ind_token.INDLocalStore()
    status = str(status if status is not None else dict(record or {}).get("status") or "").lower()
    if bill is None:
        blob = dict(record or {}).get("bill_blob")
        if blob is not None:
            try:
                bill = protocol_v3.decode_bill(bytes(blob))
            except Exception:
                bill = None
    progress_reader = getattr(store, "bill_v3_finality_progress", None)
    if callable(progress_reader) and isinstance(bill, dict):
        progress = progress_reader(bill, status=status)
        if isinstance(progress, dict):
            return progress
    spendable = bool(status and status in _spendable_v3_statuses(store))
    return {
        "status": status,
        "required_proofs": 0,
        "proven_proofs": 0,
        "pending_proofs": 0,
        "failed_proofs": 0,
        "awaiting_transparency": False,
        "divergent_witness": False,
        "spendable": spendable,
    }


# Count spendable and pending bills by denomination without loading full bill blobs.
def wallet_balance_counts(wallet_address, store=None, wallet_lines=None, bill_values=None):
    store = store or ind_token.INDLocalStore()
    bill_values = tuple(bill_values or ())
    spendable_counts = {value: 0 for value in bill_values}
    pending_counts = {value: 0 for value in bill_values}
    spendable_statuses = set(_spendable_v3_statuses(store))
    records = wallet_count_records(
        wallet_address,
        store=store,
        statuses=("settled", "verified", "pending"),
    )
    sent_sequences = wallet_sent_sequences(wallet_lines or [])
    for record in records:
        value = wallet_display_value(record.get("display_id", ""))
        if value not in spendable_counts:
            continue
        status = str(record.get("status") or "").lower()
        display_id = str(record.get("display_id") or "").strip()
        if status == "pending":
            pending_counts[value] += 1
            continue
        if status not in spendable_statuses:
            if status == "verified":
                pending_counts[value] += 1
            continue
        sent_sequence = sent_sequences.get(display_id)
        if sent_sequence is not None:
            try:
                if int(record.get("sequence")) <= int(sent_sequence):
                    continue
            except (TypeError, ValueError):
                continue
        spendable_counts[value] += 1
    total = sum(value * count for value, count in spendable_counts.items())
    return {
        "bill_counts": spendable_counts,
        "pending_bill_counts": pending_counts,
        "balance": total,
    }


def validate_wallet_address(address, label="wallet V3 address"):
    return keys_v3.validate_address(str(address).strip(), label)


def validate_recipient_address(recipient_address):
    return validate_wallet_address(recipient_address, "recipient address")


# Choose a bounded signing worker count for batch sends.
def wallet_sign_worker_count(batch_size, workers=None):
    try:
        batch_size = max(0, int(batch_size or 0))
    except (TypeError, ValueError):
        batch_size = 0
    if batch_size <= 1:
        return 1

    if workers is None:
        raw_workers = os.environ.get(WALLET_SIGN_WORKERS_ENV, "").strip()
        if raw_workers:
            try:
                workers = int(raw_workers)
            except ValueError:
                workers = None

    if workers is None:
        workers = min(os.cpu_count() or 1, WALLET_SIGN_DEFAULT_MAX_WORKERS)

    try:
        workers = int(workers)
    except (TypeError, ValueError):
        workers = 1
    return max(1, min(batch_size, workers))


def _wallet_spend_item_display_id(wallet_bill_line):
    if isinstance(wallet_bill_line, dict):
        checkpoint = wallet_bill_line.get("checkpoint_core") or {}
        display_id = str(checkpoint.get("display_id") or "").strip()
        if display_id:
            return display_id
        return str(wallet_bill_line.get("display_id") or "").strip() or None
    return _display_id_from_wallet_line(wallet_bill_line)


def _resolve_wallet_bill_v3(store, wallet_address, wallet_bill_line):
    if isinstance(wallet_bill_line, dict):
        return wallet_bill_line
    display_id = _display_id_from_wallet_line(wallet_bill_line)
    if not display_id:
        return None
    spendable_lookup = getattr(store, "get_spendable_bill_v3_by_display_id", None)
    if callable(spendable_lookup) and wallet_address:
        return spendable_lookup(display_id, wallet_address)
    return store.get_bill_v3_by_display_id(display_id)


def _batch_recipient_address(recipient_address, index, display_id):
    if isinstance(recipient_address, dict):
        return recipient_address[display_id]
    if isinstance(recipient_address, (list, tuple)):
        return recipient_address[index]
    return recipient_address


# Resolve the operator key that should be trusted for a bill or its proof bundle.
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


# Load archive segments referenced by a proof bundle when the store can provide them.
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


# Prepare one stored BillV3 transfer without mutating the wallet, store, or send queue.
def prepare_spend_wallet_bill_v3(
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
    bill = _resolve_wallet_bill_v3(store, wallet_address, wallet_bill_line)
    if not bill:
        return None
    cached_state = protocol_v3.cached_bill_state(bill)
    if wallet_address and cached_state["owner_address"] != wallet_address:
        return None
    private_key, public_key = _wallet_keys(wallet_lines)
    proof_bundle_for_transfer = proof_bundle
    if proof_bundle_for_transfer is None:
        proof_ref = bill.get("proof_bundle_ref") if isinstance(bill, dict) else None
        proof_hash = (proof_ref or {}).get("proof_bundle_hash")
        if proof_hash:
            proof_bundle_for_transfer = store.get_proof_bundle_v3(proof_hash)
    transferred_bill, state = protocol_v3.create_transfer_from_cached_bill(
        bill,
        private_key,
        public_key,
        recipient_address,
        timestamp=timestamp,
        cached_state=cached_state,
    )
    if proof_bundle_for_transfer is None:
        proof_bundle_for_transfer = store.get_proof_bundle_v3(
            transferred_bill["proof_bundle_ref"]["proof_bundle_hash"]
        )
    archive_segments = _archive_segments_for_proof_bundle(store, proof_bundle_for_transfer)
    announcement = protocol_v3.create_transfer_announcement(
        transferred_bill,
        proof_bundle=proof_bundle_for_transfer,
        archive_segments=archive_segments,
    )
    return {
        "bill": transferred_bill,
        "proof_bundle": proof_bundle_for_transfer,
        "archive_segments": archive_segments,
        "announcement": announcement,
        "state": state,
        "trusted_operator_public_key": trusted_operator_public_key,
        "history_timestamp": latest_bill_transfer_timestamp(bill=transferred_bill),
    }


# Persist a prepared spend and queue its transfer announcement for gossip.
def commit_prepared_wallet_spend_v3(prepared, store=None):
    if not prepared:
        return None
    store = store or ind_token.INDLocalStore()
    ensure_prepared_wallet_spend_is_current(prepared, store=store)
    cached_store = getattr(store, "store_cached_bill_v3", None)
    if callable(cached_store):
        cached_store(prepared["bill"], prepared["state"], status="verified")
    else:
        store.store_bill_v3(
            prepared["bill"],
            proof_bundle=prepared.get("proof_bundle"),
            status="verified",
            trusted_operator_public_key=prepared.get("trusted_operator_public_key"),
        )
    runtime_json.write_transaction_message(prepared["announcement"])
    return prepared["state"]


# Recheck the source bill tip so a prepared spend cannot commit stale state.
def ensure_prepared_wallet_spend_is_current(prepared, store=None):
    store = store or ind_token.INDLocalStore()
    bill = prepared.get("bill") if isinstance(prepared, dict) else None
    transfers = bill.get("recent_transfers") if isinstance(bill, dict) else None
    if not transfers:
        raise ind_token.ValidationError("prepared wallet spend is missing its transfer")
    transfer = transfers[-1]
    display_id = str(getattr(prepared.get("state"), "display_id", "") or "").strip()
    sender_address = str(transfer.get("sender_address") or "").strip()
    if not display_id or not sender_address:
        raise ind_token.ValidationError("prepared wallet spend is missing its source")
    source_lookup = getattr(store, "get_spendable_bill_v3_by_display_id", None)
    if not callable(source_lookup):
        return True
    source_bill = source_lookup(display_id, sender_address)
    if not source_bill:
        raise ind_token.ValidationError("bill tip changed while signing; sync and retry")
    source_state = protocol_v3.cached_bill_state(source_bill)
    if int(source_state["sequence"]) + 1 != int(transfer["sequence"]):
        raise ind_token.ValidationError("bill sequence changed while signing; sync and retry")
    if source_state["last_transfer_hash"] != transfer["previous_hash"]:
        raise ind_token.ValidationError("bill tip changed while signing; sync and retry")
    return True


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
    prepared = prepare_spend_wallet_bill_v3(
        wallet_lines,
        wallet_bill_line,
        recipient_address,
        store=store,
        proof_bundle=proof_bundle,
        trusted_operator_public_key=trusted_operator_public_key,
        timestamp=timestamp,
    )
    return commit_prepared_wallet_spend_v3(prepared, store=store)


# Sign several wallet bills concurrently but commit results in the original order.
def spend_wallet_bills_batch(
    wallet_lines,
    wallet_bill_lines,
    recipient_address,
    store=None,
    proof_bundle=None,
    trusted_operator_public_key=None,
    workers=None,
    progress_callback=None,
    timestamp=None,
):
    store = store or ind_token.INDLocalStore()
    wallet_bill_lines = list(wallet_bill_lines or [])
    results = [
        {
            "display_id": _wallet_spend_item_display_id(wallet_bill_line),
            "state": None,
            "history_timestamp": None,
            "error": None,
        }
        for wallet_bill_line in wallet_bill_lines
    ]
    ready = {}
    submitted_indices = []
    seen_display_ids = set()

    for index, _wallet_bill_line in enumerate(wallet_bill_lines):
        display_id = results[index]["display_id"]
        if not display_id:
            ready[index] = ("error", ind_token.ValidationError("wallet bill is not spendable"))
            continue
        if display_id in seen_display_ids:
            ready[index] = ("error", ind_token.ValidationError(f"duplicate bill selected: {display_id}"))
            continue
        seen_display_ids.add(display_id)
        submitted_indices.append(index)

    worker_count = wallet_sign_worker_count(len(submitted_indices), workers=workers)
    total = len(wallet_bill_lines)
    completed = 0
    next_commit_index = 0

    def emit_progress(message):
        if progress_callback:
            progress_callback(completed, total, message)

    if total:
        if worker_count > 1:
            emit_progress(f"Signing {total} bills with {worker_count} workers")
        else:
            emit_progress(f"Signing {total} bills")

    def prepare_index(index):
        display_id = results[index]["display_id"]
        recipient = _batch_recipient_address(recipient_address, index, display_id)
        prepared = prepare_spend_wallet_bill_v3(
            wallet_lines,
            wallet_bill_lines[index],
            recipient,
            store=store,
            proof_bundle=proof_bundle,
            trusted_operator_public_key=trusted_operator_public_key,
            timestamp=timestamp,
        )
        if not prepared:
            raise RuntimeError("bill is not spendable or is not settled")
        return prepared

    def commit_ready_results():
        nonlocal completed, next_commit_index
        while next_commit_index < total and next_commit_index in ready:
            index = next_commit_index
            kind, payload = ready.pop(index)
            display_id = results[index]["display_id"] or "bill"
            if kind == "prepared":
                try:
                    state = commit_prepared_wallet_spend_v3(payload, store=store)
                    results[index]["state"] = state
                    results[index]["history_timestamp"] = payload.get("history_timestamp")
                    emit_message = f"Signed {display_id}"
                except Exception as exc:
                    results[index]["error"] = exc
                    emit_message = f"Failed {display_id}"
            else:
                results[index]["error"] = payload
                emit_message = f"Failed {display_id}"
            completed += 1
            emit_progress(emit_message)
            next_commit_index += 1

    commit_ready_results()
    if not submitted_indices:
        return results

    if worker_count <= 1:
        for index in submitted_indices:
            try:
                ready[index] = ("prepared", prepare_index(index))
            except Exception as exc:
                ready[index] = ("error", exc)
            commit_ready_results()
        return results

    with ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix="INDWalletSign") as executor:
        future_by_index = {
            executor.submit(prepare_index, index): index for index in submitted_indices
        }
        for future in as_completed(future_by_index):
            index = future_by_index[future]
            try:
                ready[index] = ("prepared", future.result())
            except Exception as exc:
                ready[index] = ("error", exc)
            commit_ready_results()

    commit_ready_results()
    return results


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


# Return the store used for QR and paper-wallet claim operations.
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


# Parse and prove key ownership for the private-key payload printed on paper bills.
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


# Spend a scanned paper wallet bill into the active wallet address.
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
