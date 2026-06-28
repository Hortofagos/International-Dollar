#!/usr/bin/env python3
"""Finalize an offline mainnet treasury transfer bundle into a live V3 log/store.

The offline bundle contains signed first transfers from genesis owners, but those
transfers are not usable by wallets until an operator appends transfer and
checkpoint commitments, publishes a signed root, and stores the resulting proof
bundles plus compact BillV3 records in a node store.
"""

import argparse
import json
import os
import sys
import time
from hashlib import sha3_256
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

os.environ.setdefault("IND_NETWORK", "mainnet")
os.environ.setdefault("IND_ALLOW_UNTRUSTED_GENESIS", "0")

from ind import archive_segment_v3
from ind import genesis_manifest_v3
from ind import proof_bundle_v3
from ind import protocol_v3
from ind import spend_map_v3
from ind import transparency_client as log_client
from ind.store import INDLocalStore
from ind.transparency_server import TransparencyLog, load_or_create_operator_keys

MAINNET_NETWORK_ID = 1


def _load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _sha3_text(text):
    return sha3_256(str(text).encode("utf-8")).hexdigest()


def _die(message):
    raise RuntimeError(message)


def _range_for_serial(ranges, value, serial):
    for item in ranges:
        if item["value"] == value and item["start_serial"] <= serial <= item["end_serial"]:
            return item
    _die(f"{value}x{serial} is not covered by the manifest")


def _derive_genesis_hash(manifest, verified, range_def, value, serial):
    nonce = genesis_manifest_v3._sha3_json(
        {
            "algorithm": genesis_manifest_v3.GENESIS_NONCE_ALGORITHM,
            "manifest_hash": verified["manifest_hash"],
            "value": int(value),
            "serial": int(serial),
            "range_start_serial": int(range_def["start_serial"]),
            "range_count": int(range_def["count"]),
            "owner_address": range_def["owner_address"],
            "nonce_seed": range_def["nonce_seed"],
        }
    )
    return genesis_manifest_v3._sha3_json(
        {
            "algorithm": genesis_manifest_v3.GENESIS_HASH_ALGORITHM,
            "network_id": int(manifest["network_id"]),
            "manifest_hash": verified["manifest_hash"],
            "issuer_key_id": verified["issuer_key_id"],
            "value": int(value),
            "serial": int(serial),
            "owner_address": range_def["owner_address"],
            "issued_at": int(manifest["issued_at"]),
            "nonce": nonce,
        }
    )


def _expected_genesis_ref(manifest, verified, genesis_hash, serial):
    return {
        "type": protocol_v3.GENESIS_REF_TYPE,
        "version": protocol_v3.VERSION,
        "network_id": int(manifest["network_id"]),
        "genesis_hash": genesis_hash,
        "manifest_hash": verified["manifest_hash"],
        "issuer_key_id": verified["issuer_key_id"],
        "issue_index": int(serial),
        "issued_at": int(manifest["issued_at"]),
    }


def _expected_base_state(manifest, range_def, genesis_hash, value):
    issued_at = int(manifest["issued_at"])
    return {
        "sequence": 0,
        "owner_address": range_def["owner_address"],
        "last_transfer_hash": genesis_hash,
        "last_transfer_timestamp": issued_at,
        "last_transfer_day": issued_at // 86400,
        "transfers_in_last_day": 0,
        "display_id": f"{int(value)}x{int(range_def['_serial'])}",
        "value": int(value),
    }


def _expected_token_id(network, genesis_hash):
    return _sha3_text(f"IND:{network}:token:v3:{genesis_hash}")


def _record_evidence_message(store, message):
    with store._connect() as conn:
        store._record_message(conn, message)


def _store_verified_proof_bundle(store, proof_bundle, checkpoint_core):
    now = int(time.time())
    signed_root = proof_bundle["signed_root"]
    with store._connect() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO proof_bundles_v3(
                proof_bundle_hash, log_id, signed_root_hash, tree_size, algorithm,
                bundle_blob, first_seen, last_verified
            ) VALUES (
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                COALESCE(
                    (SELECT first_seen FROM proof_bundles_v3 WHERE proof_bundle_hash = ?),
                    ?
                ),
                ?
            )
            """,
            (
                proof_bundle["proof_bundle_hash"],
                str(proof_bundle["log_id"]),
                log_client.signed_root_id(signed_root),
                int(signed_root["tree_size"]),
                int(proof_bundle["algorithm"]),
                proof_bundle_v3.encode_proof_bundle(proof_bundle),
                proof_bundle["proof_bundle_hash"],
                now,
                now,
            ),
        )
        store._store_issued_checkpoint_v3_conn(
            conn,
            checkpoint_core,
            proof_bundle=proof_bundle,
            status="verified_checkpoint",
        )


def _store_verified_proof_bundle_conn(store, conn, proof_bundle, checkpoint_core, now):
    signed_root = proof_bundle["signed_root"]
    conn.execute(
        """
        INSERT OR REPLACE INTO proof_bundles_v3(
            proof_bundle_hash, log_id, signed_root_hash, tree_size, algorithm,
            bundle_blob, first_seen, last_verified
        ) VALUES (
            ?,
            ?,
            ?,
            ?,
            ?,
            ?,
            COALESCE(
                (SELECT first_seen FROM proof_bundles_v3 WHERE proof_bundle_hash = ?),
                ?
            ),
            ?
        )
        """,
        (
            proof_bundle["proof_bundle_hash"],
            str(proof_bundle["log_id"]),
            log_client.signed_root_id(signed_root),
            int(signed_root["tree_size"]),
            int(proof_bundle["algorithm"]),
            proof_bundle_v3.encode_proof_bundle(proof_bundle),
            proof_bundle["proof_bundle_hash"],
            now,
            now,
        ),
    )
    store._store_issued_checkpoint_v3_conn(
        conn,
        checkpoint_core,
        proof_bundle=proof_bundle,
        status="verified_checkpoint",
    )


def _store_verified_bill(store, bill, checkpoint_core, status):
    state = protocol_v3._token_state_from_v3_state(
        bill["token_id"],
        protocol_v3._initial_state_from_checkpoint_core(checkpoint_core),
    )
    with store._connect() as conn:
        return store._store_bill_v3_conn(conn, bill, state, status)


def _store_verified_bill_conn(store, conn, bill, checkpoint_core, status):
    state = protocol_v3._token_state_from_v3_state(
        bill["token_id"],
        protocol_v3._initial_state_from_checkpoint_core(checkpoint_core),
    )
    return store._store_bill_v3_conn(conn, bill, state, status)


def _store_verified_archive_segment_conn(store, conn, segment, checkpoint_core, now):
    conn.execute(
        """
        INSERT OR IGNORE INTO archive_segments_v3(
            segment_hash, token_id, start_sequence, end_sequence,
            previous_segment_hash, checkpoint_hash, segment_blob, first_seen
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            segment["segment_hash"],
            segment["token_id"],
            int(segment["start_sequence"]),
            int(segment["end_sequence"]),
            segment["previous_segment_hash"],
            checkpoint_core["checkpoint_hash"],
            archive_segment_v3.encode_archive_segment(segment),
            now,
        ),
    )
    store._store_issued_checkpoint_v3_conn(
        conn,
        checkpoint_core,
        status="archive_segment",
    )


def _cached_spend_map_proof(log, conn, spend_key, tree_size, map_size):
    spend_key = log_client._hex32(spend_key, "spend key")
    claims = log._claims_for_current_spend_key(conn, spend_key)
    if not claims:
        raise RuntimeError("spend key is not in the transparency spend map")
    audit_path = []
    node_position = log_client._spend_key_position(spend_key)
    for child_depth in range(log_client.SPEND_MAP_KEY_BITS, 0, -1):
        sibling_position = node_position ^ 1
        sibling_hash = log._spend_map_hash_at(conn, child_depth, sibling_position)
        side = "right" if node_position % 2 == 0 else "left"
        audit_path.append({"side": side, "hash": sibling_hash})
        node_position >>= 1
    return {
        "type": log_client.LOG_SPEND_MAP_PROOF_TYPE,
        "version": log_client.LOG_VERSION,
        "algorithm": log_client.LOG_SPEND_MAP_ALGORITHM,
        "spend_key": spend_key,
        "tree_size": int(tree_size),
        "map_size": int(map_size),
        "spend_claims": claims,
        "audit_path": audit_path,
    }


def _validate_header(bundle, manifest, verified, expected_manifest_hash, expected_network):
    manifest_hash = verified["manifest_hash"]
    if expected_manifest_hash and manifest_hash != expected_manifest_hash.lower():
        _die("manifest hash does not match --expected-manifest-hash")
    if bundle.get("type") != "ind.mainnet_treasury_transfer_bundle.v3":
        _die("unexpected bundle type")
    if int(bundle.get("version", 0)) != 3:
        _die("unexpected bundle version")
    if str(bundle.get("network")) != expected_network:
        _die("bundle network mismatch")
    if int(bundle.get("network_id", -1)) != int(manifest["network_id"]):
        _die("bundle network id mismatch")
    if int(bundle.get("network_id", -1)) != MAINNET_NETWORK_ID:
        _die("bundle is not mainnet network id 1")
    if str(bundle.get("manifest_hash", "")).lower() != manifest_hash:
        _die("bundle manifest hash does not match manifest")
    if str(bundle.get("status")) != "offline_signed_needs_online_finalization":
        _die("bundle status is not offline_signed_needs_online_finalization")
    if not bundle.get("online_finalization_required"):
        _die("bundle does not declare online finalization required")
    transfers = bundle.get("transfers")
    if not isinstance(transfers, list) or not transfers:
        _die("bundle has no transfers")
    if int(bundle.get("total_bill_count", 0)) != len(transfers):
        _die("bundle total_bill_count mismatch")
    return transfers


def _prepare_items(bundle, manifest, verified, transfers, limit=None, progress_interval=1000):
    expected_network = str(bundle["network"])
    expected_recipient = str(bundle["recipient_address"])
    ranges = verified["ranges"]
    prepared = []
    seen_token_ids = set()
    seen_transfer_hashes = set()
    seen_spend_keys = set()
    selected = transfers[: int(limit)] if limit else transfers
    for index, item in enumerate(selected, start=1):
        value = int(item["value"])
        serial = int(item["serial"])
        display_id = str(item["display_id"])
        if display_id != f"{value}x{serial}":
            _die(f"transfer {index} display id mismatch")
        range_def = dict(_range_for_serial(ranges, value, serial))
        range_def["_serial"] = serial
        genesis_hash = _derive_genesis_hash(manifest, verified, range_def, value, serial)
        expected_ref = _expected_genesis_ref(manifest, verified, genesis_hash, serial)
        expected_base = _expected_base_state(manifest, range_def, genesis_hash, value)
        token_id = _expected_token_id(expected_network, genesis_hash)
        transfer = item["transfer"]
        if item["genesis_ref"] != expected_ref:
            _die(f"{display_id} genesis_ref does not match manifest")
        if item["base_state"] != expected_base:
            _die(f"{display_id} base_state does not match manifest")
        if str(item["token_id"]) != token_id:
            _die(f"{display_id} token id mismatch")
        if str(transfer["recipient_address"]) != expected_recipient:
            _die(f"{display_id} recipient mismatch")
        if int(transfer["network_id"]) != MAINNET_NETWORK_ID:
            _die(f"{display_id} transfer is not mainnet")
        state = protocol_v3.verify_transfer_sequence_from_state(
            token_id,
            expected_base,
            [transfer],
            network_id=MAINNET_NETWORK_ID,
        )
        if state["owner_address"] != expected_recipient:
            _die(f"{display_id} final owner mismatch")
        transfer_hash = protocol_v3.transfer_hash(transfer)
        if str(item["transfer_hash"]).lower() != transfer_hash:
            _die(f"{display_id} transfer hash mismatch")
        spend_key = protocol_v3.spend_key_for_transfer(transfer)
        if token_id in seen_token_ids:
            _die(f"duplicate token id at {display_id}")
        if transfer_hash in seen_transfer_hashes:
            _die(f"duplicate transfer hash at {display_id}")
        if spend_key in seen_spend_keys:
            _die(f"duplicate spend key at {display_id}")
        seen_token_ids.add(token_id)
        seen_transfer_hashes.add(transfer_hash)
        seen_spend_keys.add(spend_key)
        archive_segment = archive_segment_v3.make_archive_segment(
            token_id,
            expected_ref,
            expected_base,
            [transfer],
            network_id=MAINNET_NETWORK_ID,
        )
        checkpoint_core = archive_segment_v3.verify_archive_segment(
            archive_segment,
            expected_network_id=MAINNET_NETWORK_ID,
        )
        prepared.append(
            {
                "display_id": display_id,
                "value": value,
                "serial": serial,
                "token_id": token_id,
                "genesis_ref": expected_ref,
                "base_state": expected_base,
                "transfer": transfer,
                "transfer_hash": transfer_hash,
                "spend_key": spend_key,
                "archive_segment": archive_segment,
                "checkpoint_core": checkpoint_core,
                "checkpoint_hash": checkpoint_core["checkpoint_hash"],
            }
        )
        if progress_interval and index % int(progress_interval) == 0:
            print(f"validated {index}/{len(selected)} bundle transfers", file=sys.stderr, flush=True)
    return prepared


def _append_entries(log, prepared, progress_interval=1000):
    entry_time = max(int(time.time()), max(int(item["transfer"]["timestamp"]) for item in prepared) + 1)
    if log.tree_size() == 0:
        with log._append_lock:
            rows = []
            with log._tree() as tree:
                for item in prepared:
                    transfer_leaf_index = int(
                        tree.append_entry(bytes.fromhex(item["transfer_hash"]))
                    )
                    checkpoint_leaf_index = int(
                        tree.append_entry(bytes.fromhex(item["checkpoint_hash"]))
                    )
                    rows.append(
                        (
                            item["transfer_hash"],
                            transfer_leaf_index,
                            entry_time,
                            "transfer",
                            None,
                            log_client.canonical_json(item["transfer"]),
                        )
                    )
                    rows.append(
                        (
                            item["checkpoint_hash"],
                            checkpoint_leaf_index,
                            entry_time,
                            "checkpoint",
                            log_client.canonical_json(item["checkpoint_core"]),
                            None,
                        )
                    )
                    item["transfer_leaf_index"] = transfer_leaf_index - 1
                    item["checkpoint_leaf_index"] = checkpoint_leaf_index - 1
            with log._connect() as conn:
                conn.executemany(
                    """
                    INSERT OR IGNORE INTO log_entries(
                        entry_hash, leaf_index, submitted_at, entry_kind, entry_json, transfer_json
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    rows,
                )
                for index, item in enumerate(prepared, start=1):
                    claim = protocol_v3.spend_claim_for_transfer(
                        item["transfer"],
                        log.log_id,
                        int(item["transfer_leaf_index"]),
                        entry_time,
                    )
                    log._record_spend_claim(
                        conn,
                        claim,
                        item["transfer_hash"],
                        int(item["transfer_leaf_index"]),
                        entry_time,
                    )
                    if progress_interval and index % int(progress_interval) == 0:
                        print(
                            f"bulk-appended {index}/{len(prepared)} transfers/checkpoints",
                            file=sys.stderr,
                            flush=True,
                        )
        return entry_time
    for index, item in enumerate(prepared, start=1):
        transfer_append = log.append_entry_hash(
            item["transfer_hash"],
            submitted_at=entry_time,
            transfer=item["transfer"],
        )
        claim = protocol_v3.spend_claim_for_transfer(
            item["transfer"],
            log.log_id,
            int(transfer_append["leaf_index"]),
            entry_time,
        )
        with log._connect() as conn:
            log._record_spend_claim(
                conn,
                claim,
                item["transfer_hash"],
                int(transfer_append["leaf_index"]),
                entry_time,
            )
        checkpoint_append = log.append_entry_hash(
            item["checkpoint_hash"],
            submitted_at=entry_time,
            entry_kind="checkpoint",
            entry=item["checkpoint_core"],
        )
        item["transfer_leaf_index"] = int(transfer_append["leaf_index"])
        item["checkpoint_leaf_index"] = int(checkpoint_append["leaf_index"])
        if progress_interval and index % int(progress_interval) == 0:
            print(f"appended {index}/{len(prepared)} transfers/checkpoints", file=sys.stderr, flush=True)
    return entry_time


def _store_finalized_bills(
    log,
    store,
    prepared,
    operator_public,
    root,
    status,
    record_evidence_messages,
    use_store_api,
    progress_interval=1000,
):
    tree_size = int(root["tree_size"])
    root_id = log_client.signed_root_id(root)
    store_now = int(time.time())
    store_conn = None if use_store_api else store._connect()
    proof_conn = log._connect()
    with proof_conn:
        _root_hash, map_size = log._ensure_current_spend_map(proof_conn)
    proof_conn = log._connect()
    try:
        for index, item in enumerate(prepared, start=1):
            inclusion = log.inclusion_proof(item["checkpoint_hash"], tree_size)
            spend_proof = _cached_spend_map_proof(
                log,
                proof_conn,
                item["spend_key"],
                tree_size,
                map_size,
            )
            compressed = spend_map_v3.compress_spend_map_proof(
                spend_proof,
                network_id=MAINNET_NETWORK_ID,
            )
            source_evidence = proof_bundle_v3.make_archive_segment_evidence(
                item["archive_segment"],
                network_id=MAINNET_NETWORK_ID,
                include_segment=False,
            )
            proof_bundle = proof_bundle_v3.make_proof_bundle(
                item["checkpoint_core"],
                root,
                inclusion,
                compressed,
                source_evidence,
                network_id=MAINNET_NETWORK_ID,
                created_at=int(root["timestamp"]),
            )
            bill = protocol_v3.create_bill_from_checkpoint_core(
                item["genesis_ref"],
                item["checkpoint_core"],
                proof_bundle,
                recent_transfers=[],
                network_id=MAINNET_NETWORK_ID,
                trusted_operator_public_key=operator_public,
                archive_segment_resolver=protocol_v3._embedded_archive_resolver(
                    [item["archive_segment"]],
                    fallback=store.archive_segment_resolver_v3,
                ),
                proof_bundle_resolver=store.proof_bundle_resolver_v3,
            )
            if use_store_api:
                store.store_archive_segment_v3(item["archive_segment"])
                store.store_proof_bundle_v3(
                    proof_bundle,
                    trusted_operator_public_key=operator_public,
                )
                bill_hash = store.store_bill_v3(
                    bill,
                    proof_bundle=proof_bundle,
                    status=status,
                    trusted_operator_public_key=operator_public,
                )
            else:
                _store_verified_archive_segment_conn(
                    store,
                    store_conn,
                    item["archive_segment"],
                    item["checkpoint_core"],
                    store_now,
                )
                _store_verified_proof_bundle_conn(
                    store,
                    store_conn,
                    proof_bundle,
                    item["checkpoint_core"],
                    store_now,
                )
                bill_hash = _store_verified_bill_conn(
                    store,
                    store_conn,
                    bill,
                    item["checkpoint_core"],
                    status,
                )
            if record_evidence_messages:
                archive_message = protocol_v3.create_archive_segment_announcement(
                    item["archive_segment"]
                )
                proof_message = protocol_v3.create_proof_bundle_announcement(proof_bundle)
                if use_store_api:
                    _record_evidence_message(store, archive_message)
                    _record_evidence_message(store, proof_message)
                else:
                    store._record_message(store_conn, archive_message)
                    store._record_message(store_conn, proof_message)
            item["proof_bundle_hash"] = proof_bundle["proof_bundle_hash"]
            item["archive_segment_hash"] = item["archive_segment"]["segment_hash"]
            item["bill_hash"] = bill_hash
            item["root_id"] = root_id
            if progress_interval and index % int(progress_interval) == 0:
                print(f"stored {index}/{len(prepared)} finalized bills", file=sys.stderr, flush=True)
        if store_conn is not None:
            store_conn.commit()
    finally:
        proof_conn.close()
        if store_conn is not None:
            store_conn.close()


def finalize(args):
    manifest = _load_json(args.manifest)
    expected_manifest_hash = args.expected_manifest_hash.strip().lower()
    verified = genesis_manifest_v3.verify_manifest(
        manifest,
        trusted_hashes=[expected_manifest_hash] if expected_manifest_hash else None,
        require_full_supply=args.require_full_supply_manifest,
        expected_network="mainnet",
        expected_network_id=MAINNET_NETWORK_ID,
    )
    if expected_manifest_hash:
        os.environ["IND_TRUSTED_GENESIS_MANIFEST_HASHES"] = expected_manifest_hash
    else:
        os.environ["IND_TRUSTED_GENESIS_MANIFEST_HASHES"] = verified["manifest_hash"]
    trusted_hashes = {verified["manifest_hash"]}
    protocol_v3._trusted_genesis_manifest_hashes = lambda: trusted_hashes
    protocol_v3._allow_untrusted_genesis = lambda: False
    bundle = _load_json(args.bundle)
    transfers = _validate_header(
        bundle,
        manifest,
        verified,
        expected_manifest_hash,
        "mainnet",
    )
    prepared = _prepare_items(
        bundle,
        manifest,
        verified,
        transfers,
        limit=args.limit,
        progress_interval=args.progress_interval,
    )
    if args.validate_only:
        return {
            "validated": True,
            "bundle_id": bundle["bundle_id"],
            "manifest_hash": verified["manifest_hash"],
            "transfer_count": len(prepared),
        }

    private_key, operator_public = load_or_create_operator_keys(
        args.operator_private_key_file,
        args.operator_public_key_file,
    )
    log = TransparencyLog(
        args.log_db,
        private_key,
        operator_public,
        mirror_dirs=args.mirror_dir,
        recovery_required=False,
    )
    store = INDLocalStore(
        db_path=args.store_db,
        require_transparency=False,
        transparency_verifier=None,
        transparency_submitter=None,
    )
    entry_time = _append_entries(log, prepared, progress_interval=args.progress_interval)
    root = log.publish_root(max(int(time.time()), entry_time + 1))
    _store_finalized_bills(
        log,
        store,
        prepared,
        operator_public,
        root,
        args.bill_status,
        not args.no_record_evidence_messages,
        args.use_store_api,
        progress_interval=args.progress_interval,
    )
    values = {}
    for item in prepared:
        values[str(item["value"])] = values.get(str(item["value"]), 0) + 1
    return {
        "validated": True,
        "finalized": True,
        "bundle_id": bundle["bundle_id"],
        "manifest_hash": verified["manifest_hash"],
        "recipient_address": bundle["recipient_address"],
        "transfer_count": len(prepared),
        "value_counts": dict(sorted(values.items(), key=lambda kv: int(kv[0]))),
        "operator_log_id": log.log_id,
        "operator_public_key": operator_public,
        "root_id": log_client.signed_root_id(root),
        "tree_size": int(root["tree_size"]),
        "spend_map_size": int(root.get("spend_map_size", 0)),
        "root_timestamp": int(root["timestamp"]),
        "log_db": str(Path(args.log_db)),
        "store_db": str(Path(args.store_db)),
        "first_display_id": prepared[0]["display_id"],
        "last_display_id": prepared[-1]["display_id"],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Finalize an offline signed mainnet treasury bundle into a V3 log and node store."
    )
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--log-db", required=True)
    parser.add_argument("--store-db", required=True)
    parser.add_argument("--operator-private-key-file", required=True)
    parser.add_argument("--operator-public-key-file", required=True)
    parser.add_argument("--mirror-dir", action="append", default=[])
    parser.add_argument("--expected-manifest-hash", default="")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--bill-status", choices=("verified", "settled"), default="settled")
    parser.add_argument("--progress-interval", type=int, default=1000)
    parser.add_argument("--validate-only", action="store_true")
    parser.add_argument("--no-record-evidence-messages", action="store_true")
    parser.add_argument("--use-store-api", action="store_true")
    parser.add_argument("--require-full-supply-manifest", action="store_true", default=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    summary = finalize(args)
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        for key, value in summary.items():
            if isinstance(value, (dict, list)):
                value = json.dumps(value, sort_keys=True)
            print(f"{key}: {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
