import copy
from hashlib import sha3_256

import pytest

from ind import keys_v3, protocol_v3, transparency_client as log_client
from ind import transparency_server as log_server

from .test_archive_segment_v3 import (
    BASE_TIMESTAMP,
    _operator_keypair,
    native_v3_archive_fixture,
)


def _new_log(tmp_path, label="incremental-spend-map"):
    private_key, public_key, _address = _operator_keypair(label)
    return (
        log_server.TransparencyLog(str(tmp_path / f"{label}.db"), private_key, public_key),
        public_key,
    )


def _seed(label):
    return sha3_256(str(label).encode("ascii")).digest()


def _make_transfer(index, recipient_label=None):
    sender_address, sender_private, sender_public = keys_v3.generate_keypair(
        _seed(f"sender-{index}")
    )
    recipient_address, _recipient_private, _recipient_public = keys_v3.generate_keypair(
        _seed(recipient_label or f"recipient-{index}")
    )
    base_state = {
        "sequence": 0,
        "owner_address": sender_address,
        "last_transfer_hash": sha3_256(f"genesis-{index}".encode("ascii")).hexdigest(),
        "last_transfer_timestamp": BASE_TIMESTAMP,
        "last_transfer_day": BASE_TIMESTAMP // 86400,
        "transfers_in_last_day": 0,
        "display_id": f"1x{index + 1}",
        "value": 1,
    }
    return protocol_v3.create_transfer_from_state(
        sha3_256(f"token-{index}".encode("ascii")).hexdigest(),
        base_state,
        sender_private,
        sender_public,
        recipient_address,
        timestamp=BASE_TIMESTAMP + 10 + index,
    )


def _append_claim(log, transfer, submitted_at):
    transfer_hash = protocol_v3.transfer_hash(transfer)
    append = log.append_entry_hash(
        transfer_hash,
        submitted_at=submitted_at,
        transfer=transfer,
    )
    claim = protocol_v3.spend_claim_for_transfer(
        transfer,
        log.log_id,
        append["leaf_index"],
        submitted_at,
    )
    with log._connect() as conn:
        log._record_spend_claim(
            conn,
            claim,
            transfer_hash,
            append["leaf_index"],
            submitted_at,
        )
    return claim, append


def _bill_from_fixture(fixture):
    return protocol_v3.create_bill_from_checkpoint_core(
        fixture["genesis_ref"],
        fixture["checkpoint_core"],
        fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=fixture["archive_resolver"],
    )


def _branch_transfers(fixture):
    bill = _bill_from_fixture(fixture)
    branch_a = protocol_v3.create_transfer(
        bill,
        fixture["bob_private"],
        fixture["bob_public"],
        fixture["carol_address"],
        proof_bundle=fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=fixture["archive_resolver"],
        timestamp=BASE_TIMESTAMP + 50,
    )
    branch_b = protocol_v3.create_transfer(
        bill,
        fixture["bob_private"],
        fixture["bob_public"],
        fixture["alice_address"],
        proof_bundle=fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=fixture["archive_resolver"],
        timestamp=BASE_TIMESTAMP + 51,
    )
    return branch_a["recent_transfers"][-1], branch_b["recent_transfers"][-1], branch_a, branch_b


@pytest.mark.parametrize("claim_count", [1, 2, 10, 100])
def test_incremental_spend_map_matches_canonical_after_each_append(tmp_path, claim_count):
    log, _public_key = _new_log(tmp_path, label=f"incremental-{claim_count}")

    for index in range(claim_count):
        transfer = _make_transfer(index)
        _append_claim(log, transfer, BASE_TIMESTAMP + 100 + index)
        with log._connect() as conn:
            rebuilt_claims = log._spend_claim_records(conn)
        root_hash, map_size = log.spend_map_root()
        signed_root = log.publish_root(BASE_TIMESTAMP + 1_000 + index)
        spend_key = protocol_v3.spend_key_for_transfer(transfer)
        proof = log.spend_map_proof(spend_key, signed_root["tree_size"])
        canonical = log_client.build_spend_map_proof(
            rebuilt_claims,
            spend_key,
            signed_root["tree_size"],
        )

        assert root_hash == log_client.spend_map_root(rebuilt_claims)
        assert map_size == len(rebuilt_claims) == index + 1
        assert proof == canonical
        assert log_client.verify_spend_map_proof(proof, signed_root) == (
            log_client.verify_spend_map_proof(canonical, signed_root)
        )


def test_missing_spend_map_metadata_rebuilds_same_root(tmp_path):
    fixture = native_v3_archive_fixture(tmp_path)
    before = fixture["log"].spend_map_root()

    with fixture["log"]._connect() as conn:
        conn.execute("DELETE FROM spend_map_meta_v3")

    after = fixture["log"].spend_map_root()
    with fixture["log"]._connect() as conn:
        node_count = conn.execute(
            "SELECT COUNT(*) AS count_value FROM spend_map_nodes_v3"
        ).fetchone()["count_value"]
        cached_claim_count = conn.execute(
            "SELECT COUNT(*) AS count_value FROM spend_map_claims_v3"
        ).fetchone()["count_value"]

    assert after == before
    assert node_count > 0
    assert cached_claim_count == 1


def test_missing_current_spend_map_node_repairs_before_serving_bad_proof(tmp_path):
    log, _public_key = _new_log(tmp_path, label="node-repair")
    first = _make_transfer(1)
    second = _make_transfer(2)
    _append_claim(log, first, BASE_TIMESTAMP + 101)
    _append_claim(log, second, BASE_TIMESTAMP + 102)
    signed_root = log.publish_root(BASE_TIMESTAMP + 1_010)
    spend_key = protocol_v3.spend_key_for_transfer(first)

    deleted = None
    with log._connect() as conn:
        node_position = int(spend_key, 16)
        for child_depth in range(log_client.SPEND_MAP_KEY_BITS, 0, -1):
            sibling_position = node_position ^ 1
            row = conn.execute(
                """
                SELECT node_hash FROM spend_map_nodes_v3
                WHERE depth = ? AND position = ?
                """,
                (child_depth, str(sibling_position)),
            ).fetchone()
            if row is not None:
                conn.execute(
                    """
                    DELETE FROM spend_map_nodes_v3
                    WHERE depth = ? AND position = ?
                    """,
                    (child_depth, str(sibling_position)),
                )
                deleted = (child_depth, sibling_position)
                break
            node_position >>= 1

    assert deleted is not None
    proof = log.spend_map_proof(spend_key, signed_root["tree_size"])
    with log._connect() as conn:
        repaired = conn.execute(
            """
            SELECT node_hash FROM spend_map_nodes_v3
            WHERE depth = ? AND position = ?
            """,
            (deleted[0], str(deleted[1])),
        ).fetchone()

    assert repaired is not None
    assert log_client.verify_spend_map_proof(proof, signed_root)


def test_publish_reconciles_v3_transfer_entry_missing_spend_claim(tmp_path):
    log, _public_key = _new_log(tmp_path, label="reconcile-missing-claim")
    transfer = _make_transfer(1)
    transfer_hash = protocol_v3.transfer_hash(transfer)
    append = log.append_entry_hash(
        transfer_hash,
        submitted_at=BASE_TIMESTAMP + 200,
        transfer=transfer,
    )
    with log._connect() as conn:
        claim_count = conn.execute(
            "SELECT COUNT(*) AS count_value FROM spend_claims"
        ).fetchone()["count_value"]

    signed_root = log.publish_root(BASE_TIMESTAMP + 1_200)
    proof = log.spend_map_proof(
        protocol_v3.spend_key_for_transfer(transfer),
        signed_root["tree_size"],
    )
    with log._connect() as conn:
        claims = log._spend_claim_records(conn, tree_size=signed_root["tree_size"])

    assert append["leaf_index"] == 0
    assert claim_count == 0
    assert len(claims) == 1
    assert signed_root["spend_map_root"] == log_client.spend_map_root(claims)
    assert log_client.verify_spend_map_proof(proof, signed_root)


def test_publish_quarantines_invalid_historical_transfer_body(tmp_path):
    log, _public_key = _new_log(tmp_path, label="quarantine-invalid-transfer")
    transfer = _make_transfer(1)
    entry_hash = protocol_v3.transfer_hash(transfer)
    invalid_transfer = copy.deepcopy(transfer)
    invalid_transfer["recipient_address"] = keys_v3.generate_keypair(
        _seed("mutated-recipient")
    )[0]

    append = log.append_entry_hash(
        entry_hash,
        submitted_at=BASE_TIMESTAMP + 200,
        transfer=invalid_transfer,
    )
    signed_root = log.publish_root(BASE_TIMESTAMP + 1_200)
    second_root = log.publish_root(BASE_TIMESTAMP + 1_201)

    with log._connect() as conn:
        claim_count = conn.execute(
            "SELECT COUNT(*) AS count_value FROM spend_claims"
        ).fetchone()["count_value"]
        quarantined = conn.execute(
            """
            SELECT reason, leaf_index, transfer_type
            FROM invalid_transfer_entries_v3
            WHERE entry_hash = ?
            """,
            (entry_hash,),
        ).fetchone()

    assert append["leaf_index"] == 0
    assert signed_root["tree_size"] == second_root["tree_size"] == 1
    assert signed_root["spend_map_size"] == second_root["spend_map_size"] == 0
    assert claim_count == 0
    assert quarantined is not None
    assert int(quarantined["leaf_index"]) == 1
    assert quarantined["transfer_type"] == protocol_v3.TRANSFER_TYPE
    assert "stored V3 transfer is invalid" in quarantined["reason"]


def test_publish_quarantines_non_v3_historical_transfer_body(tmp_path):
    log, _public_key = _new_log(tmp_path, label="quarantine-non-v3-transfer")
    entry_hash = sha3_256(b"non-v3-transfer-entry").hexdigest()
    unsupported_transfer = {
        "type": "ind.transfer.unsupported",
        "version": 0,
        "token_id": "unsupported_fixture",
    }

    log.append_entry_hash(
        entry_hash,
        submitted_at=BASE_TIMESTAMP + 200,
        transfer=unsupported_transfer,
    )
    signed_root = log.publish_root(BASE_TIMESTAMP + 1_200)

    with log._connect() as conn:
        claim_count = conn.execute(
            "SELECT COUNT(*) AS count_value FROM spend_claims"
        ).fetchone()["count_value"]
        quarantined = conn.execute(
            """
            SELECT reason, transfer_type
            FROM invalid_transfer_entries_v3
            WHERE entry_hash = ?
            """,
            (entry_hash,),
        ).fetchone()

    assert signed_root["tree_size"] == 1
    assert signed_root["spend_map_size"] == 0
    assert claim_count == 0
    assert quarantined is not None
    assert quarantined["transfer_type"] == "ind.transfer.unsupported"
    assert quarantined["reason"] == "stored transfer is not a V3 transfer"


def test_publish_omits_invalid_transfer_body_from_existing_spend_claim(tmp_path):
    log, _public_key = _new_log(tmp_path, label="quarantine-invalid-claim-body")
    transfer = _make_transfer(1)
    entry_hash = protocol_v3.transfer_hash(transfer)
    invalid_transfer = copy.deepcopy(transfer)
    invalid_transfer["recipient_address"] = keys_v3.generate_keypair(
        _seed("mutated-claim-body-recipient")
    )[0]
    submitted_at = BASE_TIMESTAMP + 200
    append = log.append_entry_hash(
        entry_hash,
        submitted_at=submitted_at,
        transfer=invalid_transfer,
    )
    claim = protocol_v3.spend_claim_for_transfer(
        transfer,
        log.log_id,
        append["leaf_index"],
        submitted_at,
    )
    with log._connect() as conn:
        conn.execute(
            """
            INSERT INTO spend_claims(
                spend_key, token_id, previous_hash, sequence, sender_address,
                sender_public_key, transfer_hash, transfer_leaf_index, first_seen
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                claim["spend_key"],
                claim["token_id"],
                claim["previous_hash"],
                int(claim["sequence"]),
                claim["sender_address"],
                claim["sender_public_key"],
                claim["transfer_hash"],
                int(claim["transfer_leaf_index"]),
                int(claim["accepted_at"]),
            ),
        )

    signed_root = log.publish_root(BASE_TIMESTAMP + 1_200)
    proof = log.spend_map_proof(claim["spend_key"], signed_root["tree_size"])
    claims = log_client.verify_spend_map_proof(proof, signed_root)

    with log._connect() as conn:
        quarantined = conn.execute(
            """
            SELECT reason, transfer_type
            FROM invalid_transfer_entries_v3
            WHERE entry_hash = ?
            """,
            (entry_hash,),
        ).fetchone()

    assert signed_root["spend_map_size"] == 1
    assert len(claims) == 1
    assert claims[0]["transfer_hash"] == entry_hash
    assert "transfer" not in claims[0]
    assert quarantined is not None
    assert quarantined["transfer_type"] == protocol_v3.TRANSFER_TYPE
    assert "stored transfer body omitted from spend claim" in quarantined["reason"]


def test_normal_v3_append_rejects_second_transfer_for_same_spend_key(tmp_path):
    fixture = native_v3_archive_fixture(tmp_path)
    _transfer_a, _transfer_b, branch_a, branch_b = _branch_transfers(fixture)
    announcement_a = protocol_v3.create_transfer_announcement(
        branch_a,
        proof_bundle=fixture["bundle"],
        archive_segments=[fixture["archive_segment"]],
        now=BASE_TIMESTAMP + 55,
    )
    announcement_b = protocol_v3.create_transfer_announcement(
        branch_b,
        proof_bundle=fixture["bundle"],
        archive_segments=[fixture["archive_segment"]],
        now=BASE_TIMESTAMP + 56,
    )

    fixture["log"].append_transfer_announcement(announcement_a)

    with pytest.raises(log_server.LogServerError, match="conflicting spend"):
        fixture["log"].append_transfer_announcement(announcement_b)


def test_reconstructed_conflicting_claims_remain_in_map_and_fail_safe(tmp_path):
    fixture = native_v3_archive_fixture(tmp_path)
    transfer_a, transfer_b, _branch_a, _branch_b = _branch_transfers(fixture)
    spend_key = protocol_v3.spend_key_for_transfer(transfer_a)

    for offset, transfer in enumerate((transfer_a, transfer_b)):
        transfer_hash = protocol_v3.transfer_hash(transfer)
        submitted_at = BASE_TIMESTAMP + 200 + offset
        append = fixture["log"].append_entry_hash(
            transfer_hash,
            submitted_at=submitted_at,
            transfer=transfer,
        )
        claim = protocol_v3.spend_claim_for_transfer(
            transfer,
            fixture["log"].log_id,
            append["leaf_index"],
            submitted_at,
        )
        with fixture["log"]._connect() as conn:
            fixture["log"]._record_spend_claim(
                conn,
                claim,
                transfer_hash,
                append["leaf_index"],
                submitted_at,
            )

    with pytest.raises(log_server.LogServerError, match="conflicting spend claims"):
        fixture["log"].publish_root(BASE_TIMESTAMP + 300)

    with fixture["log"]._connect() as conn:
        cached_claim_count = conn.execute(
            """
            SELECT COUNT(*) AS count_value FROM spend_map_claims_v3
            WHERE spend_key = ?
            """,
            (spend_key,),
        ).fetchone()["count_value"]

    assert cached_claim_count == 2
    assert fixture["log"].operator_state() == log_server.OPERATOR_STATE_FAILED_SAFE
