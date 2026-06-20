import copy
import json
import threading
import urllib.error
import urllib.request

import pytest

from ind import node_client, protocol as legacy_protocol, protocol_v3
from ind import token as ind_token
from ind import transparency_client as log_client
from ind import transparency_server as log_server
from ind.store import INDLocalStore

from .test_archive_segment_v3 import BASE_TIMESTAMP, _operator_keypair, native_v3_archive_fixture


def _unsafe_dev_verifier(log):
    operator = log_client.LocalTransparencyOperator(log)
    mirror = log_client.LocalTransparencyOperator(log)
    mirror.identity_id = ("test-mirror", str(log.db_path))
    return log_client.TransparencyVerifier(
        operator,
        [mirror],
        min_mirrors=1,
        allow_unsafe_single_mirror=True,
        observed_root_store=log_client.InMemoryObservedRootStore(),
        run_startup_check=False,
    )


def _v3_bill_and_transfer(fixture, timestamp=BASE_TIMESTAMP + 50):
    bill = protocol_v3.create_bill_from_checkpoint_core(
        fixture["genesis_ref"],
        fixture["checkpoint_core"],
        fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=fixture["archive_resolver"],
    )
    transferred = protocol_v3.create_transfer(
        bill,
        fixture["bob_private"],
        fixture["bob_public"],
        fixture["carol_address"],
        proof_bundle=fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=fixture["archive_resolver"],
        timestamp=timestamp,
    )
    return bill, transferred


def test_v3_transfer_announcement_ingests_with_embedded_proof_and_archive(tmp_path):
    fixture = native_v3_archive_fixture(tmp_path)
    _bill, transferred = _v3_bill_and_transfer(fixture)
    announcement = protocol_v3.create_transfer_announcement(
        transferred,
        proof_bundle=fixture["bundle"],
        archive_segments=[fixture["archive_segment"]],
        now=BASE_TIMESTAMP + 55,
    )
    store = INDLocalStore(
        db_path=tmp_path / "receiver.db",
        require_transparency=False,
        transparency_verifier=_unsafe_dev_verifier(fixture["log"]),
    )

    result = store.ingest_message(announcement)

    assert result["accepted"]
    assert result["status"] == "verified"
    stored = store.get_bill_v3_by_token_id(fixture["token_id"])
    assert stored["recent_transfers"][0]["recipient_address"] == fixture["carol_address"]
    assert store.get_proof_bundle_v3(fixture["bundle"]["proof_bundle_hash"]) == fixture["bundle"]
    assert store.get_archive_segment_v3(fixture["archive_segment"]["segment_hash"])


def test_operator_accepts_v3_transfer_announcement_and_serves_cached_spend_proof(tmp_path):
    fixture = native_v3_archive_fixture(tmp_path)
    _bill, transferred = _v3_bill_and_transfer(fixture)
    transfer = transferred["recent_transfers"][-1]
    announcement = protocol_v3.create_transfer_announcement(
        transferred,
        proof_bundle=fixture["bundle"],
        archive_segments=[fixture["archive_segment"]],
        now=BASE_TIMESTAMP + 55,
    )

    append_result = fixture["log"].append_transfer_announcement(announcement)
    root = fixture["log"].publish_root(BASE_TIMESTAMP + 90)
    proof = fixture["log"].spend_map_proof(
        protocol_v3.spend_key_for_transfer(transfer),
        root["tree_size"],
    )
    with fixture["log"]._connect() as conn:
        rebuilt_claims = fixture["log"]._spend_claim_records(conn, tree_size=root["tree_size"])

    assert append_result["entry_hash"] == protocol_v3.transfer_hash(transfer)
    assert root["spend_map_root"] == log_client.spend_map_root(rebuilt_claims)
    assert len(rebuilt_claims) == root["spend_map_size"]
    assert log_client.verify_spend_map_proof(proof, root)


def test_operator_accepts_transfer_checkpointed_by_configured_peer_operator(
    tmp_path, monkeypatch
):
    source = native_v3_archive_fixture(
        tmp_path / "source",
        operator_label="source-log",
        token_label="source-token",
        genesis_label="source-genesis",
        display_id="1x301",
    )
    witness = native_v3_archive_fixture(
        tmp_path / "witness",
        operator_label="witness-log",
        token_label="witness-token",
        genesis_label="witness-genesis",
        display_id="1x302",
    )
    _bill, transferred = _v3_bill_and_transfer(source)
    transfer = transferred["recent_transfers"][-1]
    announcement = protocol_v3.create_transfer_announcement(
        transferred,
        proof_bundle=source["bundle"],
        archive_segments=[source["archive_segment"]],
        now=BASE_TIMESTAMP + 55,
    )

    with pytest.raises(log_server.LogServerError, match="unexpected operator"):
        witness["log"].append_transfer_announcement(announcement)

    monkeypatch.setenv(
        "IND_LOG_OPERATORS",
        json.dumps(
            [
                {"url": "http://source.invalid", "public_key": source["log_public"]},
                {"url": "http://witness.invalid", "public_key": witness["log_public"]},
            ]
        ),
    )

    append_result = witness["log"].append_transfer_announcement(announcement)
    root = witness["log"].publish_root(BASE_TIMESTAMP + 90)
    proof = witness["log"].spend_map_proof(
        protocol_v3.spend_key_for_transfer(transfer),
        root["tree_size"],
    )

    assert append_result["entry_hash"] == protocol_v3.transfer_hash(transfer)
    assert append_result["spend_key"] == protocol_v3.spend_key_for_transfer(transfer)
    assert log_client.verify_spend_map_proof(proof, root)


def test_operator_accepts_native_v3_checkpoint_announcement(tmp_path):
    fixture = native_v3_archive_fixture(tmp_path)
    announcement = protocol_v3.create_checkpoint_announcement(
        fixture["checkpoint_core"],
        [fixture["archive_segment"]],
        now=BASE_TIMESTAMP + 56,
    )

    append_result = fixture["log"].append_checkpoint_announcement(announcement)
    bill = protocol_v3.create_bill_from_checkpoint_core(
        fixture["genesis_ref"],
        fixture["checkpoint_core"],
        fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=fixture["archive_resolver"],
    )

    assert append_result["accepted"]
    assert append_result["entry_hash"] == fixture["checkpoint_core"]["checkpoint_hash"]
    assert append_result["checkpoint_hash"] == fixture["checkpoint_core"]["checkpoint_hash"]
    assert bill["checkpoint_core"] == fixture["checkpoint_core"]


def test_http_operator_accepts_native_v3_checkpoint_announcement(tmp_path):
    fixture = native_v3_archive_fixture(tmp_path)
    announcement = protocol_v3.create_checkpoint_announcement(
        fixture["checkpoint_core"],
        [fixture["archive_segment"]],
        now=BASE_TIMESTAMP + 56,
    )
    server = log_server.ThreadingHTTPServer(("127.0.0.1", 0), log_server.TransparencyLogHandler)
    server.transparency_log = fixture["log"]
    server.root_interval_seconds = 60
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    operator = log_client.HTTPTransparencyOperator(
        f"http://127.0.0.1:{server.server_address[1]}",
        timeout=3,
    )

    try:
        append_result = operator.submit_checkpoint_announcement(announcement)
    finally:
        server.shutdown()
        server.server_close()

    assert append_result["accepted"]
    assert append_result["entry_hash"] == fixture["checkpoint_core"]["checkpoint_hash"]
    assert append_result["checkpoint_hash"] == fixture["checkpoint_core"]["checkpoint_hash"]


def test_http_operator_rejects_append_with_text_plain_content_type(tmp_path):
    fixture = native_v3_archive_fixture(tmp_path)
    server = log_server.ThreadingHTTPServer(("127.0.0.1", 0), log_server.TransparencyLogHandler)
    server.transparency_log = fixture["log"]
    server.root_interval_seconds = 60
    before_tree_size = fixture["log"].tree_size()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    request = urllib.request.Request(
        f"http://127.0.0.1:{server.server_address[1]}/v3/append",
        data=b"{}",
        headers={"Content-Type": "text/plain"},
        method="POST",
    )

    try:
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(request, timeout=3)
    finally:
        server.shutdown()
        server.server_close()

    assert exc_info.value.code == 415
    assert fixture["log"].tree_size() == before_tree_size


def test_http_operator_get_append_returns_method_not_allowed(tmp_path):
    fixture = native_v3_archive_fixture(tmp_path)
    server = log_server.ThreadingHTTPServer(("127.0.0.1", 0), log_server.TransparencyLogHandler)
    server.transparency_log = fixture["log"]
    server.root_interval_seconds = 60
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(
                f"http://127.0.0.1:{server.server_address[1]}/v3/append",
                timeout=3,
            )
    finally:
        server.shutdown()
        server.server_close()

    assert exc_info.value.code == 405
    assert exc_info.value.headers["Allow"] == "POST"


def test_recovering_http_operator_get_append_still_returns_method_not_allowed(tmp_path):
    log_private, log_public, _address = _operator_keypair("recovering-get-append")
    log = log_server.TransparencyLog(
        str(tmp_path / "recovering.db"),
        log_private,
        log_public,
        recovery_required=True,
    )
    server = log_server.ThreadingHTTPServer(("127.0.0.1", 0), log_server.TransparencyLogHandler)
    server.transparency_log = log
    server.root_interval_seconds = 60
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(
                f"http://127.0.0.1:{server.server_address[1]}/v3/append",
                timeout=3,
            )
    finally:
        server.shutdown()
        server.server_close()

    assert exc_info.value.code == 405
    assert exc_info.value.headers["Allow"] == "POST"


def test_v3_proof_and_archive_announcements_ingest_individually(tmp_path):
    fixture = native_v3_archive_fixture(tmp_path)
    store = INDLocalStore(
        db_path=tmp_path / "receiver.db",
        require_transparency=False,
        transparency_verifier=_unsafe_dev_verifier(fixture["log"]),
    )
    archive_message = protocol_v3.create_archive_segment_announcement(
        fixture["archive_segment"],
        now=BASE_TIMESTAMP + 52,
    )
    proof_message = protocol_v3.create_proof_bundle_announcement(
        fixture["bundle"],
        now=BASE_TIMESTAMP + 53,
    )

    archive_result = store.ingest_message(archive_message)
    proof_result = store.ingest_message(proof_message)

    assert archive_result["status"] == "archive_segment_v3"
    assert proof_result["status"] == "proof_bundle_v3"
    assert store.get_archive_segment_v3(fixture["archive_segment"]["segment_hash"])
    assert store.get_proof_bundle_v3(fixture["bundle"]["proof_bundle_hash"])


def test_v3_gossip_rejects_malformed_binary_payload(tmp_path):
    fixture = native_v3_archive_fixture(tmp_path)
    _bill, transferred = _v3_bill_and_transfer(fixture)
    announcement = protocol_v3.create_transfer_announcement(
        transferred,
        proof_bundle=fixture["bundle"],
        archive_segments=[fixture["archive_segment"]],
    )
    bad = copy.deepcopy(announcement)
    bad["bill"] = "indb3:not-valid-base85!!!!"

    with pytest.raises(protocol_v3.ProtocolV3Error, match="payload|BillV3"):
        protocol_v3.verify_transfer_announcement(
            bad,
            trusted_operator_public_key=fixture["log_public"],
        )


def test_v3_only_rejects_legacy_bill_gossip(tmp_path):
    store = INDLocalStore(db_path=tmp_path / "receiver.db", require_transparency=False)
    legacy_message = {
        "type": ind_token.TRANSFER_ANNOUNCEMENT_TYPE,
        "version": ind_token.TOKEN_VERSION,
        "token": {},
        "announced_at": BASE_TIMESTAMP,
    }

    with pytest.raises(ind_token.ValidationError, match="V3 is the only active bill protocol"):
        store.ingest_message(legacy_message)


def test_v3_only_rejects_legacy_operator_append(tmp_path):
    fixture = native_v3_archive_fixture(tmp_path)
    legacy_message = {
        "type": ind_token.TRANSFER_ANNOUNCEMENT_TYPE,
        "version": ind_token.TOKEN_VERSION,
        "token": {},
        "announced_at": BASE_TIMESTAMP,
    }

    with pytest.raises(log_server.LogServerError, match="V3 is the only active bill protocol"):
        fixture["log"].append_transfer_announcement(legacy_message)


@pytest.mark.parametrize(
    "api_name",
    [
        "make_genesis_token",
        "make_lazy_genesis_token",
        "create_transfer",
        "create_receipt_announcement",
        "create_conflict_proof",
        "verify_token",
    ],
)
def test_public_legacy_bill_api_is_disabled(api_name):
    with pytest.raises(ind_token.ValidationError, match="V3 is the only active bill protocol"):
        getattr(ind_token, api_name)()


def test_direct_legacy_protocol_bill_api_is_disabled():
    with pytest.raises(legacy_protocol.ValidationError, match="V3 is the only active bill protocol"):
        legacy_protocol.create_transfer()


@pytest.mark.parametrize("payload", ["[]", '"string"', "123", "true", "null"])
def test_non_object_wire_gossip_is_clean_invalid(payload, tmp_path):
    seen = node_client.BoundedSeenSet()
    limiter = node_client.PeerRateLimiter()
    store = INDLocalStore(db_path=tmp_path / "receiver.db", require_transparency=False)
    penalties = node_client.PeerPenaltyBook()

    with pytest.raises(ind_token.ValidationError, match="malformed gossip message"):
        node_client.prepare_incoming_gossip("203.0.113.44", payload, seen, limiter)

    response = node_client.handle_incoming_gossip(
        "203.0.113.44",
        payload,
        seen,
        limiter,
        store,
        [],
        penalties,
    )

    assert response == "invalid"
