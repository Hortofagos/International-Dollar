import copy
import json
import threading
import urllib.error
import urllib.request
from hashlib import sha3_256

import pytest

from ind import keys_v3, protocol_v3
from ind import token as ind_token
from ind import transparency_client as log_client
from ind import transparency_server as log_server

from .test_archive_segment_v3 import native_v3_archive_fixture


def _operator_keypair(label):
    seed = sha3_256(label.encode("utf-8")).digest()
    _address, private_key, public_key = keys_v3.generate_keypair(seed)
    return private_key, public_key


def _v3_transfer_announcement(tmp_path, *, timestamp=1_700_000_050, announced_at=None):
    fixture = native_v3_archive_fixture(tmp_path)
    bill = protocol_v3.create_bill_from_checkpoint_core(
        fixture["genesis_ref"],
        fixture["checkpoint_core"],
        fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=fixture["archive_resolver"],
    )
    next_bill = protocol_v3.create_transfer(
        bill,
        fixture["bob_private"],
        fixture["bob_public"],
        fixture["carol_address"],
        proof_bundle=fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=fixture["archive_resolver"],
        timestamp=timestamp,
    )
    announcement = protocol_v3.create_transfer_announcement(
        next_bill,
        proof_bundle=fixture["bundle"],
        archive_segments=[fixture["archive_segment"]],
        now=announced_at or timestamp + 1,
    )
    return fixture, next_bill["recent_transfers"][-1], announcement


def _feed_witness(message_hash, feed_id, first_seen, segment_hash):
    private_key, public_key = _operator_keypair(feed_id)
    return log_client.make_recovery_witness(
        message_hash,
        feed_id,
        first_seen,
        segment_hash,
        private_key,
        public_key,
    )


def _recovery_feed(feed_id, announcement, transfer, *, include_witness=True):
    message_hash = ind_token.message_hash(announcement)
    segment_hash = ind_token.sha3_hex((feed_id + message_hash).encode("utf-8"))
    witnesses = []
    if include_witness:
        witnesses.append(
            _feed_witness(message_hash, feed_id, int(transfer["timestamp"]) + 10, segment_hash)
        )
    return {
        "feed_id": feed_id,
        "feed_public_key": _operator_keypair(feed_id)[1],
        "high_watermark": int(announcement["announced_at"]) + 60,
        "stable_at": 0,
        "entries": [
            {
                "message": copy.deepcopy(announcement),
                "witnesses": witnesses,
                "source_segment_hash": segment_hash,
            }
        ],
    }


def test_recovery_required_operator_rejects_http_append_but_serves_status(tmp_path):
    log_private, log_public = _operator_keypair("operator-gate")
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
    base_url = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        status = json.loads(urllib.request.urlopen(base_url + "/v3/status").read().decode("utf-8"))
        assert status["state"] == log_server.OPERATOR_STATE_RECOVERING

        request = urllib.request.Request(
            base_url + "/v3/append",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(request)
        assert exc_info.value.code == 503
        body = json.loads(exc_info.value.read().decode("utf-8"))
        assert body["error"] == "operator_recovering"
    finally:
        server.shutdown()
        server.server_close()


def test_recovery_feed_quorum_replays_missed_v3_transfer_and_activates(tmp_path):
    fixture, transfer, announcement = _v3_transfer_announcement(tmp_path)
    log = log_server.TransparencyLog(
        str(tmp_path / "operator.db"),
        fixture["log"].private_key,
        fixture["log_public"],
        recovery_required=True,
        recovery_feeds=[
            _recovery_feed("feed-a", announcement, transfer),
            _recovery_feed("feed-b", announcement, transfer),
        ],
        recovery_min_feeds=2,
        max_root_lag_seconds=60,
        enforce_late_witnesses=True,
    )

    report = log.run_recovery()

    assert log.operator_state() == log_server.OPERATOR_STATE_ACTIVE
    assert log.tree_size() == 1
    assert [item["entry_hash"] for item in report["appended"]] == [
        protocol_v3.transfer_hash(transfer)
    ]
    assert log.latest_root()["tree_size"] == 1


def test_recovery_feed_quorum_failure_enters_failed_safe(tmp_path):
    fixture, transfer, announcement = _v3_transfer_announcement(tmp_path)
    log = log_server.TransparencyLog(
        str(tmp_path / "operator.db"),
        fixture["log"].private_key,
        fixture["log_public"],
        recovery_required=True,
        recovery_feeds=[_recovery_feed("feed-a", announcement, transfer)],
        recovery_min_feeds=2,
    )

    with pytest.raises(log_server.LogServerError, match="quorum"):
        log.run_recovery()

    assert log.operator_state() == log_server.OPERATOR_STATE_FAILED_SAFE
    assert log.tree_size() == 0


def test_recovery_rebuilds_missing_prefix_from_proof_archive(tmp_path, monkeypatch):
    log_private, log_public = _operator_keypair("operator-archive-prefix")
    mirror_dir = tmp_path / "mirror"
    monkeypatch.setattr(log_server, "WRITE_MIRROR_PROOF_ARCHIVES", True)
    source_log = log_server.TransparencyLog(
        str(tmp_path / "source.db"),
        log_private,
        log_public,
        mirror_dirs=[mirror_dir],
    )
    first_hash = ind_token.sha3_hex(b"first archived entry")
    second_hash = ind_token.sha3_hex(b"second archived entry")
    source_log.append_entry_hash(first_hash, submitted_at=1_700_000_001)
    source_log.append_entry_hash(second_hash, submitted_at=1_700_000_002)
    root = source_log.publish_root(1_700_000_010)
    recovering_log = log_server.TransparencyLog(
        str(tmp_path / "recovering.db"),
        log_private,
        log_public,
        recovery_required=True,
        recovery_mirrors=[str(mirror_dir)],
    )

    checked = recovering_log.verify_recovery_sources()

    assert checked >= 1
    assert recovering_log.tree_size() == 2
    assert recovering_log.current_root_hash(2) == root["root_hash"]
    assert recovering_log.entries(start=0, end=1, limit=2) == [
        {"leaf_index": 0, "entry_hash": first_hash, "submitted_at": 1_700_000_001},
        {"leaf_index": 1, "entry_hash": second_hash, "submitted_at": 1_700_000_002},
    ]


def test_stale_recovery_candidate_requires_witness_quorum(tmp_path):
    fixture, transfer, announcement = _v3_transfer_announcement(tmp_path)
    log = log_server.TransparencyLog(
        str(tmp_path / "operator.db"),
        fixture["log"].private_key,
        fixture["log_public"],
        recovery_required=True,
        recovery_min_feeds=2,
        max_root_lag_seconds=60,
        enforce_late_witnesses=True,
    )

    with pytest.raises(log_client.RootVerificationError, match="witness quorum"):
        log.append_transfer_announcement(
            announcement,
            allow_recovery=True,
            recovery_witnesses=[],
        )


def test_late_historical_root_requires_recovery_witness_quorum(tmp_path):
    fixture, transfer, announcement = _v3_transfer_announcement(tmp_path)
    entry_hash = protocol_v3.transfer_hash(transfer)
    log = log_server.TransparencyLog(
        str(tmp_path / "operator.db"),
        fixture["log"].private_key,
        fixture["log_public"],
    )
    append = log.append_entry_hash(entry_hash, submitted_at=int(transfer["timestamp"]) + 900)
    root = log.publish_root(int(transfer["timestamp"]) + 900)
    verifier = log_client.TransparencyVerifier(
        log_client.LocalTransparencyOperator(log),
        [
            log_client.StaticRootMirror([root], identity_id="mirror-a"),
            log_client.StaticRootMirror([root], identity_id="mirror-b"),
        ],
        operator_public_key=fixture["log_public"],
        max_root_lag_seconds=60,
        observed_root_store=log_client.InMemoryObservedRootStore(),
        run_startup_check=False,
    )

    with pytest.raises(log_client.RootVerificationError, match="close enough"):
        verifier.mirrored_root_containing_leaf(int(transfer["timestamp"]), append["leaf_index"])

    witnesses = [
        _recovery_feed("feed-a", announcement, transfer)["entries"][0]["witnesses"][0],
        _recovery_feed("feed-b", announcement, transfer)["entries"][0]["witnesses"][0],
    ]
    recovered = verifier.mirrored_root_containing_leaf(
        int(transfer["timestamp"]),
        append["leaf_index"],
        recovery_witnesses=witnesses,
        recovery_message_hash=ind_token.message_hash(announcement),
    )
    assert log_client.signed_root_id(recovered) == log_client.signed_root_id(root)


def _two_root_log(tmp_path):
    private_key, public_key = _operator_keypair("lagging-current-root")
    log = log_server.TransparencyLog(str(tmp_path / "operator.db"), private_key, public_key)
    log.append_entry_hash("11" * 32, submitted_at=1_700_000_010)
    first_root = log.publish_root(1_700_000_020)
    log.append_entry_hash("22" * 32, submitted_at=1_700_000_030)
    second_root = log.publish_root(1_700_000_040)
    return log, public_key, first_root, second_root


def test_current_root_check_tolerates_independently_lagging_mirror(tmp_path):
    log, public_key, first_root, second_root = _two_root_log(tmp_path)
    observed = log_client.InMemoryObservedRootStore()
    verifier = log_client.TransparencyVerifier(
        log_client.LocalTransparencyOperator(log),
        [
            log_client.StaticRootMirror([first_root], identity_id="slow-mirror"),
            log_client.StaticRootMirror([second_root], identity_id="fast-mirror"),
        ],
        operator_public_key=public_key,
        min_mirrors=2,
        max_current_root_age_seconds=1_000,
        observed_root_store=observed,
        run_startup_check=False,
    )
    verifier.observe_root(second_root, ("test", "already-saw-fast-root"))

    root = verifier.current_mirrored_root(now=1_700_000_050)

    assert log_client.signed_root_id(root) == log_client.signed_root_id(second_root)
    assert observed.status(second_root["log_id"])["status"] == "active"


def test_strict_consistency_refreshes_when_root_is_unchanged(tmp_path, monkeypatch):
    log, public_key, _first_root, second_root = _two_root_log(tmp_path)
    observed = log_client.InMemoryObservedRootStore()
    verifier = log_client.TransparencyVerifier(
        log_client.LocalTransparencyOperator(log),
        [
            log_client.StaticRootMirror([second_root], identity_id="steady-mirror-a"),
            log_client.StaticRootMirror([second_root], identity_id="steady-mirror-b"),
        ],
        operator_public_key=public_key,
        min_mirrors=2,
        strict_mode=True,
        consistency_max_stale_seconds=60,
        observed_root_store=observed,
        run_startup_check=False,
    )

    monkeypatch.setattr(log_client.time, "time", lambda: 1_700_000_050)
    verifier.observe_root(second_root, ("test", "initial"))
    monkeypatch.setattr(log_client.time, "time", lambda: 1_700_000_200)

    refreshed = verifier.observe_root(second_root, ("test", "same-root"))

    assert refreshed == second_root
    status = observed.status(second_root["log_id"])
    assert status["status"] == "active"
    assert status["last_successful_consistency_at"] == 1_700_000_200


def test_current_root_check_rejects_signed_rollback_after_newer_tree(tmp_path):
    log, public_key, first_root, second_root = _two_root_log(tmp_path)
    rollback_root = log_client.make_signed_root(
        first_root["tree_size"],
        first_root["root_hash"],
        int(second_root["timestamp"]) + 1,
        log.private_key,
        public_key,
        spend_map_root=first_root["spend_map_root"],
        spend_map_size=first_root["spend_map_size"],
    )
    verifier = log_client.TransparencyVerifier(
        log_client.LocalTransparencyOperator(log),
        [
            log_client.StaticRootMirror([rollback_root], identity_id="rollback-mirror"),
            log_client.StaticRootMirror([second_root], identity_id="honest-mirror"),
        ],
        operator_public_key=public_key,
        min_mirrors=2,
        max_current_root_age_seconds=1_000,
        observed_root_store=log_client.InMemoryObservedRootStore(),
        run_startup_check=False,
    )
    verifier.observe_root(second_root, ("test", "already-saw-fast-root"))

    with pytest.raises(log_client.ConsistencyProofError, match="CRITICAL"):
        verifier.current_mirrored_root(now=1_700_000_050)


def test_multi_operator_submitter_skips_recovering_operator():
    calls = []

    class RecoveringOperator:
        def status(self):
            return {"state": "recovering"}

        def submit_transfer_announcement(self, announcement):
            raise AssertionError("recovering operator should be skipped")

    class ActiveOperator:
        def status(self):
            return {"state": "active"}

        def submit_transfer_announcement(self, announcement):
            calls.append(announcement)
            return {"accepted": True, "entry_hash": "aa" * 32, "leaf_index": 0, "tree_size": 1}

    submitter = log_client.MultiTransparencySubmitter([RecoveringOperator(), ActiveOperator()])

    result = submitter.submit_transfer_announcement({"type": "test"})

    assert result["accepted"] is True
    assert calls == [{"type": "test"}]
