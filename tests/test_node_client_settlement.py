import json
import threading
import time

from ind import node_client
from ind import keys_v3
from ind import protocol_v3
from ind import proof_bundle_v3
from ind import token as ind_token

from .test_archive_segment_v3 import native_v3_archive_fixture


class FakeStore:
    def __init__(self, status=None):
        self.status = status
        self.ingested = []

    def ingest_wire_message(self, raw, peer_id=None):
        self.ingested.append((raw, peer_id))
        return {"accepted": True}

    def status_record_for_ref(self, _ref):
        if self.status is None:
            return None
        return {"status": self.status}


class FakeGossipStore:
    def __init__(self):
        self.ingested = []

    def ingest_message(self, message, peer_id=None):
        self.ingested.append((message, peer_id))
        return {"accepted": True}


class TransientMirrorGossipStore:
    def __init__(self):
        self.ingested = []

    def ingest_message(self, message, peer_id=None):
        self.ingested.append((message, peer_id))
        raise ind_token.ValidationError(
            "not enough usable transparency root mirrors containing leaf: "
            "no mirrored transparency root close enough to transfer timestamp"
        )


class FakeStatusStore:
    def __init__(self):
        self.refs = []

    def status_record_for_ref(self, ref):
        self.refs.append(ref)
        return {
            "display_id": "1x42",
            "owner_address": "xowner",
            "sequence": 3,
            "status": "pending",
        }


def _minimal_v3_bill():
    owner_address, owner_private, owner_public = keys_v3.generate_keypair(
        b"settlement-owner".ljust(32, b"\0")
    )
    recipient_address, recipient_private, recipient_public = keys_v3.generate_keypair(
        b"settlement-recipient".ljust(32, b"\0")
    )
    final_address, _final_private, _final_public = keys_v3.generate_keypair(
        b"settlement-final".ljust(32, b"\0")
    )
    token_id = "aa" * 32
    genesis_hash = "bb" * 32
    issued_at = 1_700_000_000
    genesis_ref = {
        "type": protocol_v3.GENESIS_REF_TYPE,
        "version": protocol_v3.VERSION,
        "network_id": protocol_v3.DEFAULT_NETWORK_ID,
        "genesis_hash": genesis_hash,
        "manifest_hash": None,
        "issuer_key_id": None,
        "issue_index": 42,
        "issued_at": issued_at,
    }
    base_state = {
        "sequence": 0,
        "owner_address": owner_address,
        "last_transfer_hash": genesis_hash,
        "last_transfer_timestamp": issued_at,
        "last_transfer_day": issued_at // 86400,
        "transfers_in_last_day": 0,
        "display_id": "1x42",
        "value": 1,
    }
    transfer = protocol_v3.create_transfer_from_state(
        token_id,
        base_state,
        owner_private,
        owner_public,
        recipient_address,
        timestamp=issued_at + 1,
    )
    state_after_transfer = {
        "sequence": 1,
        "owner_address": recipient_address,
        "last_transfer_hash": protocol_v3.transfer_hash(transfer),
        "last_transfer_timestamp": issued_at + 1,
        "last_transfer_day": (issued_at + 1) // 86400,
        "transfers_in_last_day": 1,
        "display_id": "1x42",
        "value": 1,
    }
    checkpoint_core = protocol_v3.checkpoint_core_from_state(
        token_id,
        genesis_hash,
        state_after_transfer,
    )
    recent_transfer = protocol_v3.create_transfer_from_state(
        token_id,
        state_after_transfer,
        recipient_private,
        recipient_public,
        final_address,
        timestamp=issued_at + 2,
    )
    proof_ref = {
        "type": proof_bundle_v3.PROOF_BUNDLE_REF_TYPE,
        "version": proof_bundle_v3.PROOF_BUNDLE_VERSION,
        "network_id": protocol_v3.DEFAULT_NETWORK_ID,
        "log_id": "test-log",
        "signed_root_hash": "cc" * 32,
        "tree_size": 1,
        "proof_bundle_algorithm": 1,
        "proof_bundle_hash": "dd" * 32,
    }
    return {
        "type": protocol_v3.BILL_TYPE,
        "version": protocol_v3.VERSION,
        "network_id": protocol_v3.DEFAULT_NETWORK_ID,
        "token_id": token_id,
        "value": 1,
        "genesis_ref": genesis_ref,
        "checkpoint_core": checkpoint_core,
        "proof_bundle_ref": proof_ref,
        "recent_transfers": [recent_transfer],
    }


def _v3_transfer_message(announced_at=1):
    return {
        "type": protocol_v3.TRANSFER_ANNOUNCEMENT_TYPE,
        "version": protocol_v3.VERSION,
        "network_id": protocol_v3.DEFAULT_NETWORK_ID,
        "payload_encoding": protocol_v3.V3_PAYLOAD_ENCODING,
        "bill": protocol_v3.encode_wire_payload(protocol_v3.encode_bill(_minimal_v3_bill())),
        "proof_bundle": None,
        "archive_segments": [],
        "announced_at": int(announced_at),
    }


def _v3_transfer_wire(announced_at=1):
    return ind_token.pack_wire_message(_v3_transfer_message(announced_at))


def _v3_transfer_message_with_embedded_bundle(tmp_path):
    fixture = native_v3_archive_fixture(tmp_path, display_id="1x42")
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
    )
    return protocol_v3.create_transfer_announcement(
        transferred,
        proof_bundle=fixture["bundle"],
        archive_segments=[fixture["archive_segment"]],
    )


def _mutate_payload_text(payload):
    index = len(payload) // 2
    replacement = "0" if payload[index] != "0" else "1"
    return payload[:index] + replacement + payload[index + 1 :]


def _v3_conflict_proof_message():
    owner_address, owner_private, owner_public = keys_v3.generate_keypair(
        b"settlement-conflict-owner".ljust(32, b"\0")
    )
    recipient_a, _private_a, _public_a = keys_v3.generate_keypair(
        b"settlement-conflict-recipient-a".ljust(32, b"\0")
    )
    recipient_b, _private_b, _public_b = keys_v3.generate_keypair(
        b"settlement-conflict-recipient-b".ljust(32, b"\0")
    )
    token_id = "12" * 32
    genesis_hash = "34" * 32
    issued_at = 1_700_000_000
    base_state = {
        "sequence": 0,
        "owner_address": owner_address,
        "last_transfer_hash": genesis_hash,
        "last_transfer_timestamp": issued_at,
        "last_transfer_day": issued_at // 86400,
        "transfers_in_last_day": 0,
        "display_id": "1x42",
        "value": 1,
    }
    transfer_a = protocol_v3.create_transfer_from_state(
        token_id,
        base_state,
        owner_private,
        owner_public,
        recipient_a,
        timestamp=issued_at + 1,
    )
    transfer_b = protocol_v3.create_transfer_from_state(
        token_id,
        base_state,
        owner_private,
        owner_public,
        recipient_b,
        timestamp=issued_at + 2,
    )
    return protocol_v3.create_conflict_proof_from_transfers(
        transfer_a,
        transfer_b,
        detected_at=issued_at + 3,
    )


def _enable_settlement(monkeypatch, response):
    monkeypatch.setattr(node_client, "_settlement_enabled", lambda: True)
    monkeypatch.setattr(node_client, "_settlement_peers", lambda: ["peer-a"])
    monkeypatch.setattr(
        node_client.ind_settings,
        "settlement_min_remote_confirmations",
        lambda: 1,
    )
    monkeypatch.setattr(
        node_client.ind_settings,
        "settlement_require_all_configured_peers",
        lambda: True,
    )
    monkeypatch.setattr(
        node_client,
        "_query_settlement_peer",
        lambda peer, query: {"ok": True, "peer": peer, "response": response},
    )


def test_public_status_lookup_does_not_finalize_pending(monkeypatch):
    def fail_finalize(*_args, **_kwargs):
        raise AssertionError("public status must not run settlement finalization")

    store = FakeStatusStore()
    monkeypatch.setattr(node_client, "_finalize_pending_for_node", fail_finalize)

    response = node_client._status_response_for_request("1x42", store=store)

    assert response == "1x42\nxowner\n3\npending"
    assert store.refs == ["1x42"]


def test_v3_settlement_reconcile_settles_matching_peer(monkeypatch):
    response = {
        "type": "ind.peer_settlement_response.v3",
        "token_id": "token-a",
        "matches_query": True,
        "messages": [],
    }
    _enable_settlement(monkeypatch, response)

    decision = node_client._reconcile_v3_settlement_candidate(
        FakeStore(),
        {"token_id": "token-a", "query": {"token_id": "token-a"}},
    )

    assert decision["decision"] == "settle"


def test_v3_settlement_reconcile_blocks_divergent_peer(monkeypatch):
    response = {
        "type": "ind.peer_settlement_response.v3",
        "token_id": "token-a",
        "matches_query": False,
        "local_transfer_hash": "different-branch",
        "messages": [],
    }
    _enable_settlement(monkeypatch, response)

    decision = node_client._reconcile_v3_settlement_candidate(
        FakeStore(),
        {"token_id": "token-a", "query": {"token_id": "token-a"}},
    )

    assert decision["decision"] == "await"
    assert decision["reason"] == "peer has divergent spend"


def test_v3_settlement_reconcile_treats_peer_conflict_as_conflict(monkeypatch):
    response = {
        "type": "ind.peer_settlement_response.v3",
        "token_id": "token-a",
        "matches_query": False,
        "conflict": True,
        "messages": ["packed-conflict"],
    }
    _enable_settlement(monkeypatch, response)
    store = FakeStore()

    decision = node_client._reconcile_v3_settlement_candidate(
        store,
        {"token_id": "token-a", "query": {"token_id": "token-a"}},
    )

    assert decision["decision"] == "conflict"
    assert store.ingested == [("packed-conflict", "peer-a")]


def test_token_bucket_refills_and_lanes_are_isolated():
    now = [100.0]
    limits = {
        "gossip": {
            "global": (1, 1),
            "subnet": (1, 1),
            "ip": (1, 1),
        },
        "critical": {
            "global": (10, 10),
            "subnet": (10, 10),
            "ip": (10, 10),
        },
        "control": {
            "global": (10, 10),
            "subnet": (10, 10),
            "ip": (10, 10),
        },
        "invalid": {
            "global": (10, 10),
            "subnet": (10, 10),
            "ip": (10, 10),
        },
    }
    rate_limiter = node_client.PeerRateLimiter(
        now_func=lambda: now[0],
        limits=limits,
    )

    assert rate_limiter.allow_lane("203.0.113.10", "gossip").allowed
    blocked = rate_limiter.allow_lane("203.0.113.10", "gossip")
    assert not blocked.allowed
    assert blocked.retry_after_seconds == 1
    assert rate_limiter.allow_lane("203.0.113.10", "critical").allowed

    now[0] = 101.0
    assert rate_limiter.allow_lane("203.0.113.10", "gossip").allowed


def test_token_bucket_enforces_subnet_and_global_caps():
    limits = {
        "gossip": {
            "global": (100, 2),
            "subnet": (100, 1),
            "ip": (100, 10),
        },
        "critical": {
            "global": (100, 10),
            "subnet": (100, 10),
            "ip": (100, 10),
        },
        "control": {
            "global": (100, 10),
            "subnet": (100, 10),
            "ip": (100, 10),
        },
        "invalid": {
            "global": (100, 10),
            "subnet": (100, 10),
            "ip": (100, 10),
        },
    }
    rate_limiter = node_client.PeerRateLimiter(now_func=lambda: 100.0, limits=limits)

    assert rate_limiter.allow_lane("203.0.113.10", "gossip").allowed
    assert not rate_limiter.allow_lane("203.0.113.11", "gossip").allowed

    limits["gossip"]["subnet"] = (100, 10)
    rate_limiter = node_client.PeerRateLimiter(now_func=lambda: 100.0, limits=limits)
    assert rate_limiter.allow_lane("203.0.113.10", "gossip").allowed
    assert rate_limiter.allow_lane("198.51.100.10", "gossip").allowed
    assert not rate_limiter.allow_lane("192.0.2.10", "gossip").allowed


def test_receipt_gossip_no_longer_has_separate_bucket():
    limits = {
        "gossip": {
            "global": (1, 1),
            "subnet": (1, 1),
            "ip": (1, 1),
        },
        "critical": {
            "global": (10, 10),
            "subnet": (10, 10),
            "ip": (10, 10),
        },
        "control": {
            "global": (10, 10),
            "subnet": (10, 10),
            "ip": (10, 10),
        },
        "invalid": {
            "global": (10, 10),
            "subnet": (10, 10),
            "ip": (10, 10),
        },
    }
    rate_limiter = node_client.PeerRateLimiter(now_func=lambda: 100.0, limits=limits)
    penalties = node_client.PeerPenaltyBook()
    seen = node_client.BoundedSeenSet()
    store = FakeGossipStore()
    gossip_pool = []
    transfer_a = _v3_transfer_wire(1)
    transfer_b = _v3_transfer_wire(2)
    receipt = ind_token.pack_wire_message(
        {"type": ind_token.RECEIPT_ANNOUNCEMENT_TYPE, "nonce": "receipt"}
    )

    assert (
        node_client.handle_incoming_gossip(
            "peer-a", transfer_a, seen, rate_limiter, store, gossip_pool, penalties
        )
        == "ok"
    )
    assert (
        node_client.handle_incoming_gossip(
            "peer-a", transfer_b, seen, rate_limiter, store, gossip_pool, penalties
        )
        == "rate_limited:1"
    )
    assert (
        node_client.handle_incoming_gossip(
            "peer-a", receipt, seen, rate_limiter, store, gossip_pool, penalties
        )
        == "invalid"
    )

    assert [item[0]["type"] for item in store.ingested] == [
        ind_token.TRANSFER_ANNOUNCEMENT_TYPE,
    ]


def test_invalid_gossip_penalty_does_not_allow_receipts():
    rate_limiter = node_client.PeerRateLimiter(window_seconds=60)
    penalties = node_client.PeerPenaltyBook(threshold=1)
    penalties.penalize("peer-a")
    seen = node_client.BoundedSeenSet()
    store = FakeGossipStore()
    gossip_pool = []
    transfer = _v3_transfer_wire()
    receipt = ind_token.pack_wire_message(
        {"type": ind_token.RECEIPT_ANNOUNCEMENT_TYPE, "nonce": "receipt"}
    )

    assert (
        node_client.handle_incoming_gossip(
            "peer-a", transfer, seen, rate_limiter, store, gossip_pool, penalties
        )
        == "rate_limited:1"
    )
    assert (
        node_client.handle_incoming_gossip(
            "peer-a", receipt, seen, rate_limiter, store, gossip_pool, penalties
        )
        == "invalid"
    )

    assert store.ingested == []


def test_transient_transparency_lag_is_retryable_not_peer_penalty():
    rate_limiter = node_client.PeerRateLimiter(window_seconds=60)
    penalties = node_client.PeerPenaltyBook(threshold=1)
    seen = node_client.BoundedSeenSet()
    store = TransientMirrorGossipStore()
    gossip_pool = []
    transfer = _v3_transfer_wire()

    response = node_client.handle_incoming_gossip(
        "peer-a",
        transfer,
        seen,
        rate_limiter,
        store,
        gossip_pool,
        penalties,
        async_transfer_ingest=False,
    )

    assert response.startswith("rate_limited:")
    assert penalties.allow("peer-a")
    assert store.ingested


def test_bounded_ingest_queue_backpressures_without_blocking_critical():
    rate_limiter = node_client.PeerRateLimiter()
    penalties = node_client.PeerPenaltyBook()
    seen = node_client.BoundedSeenSet()
    store = FakeGossipStore()
    gossip_pool = []
    ingest_queue = node_client.GossipIngestQueue(
        store,
        gossip_pool,
        seen,
        penalties,
        workers=0,
        gossip_max=1,
        critical_max=1,
    )
    ingest_queue.queues["gossip"].put_nowait(("peer-a", {"message_hash": "held"}))

    transfer = _v3_transfer_wire()
    proof = ind_token.pack_wire_message(_v3_conflict_proof_message())

    assert node_client.handle_incoming_gossip(
        "peer-a",
        transfer,
        seen,
        rate_limiter,
        store,
        gossip_pool,
        penalties,
        ingest_queue=ingest_queue,
    ).startswith("rate_limited:")
    assert (
        node_client.handle_incoming_gossip(
            "peer-a",
            proof,
            seen,
            rate_limiter,
            store,
            gossip_pool,
            penalties,
            ingest_queue=ingest_queue,
        )
        == "ok"
    )


def test_batch_gossip_reports_mixed_results():
    rate_limiter = node_client.PeerRateLimiter()
    penalties = node_client.PeerPenaltyBook()
    seen = node_client.BoundedSeenSet()
    store = FakeGossipStore()
    gossip_pool = []
    accepted = _v3_transfer_wire(1)
    duplicate = _v3_transfer_wire(2)
    duplicate_hash = ind_token.message_hash(ind_token.unpack_wire_message(duplicate))
    seen.add(duplicate_hash)
    batch = json.dumps(
        {
            "type": node_client.GOSSIP_BATCH_TYPE,
            "messages": [accepted, duplicate, "not json"],
        }
    )

    response = json.loads(
        node_client.handle_incoming_gossip_batch(
            "peer-a",
            batch,
            seen,
            rate_limiter,
            store,
            gossip_pool,
            penalties,
        )
    )

    assert response["type"] == node_client.GOSSIP_BATCH_RESPONSE_TYPE
    assert response["status"] == "partial"
    assert response["accepted"] == 1
    assert response["duplicate"] == 1
    assert response["rejected"] == 1


def test_operator_profile_has_higher_defaults(monkeypatch):
    monkeypatch.setenv("IND_NODE_CAPACITY_PROFILE", "operator")
    operator_limits = node_client._lane_limit_config()
    monkeypatch.setenv("IND_NODE_CAPACITY_PROFILE", "desktop")
    desktop_limits = node_client._lane_limit_config()

    assert operator_limits["gossip"]["global"][0] > desktop_limits["gossip"]["global"][0]
    assert operator_limits["gossip"]["ip"][1] > desktop_limits["gossip"]["ip"][1]


def test_auto_capacity_profile_uses_local_operator_role(monkeypatch):
    monkeypatch.setenv("IND_NODE_CAPACITY_PROFILE", "auto")
    monkeypatch.setattr(node_client, "_settings_operator_role", lambda: True)
    monkeypatch.setattr(node_client, "_runtime_operator_enabled", lambda: False)

    assert node_client.resolve_node_capacity_profile() == "operator"


def test_v3_transfer_gossip_acknowledges_before_store_ingest_finishes():
    started = threading.Event()
    release = threading.Event()
    finished = threading.Event()

    class SlowStore:
        def __init__(self):
            self.ingested = []

        def ingest_message(self, message, peer_id=None):
            started.set()
            release.wait(timeout=5)
            self.ingested.append((message, peer_id))
            finished.set()
            return {"accepted": True}

    rate_limiter = node_client.PeerRateLimiter(window_seconds=60)
    penalties = node_client.PeerPenaltyBook()
    seen = node_client.BoundedSeenSet()
    store = SlowStore()
    gossip_pool = []
    message = _v3_transfer_message()
    payload = ind_token.pack_wire_message(message)

    response = node_client.handle_incoming_gossip(
        "peer-a",
        payload,
        seen,
        rate_limiter,
        store,
        gossip_pool,
        penalties,
    )

    assert response == "ok"
    assert started.wait(timeout=1)
    assert not finished.is_set()

    release.set()
    assert finished.wait(timeout=1)
    assert store.ingested == [(message, "peer-a")]
    for _ in range(20):
        if gossip_pool == [payload]:
            break
        time.sleep(0.01)
    assert gossip_pool == [payload]


def test_v3_gossip_extra_top_level_field_rejected_before_queue():
    rate_limiter = node_client.PeerRateLimiter(window_seconds=60)
    penalties = node_client.PeerPenaltyBook()
    seen = node_client.BoundedSeenSet()
    store = FakeGossipStore()
    gossip_pool = []
    ingest_queue = node_client.GossipIngestQueue(
        store,
        gossip_pool,
        seen,
        penalties,
        workers=0,
        gossip_max=10,
        critical_max=10,
    )
    message = _v3_transfer_message()
    message["probe_nonce"] = "extra"

    response = node_client.handle_incoming_gossip(
        "peer-a",
        ind_token.pack_wire_message(message),
        seen,
        rate_limiter,
        store,
        gossip_pool,
        penalties,
        ingest_queue=ingest_queue,
    )

    assert response == "invalid"
    assert store.ingested == []
    assert len(ingest_queue.queues["gossip"].queue) == 0


def test_v3_transfer_tampered_encoded_bill_rejected_before_queue(tmp_path):
    rate_limiter = node_client.PeerRateLimiter(window_seconds=60)
    penalties = node_client.PeerPenaltyBook()
    seen = node_client.BoundedSeenSet()
    store = FakeGossipStore()
    gossip_pool = []
    ingest_queue = node_client.GossipIngestQueue(
        store,
        gossip_pool,
        seen,
        penalties,
        workers=0,
        gossip_max=10,
        critical_max=10,
    )
    message = _v3_transfer_message_with_embedded_bundle(tmp_path)
    message["bill"] = _mutate_payload_text(message["bill"])

    response = node_client.handle_incoming_gossip(
        "peer-a",
        ind_token.pack_wire_message(message),
        seen,
        rate_limiter,
        store,
        gossip_pool,
        penalties,
        ingest_queue=ingest_queue,
    )

    assert response == "invalid"
    assert store.ingested == []
    assert len(ingest_queue.queues["gossip"].queue) == 0


def test_v3_conflict_proof_extra_top_level_field_rejected_before_queue():
    rate_limiter = node_client.PeerRateLimiter(window_seconds=60)
    penalties = node_client.PeerPenaltyBook()
    seen = node_client.BoundedSeenSet()
    store = FakeGossipStore()
    gossip_pool = []
    ingest_queue = node_client.GossipIngestQueue(
        store,
        gossip_pool,
        seen,
        penalties,
        workers=0,
        gossip_max=10,
        critical_max=10,
    )
    message = _v3_conflict_proof_message()
    message["probe_nonce"] = "extra"

    response = node_client.handle_incoming_gossip(
        "peer-a",
        ind_token.pack_wire_message(message),
        seen,
        rate_limiter,
        store,
        gossip_pool,
        penalties,
        ingest_queue=ingest_queue,
    )

    assert response == "invalid"
    assert store.ingested == []
    assert len(ingest_queue.queues["critical"].queue) == 0


def test_unknown_v3_gossip_type_rejected_before_queue():
    rate_limiter = node_client.PeerRateLimiter(window_seconds=60)
    penalties = node_client.PeerPenaltyBook()
    seen = node_client.BoundedSeenSet()
    store = FakeGossipStore()
    gossip_pool = []
    ingest_queue = node_client.GossipIngestQueue(
        store,
        gossip_pool,
        seen,
        penalties,
        workers=0,
        gossip_max=10,
        critical_max=10,
    )
    message = {
        "type": "ind.future_probe.v3",
        "version": protocol_v3.VERSION,
        "network_id": protocol_v3.DEFAULT_NETWORK_ID,
    }

    response = node_client.handle_incoming_gossip(
        "peer-a",
        ind_token.pack_wire_message(message),
        seen,
        rate_limiter,
        store,
        gossip_pool,
        penalties,
        ingest_queue=ingest_queue,
    )

    assert response == "invalid"
    assert store.ingested == []
