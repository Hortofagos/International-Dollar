import copy

from ind import archive_segment_v3
from ind import keys_v3
from ind import node_client
from ind import proof_bundle_v3
from ind import protocol_v3
from ind import token as ind_token

from .test_archive_segment_v3 import BASE_TIMESTAMP, native_v3_archive_fixture


class FakeGossipStore:
    def __init__(self):
        self.ingested = []

    def ingest_message(self, message, peer_id=None):
        self.ingested.append((message, peer_id))
        return {"accepted": True}


def _mutate_text(payload):
    index = len(payload) // 2
    replacement = "0" if payload[index] != "0" else "1"
    return payload[:index] + replacement + payload[index + 1 :]


def _mutate_signature(value):
    if isinstance(value, dict):
        for key in sorted(value):
            if key == "signature" and isinstance(value[key], str) and value[key]:
                value[key] = value[key][:-1] + ("0" if value[key][-1] != "0" else "1")
                return True
            if _mutate_signature(value[key]):
                return True
    if isinstance(value, list):
        for item in value:
            if _mutate_signature(item):
                return True
    return False


def _encoded_bill(message, mutator):
    bill = protocol_v3.decode_bill(protocol_v3.decode_wire_payload(message["bill"]))
    mutator(bill)
    message["bill"] = protocol_v3.encode_wire_payload(protocol_v3.encode_bill(bill))


def _encoded_proof_bundle(message, mutator):
    bundle = proof_bundle_v3.decode_proof_bundle(
        protocol_v3.decode_wire_payload(message["proof_bundle"])
    )
    mutator(bundle)
    message["proof_bundle"] = protocol_v3.encode_wire_payload(
        proof_bundle_v3.encode_proof_bundle(bundle)
    )


def _encoded_archive_segment(message, field, mutator):
    segment = archive_segment_v3.decode_archive_segment(
        protocol_v3.decode_wire_payload(message[field])
    )
    mutator(segment)
    message[field] = protocol_v3.encode_wire_payload(
        archive_segment_v3.encode_archive_segment(segment)
    )


def _encoded_checkpoint_core(message, mutator):
    checkpoint = protocol_v3.decode_checkpoint_core(
        protocol_v3.decode_wire_payload(message["checkpoint_core"])
    )
    mutator(checkpoint)
    message["checkpoint_core"] = protocol_v3.encode_wire_payload(
        protocol_v3.encode_checkpoint_core(checkpoint)
    )


def _valid_messages(tmp_path):
    fixture = native_v3_archive_fixture(tmp_path, display_id="1x42")
    bill = protocol_v3.create_bill_from_checkpoint_core(
        fixture["genesis_ref"],
        fixture["checkpoint_core"],
        fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=fixture["archive_resolver"],
    )
    dave_address, _dave_private, _dave_public = keys_v3.generate_keypair(b"\x24" * 32)
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
        dave_address,
        proof_bundle=fixture["bundle"],
        trusted_operator_public_key=fixture["log_public"],
        archive_segment_resolver=fixture["archive_resolver"],
        timestamp=BASE_TIMESTAMP + 51,
    )
    return {
        "transfer": protocol_v3.create_transfer_announcement(
            branch_a,
            proof_bundle=fixture["bundle"],
            archive_segments=[fixture["archive_segment"]],
            now=BASE_TIMESTAMP + 52,
        ),
        "proof_bundle": protocol_v3.create_proof_bundle_announcement(
            fixture["bundle"], now=BASE_TIMESTAMP + 53
        ),
        "archive_segment": protocol_v3.create_archive_segment_announcement(
            fixture["archive_segment"], now=BASE_TIMESTAMP + 54
        ),
        "checkpoint": protocol_v3.create_checkpoint_announcement(
            fixture["checkpoint_core"],
            [fixture["archive_segment"]],
            now=BASE_TIMESTAMP + 55,
        ),
        "conflict_proof": protocol_v3.create_conflict_proof(
            branch_a,
            branch_b,
            proof_bundle_a=fixture["bundle"],
            proof_bundle_b=fixture["bundle"],
            trusted_operator_public_key=fixture["log_public"],
            archive_segment_resolver=fixture["archive_resolver"],
            detected_at=BASE_TIMESTAMP + 56,
        ),
    }


def _assert_invalid_before_queue(message, case_name):
    rate_limiter = node_client.PeerRateLimiter(window_seconds=60)
    penalties = node_client.PeerPenaltyBook(threshold=100)
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

    response = node_client.handle_incoming_gossip(
        f"peer-{case_name}",
        ind_token.pack_wire_message(message),
        seen,
        rate_limiter,
        store,
        gossip_pool,
        penalties,
        ingest_queue=ingest_queue,
    )

    assert response == "invalid", case_name
    assert store.ingested == [], case_name
    assert len(ingest_queue.queues["gossip"].queue) == 0, case_name
    assert len(ingest_queue.queues["critical"].queue) == 0, case_name


def _case_extra_field(message):
    message["probe_extra"] = "reject-me"


def _case_missing_field(message, field):
    message.pop(field)


def _case_wrong_network(message):
    message["network_id"] = int(message["network_id"]) + 1


def _case_transfer_wrong_hash(message):
    _encoded_bill(
        message,
        lambda bill: bill["checkpoint_core"].__setitem__("checkpoint_hash", "00" * 32),
    )


def _case_transfer_wrong_proof_ref(message):
    _encoded_bill(
        message,
        lambda bill: bill["proof_bundle_ref"].__setitem__("proof_bundle_hash", "00" * 32),
    )


def _case_transfer_wrong_signature(message):
    def mutate(bill):
        assert _mutate_signature(bill["recent_transfers"])

    _encoded_bill(message, mutate)


def _case_proof_bundle_wrong_hash(message):
    _encoded_proof_bundle(
        message,
        lambda bundle: bundle.__setitem__("proof_bundle_hash", "00" * 32),
    )


def _case_proof_bundle_wrong_signature(message):
    def mutate(bundle):
        assert _mutate_signature(bundle["signed_root"])
        finalized = proof_bundle_v3.finalize_proof_bundle(bundle)
        bundle.clear()
        bundle.update(finalized)

    _encoded_proof_bundle(message, mutate)


def _case_archive_wrong_hash(message):
    _encoded_archive_segment(
        message,
        "archive_segment",
        lambda segment: segment.__setitem__("segment_hash", "00" * 32),
    )


def _case_archive_wrong_signature(message):
    def mutate(segment):
        assert _mutate_signature(segment["transfers"])
        finalized = archive_segment_v3.finalize_archive_segment(segment)
        segment.clear()
        segment.update(finalized)

    _encoded_archive_segment(message, "archive_segment", mutate)


def _case_checkpoint_wrong_hash(message):
    _encoded_checkpoint_core(
        message,
        lambda checkpoint: checkpoint.__setitem__("checkpoint_hash", "00" * 32),
    )


def _case_checkpoint_wrong_signature(message):
    def mutate(segment):
        assert _mutate_signature(segment["transfers"])
        finalized = archive_segment_v3.finalize_archive_segment(segment)
        segment.clear()
        segment.update(finalized)

    payloads = message["archive_segments"]
    segment = archive_segment_v3.decode_archive_segment(
        protocol_v3.decode_wire_payload(payloads[0])
    )
    mutate(segment)
    payloads[0] = protocol_v3.encode_wire_payload(
        archive_segment_v3.encode_archive_segment(segment)
    )


def _case_conflict_wrong_hash(message):
    message["proof_hash"] = "00" * 32


def _case_conflict_wrong_signature(message):
    assert _mutate_signature(message["transfer_a"])
    message["proof_hash"] = protocol_v3.conflict_proof_hash(message)


def test_v3_gossip_adversarial_matrix_rejects_before_queue(tmp_path):
    valid = _valid_messages(tmp_path)
    cases = []
    missing_fields = {
        "transfer": "bill",
        "proof_bundle": "proof_bundle",
        "archive_segment": "archive_segment",
        "checkpoint": "checkpoint_core",
        "conflict_proof": "proof_hash",
    }
    encoded_fields = {
        "transfer": "bill",
        "proof_bundle": "proof_bundle",
        "archive_segment": "archive_segment",
        "checkpoint": "checkpoint_core",
    }
    wrong_hash = {
        "transfer": _case_transfer_wrong_hash,
        "proof_bundle": _case_proof_bundle_wrong_hash,
        "archive_segment": _case_archive_wrong_hash,
        "checkpoint": _case_checkpoint_wrong_hash,
        "conflict_proof": _case_conflict_wrong_hash,
    }
    wrong_signature = {
        "transfer": _case_transfer_wrong_signature,
        "proof_bundle": _case_proof_bundle_wrong_signature,
        "archive_segment": _case_archive_wrong_signature,
        "checkpoint": _case_checkpoint_wrong_signature,
        "conflict_proof": _case_conflict_wrong_signature,
    }

    for name, _message in valid.items():
        cases.extend(
            [
                (name, "extra_field", _case_extra_field),
                (name, "missing_field", lambda msg, field=missing_fields[name]: _case_missing_field(msg, field)),
                (name, "wrong_network_id", _case_wrong_network),
                (name, "valid_decode_wrong_hash", wrong_hash[name]),
                (name, "wrong_signature", wrong_signature[name]),
            ]
        )
        if name in encoded_fields:
            cases.append(
                (
                    name,
                    "bad_encoded_payload",
                    lambda msg, field=encoded_fields[name]: msg.__setitem__(
                        field, _mutate_text(msg[field])
                    ),
                )
            )
        if name == "transfer":
            cases.append((name, "wrong_proof_ref", _case_transfer_wrong_proof_ref))

    for message_name, mutation_name, mutate in cases:
        message = copy.deepcopy(valid[message_name])
        mutate(message)
        _assert_invalid_before_queue(message, f"{message_name}:{mutation_name}")
