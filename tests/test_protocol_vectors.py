from ind import keys_v3, protocol_v3


BASE_TIMESTAMP = 1_700_000_000


def test_deterministic_transfer_v3_vector():
    alice_address, alice_private, alice_public = keys_v3.generate_keypair(b"\x02" * 32)
    bob_address, _bob_private, _bob_public = keys_v3.generate_keypair(b"\x03" * 32)
    state = {
        "sequence": 0,
        "owner_address": alice_address,
        "last_transfer_hash": "11" * 32,
        "last_transfer_timestamp": BASE_TIMESTAMP,
        "last_transfer_day": BASE_TIMESTAMP // 86400,
        "transfers_in_last_day": 0,
        "display_id": "5x4242",
        "value": 5,
    }

    transfer = protocol_v3.create_transfer_from_state(
        "22" * 32,
        state,
        alice_private,
        alice_public,
        bob_address,
        metadata={"memo": "vector"},
        timestamp=BASE_TIMESTAMP + 10,
    )

    assert alice_address == "x3HEcNbGeQNvsbiVh6ZmNEeoi63j4mEDx"
    assert bob_address == "x36nSFahafV9m75PmpPgPE5H4y7S9wGBx"
    assert transfer["signature"] == (
        "b8a0e0f3f238da3a7c24bfea4e7acac9f1808ad156de4c67e40688bd7a4dd406"
        "c0606dfc499ffd811c2fb021e190f01a8d230548474486278b0590e9b8b46b04"
    )
    assert protocol_v3.transfer_hash(transfer) == (
        "6b0eaa03aeeb01080c99ba2d177d8a08fd3af3147a027b38167ba308b1f0a09b"
    )
    assert protocol_v3.spend_key_for_transfer(transfer) == (
        "886615191c05b8f7b86459dbcea0174203797dccb125f1c081564a11acf16f74"
    )
    assert protocol_v3.decode_transfer(protocol_v3.encode_transfer(transfer)) == transfer
