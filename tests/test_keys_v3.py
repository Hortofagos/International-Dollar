import pytest

from ind import keys_v3
from ind import token as ind_token
from ind.protocol import ValidationError


def test_v3_keypair_text_formats_and_address_round_trip():
    seed = bytes.fromhex("01" * 32)
    address, private_key, public_key = keys_v3.generate_keypair(seed)

    assert private_key.startswith("indsk3:")
    assert public_key.startswith("indpk3:")
    assert address.startswith("x3")
    assert address.endswith("x")
    assert len(keys_v3.decode_private_key(private_key)) == 32
    assert len(keys_v3.decode_public_key(public_key)) == 32
    assert keys_v3.validate_address(address) == address
    assert keys_v3.address_from_public_key(public_key) == address
    assert keys_v3.public_key_matches_address(public_key, address)


def test_v3_address_checksum_rejects_tampering():
    address, _private_key, public_key = keys_v3.generate_keypair(b"\x02" * 32)
    replacement = "2" if address[-2] != "2" else "3"
    tampered = address[:-2] + replacement + address[-1]

    assert not keys_v3.is_address(tampered)
    assert not keys_v3.public_key_matches_address(public_key, tampered)
    with pytest.raises(ValidationError):
        keys_v3.validate_address(tampered)


def test_v3_and_v1_keys_do_not_satisfy_each_other_addresses():
    v3_address, _v3_private, v3_public = keys_v3.generate_keypair(b"\x03" * 32)
    v1_private, v1_public, v1_address = _deterministic_v1_keypair()

    assert v1_private
    assert ind_token.public_key_matches_address(v1_public, v1_address)
    assert not ind_token.public_key_matches_address(v3_public, v1_address)
    assert not ind_token.public_key_matches_address(v3_public, v3_address)
    assert not keys_v3.public_key_matches_address(v1_public, v3_address)


def test_v3_key_decoders_reject_wrong_prefix_and_length():
    with pytest.raises(ValidationError):
        keys_v3.decode_private_key("indpk3:" + "0" * 40)
    with pytest.raises(ValidationError):
        keys_v3.decode_public_key("indsk3:" + "0" * 40)
    with pytest.raises(ValidationError):
        keys_v3.decode_private_key("indsk3:short")
    with pytest.raises(ValidationError):
        keys_v3.decode_public_key("indpk3:short")


def test_v3_sign_and_verify_from_text_keys():
    _address, private_key, public_key = keys_v3.generate_keypair(b"\x04" * 32)
    signature = keys_v3.sign(private_key, b"payload")

    assert len(signature) == 64
    assert keys_v3.verify(public_key, signature, b"payload")
    assert not keys_v3.verify(public_key, signature, b"changed")


def _deterministic_v1_keypair():
    import base64

    private_key = base64.b85encode(b"\x11" * 32).decode("ascii")
    public_key = base64.b85encode(b"\x22" * 64).decode("ascii")
    return private_key, public_key, ind_token.address_from_public_key(public_key)
