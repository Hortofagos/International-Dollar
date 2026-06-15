import pytest

from ind import binary_v3
from ind.protocol import ValidationError


@pytest.mark.parametrize(
    ("value", "encoded_hex"),
    [
        (0, "00"),
        (1, "01"),
        (127, "7f"),
        (128, "8001"),
        (255, "ff01"),
        (300, "ac02"),
        (16_384, "808001"),
    ],
)
def test_uvarint_vectors(value, encoded_hex):
    encoded = bytes.fromhex(encoded_hex)

    assert binary_v3.encode_uvarint(value) == encoded
    assert binary_v3.decode_uvarint(encoded) == value


def test_uvarint_rejects_non_minimal_truncated_and_trailing():
    for raw in (b"\x80\x00", b"\x81\x00", b"\xff\x00"):
        with pytest.raises(ValidationError, match="non-minimal"):
            binary_v3.decode_uvarint(raw)

    with pytest.raises(ValidationError, match="truncated"):
        binary_v3.decode_uvarint(b"\x80")
    with pytest.raises(ValidationError, match="trailing bytes"):
        binary_v3.decode_uvarint(b"\x00\x00")


def test_bounded_bytes_round_trip_and_limits():
    encoded = binary_v3.encode_bytes(b"abc", max_length=3)
    reader = binary_v3.Reader(encoded)

    assert reader.read_bytes(max_length=3) == b"abc"
    assert reader.require_eof()

    with pytest.raises(ValidationError, match="exceed"):
        binary_v3.encode_bytes(b"abcd", max_length=3)
    with pytest.raises(ValidationError, match="exceed"):
        binary_v3.Reader(binary_v3.encode_uvarint(4) + b"abcd").read_bytes(max_length=3)


def test_nullable_hash_round_trip_and_bad_marker():
    digest = b"\x55" * 32

    assert binary_v3.Reader(binary_v3.encode_nullable_hash(None)).read_nullable_hash() is None
    assert binary_v3.Reader(binary_v3.encode_nullable_hash(digest)).read_nullable_hash() == digest

    with pytest.raises(ValidationError, match="invalid nullable hash marker"):
        binary_v3.Reader(b"\x02" + digest).read_nullable_hash()
    with pytest.raises(ValidationError):
        binary_v3.encode_nullable_hash(b"short")


def test_ascii_fields_are_strict_ascii():
    encoded = binary_v3.encode_ascii("ind.transfer.v3", max_length=32)
    assert binary_v3.Reader(encoded).read_ascii(max_length=32) == "ind.transfer.v3"

    with pytest.raises(ValidationError, match="non-ASCII"):
        binary_v3.encode_ascii("ind.transfer.v3.\u2603")


def test_decode_all_rejects_trailing_bytes():
    data = binary_v3.encode_bytes(b"ok") + b"\x00"

    with pytest.raises(ValidationError, match="trailing bytes"):
        binary_v3.decode_all(data, lambda reader: reader.read_bytes())


def test_signing_preimage_is_domain_separated_and_bounded():
    payload = b"canonical-object"
    preimage = binary_v3.signing_preimage(
        1,
        "ind.transfer.v3",
        3,
        binary_v3.SIGNATURE_ALGORITHM_ID,
        "ind.transfer.v3",
        payload,
    )
    changed_domain = binary_v3.signing_preimage(
        1,
        "ind.transfer.v3",
        3,
        binary_v3.SIGNATURE_ALGORITHM_ID,
        "ind.receipt.v3",
        payload,
    )

    assert preimage.startswith(binary_v3.SIGNATURE_PREIMAGE_MAGIC)
    assert preimage != changed_domain

    with pytest.raises(ValidationError, match="exceed"):
        binary_v3.signing_preimage(
            1,
            "ind.transfer.v3",
            3,
            binary_v3.SIGNATURE_ALGORITHM_ID,
            "ind.transfer.v3",
            b"x" * (binary_v3.MAX_SIGNING_PREIMAGE_OBJECT_BYTES + 1),
        )
