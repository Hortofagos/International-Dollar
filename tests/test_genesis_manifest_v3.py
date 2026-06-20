import copy

import pytest

from ind import genesis_manifest_v3, keys_v3, protocol as ind_token, protocol_v3


ISSUED_AT = 1_800_000_000


def _keypair(seed_byte):
    return keys_v3.generate_keypair(bytes([seed_byte]) * 32)


def _manifest():
    owner_address, _owner_private, _owner_public = _keypair(0x41)
    _issuer_address, issuer_private, _issuer_public = _keypair(0x42)
    ranges = genesis_manifest_v3.full_supply_ranges(owner_address)
    return genesis_manifest_v3.make_manifest(
        ranges,
        issuer_private,
        issued_at=ISSUED_AT,
        network="mainnet",
        network_id=1,
        metadata={"purpose": "unit test mainnet genesis manifest"},
    )


def test_native_v3_genesis_manifest_round_trips_full_supply():
    manifest = _manifest()

    verified = genesis_manifest_v3.verify_manifest(
        manifest,
        trusted_hashes=[manifest["manifest_hash"]],
        require_full_supply=True,
        expected_network="mainnet",
        expected_network_id=1,
    )

    assert verified["manifest_hash"] == manifest["manifest_hash"]
    assert verified["total_token_count"] == ind_token.TOTAL_SUPPLY
    assert verified["issuer_key_id"] == manifest["issuer_key_id"]


def test_native_v3_genesis_manifest_derives_genesis_ref_and_base_state():
    manifest = _manifest()

    ref = genesis_manifest_v3.derive_genesis_ref(manifest, 20, 1727272)
    base_state = genesis_manifest_v3.derive_base_state(manifest, 20, 1727272)

    assert ref["type"] == protocol_v3.GENESIS_REF_TYPE
    assert ref["manifest_hash"] == manifest["manifest_hash"]
    assert ref["issuer_key_id"] == manifest["issuer_key_id"]
    assert ref["issue_index"] == 1727272
    assert base_state["display_id"] == "20x1727272"
    assert base_state["last_transfer_hash"] == ref["genesis_hash"]
    assert base_state["sequence"] == 0


def test_native_v3_genesis_manifest_rejects_bad_signature():
    manifest = _manifest()
    bad = copy.deepcopy(manifest)
    bad["signature"] = "00" + bad["signature"][2:]

    with pytest.raises(genesis_manifest_v3.GenesisManifestV3Error, match="signature"):
        genesis_manifest_v3.verify_manifest(bad)


def test_native_v3_genesis_manifest_rejects_untrusted_hash():
    manifest = _manifest()

    with pytest.raises(genesis_manifest_v3.GenesisManifestV3Error, match="not trusted"):
        genesis_manifest_v3.verify_manifest(manifest, trusted_hashes=["00" * 32])


def test_native_v3_genesis_manifest_rejects_overlapping_ranges():
    owner_address, _owner_private, _owner_public = _keypair(0x43)
    _issuer_address, issuer_private, _issuer_public = _keypair(0x44)
    ranges = [
        {
            "value": 1,
            "start_serial": 1,
            "count": 2,
            "owner_address": owner_address,
            "nonce_seed": "11" * 32,
        },
        {
            "value": 1,
            "start_serial": 2,
            "count": 2,
            "owner_address": owner_address,
            "nonce_seed": "22" * 32,
        },
    ]

    with pytest.raises(genesis_manifest_v3.GenesisManifestV3Error, match="overlap"):
        genesis_manifest_v3.make_manifest(ranges, issuer_private, issued_at=ISSUED_AT)


def _genesis_ref(manifest_hash):
    return {
        "type": protocol_v3.GENESIS_REF_TYPE,
        "version": protocol_v3.VERSION,
        "network_id": 1,
        "genesis_hash": "11" * 32,
        "manifest_hash": manifest_hash,
        "issuer_key_id": "22" * 32,
        "issue_index": 1,
        "issued_at": ISSUED_AT,
    }


def test_protocol_v3_rejects_unpinned_genesis_ref_when_manifest_hashes_are_trusted(
    monkeypatch,
):
    trusted_hash = "aa" * 32
    monkeypatch.setenv("IND_ALLOW_UNTRUSTED_GENESIS", "0")
    monkeypatch.setenv("IND_TRUSTED_GENESIS_MANIFEST_HASHES", trusted_hash)

    with pytest.raises(protocol_v3.ProtocolV3Error, match="not trusted"):
        protocol_v3._validate_genesis_ref(_genesis_ref(None), 1)

    with pytest.raises(protocol_v3.ProtocolV3Error, match="not trusted"):
        protocol_v3._validate_genesis_ref(_genesis_ref("bb" * 32), 1)

    protocol_v3._validate_genesis_ref(_genesis_ref(trusted_hash), 1)


def test_protocol_v3_allows_untrusted_genesis_escape_hatch(monkeypatch):
    monkeypatch.setenv("IND_ALLOW_UNTRUSTED_GENESIS", "1")
    monkeypatch.setenv("IND_TRUSTED_GENESIS_MANIFEST_HASHES", "aa" * 32)

    protocol_v3._validate_genesis_ref(_genesis_ref(None), 1)
