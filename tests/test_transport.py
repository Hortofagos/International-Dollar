import base64
import json

import pytest

from ind import transport


def _pinned_peer_key(tmp_path, peer_ip):
    safe = peer_ip.replace(":", "_").replace("/", "_").replace("\\", "_")
    path = tmp_path / "files" / "noise_peers" / f"{safe}.json"
    return json.loads(path.read_text(encoding="utf-8"))["public_key"]


def test_transport_peer_key_rotation_updates_pin_by_default(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("IND_NETWORK", raising=False)
    monkeypatch.delenv("IND_REJECT_PEER_KEY_CHANGES", raising=False)
    first_key = b"\x01" * 32
    rotated_key = b"\x02" * 32

    transport.verify_or_pin_peer_key("127.0.0.1", first_key)
    transport.verify_or_pin_peer_key("127.0.0.1", rotated_key)

    assert _pinned_peer_key(tmp_path, "127.0.0.1") == base64.b64encode(
        rotated_key
    ).decode("ascii")


def test_transport_peer_key_rotation_can_be_strictly_rejected(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("IND_NETWORK", raising=False)
    monkeypatch.setenv("IND_REJECT_PEER_KEY_CHANGES", "1")
    first_key = b"\x01" * 32
    rotated_key = b"\x02" * 32

    transport.verify_or_pin_peer_key("127.0.0.1", first_key)

    with pytest.raises(transport.PeerKeyMismatch):
        transport.verify_or_pin_peer_key("127.0.0.1", rotated_key)
