import json

import pytest

from tools import publish_testnet_static_mirror


def _root(timestamp=1_700_000_000, tree_size=10, root_hash="aa"):
    return {
        "log_id": "test-log",
        "tree_size": tree_size,
        "timestamp": timestamp,
        "root_hash": root_hash * 32,
    }


def _mirror_manifest(root):
    return {
        "type": "ind.transparency_root_mirror_manifest.v3",
        "version": 1,
        "root_count": 1,
        "latest_root_id": "root-id",
        "latest_timestamp": int(root["timestamp"]),
        "latest_tree_size": int(root["tree_size"]),
    }


def _json_bytes(data):
    return (json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def test_copy_public_transparency_can_publish_roots_when_archive_is_missing(tmp_path, monkeypatch):
    root = _root(timestamp=1_700_000_100)
    target = tmp_path / "mirror"
    old_archive = target / "transparency" / "archive" / "manifest.json"
    old_archive.parent.mkdir(parents=True)
    old_archive.write_text('{"old":true}\n', encoding="utf-8")

    def fake_fetch(url):
        if url.endswith("/latest.json"):
            return _json_bytes(root)
        if url.endswith("/manifest.json") and "/archive/" not in url:
            return _json_bytes(_mirror_manifest(root))
        if url.endswith("/roots.jsonl"):
            return _json_bytes(root)
        if url.endswith("/archive/manifest.json"):
            raise RuntimeError("archive unavailable")
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(publish_testnet_static_mirror, "fetch_bytes", fake_fetch)

    result = publish_testnet_static_mirror.copy_public_transparency(
        "https://source.example/transparency",
        target,
        include_archive=True,
        allow_missing_archive=True,
    )

    latest = json.loads((target / "transparency" / "latest.json").read_text(encoding="utf-8"))
    assert latest["timestamp"] == root["timestamp"]
    assert result["archive_requested"] is True
    assert result["archive_ok"] is False
    assert "archive unavailable" in result["archive_error"]
    assert old_archive.read_text(encoding="utf-8") == '{"old":true}\n'


def test_copy_public_transparency_is_strict_about_archive_by_default(tmp_path, monkeypatch):
    root = _root()

    def fake_fetch(url):
        if url.endswith("/latest.json"):
            return _json_bytes(root)
        if url.endswith("/manifest.json") and "/archive/" not in url:
            return _json_bytes(_mirror_manifest(root))
        if url.endswith("/roots.jsonl"):
            return _json_bytes(root)
        if url.endswith("/archive/manifest.json"):
            raise RuntimeError("archive unavailable")
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(publish_testnet_static_mirror, "fetch_bytes", fake_fetch)

    with pytest.raises(RuntimeError, match="archive unavailable"):
        publish_testnet_static_mirror.copy_public_transparency(
            "https://source.example/transparency",
            tmp_path,
            include_archive=True,
        )


def test_copy_public_transparency_replaces_archive_after_manifest_fetch(tmp_path, monkeypatch):
    root = _root()
    target = tmp_path / "mirror"
    stale_file = target / "transparency" / "archive" / "stale.json"
    stale_file.parent.mkdir(parents=True)
    stale_file.write_text("{}\n", encoding="utf-8")
    archive_manifest = {"segments": [{"path": "entries/entries_000000000000_000000000009.jsonl"}]}

    def fake_fetch(url):
        if url.endswith("/latest.json"):
            return _json_bytes(root)
        if url.endswith("/manifest.json") and "/archive/" not in url:
            return _json_bytes(_mirror_manifest(root))
        if url.endswith("/roots.jsonl"):
            return _json_bytes(root)
        if url.endswith("/archive/manifest.json"):
            return _json_bytes(archive_manifest)
        if url.endswith("/archive/entries/entries_000000000000_000000000009.jsonl"):
            return b'{"leaf_index":0}\n'
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(publish_testnet_static_mirror, "fetch_bytes", fake_fetch)

    result = publish_testnet_static_mirror.copy_public_transparency(
        "https://source.example/transparency",
        target,
        include_archive=True,
        allow_missing_archive=True,
    )

    assert result["archive_ok"] is True
    assert not stale_file.exists()
    assert (target / "transparency" / "archive" / "manifest.json").exists()


def test_copy_public_transparency_rejects_latest_tree_rollback(tmp_path, monkeypatch):
    target = tmp_path / "mirror"
    existing = _root(timestamp=1_700_000_200, tree_size=20, root_hash="bb")
    incoming = _root(timestamp=1_700_000_300, tree_size=10, root_hash="aa")
    latest_path = target / "transparency" / "latest.json"
    latest_path.parent.mkdir(parents=True)
    latest_path.write_bytes(_json_bytes(existing))

    def fake_fetch(url):
        if url.endswith("/latest.json"):
            return _json_bytes(incoming)
        if url.endswith("/manifest.json") and "/archive/" not in url:
            return _json_bytes(_mirror_manifest(incoming))
        if url.endswith("/roots.jsonl"):
            return _json_bytes(incoming)
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(publish_testnet_static_mirror, "fetch_bytes", fake_fetch)

    with pytest.raises(publish_testnet_static_mirror.MirrorPublishError, match="roll"):
        publish_testnet_static_mirror.copy_public_transparency(
            "https://source.example/transparency",
            target,
            include_archive=False,
        )

    assert json.loads(latest_path.read_text(encoding="utf-8"))["tree_size"] == 20


def test_copy_public_transparency_rejects_same_size_root_swap(tmp_path, monkeypatch):
    target = tmp_path / "mirror"
    existing = _root(timestamp=1_700_000_200, tree_size=20, root_hash="bb")
    incoming = _root(timestamp=1_700_000_300, tree_size=20, root_hash="aa")
    latest_path = target / "transparency" / "latest.json"
    latest_path.parent.mkdir(parents=True)
    latest_path.write_bytes(_json_bytes(existing))

    def fake_fetch(url):
        if url.endswith("/latest.json"):
            return _json_bytes(incoming)
        if url.endswith("/manifest.json") and "/archive/" not in url:
            return _json_bytes(_mirror_manifest(incoming))
        if url.endswith("/roots.jsonl"):
            return _json_bytes(incoming)
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(publish_testnet_static_mirror, "fetch_bytes", fake_fetch)

    with pytest.raises(publish_testnet_static_mirror.MirrorPublishError, match="different hash"):
        publish_testnet_static_mirror.copy_public_transparency(
            "https://source.example/transparency",
            target,
            include_archive=False,
        )

    assert json.loads(latest_path.read_text(encoding="utf-8"))["root_hash"] == existing["root_hash"]
