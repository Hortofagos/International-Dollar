import json
import types

from tools import testnet_monitor


def _root(timestamp, tree_size=10, root_hash="aa"):
    return {
        "log_id": "test-log",
        "tree_size": tree_size,
        "timestamp": timestamp,
        "root_hash": root_hash * 32,
    }


def _write_json(path, data):
    path.write_text(json.dumps(data, sort_keys=True) + "\n", encoding="utf-8")


def test_collect_transparency_flags_required_public_mirror_staleness(tmp_path, monkeypatch):
    static_root_path = tmp_path / "latest.json"
    archive_path = tmp_path / "archive-manifest.json"
    _write_json(static_root_path, _root(timestamp=990))
    _write_json(
        archive_path,
        {
            "archived_entry_count": 10,
            "signed_root_tree_size": 10,
            "signed_root_timestamp": 990,
            "manifest_timestamp": 990,
            "segments": [],
        },
    )

    def fake_fetch(url, timeout=10):
        if url == "https://operator.example/v3/root":
            return _root(timestamp=990)
        if url == "https://mirror.example/transparency/latest.json":
            return _root(timestamp=700)
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(testnet_monitor, "fetch_json", fake_fetch)
    report = {"timestamp": 1_000, "issues": []}

    testnet_monitor.collect_transparency(
        report,
        "https://operator.example/v3/root",
        static_root_path,
        archive_path,
        freshness_warn_seconds=180,
        mirror_root_urls=["https://mirror.example/transparency"],
    )

    codes = {issue["code"] for issue in report["issues"]}
    assert "mirror_root_stale" in codes
    assert report["transparency"]["mirror_roots"][0]["ok"] is False
    assert report["transparency"]["mirror_roots"][0]["url"].endswith("/latest.json")


def test_collect_transparency_flags_same_size_mirror_hash_mismatch(tmp_path, monkeypatch):
    static_root_path = tmp_path / "latest.json"
    archive_path = tmp_path / "archive-manifest.json"
    _write_json(static_root_path, _root(timestamp=990))
    _write_json(
        archive_path,
        {
            "archived_entry_count": 10,
            "signed_root_tree_size": 10,
            "signed_root_timestamp": 990,
            "manifest_timestamp": 990,
            "segments": [],
        },
    )

    def fake_fetch(url, timeout=10):
        if url == "https://operator.example/v3/root":
            return _root(timestamp=990, root_hash="aa")
        if url == "https://mirror.example/latest.json":
            return _root(timestamp=990, root_hash="bb")
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(testnet_monitor, "fetch_json", fake_fetch)
    report = {"timestamp": 1_000, "issues": []}

    testnet_monitor.collect_transparency(
        report,
        "https://operator.example/v3/root",
        static_root_path,
        archive_path,
        freshness_warn_seconds=180,
        mirror_root_urls=["https://mirror.example/latest.json"],
    )

    codes = {issue["code"] for issue in report["issues"]}
    assert "mirror_root_hash_mismatch" in codes
    assert report["transparency"]["mirror_roots"][0]["ok"] is False


def test_build_report_with_retries_stops_after_ok(monkeypatch):
    reports = iter(
        [
            {"ok": False, "issues": [{"level": "error", "code": "stale"}]},
            {"ok": True, "issues": []},
        ]
    )
    monkeypatch.setattr(testnet_monitor, "build_report", lambda _args: next(reports))
    sleeps = []
    monkeypatch.setattr(testnet_monitor.time, "sleep", sleeps.append)

    args = types.SimpleNamespace(retry_count=3, retry_delay_seconds=2)
    report = testnet_monitor.build_report_with_retries(args)

    assert report["ok"] is True
    assert report["attempt"] == 2
    assert report["max_attempts"] == 3
    assert sleeps == [2.0]
