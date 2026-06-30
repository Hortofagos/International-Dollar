from ind import memory_pressure


def test_memory_pressure_trim_is_rate_limited(monkeypatch):
    calls = []
    monkeypatch.setenv("IND_MEMORY_TRIM_ENABLED", "1")
    monkeypatch.setenv("IND_MEMORY_TRIM_INTERVAL_SECONDS", "60")
    monkeypatch.setenv("IND_MEMORY_TRIM_MIN_RSS_MB", "0")
    monkeypatch.setattr(memory_pressure.gc, "collect", lambda: calls.append("gc") or 3)
    monkeypatch.setattr(memory_pressure, "_rss_bytes", lambda: 512 * 1024 * 1024)
    monkeypatch.setattr(memory_pressure, "_load_malloc_trim", lambda: (lambda _pad: 1))
    memory_pressure._reset_for_tests()

    first = memory_pressure.maybe_collect_after_pressure("test")
    second = memory_pressure.maybe_collect_after_pressure("test")

    assert first["ran"]
    assert first["malloc_trim"]
    assert first["collected"] == 3
    assert second == {"ran": False, "reason": "rate_limited"}
    assert calls == ["gc"]


def test_memory_pressure_trim_can_be_disabled(monkeypatch):
    monkeypatch.setenv("IND_MEMORY_TRIM_ENABLED", "0")
    memory_pressure._reset_for_tests()

    assert memory_pressure.maybe_collect_after_pressure("test", force=True) == {
        "ran": False,
        "reason": "disabled",
    }


def test_memory_pressure_trim_obeys_rss_threshold(monkeypatch):
    monkeypatch.setenv("IND_MEMORY_TRIM_ENABLED", "1")
    monkeypatch.setenv("IND_MEMORY_TRIM_INTERVAL_SECONDS", "0")
    monkeypatch.setenv("IND_MEMORY_TRIM_MIN_RSS_MB", "256")
    monkeypatch.setattr(memory_pressure, "_rss_bytes", lambda: 128 * 1024 * 1024)
    memory_pressure._reset_for_tests()

    assert memory_pressure.maybe_collect_after_pressure("test") == {
        "ran": False,
        "reason": "below_rss_threshold",
    }
