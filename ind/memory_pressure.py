# Opportunistic heap cleanup for long-lived node processes.

import ctypes
import gc
import os
import threading
import time

from . import env as ind_env

DEFAULT_MEMORY_TRIM_INTERVAL_SECONDS = 60
DEFAULT_MEMORY_TRIM_MIN_RSS_MB = 256

_trim_lock = threading.Lock()
_last_trim_at = 0.0
_malloc_trim = None
_malloc_trim_checked = False


def _rss_bytes():
    if os.name != "posix":
        return 0
    try:
        with open("/proc/self/statm", encoding="ascii") as handle:
            fields = handle.read().split()
        if len(fields) < 2:
            return 0
        return int(fields[1]) * int(os.sysconf("SC_PAGE_SIZE"))
    except Exception:
        return 0


def _load_malloc_trim():
    global _malloc_trim, _malloc_trim_checked
    if _malloc_trim_checked:
        return _malloc_trim
    _malloc_trim_checked = True
    if os.name != "posix":
        return None
    try:
        trim = ctypes.CDLL(None).malloc_trim
        trim.argtypes = [ctypes.c_size_t]
        trim.restype = ctypes.c_int
        _malloc_trim = trim
    except Exception:
        _malloc_trim = None
    return _malloc_trim


def collect_and_trim():
    collected = gc.collect()
    trim = _load_malloc_trim()
    trimmed = False
    if trim is not None:
        try:
            trimmed = bool(trim(0))
        except Exception:
            trimmed = False
    return {"collected": collected, "malloc_trim": trimmed}


def maybe_collect_after_pressure(reason="", *, force=False):
    global _last_trim_at

    if not ind_env.bool_value("IND_MEMORY_TRIM_ENABLED", True):
        return {"ran": False, "reason": "disabled"}

    interval = ind_env.float_value(
        "IND_MEMORY_TRIM_INTERVAL_SECONDS",
        DEFAULT_MEMORY_TRIM_INTERVAL_SECONDS,
        minimum=0,
    )
    now = time.monotonic()
    if not force and interval > 0 and now - _last_trim_at < interval:
        return {"ran": False, "reason": "rate_limited"}

    min_rss_mb = ind_env.int_value(
        "IND_MEMORY_TRIM_MIN_RSS_MB",
        DEFAULT_MEMORY_TRIM_MIN_RSS_MB,
        minimum=0,
    )
    if not force and min_rss_mb > 0 and _rss_bytes() < min_rss_mb * 1024 * 1024:
        return {"ran": False, "reason": "below_rss_threshold"}

    with _trim_lock:
        now = time.monotonic()
        if not force and interval > 0 and now - _last_trim_at < interval:
            return {"ran": False, "reason": "rate_limited"}
        _last_trim_at = now
        result = collect_and_trim()
    result.update({"ran": True, "reason": str(reason or "memory_pressure")})
    return result


def _reset_for_tests():
    global _last_trim_at, _malloc_trim, _malloc_trim_checked
    _last_trim_at = 0.0
    _malloc_trim = None
    _malloc_trim_checked = False
