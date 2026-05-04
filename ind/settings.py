import copy
import json
import os
from pathlib import Path
from urllib.parse import urlparse


SETTINGS_PATH = Path("files/security_settings.json")
MIN_FINALITY_BUFFER_SECONDS = 60

DEFAULT_SECURITY_SETTINGS = {
    "peer_ping_servers": [],
    "trusted_root_domains": [],
    "trusted_root_mirrors": [],
    "transparency_operator_url": "",
    "transparency_operator_public_key": "",
    "require_transparency_log": False,
    "min_root_mirrors": 2,
    "max_root_lag_seconds": 120,
    "max_current_root_age_seconds": 300,
    "current_root_future_skew_seconds": 120,
    "transparency_observed_roots_db": "files/transparency_observed_roots.db",
    "transparency_consistency_anchor_path": "",
    "transparency_consistency_check_interval_seconds": 900,
    "transparency_consistency_max_stale_seconds": 3600,
    "transparency_root_gossip": True,
    "finality_buffer_seconds": MIN_FINALITY_BUFFER_SECONDS,
    "peer_request_timeout_seconds": 4,
    "reject_peer_key_changes": True,
    "trusted_genesis_issuer_keys": [],
    "trusted_genesis_manifest_hashes": [],
    "allow_untrusted_genesis": False,
}


def default_settings():
    return copy.deepcopy(DEFAULT_SECURITY_SETTINGS)


def default_settings_json():
    return json.dumps(DEFAULT_SECURITY_SETTINGS, indent=2, sort_keys=True) + "\n"


def _env_true(name):
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _as_bool(value, default=False):
    if isinstance(value, bool):
        return value
    if value is None:
        return bool(default)
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _as_int(value, default, minimum=None, maximum=None):
    try:
        result = int(str(value).strip())
    except Exception:
        result = int(default)
    if minimum is not None:
        result = max(int(minimum), result)
    if maximum is not None:
        result = min(int(maximum), result)
    return result


def _as_lines(value):
    if value is None:
        return []
    if isinstance(value, str):
        return value.splitlines()
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [str(value)]


def _dedupe(items):
    seen = set()
    result = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            result.append(item)
    return result


def _normalize_server(value):
    value = str(value).strip()
    if not value:
        return ""
    if "://" in value:
        parsed = urlparse(value)
    else:
        parsed = urlparse("ind://" + value)
    host = parsed.hostname or value.split("/")[0].split(":")[0]
    return host.strip().lower()


def _normalize_domain(value):
    value = str(value).strip().lower()
    if not value:
        return ""
    if "://" in value:
        parsed = urlparse(value)
        value = parsed.hostname or ""
    value = value.split("/")[0].split(":")[0].strip(".")
    if value.startswith("*."):
        value = value[2:]
    return value


def _normalize_mirror(value):
    value = str(value).strip()
    if not value:
        return ""
    if value.startswith(("http://", "https://")):
        return value.rstrip("/")
    return value


def normalize_security_settings(settings):
    merged = default_settings()
    if isinstance(settings, dict):
        merged.update(settings)

    normalized = default_settings()
    normalized["peer_ping_servers"] = _dedupe(
        _normalize_server(item) for item in _as_lines(merged.get("peer_ping_servers"))
    )
    normalized["trusted_root_domains"] = _dedupe(
        _normalize_domain(item) for item in _as_lines(merged.get("trusted_root_domains"))
    )
    normalized["trusted_root_mirrors"] = _dedupe(
        _normalize_mirror(item) for item in _as_lines(merged.get("trusted_root_mirrors"))
    )
    normalized["transparency_operator_url"] = _normalize_mirror(merged.get("transparency_operator_url"))
    normalized["transparency_operator_public_key"] = str(
        merged.get("transparency_operator_public_key", "")
    ).strip()
    normalized["require_transparency_log"] = _as_bool(merged.get("require_transparency_log"))
    normalized["min_root_mirrors"] = _as_int(merged.get("min_root_mirrors"), 2, minimum=0, maximum=10)
    normalized["max_root_lag_seconds"] = _as_int(
        merged.get("max_root_lag_seconds"), 120, minimum=0, maximum=86400
    )
    normalized["max_current_root_age_seconds"] = _as_int(
        merged.get("max_current_root_age_seconds"), 300, minimum=1, maximum=86400
    )
    normalized["current_root_future_skew_seconds"] = _as_int(
        merged.get("current_root_future_skew_seconds"), 120, minimum=0, maximum=86400
    )
    normalized["transparency_observed_roots_db"] = str(
        merged.get("transparency_observed_roots_db", "files/transparency_observed_roots.db")
    ).strip() or "files/transparency_observed_roots.db"
    normalized["transparency_consistency_anchor_path"] = str(
        merged.get("transparency_consistency_anchor_path", "")
    ).strip()
    normalized["transparency_consistency_check_interval_seconds"] = _as_int(
        merged.get("transparency_consistency_check_interval_seconds"), 900, minimum=0, maximum=86400
    )
    normalized["transparency_consistency_max_stale_seconds"] = _as_int(
        merged.get("transparency_consistency_max_stale_seconds"), 3600, minimum=60, maximum=604800
    )
    normalized["transparency_root_gossip"] = _as_bool(merged.get("transparency_root_gossip"), True)
    normalized["finality_buffer_seconds"] = _as_int(
        merged.get("finality_buffer_seconds"),
        MIN_FINALITY_BUFFER_SECONDS,
        minimum=MIN_FINALITY_BUFFER_SECONDS,
        maximum=86400,
    )
    normalized["peer_request_timeout_seconds"] = _as_int(
        merged.get("peer_request_timeout_seconds"), 4, minimum=1, maximum=30
    )
    normalized["reject_peer_key_changes"] = _as_bool(merged.get("reject_peer_key_changes"), True)
    normalized["trusted_genesis_issuer_keys"] = _dedupe(
        str(item).strip() for item in _as_lines(merged.get("trusted_genesis_issuer_keys"))
    )
    normalized["trusted_genesis_manifest_hashes"] = _dedupe(
        str(item).strip().lower() for item in _as_lines(merged.get("trusted_genesis_manifest_hashes"))
    )
    normalized["allow_untrusted_genesis"] = _as_bool(merged.get("allow_untrusted_genesis"))
    return normalized


def load_security_settings(path=SETTINGS_PATH):
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        data = {}
    except Exception:
        data = {}
    return normalize_security_settings(data)


def save_security_settings(settings, path=SETTINGS_PATH):
    normalized = normalize_security_settings(settings)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(normalized, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return normalized


def reset_security_settings(path=SETTINGS_PATH):
    return save_security_settings(default_settings(), path=path)


def finality_buffer_seconds(settings=None):
    settings = settings or load_security_settings()
    return int(settings["finality_buffer_seconds"])


def peer_request_timeout_seconds(settings=None):
    settings = settings or load_security_settings()
    return int(settings["peer_request_timeout_seconds"])


def peer_ping_servers(settings=None):
    settings = settings or load_security_settings()
    return list(settings["peer_ping_servers"])


def require_transparency_log(settings=None):
    settings = settings or load_security_settings()
    return _env_true("IND_REQUIRE_TRANSPARENCY_LOG") or bool(settings["require_transparency_log"])


def transparency_operator_url(settings=None):
    settings = settings or load_security_settings()
    return os.environ.get("IND_LOG_OPERATOR_URL", "").strip() or settings["transparency_operator_url"]


def transparency_operator_public_key(settings=None):
    settings = settings or load_security_settings()
    env_value = os.environ.get("IND_LOG_OPERATOR_PUBLIC_KEY", "").strip()
    return env_value or settings["transparency_operator_public_key"]


def max_root_lag_seconds(settings=None):
    settings = settings or load_security_settings()
    return _as_int(
        os.environ.get("IND_LOG_MAX_ROOT_LAG_SECONDS", settings["max_root_lag_seconds"]),
        settings["max_root_lag_seconds"],
        minimum=0,
        maximum=86400,
    )


def max_current_root_age_seconds(settings=None):
    settings = settings or load_security_settings()
    return _as_int(
        os.environ.get("IND_LOG_MAX_CURRENT_ROOT_AGE_SECONDS", settings["max_current_root_age_seconds"]),
        settings["max_current_root_age_seconds"],
        minimum=1,
        maximum=86400,
    )


def current_root_future_skew_seconds(settings=None):
    settings = settings or load_security_settings()
    return _as_int(
        os.environ.get("IND_LOG_CURRENT_ROOT_FUTURE_SKEW_SECONDS", settings["current_root_future_skew_seconds"]),
        settings["current_root_future_skew_seconds"],
        minimum=0,
        maximum=86400,
    )


def min_root_mirrors(settings=None):
    settings = settings or load_security_settings()
    return _as_int(
        os.environ.get("IND_LOG_MIN_MIRRORS", settings["min_root_mirrors"]),
        settings["min_root_mirrors"],
        minimum=0,
        maximum=10,
    )


def unsafe_single_mirror():
    return _env_true("IND_LOG_UNSAFE_SINGLE_MIRROR")


def transparency_observed_roots_db(settings=None):
    settings = settings or load_security_settings()
    return (
        os.environ.get("IND_LOG_OBSERVED_ROOTS_DB", "").strip()
        or settings["transparency_observed_roots_db"]
    )


def transparency_consistency_anchor_path(settings=None):
    settings = settings or load_security_settings()
    return (
        os.environ.get("IND_LOG_CONSISTENCY_ANCHOR", "").strip()
        or settings["transparency_consistency_anchor_path"]
    )


def transparency_consistency_check_interval_seconds(settings=None):
    settings = settings or load_security_settings()
    return _as_int(
        os.environ.get(
            "IND_LOG_CONSISTENCY_CHECK_INTERVAL_SECONDS",
            settings["transparency_consistency_check_interval_seconds"],
        ),
        settings["transparency_consistency_check_interval_seconds"],
        minimum=0,
        maximum=86400,
    )


def transparency_consistency_max_stale_seconds(settings=None):
    settings = settings or load_security_settings()
    return _as_int(
        os.environ.get(
            "IND_LOG_CONSISTENCY_MAX_STALE_SECONDS",
            settings["transparency_consistency_max_stale_seconds"],
        ),
        settings["transparency_consistency_max_stale_seconds"],
        minimum=60,
        maximum=604800,
    )


def transparency_root_gossip(settings=None):
    settings = settings or load_security_settings()
    env_value = os.environ.get("IND_LOG_ROOT_GOSSIP", "").strip()
    if env_value:
        return _as_bool(env_value, True)
    return bool(settings["transparency_root_gossip"])


def _host_matches_domain(host, domain):
    host = host.lower().strip(".")
    domain = domain.lower().strip(".")
    return host == domain or host.endswith("." + domain)


def mirror_allowed_by_domains(mirror, domains):
    if not domains:
        return True
    parsed = urlparse(str(mirror))
    if parsed.scheme not in {"http", "https"}:
        return True
    host = (parsed.hostname or "").lower()
    return bool(host) and any(_host_matches_domain(host, domain) for domain in domains)


def trusted_root_mirrors(settings=None):
    settings = settings or load_security_settings()
    env_raw = os.environ.get("IND_LOG_MIRROR_URLS", "").strip()
    if env_raw:
        mirrors = [item.strip() for item in env_raw.split(",") if item.strip()]
    else:
        mirrors = list(settings["trusted_root_mirrors"])
    domains = list(settings["trusted_root_domains"])
    return [mirror for mirror in mirrors if mirror_allowed_by_domains(mirror, domains)]


def trusted_genesis_issuer_keys(settings=None):
    settings = settings or load_security_settings()
    env_raw = os.environ.get("IND_TRUSTED_GENESIS_ISSUER_KEYS", "")
    env_items = [item.strip() for item in env_raw.split(",") if item.strip()]
    return set(_dedupe(env_items + list(settings["trusted_genesis_issuer_keys"])))


def trusted_genesis_manifest_hashes(settings=None):
    settings = settings or load_security_settings()
    env_raw = os.environ.get("IND_TRUSTED_GENESIS_MANIFEST_HASHES", "")
    env_items = [item.strip().lower() for item in env_raw.split(",") if item.strip()]
    return set(_dedupe(env_items + list(settings["trusted_genesis_manifest_hashes"])))


def allow_untrusted_genesis(settings=None):
    settings = settings or load_security_settings()
    return _env_true("IND_ALLOW_UNTRUSTED_GENESIS") or bool(settings["allow_untrusted_genesis"])
