# Security, network, transparency, and update settings for IND clients.

import copy
import ipaddress
import json
import os
from pathlib import Path
from urllib.parse import unquote, urlparse

from . import env as ind_env

SETTINGS_PATH = Path("files/security_settings.json")
MAINNET_NETWORK = "mainnet"
TESTNET_NETWORK = "testnet"
KNOWN_NETWORKS = {MAINNET_NETWORK, TESTNET_NETWORK}
DEFAULT_MAINNET_NODE_PORT = 8888
DEFAULT_TESTNET_NODE_PORT = 18888
DEFAULT_NODE_PORTS = {
    MAINNET_NETWORK: DEFAULT_MAINNET_NODE_PORT,
    TESTNET_NETWORK: DEFAULT_TESTNET_NODE_PORT,
}
DEFAULT_STORE_PATHS = {
    MAINNET_NETWORK: "ind_gossip.db",
    TESTNET_NETWORK: "ind_gossip_testnet.db",
}
DEFAULT_FINALITY_BUFFER_SECONDS = 60
MIN_FINALITY_BUFFER_SECONDS = 0
DEFAULT_PEER_REQUEST_TIMEOUT_SECONDS = 10
MAX_PEER_REQUEST_TIMEOUT_SECONDS = 30
DEFAULT_UPDATE_SOURCE = "international-dollar.com/update"
DEFAULT_UPDATE_CHANNEL = "stable"
DEFAULT_GUI_SCALE = "auto"
GUI_SCALE_PRESETS = ("1.0", "1.25", "1.5", "2.0")
DEFAULT_DNS_SEED_HOSTS = [
    "seed.international-dollar.com",
    "seed.internetofthebots.com",
]
LEGACY_MAINNET_DNS_SEED_HOSTS = [
    "seed.international-dollar.com",
    "seed.linkifier.me",
    "seed.internetofthebots.com",
]
DEFAULT_TESTNET_DNS_SEED_HOSTS = [
    "testnet-seed.international-dollar.com",
    "testnet-seed.internetofthebots.com",
]
DEFAULT_OPERATOR_APPEND_FANOUT = 5
MAX_OPERATOR_APPEND_FANOUT = 50
DEFAULT_OPERATOR_CORE_DOMAINS = [
    "international-dollar.com",
    "internetofthebots.com",
]
DEFAULT_MAINNET_ROOT_DOMAINS = [
    *DEFAULT_OPERATOR_CORE_DOMAINS,
    "91.99.175.174",
    "108.61.23.82",
]
DEFAULT_TESTNET_ROOT_DOMAINS = [
    *DEFAULT_OPERATOR_CORE_DOMAINS,
    "167.233.115.216",
    "91.99.175.174",
]
DEFAULT_MAINNET_PEER_PING_SERVERS = [
    "seed.international-dollar.com",
    "seed.internetofthebots.com",
    "51.83.199.25",
]
LEGACY_MAINNET_PEER_PING_SERVERS = [
    "91.99.175.174",
    "51.83.199.25",
    "108.61.23.82",
]
DEFAULT_TESTNET_PEER_PING_SERVERS = [
    "testnet-seed.international-dollar.com",
    "testnet-seed.internetofthebots.com",
    "51.83.199.25",
    "108.61.23.82",
]
DEFAULT_MAINNET_TRANSPARENCY_OPERATOR_URL = "http://167.233.115.216/mainnet-operator-api"
DEFAULT_MAINNET_TRANSPARENCY_OPERATOR_PUBLIC_KEY = (
    "indpk3:Qu)F<E@Jz(MQ6iS8NLT+N-tt-O3|`^z6CsWx{Br7"
)
DEFAULT_MAINNET_ROOT_MIRRORS = [
    "http://91.99.175.174/mainnet-transparency",
    "http://108.61.23.82/mainnet-transparency",
]
DEFAULT_MAINNET_PROOF_ARCHIVES = [
    "http://91.99.175.174/mainnet-transparency",
    "http://108.61.23.82/mainnet-transparency",
]
DEFAULT_MAINNET_IOTB_OPERATOR_URL = (
    "https://testnet-seed.internetofthebots.com/mainnet-iotb-operator-api"
)
DEFAULT_MAINNET_IOTB_OPERATOR_PUBLIC_KEY = (
    "indpk3:i8x(A2B9u``X1Ny>r2)2`evenV>4H=Pz~{&*%j`u"
)
DEFAULT_MAINNET_IOTB_ROOT_MIRRORS = [
    "https://international-dollar.com/mainnet-iotb-operator/transparency",
    "http://108.61.23.82/mainnet-iotb-operator/transparency",
]
DEFAULT_MAINNET_IOTB_PROOF_ARCHIVES = [
    "https://international-dollar.com/mainnet-iotb-operator/transparency",
    "http://108.61.23.82/mainnet-iotb-operator/transparency",
]
DEFAULT_TESTNET_TRANSPARENCY_OPERATOR_URL = (
    "https://testnet-seed.international-dollar.com/operator-api"
)
DEFAULT_TESTNET_TRANSPARENCY_OPERATOR_PUBLIC_KEY = (
    "indpk3:=B-fA7q0hRg#HKK4CBl87c!T;r&B&#5G^3#wd<@)"
)
DEFAULT_TESTNET_ROOT_MIRRORS = [
    "https://international-dollar.com/transparency",
    "https://testnet-seed.internetofthebots.com/transparency",
]
DEFAULT_TESTNET_PROOF_ARCHIVES = [
    "https://international-dollar.com/transparency/archive",
    "https://testnet-seed.internetofthebots.com/transparency/archive",
]
DEFAULT_MAINNET_TRANSPARENCY_OPERATORS = [
    {
        "url": DEFAULT_MAINNET_TRANSPARENCY_OPERATOR_URL,
        "public_key": DEFAULT_MAINNET_TRANSPARENCY_OPERATOR_PUBLIC_KEY,
        "mirrors": DEFAULT_MAINNET_ROOT_MIRRORS,
        "proof_archives": DEFAULT_MAINNET_PROOF_ARCHIVES,
    },
    {
        "url": DEFAULT_MAINNET_IOTB_OPERATOR_URL,
        "public_key": DEFAULT_MAINNET_IOTB_OPERATOR_PUBLIC_KEY,
        "mirrors": DEFAULT_MAINNET_IOTB_ROOT_MIRRORS,
        "proof_archives": DEFAULT_MAINNET_IOTB_PROOF_ARCHIVES,
    }
]
DEFAULT_TESTNET_TRANSPARENCY_OPERATORS = [
    {
        "url": DEFAULT_TESTNET_TRANSPARENCY_OPERATOR_URL,
        "public_key": DEFAULT_TESTNET_TRANSPARENCY_OPERATOR_PUBLIC_KEY,
        "mirrors": DEFAULT_TESTNET_ROOT_MIRRORS,
        "proof_archives": DEFAULT_TESTNET_PROOF_ARCHIVES,
    },
    {
        "url": "https://testnet-seed.internetofthebots.com/operator-api",
        "public_key": "indpk3:*EGNObOb5(62ZHerk?UG&Rr&^IkI%cUyS$uZ5Qno",
        "mirrors": [
            "https://international-dollar.com/iotb-operator/transparency",
            "https://testnet-seed.international-dollar.com/iotb-operator/transparency",
        ],
        "proof_archives": [
            "https://international-dollar.com/iotb-operator/transparency/archive",
            "https://testnet-seed.international-dollar.com/iotb-operator/transparency/archive",
        ],
    },
    {
        "url": "http://108.61.23.82/operator-api",
        "public_key": "indpk3:KY$x=dWlnoIr>|D%-_QKr2#KPNuxNT(NV73KD~{}",
        "mirrors": [
            "http://167.233.115.216/operator3/transparency",
            "http://91.99.175.174/operator3/transparency",
        ],
        "proof_archives": [
            "http://167.233.115.216/operator3/transparency/archive",
            "http://91.99.175.174/operator3/transparency/archive",
        ],
    },
]
DEFAULT_MAINNET_GENESIS_ISSUER_KEYS = [
    "indpk3:s%?Mj7Z|(BIPB>&JkAAP!$&u9<uZnl4AxcNv*`s9",
]
DEFAULT_MAINNET_GENESIS_MANIFEST_HASHES = [
    "81a79b2567f5eaf83a92d5f60c0b754106329d3f3cc17f895a575ecf21a39e36",
]
DEFAULT_TESTNET_GENESIS_ISSUER_KEYS = [
    "indpk3:x=P|+kInO1oQ<Y4Y;fNA`{q$dJ&!CRUxU^C!RkaH",
]
DEFAULT_TESTNET_GENESIS_MANIFEST_HASHES = [
    "9d1a9cfeb6ceefa4aa39b702af1f5c6be204ddd5fb2e8dd1df0041a47dd31aa6",
]

DEFAULT_SECURITY_SETTINGS = {
    "network": MAINNET_NETWORK,
    "security_profile": "development",
    "security_role": "client",
    "node_port": DEFAULT_MAINNET_NODE_PORT,
    "peer_ping_servers": DEFAULT_MAINNET_PEER_PING_SERVERS,
    "dns_seed_hosts": DEFAULT_DNS_SEED_HOSTS,
    "trusted_root_domains": DEFAULT_MAINNET_ROOT_DOMAINS,
    "trusted_root_mirrors": DEFAULT_MAINNET_ROOT_MIRRORS,
    "transparency_proof_archives": DEFAULT_MAINNET_PROOF_ARCHIVES,
    "transparency_operator_url": DEFAULT_MAINNET_TRANSPARENCY_OPERATOR_URL,
    "transparency_operator_public_key": DEFAULT_MAINNET_TRANSPARENCY_OPERATOR_PUBLIC_KEY,
    "transparency_operators": DEFAULT_MAINNET_TRANSPARENCY_OPERATORS,
    "require_transparency_log": True,
    "submit_to_transparency_log": True,
    "min_root_mirrors": 2,
    "max_root_lag_seconds": 120,
    "max_current_root_age_seconds": 300,
    "current_root_future_skew_seconds": 120,
    "operator_recovery_feeds": [],
    "operator_recovery_min_feeds": 2,
    "operator_recovery_stable_seconds": 120,
    "transparency_observed_roots_db": "files/transparency_observed_roots.db",
    "transparency_consistency_anchor_path": "",
    "transparency_consistency_check_interval_seconds": 900,
    "transparency_consistency_max_stale_seconds": 3600,
    "transparency_root_gossip": True,
    "operator_finality_min_proofs": 0,
    "operator_append_fanout": DEFAULT_OPERATOR_APPEND_FANOUT,
    "operator_core_domains": DEFAULT_OPERATOR_CORE_DOMAINS,
    "finality_buffer_seconds": DEFAULT_FINALITY_BUFFER_SECONDS,
    "settlement_quorum_enabled": False,
    "settlement_peers": [],
    "settlement_min_remote_confirmations": 1,
    "settlement_require_all_configured_peers": False,
    "transparency_submit_async": False,
    "peer_request_timeout_seconds": DEFAULT_PEER_REQUEST_TIMEOUT_SECONDS,
    "reject_peer_key_changes": False,
    "trusted_genesis_issuer_keys": DEFAULT_MAINNET_GENESIS_ISSUER_KEYS,
    "trusted_genesis_manifest_hashes": DEFAULT_MAINNET_GENESIS_MANIFEST_HASHES,
    "allow_untrusted_genesis": False,
    "update_source": DEFAULT_UPDATE_SOURCE,
    "update_channel": DEFAULT_UPDATE_CHANNEL,
    "trusted_update_signing_keys": [],
    "update_check_on_startup": False,
    "auto_sync_on_wallet_sign_in": True,
    "gui_scale": DEFAULT_GUI_SCALE,
}


def default_settings():
    return copy.deepcopy(DEFAULT_SECURITY_SETTINGS)


def default_settings_json():
    return json.dumps(DEFAULT_SECURITY_SETTINGS, indent=2, sort_keys=True) + "\n"


_env_true = ind_env.enabled
_env_false = ind_env.disabled


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
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError:
        pass
    parsed = urlparse(value) if "://" in value else urlparse("ind://" + value)
    host = parsed.hostname or value.split("/")[0].split(":")[0]
    host = host.strip().lower()
    try:
        return ipaddress.ip_address(host).compressed
    except ValueError:
        return host


def _normalize_network(value):
    value = str(value or "").strip().lower().replace("_", "-")
    aliases = {
        "main": MAINNET_NETWORK,
        "main-net": MAINNET_NETWORK,
        "mainnet": MAINNET_NETWORK,
        "production": MAINNET_NETWORK,
        "prod": MAINNET_NETWORK,
        "test": TESTNET_NETWORK,
        "test-net": TESTNET_NETWORK,
        "testnet": TESTNET_NETWORK,
        "public-testnet": TESTNET_NETWORK,
    }
    return aliases.get(value, MAINNET_NETWORK)


def _settings_defaults_for_network(network):
    network = _normalize_network(network)
    defaults = default_settings()
    if network != TESTNET_NETWORK:
        return defaults
    defaults.update(
        {
            "network": TESTNET_NETWORK,
            "node_port": DEFAULT_TESTNET_NODE_PORT,
            "peer_ping_servers": DEFAULT_TESTNET_PEER_PING_SERVERS,
            "dns_seed_hosts": DEFAULT_TESTNET_DNS_SEED_HOSTS,
            "trusted_root_domains": DEFAULT_TESTNET_ROOT_DOMAINS,
            "trusted_root_mirrors": DEFAULT_TESTNET_ROOT_MIRRORS,
            "transparency_proof_archives": DEFAULT_TESTNET_PROOF_ARCHIVES,
            "transparency_operator_url": DEFAULT_TESTNET_TRANSPARENCY_OPERATOR_URL,
            "transparency_operator_public_key": DEFAULT_TESTNET_TRANSPARENCY_OPERATOR_PUBLIC_KEY,
            "transparency_operators": DEFAULT_TESTNET_TRANSPARENCY_OPERATORS,
            "trusted_genesis_issuer_keys": DEFAULT_TESTNET_GENESIS_ISSUER_KEYS,
            "trusted_genesis_manifest_hashes": DEFAULT_TESTNET_GENESIS_MANIFEST_HASHES,
        }
    )
    return defaults


def _list_matches(value, expected):
    return [str(item).strip() for item in _as_lines(value)] == [
        str(item).strip() for item in _as_lines(expected)
    ]


def _list_matches_any(value, candidates):
    return any(_list_matches(value, candidate) for candidate in candidates)


def _operators_match(value, expected):
    try:
        left = json.dumps(value or [], sort_keys=True, separators=(",", ":"))
        right = json.dumps(expected or [], sort_keys=True, separators=(",", ":"))
    except TypeError:
        return False
    return left == right


def _list_for_network_default(value, key, network, *, legacy_mainnet_defaults=()):
    if network == TESTNET_NETWORK and _list_matches_any(
        value, (DEFAULT_SECURITY_SETTINGS.get(key, []), *legacy_mainnet_defaults)
    ):
        return list(_settings_defaults_for_network(network).get(key, []))
    if network == MAINNET_NETWORK and _list_matches_any(value, legacy_mainnet_defaults):
        return list(_settings_defaults_for_network(network).get(key, []))
    return value


def _scalar_for_network_default(value, key, network, *, legacy_mainnet_defaults=()):
    text = str(value or "").strip()
    mainnet_default = str(DEFAULT_SECURITY_SETTINGS.get(key, "") or "").strip()
    legacy = {str(item or "").strip() for item in legacy_mainnet_defaults}
    if network == TESTNET_NETWORK and text in ({mainnet_default} | legacy):
        return _settings_defaults_for_network(network).get(key)
    if network == MAINNET_NETWORK and text in legacy:
        return _settings_defaults_for_network(network).get(key)
    return value


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
        if not _safe_http_base_url(value):
            return ""
        return value.rstrip("/")
    return value


def _normalize_operator_config(value):
    if not isinstance(value, dict):
        return None
    url = _normalize_mirror(value.get("url", ""))
    public_key = str(value.get("public_key", "")).strip()
    mirrors = _dedupe(_normalize_mirror(item) for item in _as_lines(value.get("mirrors")))
    proof_archives = _dedupe(
        _normalize_mirror(item) for item in _as_lines(value.get("proof_archives"))
    )
    if not url and not public_key and not mirrors and not proof_archives:
        return None
    return {
        "url": url,
        "public_key": public_key,
        "mirrors": mirrors,
        "proof_archives": proof_archives,
    }


def _safe_http_base_url(value):
    parsed = urlparse(str(value).strip())
    if parsed.scheme not in {"http", "https"}:
        return True
    if not parsed.hostname or parsed.query or parsed.fragment:
        return False
    decoded_path = parsed.path or ""
    for _ in range(3):
        next_path = unquote(decoded_path)
        if next_path == decoded_path:
            break
        decoded_path = next_path
    return "\\" not in decoded_path and not any(
        segment == ".." for segment in decoded_path.split("/")
    )


def _normalize_update_source(value):
    value = str(value).strip()
    return value.rstrip("/") if value else DEFAULT_UPDATE_SOURCE


def _normalize_update_channel(value):
    value = str(value or "").strip().lower()
    if not value:
        return DEFAULT_UPDATE_CHANNEL
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-_.")
    return value if all(char in allowed for char in value) else DEFAULT_UPDATE_CHANNEL


def _normalize_gui_scale(value):
    raw = str(value or "").strip().lower()
    if raw in {"", "auto", "automatic", "system"}:
        return DEFAULT_GUI_SCALE
    while raw.endswith("x"):
        raw = raw[:-1].strip()
    try:
        requested = float(raw)
    except Exception:
        return DEFAULT_GUI_SCALE
    for scale in GUI_SCALE_PRESETS:
        if abs(requested - float(scale)) < 0.001:
            return scale
    return DEFAULT_GUI_SCALE


def normalize_security_settings(settings):
    """Merge user settings with defaults and coerce them into safe ranges.

    The returned dictionary is the canonical shape used by the GUI, node, and
    verifier code. Invalid enum values fall back to development/client defaults,
    numeric values are clamped, and list-like values are normalized/deduped.
    """

    raw_settings = settings if isinstance(settings, dict) else {}
    requested_network = _normalize_network(raw_settings.get("network", MAINNET_NETWORK))
    merged = _settings_defaults_for_network(requested_network)
    merged.update(raw_settings)

    normalized_network = _normalize_network(merged.get("network", requested_network))
    normalized = _settings_defaults_for_network(normalized_network)
    # Core network identity and runtime role.
    normalized["network"] = normalized_network
    security_profile = (
        str(merged.get("security_profile", "development")).strip().lower() or "development"
    )
    if security_profile not in {"development", "production"}:
        security_profile = "development"
    normalized["security_profile"] = security_profile
    security_role = str(merged.get("security_role", "client")).strip().lower() or "client"
    if security_role not in {"client", "operator"}:
        security_role = "client"
    normalized["security_role"] = security_role
    configured_node_port = _as_int(merged.get("node_port"), 0, minimum=0, maximum=65535)
    if normalized_network == TESTNET_NETWORK and configured_node_port in {
        0,
        DEFAULT_MAINNET_NODE_PORT,
    }:
        configured_node_port = DEFAULT_TESTNET_NODE_PORT
    elif normalized_network == MAINNET_NETWORK and configured_node_port == 0:
        configured_node_port = DEFAULT_MAINNET_NODE_PORT
    normalized["node_port"] = configured_node_port

    # Peer and mirror lists accept multiline text from the GUI.
    merged_peer_ping_servers = _list_for_network_default(
        merged.get("peer_ping_servers"),
        "peer_ping_servers",
        normalized_network,
        legacy_mainnet_defaults=(LEGACY_MAINNET_PEER_PING_SERVERS, []),
    )
    merged_dns_seed_hosts = _list_for_network_default(
        merged.get("dns_seed_hosts"),
        "dns_seed_hosts",
        normalized_network,
        legacy_mainnet_defaults=(LEGACY_MAINNET_DNS_SEED_HOSTS, []),
    )
    merged_root_mirrors = _list_for_network_default(
        merged.get("trusted_root_mirrors"),
        "trusted_root_mirrors",
        normalized_network,
        legacy_mainnet_defaults=([],),
    )
    merged_proof_archives = _list_for_network_default(
        merged.get("transparency_proof_archives"),
        "transparency_proof_archives",
        normalized_network,
        legacy_mainnet_defaults=([DEFAULT_MAINNET_TRANSPARENCY_OPERATOR_URL], []),
    )
    merged_root_domains = merged.get("trusted_root_domains")
    if not _as_lines(merged_root_domains) and _list_matches(
        merged_root_mirrors,
        _settings_defaults_for_network(normalized_network).get("trusted_root_mirrors", []),
    ):
        merged_root_domains = _settings_defaults_for_network(normalized_network).get(
            "trusted_root_domains", []
        )
    normalized["peer_ping_servers"] = _dedupe(
        _normalize_server(item) for item in _as_lines(merged_peer_ping_servers)
    )
    normalized["dns_seed_hosts"] = _dedupe(
        _normalize_server(item) for item in _as_lines(merged_dns_seed_hosts)
    )
    normalized["trusted_root_domains"] = _dedupe(
        _normalize_domain(item) for item in _as_lines(merged_root_domains)
    )
    normalized["trusted_root_mirrors"] = _dedupe(
        _normalize_mirror(item) for item in _as_lines(merged_root_mirrors)
    )
    normalized["transparency_proof_archives"] = _dedupe(
        _normalize_mirror(item) for item in _as_lines(merged_proof_archives)
    )
    normalized["transparency_operator_url"] = _normalize_mirror(
        _scalar_for_network_default(
            merged.get("transparency_operator_url"),
            "transparency_operator_url",
            normalized_network,
            legacy_mainnet_defaults=("",),
        )
    )
    normalized["transparency_operator_public_key"] = str(
        _scalar_for_network_default(
            merged.get("transparency_operator_public_key", ""),
            "transparency_operator_public_key",
            normalized_network,
            legacy_mainnet_defaults=("",),
        )
    ).strip()
    operators = []
    raw_operators = merged.get("transparency_operators")
    if (
        not raw_operators
        or _operators_match(raw_operators, DEFAULT_SECURITY_SETTINGS["transparency_operators"])
    ):
        default_url = str(DEFAULT_SECURITY_SETTINGS["transparency_operator_url"]).strip()
        merged_url = str(merged.get("transparency_operator_url") or "").strip()
        if normalized_network == TESTNET_NETWORK and merged_url in {"", default_url}:
            raw_operators = DEFAULT_TESTNET_TRANSPARENCY_OPERATORS
        elif normalized_network == MAINNET_NETWORK and merged_url in {"", default_url}:
            raw_operators = DEFAULT_MAINNET_TRANSPARENCY_OPERATORS
    if isinstance(raw_operators, str):
        try:
            raw_operators = json.loads(raw_operators)
        except json.JSONDecodeError:
            raw_operators = []
    if isinstance(raw_operators, (list, tuple)):
        for item in raw_operators:
            operator = _normalize_operator_config(item)
            if operator:
                operators.append(operator)
    normalized["transparency_operators"] = operators

    # Transparency knobs are bounded here so production checks can reason over one shape.
    normalized["require_transparency_log"] = _as_bool(merged.get("require_transparency_log"))
    normalized["submit_to_transparency_log"] = _as_bool(
        merged.get("submit_to_transparency_log"), True
    )
    normalized["min_root_mirrors"] = _as_int(
        merged.get("min_root_mirrors"), 2, minimum=0, maximum=10
    )
    normalized["max_root_lag_seconds"] = _as_int(
        merged.get("max_root_lag_seconds"), 120, minimum=0, maximum=86400
    )
    normalized["max_current_root_age_seconds"] = _as_int(
        merged.get("max_current_root_age_seconds"), 300, minimum=1, maximum=86400
    )
    normalized["current_root_future_skew_seconds"] = _as_int(
        merged.get("current_root_future_skew_seconds"), 120, minimum=0, maximum=86400
    )
    normalized["operator_recovery_feeds"] = _dedupe(
        _normalize_mirror(item) for item in _as_lines(merged.get("operator_recovery_feeds"))
    )
    normalized["operator_recovery_min_feeds"] = _as_int(
        merged.get("operator_recovery_min_feeds"), 2, minimum=1, maximum=10
    )
    normalized["operator_recovery_stable_seconds"] = _as_int(
        merged.get("operator_recovery_stable_seconds"), 120, minimum=0, maximum=86400
    )
    normalized["transparency_observed_roots_db"] = (
        str(
            merged.get("transparency_observed_roots_db", "files/transparency_observed_roots.db")
        ).strip()
        or "files/transparency_observed_roots.db"
    )
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
    normalized["operator_finality_min_proofs"] = _as_int(
        merged.get("operator_finality_min_proofs"),
        0,
        minimum=0,
        maximum=10,
    )
    normalized["operator_append_fanout"] = _as_int(
        merged.get("operator_append_fanout"),
        DEFAULT_OPERATOR_APPEND_FANOUT,
        minimum=1,
        maximum=MAX_OPERATOR_APPEND_FANOUT,
    )
    normalized["operator_core_domains"] = _dedupe(
        _normalize_domain(item) for item in _as_lines(merged.get("operator_core_domains"))
    )
    normalized["finality_buffer_seconds"] = _as_int(
        merged.get("finality_buffer_seconds"),
        DEFAULT_FINALITY_BUFFER_SECONDS,
        minimum=MIN_FINALITY_BUFFER_SECONDS,
        maximum=86400,
    )
    normalized["settlement_quorum_enabled"] = _as_bool(
        merged.get("settlement_quorum_enabled"), False
    )
    normalized["settlement_peers"] = _dedupe(
        _normalize_server(item) for item in _as_lines(merged.get("settlement_peers"))
    )
    normalized["settlement_min_remote_confirmations"] = _as_int(
        merged.get("settlement_min_remote_confirmations"),
        1,
        minimum=0,
        maximum=10,
    )
    normalized["settlement_require_all_configured_peers"] = _as_bool(
        merged.get("settlement_require_all_configured_peers"), False
    )
    normalized["transparency_submit_async"] = _as_bool(
        merged.get("transparency_submit_async"), False
    )
    normalized["peer_request_timeout_seconds"] = _as_int(
        merged.get("peer_request_timeout_seconds"),
        DEFAULT_PEER_REQUEST_TIMEOUT_SECONDS,
        minimum=1,
        maximum=MAX_PEER_REQUEST_TIMEOUT_SECONDS,
    )
    normalized["reject_peer_key_changes"] = _as_bool(merged.get("reject_peer_key_changes"), False)

    # Genesis trust pins are intentionally exact strings/hashes after whitespace cleanup.
    merged_genesis_issuer_keys = _list_for_network_default(
        merged.get("trusted_genesis_issuer_keys"),
        "trusted_genesis_issuer_keys",
        normalized_network,
        legacy_mainnet_defaults=([],),
    )
    merged_genesis_manifest_hashes = _list_for_network_default(
        merged.get("trusted_genesis_manifest_hashes"),
        "trusted_genesis_manifest_hashes",
        normalized_network,
        legacy_mainnet_defaults=([],),
    )
    normalized["trusted_genesis_issuer_keys"] = _dedupe(
        str(item).strip() for item in _as_lines(merged_genesis_issuer_keys)
    )
    normalized["trusted_genesis_manifest_hashes"] = _dedupe(
        str(item).strip().lower() for item in _as_lines(merged_genesis_manifest_hashes)
    )
    normalized["allow_untrusted_genesis"] = _as_bool(merged.get("allow_untrusted_genesis"))
    normalized["update_source"] = _normalize_update_source(
        merged.get("update_source", DEFAULT_UPDATE_SOURCE)
    )
    normalized["update_channel"] = _normalize_update_channel(
        merged.get("update_channel", DEFAULT_UPDATE_CHANNEL)
    )
    normalized["trusted_update_signing_keys"] = _dedupe(
        str(item).strip() for item in _as_lines(merged.get("trusted_update_signing_keys"))
    )
    normalized["update_check_on_startup"] = _as_bool(merged.get("update_check_on_startup"), False)
    normalized["auto_sync_on_wallet_sign_in"] = _as_bool(
        merged.get("auto_sync_on_wallet_sign_in"), True
    )
    normalized["gui_scale"] = _normalize_gui_scale(merged.get("gui_scale", DEFAULT_GUI_SCALE))
    return normalized


def production_mode(settings=None):
    if (
        _env_true("IND_PRODUCTION")
        or os.environ.get("IND_SECURITY_PROFILE", "").strip().lower() == "production"
    ):
        return True
    settings = settings or {}
    return str(settings.get("security_profile", "")).strip().lower() == "production"


def production_security_issues(settings, role=None):
    settings = normalize_security_settings(settings)
    if role is not None:
        role = str(role).strip().lower()
        if role in {"client", "operator"}:
            settings["security_role"] = role
    issues = []
    configured_operators = transparency_operators(settings)
    if not require_transparency_log(settings):
        issues.append("require_transparency_log must be true")
    if not submit_to_transparency_log(settings):
        issues.append("submit_to_transparency_log must be true")
    if not configured_operators:
        issues.append("transparency_operator_url or transparency_operators must be configured")
    if not any(operator.get("public_key") for operator in configured_operators):
        issues.append("transparency operator public key must be pinned")
    configured_min_mirrors = min_root_mirrors(settings)
    configured_root_mirrors = trusted_root_mirrors(settings)
    operator_mirror_counts = [len(operator.get("mirrors", [])) for operator in configured_operators]
    if configured_min_mirrors < 2:
        issues.append("min_root_mirrors must be at least 2")
    if len(configured_root_mirrors) < configured_min_mirrors and not any(
        count >= configured_min_mirrors for count in operator_mirror_counts
    ):
        issues.append("trusted_root_mirrors must contain enough independent mirrors")
    if _env_true("IND_LOG_UNSAFE_SINGLE_MIRROR"):
        issues.append("IND_LOG_UNSAFE_SINGLE_MIRROR is forbidden in production")
    if allow_untrusted_genesis(settings):
        issues.append("untrusted genesis must be disabled")
    if not trusted_genesis_issuer_keys(settings) and not trusted_genesis_manifest_hashes(settings):
        issues.append("trusted genesis issuer keys or manifest hashes must be pinned")
    if max_current_root_age_seconds(settings) > 600:
        issues.append("max_current_root_age_seconds must be 600 or less")
    if current_root_future_skew_seconds(settings) >= max_current_root_age_seconds(settings):
        issues.append(
            "current_root_future_skew_seconds must be smaller than max_current_root_age_seconds"
        )
    append_operator_count = append_capable_operator_count(settings)
    configured_finality = operator_finality_min_proofs(settings)
    append_fanout = operator_append_fanout(settings)
    if append_operator_count > 0 and configured_finality > append_fanout:
        issues.append("operator_finality_min_proofs must not exceed operator_append_fanout")
    if not transparency_proof_archives(settings):
        issues.append("at least one transparency proof archive mirror should be configured")
    return issues


def assert_production_security(settings, role=None):
    issues = production_security_issues(settings, role=role)
    if issues:
        raise ValueError("production IND security settings are incomplete: " + "; ".join(issues))
    return True


def load_security_settings(path=SETTINGS_PATH, validate_production=True):
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        data = {}
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid IND security settings JSON in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"IND security settings in {path} must be a JSON object")
    env_network = os.environ.get("IND_NETWORK", "").strip()
    if env_network:
        data = dict(data)
        data["network"] = env_network
    normalized = normalize_security_settings(data)
    if validate_production and production_mode(normalized):
        assert_production_security(normalized)
    return normalized


def save_security_settings(settings, path=SETTINGS_PATH):
    normalized = normalize_security_settings(settings)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(normalized, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return normalized


def reset_security_settings(path=SETTINGS_PATH):
    return save_security_settings(default_settings(), path=path)


def security_profile(settings=None):
    settings = settings or load_security_settings()
    return settings["security_profile"]


def security_role(settings=None):
    settings = settings or load_security_settings()
    return settings["security_role"]


def network_name(settings=None):
    env_value = os.environ.get("IND_NETWORK", "").strip()
    if env_value:
        return _normalize_network(env_value)
    settings = settings or load_security_settings()
    return _normalize_network(settings.get("network", MAINNET_NETWORK))


def is_testnet(settings=None):
    return network_name(settings) == TESTNET_NETWORK


def network_runtime_namespace(settings=None):
    name = network_name(settings)
    return "" if name == MAINNET_NETWORK else name


def node_port(settings=None):
    settings = settings or load_security_settings()
    env_value = os.environ.get("IND_NODE_PORT", "").strip()
    if env_value:
        return _as_int(
            env_value, DEFAULT_NODE_PORTS[network_name(settings)], minimum=1, maximum=65535
        )
    configured = _as_int(settings.get("node_port"), 0, minimum=0, maximum=65535)
    if configured:
        return configured
    return DEFAULT_NODE_PORTS[network_name(settings)]


def default_store_path(settings=None):
    settings = settings or load_security_settings()
    env_value = os.environ.get("IND_STORE_PATH", "").strip()
    if env_value:
        return env_value
    return DEFAULT_STORE_PATHS[network_name(settings)]


def finality_buffer_seconds(settings=None):
    settings = settings or load_security_settings()
    return int(settings["finality_buffer_seconds"])


def append_capable_operator_count(settings=None):
    settings = settings or load_security_settings()
    return sum(1 for operator in transparency_operators(settings) if operator.get("url"))


def operator_finality_min_proofs(settings=None):
    settings = settings or load_security_settings()
    configured = _as_int(
        os.environ.get(
            "IND_OPERATOR_FINALITY_MIN_PROOFS",
            settings.get("operator_finality_min_proofs", 0),
        ),
        settings.get("operator_finality_min_proofs", 0),
        minimum=0,
        maximum=10,
    )
    if configured > 0:
        return configured
    operator_count = append_capable_operator_count(settings)
    if operator_count <= 0:
        return 0
    selected_count = min(operator_count, operator_append_fanout(settings))
    return selected_count // 2 + 1


def operator_append_fanout(settings=None):
    settings = settings or load_security_settings()
    return _as_int(
        os.environ.get(
            "IND_OPERATOR_APPEND_FANOUT",
            settings.get("operator_append_fanout", DEFAULT_OPERATOR_APPEND_FANOUT),
        ),
        settings.get("operator_append_fanout", DEFAULT_OPERATOR_APPEND_FANOUT),
        minimum=1,
        maximum=MAX_OPERATOR_APPEND_FANOUT,
    )


def operator_core_domains(settings=None):
    settings = settings or load_security_settings()
    env_raw = os.environ.get("IND_OPERATOR_CORE_DOMAINS", "").strip()
    if env_raw:
        return _dedupe(
            _normalize_domain(item)
            for item in env_raw.replace("\n", ",").split(",")
            if item.strip()
        )
    return list(settings.get("operator_core_domains", DEFAULT_OPERATOR_CORE_DOMAINS))


def settlement_quorum_enabled(settings=None):
    settings = settings or load_security_settings()
    if _env_false("IND_SETTLEMENT_QUORUM_ENABLED"):
        return False
    if _env_true("IND_SETTLEMENT_QUORUM_ENABLED"):
        return True
    return bool(settings.get("settlement_quorum_enabled", False))


def settlement_peers(settings=None):
    settings = settings or load_security_settings()
    env_raw = os.environ.get("IND_SETTLEMENT_PEERS", "").strip()
    if env_raw:
        return _dedupe(
            _normalize_server(item)
            for item in env_raw.replace("\n", ",").split(",")
            if item.strip()
        )
    return list(settings.get("settlement_peers", []))


def settlement_min_remote_confirmations(settings=None):
    settings = settings or load_security_settings()
    return _as_int(
        os.environ.get(
            "IND_SETTLEMENT_MIN_REMOTE_CONFIRMATIONS",
            settings.get("settlement_min_remote_confirmations", 1),
        ),
        settings.get("settlement_min_remote_confirmations", 1),
        minimum=0,
        maximum=10,
    )


def settlement_require_all_configured_peers(settings=None):
    settings = settings or load_security_settings()
    if _env_false("IND_SETTLEMENT_REQUIRE_ALL_CONFIGURED_PEERS"):
        return False
    if _env_true("IND_SETTLEMENT_REQUIRE_ALL_CONFIGURED_PEERS"):
        return True
    return bool(settings.get("settlement_require_all_configured_peers", False))


def transparency_submit_async(settings=None):
    settings = settings or load_security_settings()
    if _env_false("IND_TRANSPARENCY_SUBMIT_ASYNC"):
        return False
    if _env_true("IND_TRANSPARENCY_SUBMIT_ASYNC"):
        return True
    return bool(settings.get("transparency_submit_async", False))


def peer_request_timeout_seconds(settings=None):
    settings = settings or load_security_settings()
    return int(settings["peer_request_timeout_seconds"])


def reject_peer_key_changes(settings=None):
    settings = settings or load_security_settings()
    if _env_false("IND_REJECT_PEER_KEY_CHANGES"):
        return False
    if _env_true("IND_REJECT_PEER_KEY_CHANGES"):
        return True
    return bool(settings["reject_peer_key_changes"])


def peer_ping_servers(settings=None):
    settings = settings or load_security_settings()
    env_raw = os.environ.get("IND_PEER_PING_SERVERS", "").strip()
    if env_raw:
        return _dedupe(
            _normalize_server(item)
            for item in env_raw.replace("\n", ",").split(",")
            if item.strip()
        )
    return list(settings["peer_ping_servers"])


def dns_seed_hosts(settings=None):
    settings = settings or load_security_settings()
    env_raw = os.environ.get("IND_DNS_SEED_HOSTS", "").strip()
    if env_raw:
        return _dedupe(
            _normalize_server(item)
            for item in env_raw.replace("\n", ",").split(",")
            if item.strip()
        )
    if (
        network_name(settings) == TESTNET_NETWORK
        and list(settings["dns_seed_hosts"]) == DEFAULT_DNS_SEED_HOSTS
    ):
        return list(DEFAULT_TESTNET_DNS_SEED_HOSTS)
    return list(settings["dns_seed_hosts"])


def require_transparency_log(settings=None):
    settings = settings or load_security_settings()
    if _env_false("IND_REQUIRE_TRANSPARENCY_LOG"):
        return False
    if _env_true("IND_REQUIRE_TRANSPARENCY_LOG"):
        return True
    return bool(settings["require_transparency_log"])


def submit_to_transparency_log(settings=None):
    settings = settings or load_security_settings()
    if _env_false("IND_SUBMIT_TO_TRANSPARENCY_LOG"):
        return False
    if _env_true("IND_SUBMIT_TO_TRANSPARENCY_LOG"):
        return True
    return bool(settings.get("submit_to_transparency_log", True))


def transparency_operator_url(settings=None):
    settings = settings or load_security_settings()
    return (
        os.environ.get("IND_LOG_OPERATOR_URL", "").strip() or settings["transparency_operator_url"]
    )


def transparency_operator_public_key(settings=None):
    settings = settings or load_security_settings()
    env_value = os.environ.get("IND_LOG_OPERATOR_PUBLIC_KEY", "").strip()
    return env_value or settings["transparency_operator_public_key"]


def transparency_operators(settings=None):
    settings = settings or load_security_settings()
    env_value = os.environ.get("IND_LOG_OPERATORS", "").strip()
    if env_value:
        try:
            raw_operators = json.loads(env_value)
        except json.JSONDecodeError:
            raw_operators = []
        operators = []
        if isinstance(raw_operators, list):
            for item in raw_operators:
                operator = _normalize_operator_config(item)
                if operator:
                    operators.append(operator)
        return operators
    operators = [copy.deepcopy(item) for item in settings.get("transparency_operators", [])]
    if operators:
        return operators
    operator_url = transparency_operator_url(settings)
    if not operator_url:
        return []
    return [
        {
            "url": operator_url,
            "public_key": transparency_operator_public_key(settings),
            "mirrors": trusted_root_mirrors(settings),
            "proof_archives": transparency_proof_archives(settings),
        }
    ]


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
        os.environ.get(
            "IND_LOG_MAX_CURRENT_ROOT_AGE_SECONDS", settings["max_current_root_age_seconds"]
        ),
        settings["max_current_root_age_seconds"],
        minimum=1,
        maximum=86400,
    )


def current_root_future_skew_seconds(settings=None):
    settings = settings or load_security_settings()
    return _as_int(
        os.environ.get(
            "IND_LOG_CURRENT_ROOT_FUTURE_SKEW_SECONDS", settings["current_root_future_skew_seconds"]
        ),
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


def operator_recovery_feeds(settings=None):
    settings = settings or load_security_settings()
    env_raw = os.environ.get("IND_OPERATOR_RECOVERY_FEEDS", "").strip()
    if env_raw:
        return [
            _normalize_mirror(item)
            for item in env_raw.replace("\n", ",").split(",")
            if item.strip()
        ]
    return list(settings["operator_recovery_feeds"])


def operator_recovery_min_feeds(settings=None):
    settings = settings or load_security_settings()
    return _as_int(
        os.environ.get("IND_OPERATOR_RECOVERY_MIN_FEEDS", settings["operator_recovery_min_feeds"]),
        settings["operator_recovery_min_feeds"],
        minimum=1,
        maximum=10,
    )


def operator_recovery_stable_seconds(settings=None):
    settings = settings or load_security_settings()
    return _as_int(
        os.environ.get(
            "IND_OPERATOR_RECOVERY_STABLE_SECONDS",
            settings["operator_recovery_stable_seconds"],
        ),
        settings["operator_recovery_stable_seconds"],
        minimum=0,
        maximum=86400,
    )


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


def transparency_proof_archives(settings=None):
    settings = settings or load_security_settings()
    env_raw = os.environ.get("IND_LOG_PROOF_ARCHIVES", "").strip()
    if env_raw:
        return [
            _normalize_mirror(item)
            for item in env_raw.replace("\n", ",").split(",")
            if item.strip()
        ]
    return list(settings["transparency_proof_archives"])


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


def update_source(settings=None):
    settings = settings or load_security_settings()
    return (
        os.environ.get("IND_UPDATE_SOURCE", "").strip()
        or os.environ.get("IND_UPDATE_REMOTE", "").strip()
        or settings["update_source"]
    )


def update_channel(settings=None):
    settings = settings or load_security_settings()
    env_value = os.environ.get("IND_UPDATE_CHANNEL", "").strip()
    return _normalize_update_channel(
        env_value or settings.get("update_channel", DEFAULT_UPDATE_CHANNEL)
    )


def trusted_update_signing_keys(settings=None):
    settings = settings or load_security_settings()
    env_raw = os.environ.get("IND_UPDATE_SIGNING_KEYS", "")
    env_items = [item.strip() for item in env_raw.replace("\n", ",").split(",") if item.strip()]
    return _dedupe(env_items + list(settings.get("trusted_update_signing_keys", [])))


def update_check_on_startup(settings=None):
    settings = settings or load_security_settings()
    env_value = os.environ.get("IND_AUTO_UPDATE", "").strip()
    if env_value:
        return _as_bool(env_value, True)
    return bool(settings["update_check_on_startup"])


def auto_sync_on_wallet_sign_in(settings=None):
    settings = settings or load_security_settings()
    env_value = os.environ.get("IND_AUTO_SYNC_ON_WALLET_SIGN_IN", "").strip()
    if env_value:
        return _as_bool(env_value, True)
    return bool(settings.get("auto_sync_on_wallet_sign_in", True))


def gui_scale(settings=None):
    settings = settings or load_security_settings()
    env_value = os.environ.get("IND_GUI_SCALE", "").strip()
    if env_value:
        return _normalize_gui_scale(env_value)
    return _normalize_gui_scale(settings.get("gui_scale", DEFAULT_GUI_SCALE))
