"""Shared public-testnet peer parsing and broadcast helpers."""

import json
import sys
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from ind import sender_node
from ind import token as ind_token


DEFAULT_TESTNET_CONFIG = ROOT_DIR / "testnet" / "testnet.json"


def _dedupe(items):
    seen = set()
    result = []
    for item in items:
        value = str(item).strip()
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _split_peer_values(values):
    result = []
    for value in values or []:
        for item in str(value).replace("\n", ",").split(","):
            item = item.strip()
            if item:
                result.append(item)
    return result


def testnet_seed_hosts(config_path=DEFAULT_TESTNET_CONFIG):
    """Return durable public-testnet seed hostnames from testnet/testnet.json."""

    try:
        data = json.loads(Path(config_path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    if isinstance(data, dict):
        hosts = data.get("dns_seed_hosts", [])
    elif isinstance(data, list):
        hosts = data
    else:
        hosts = []
    return _dedupe(hosts)


def parse_peer_args(values, *, config_path=DEFAULT_TESTNET_CONFIG, default_to_config=True):
    """Parse repeated and comma-separated peer arguments."""

    peers = _split_peer_values(values)
    if not peers and default_to_config:
        peers = testnet_seed_hosts(config_path)
    return _dedupe(peers)


def peers_env_value(peers):
    return ",".join(parse_peer_args(peers, default_to_config=False))


def broadcast_message_to_peers(message, peers, *, delay_seconds=0.05):
    """Broadcast one public gossip message to every configured seed."""

    raw = ind_token.pack_wire_message(message)
    results = []
    for peer in parse_peer_args(peers, default_to_config=False):
        started = time.time()
        response = sender_node.connect("b", raw, [peer])
        ok = sender_node.response_indicates_success(response)
        results.append(
            {
                "peer": peer,
                "ok": bool(ok),
                "response": response,
                "elapsed_seconds": round(time.time() - started, 3),
            }
        )
        if delay_seconds:
            time.sleep(float(delay_seconds))
    return results
