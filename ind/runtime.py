import contextlib
import ipaddress
import json
import os
import tempfile
import threading
import time
from pathlib import Path

from . import settings as ind_settings

RUNTIME_DIRS = (
    "files",
    "wallet_folder",
    "transaction_folder",
    "print_folder",
    "ip_folder/1",
    "ip_folder/2",
    "ip_folder/3",
    "full_activation",
)

RUNTIME_STATE_PATH = Path("files/runtime_state.json")
WALLET_GENERATION_PATH = Path("files/wallet_generation.json")
PASSPHRASE_REQUEST_PATH = Path("files/passphrase.json")
WALLET_DIR = Path("wallet_folder")
TRANSACTION_DIR = Path("transaction_folder")
PEER_ROOT = Path("ip_folder")

WALLET_ENCRYPTED_PREFIX = "wallet_encrypted_"
WALLET_DECRYPTED_PREFIX = "wallet_decrypted_"
_DECRYPTED_WALLETS = {}
_PASSPHRASE_REQUEST = None
_WALLET_GENERATION = None
_WRITE_LOCK = threading.RLock()

DEFAULT_STATE = {
    "schema": 1,
    "my_public_ip": "",
    "spam_protection": "",
    "kill_node": True,
    "check_signed_in": False,
    "node": {
        "class": "NODE",
        "run_on_startup": "NO",
        "run_in_background": "NO",
        "transparency_operator": "NO",
    },
}

DEFAULT_WALLET_GENERATION = {
    "schema": 1,
    "address": "",
    "private_key": "",
    "public_key": "",
    "passphrase": "",
    "bills": [],
}

DEFAULT_PASSPHRASE_REQUEST = {
    "schema": 1,
    "passphrase": "",
    "address": "",
}


def _network_namespace():
    return ind_settings.network_runtime_namespace()


def _network_path(path):
    path = Path(path)
    namespace = _network_namespace()
    if not namespace or path.is_absolute():
        return path
    parts = path.parts
    if parts and parts[0] in {
        "files",
        "wallet_folder",
        "transaction_folder",
        "print_folder",
        "ip_folder",
        "full_activation",
    }:
        return Path(parts[0]) / namespace / Path(*parts[1:])
    return path


def runtime_dirs():
    return tuple(str(_network_path(path)) for path in RUNTIME_DIRS)


def runtime_state_path():
    return _network_path(RUNTIME_STATE_PATH)


def wallet_generation_path():
    return _network_path(WALLET_GENERATION_PATH)


def passphrase_request_path():
    return _network_path(PASSPHRASE_REQUEST_PATH)


def wallet_dir():
    return _network_path(WALLET_DIR)


def transaction_dir():
    return _network_path(TRANSACTION_DIR)


def peer_root():
    return _network_path(PEER_ROOT)


def _clone(data):
    return json.loads(json.dumps(data))


def _bill_lines_from_wallet_data(data):
    if not isinstance(data, dict):
        return []
    return list(data.get("bills") or data.get("tokens") or [])


def _write_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = None
    with _WRITE_LOCK:
        try:
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                dir=path.parent,
                prefix=path.name + ".",
                suffix=".tmp",
                delete=False,
            ) as handle:
                tmp_path = Path(handle.name)
                handle.write(json.dumps(data, sort_keys=True, indent=2, ensure_ascii=True) + "\n")
            for attempt in range(5):
                try:
                    os.replace(tmp_path, path)
                    break
                except PermissionError:
                    if os.name != "nt" or attempt == 4:
                        raise
                    time.sleep(0.05 * (attempt + 1))
        finally:
            if tmp_path is not None:
                with contextlib.suppress(OSError):
                    tmp_path.unlink(missing_ok=True)


def _read_json(path, default=None):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return _clone(default) if default is not None else None


def _read_legacy_text(path):
    try:
        return Path(path).read_text(encoding="utf-8")
    except (FileNotFoundError, OSError, UnicodeDecodeError):
        return ""


def _parse_bool(value, default=False):
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"true", "1", "yes", "y"}:
        return True
    if text in {"false", "0", "no", "n", ""}:
        return False
    return default


def _merge_state(data):
    merged = _clone(DEFAULT_STATE)
    legacy_node = (
        data.get("node") if isinstance(data, dict) and isinstance(data.get("node"), dict) else {}
    )
    if isinstance(data, dict):
        for key, value in data.items():
            if key == "node" and isinstance(value, dict):
                merged["node"].update(value)
            elif key in merged:
                merged[key] = value
    node = merged["node"]
    if "transparency_operator" not in legacy_node and "full_operator" in legacy_node:
        node["transparency_operator"] = legacy_node["full_operator"]
    if str(node.get("class", "")).strip() == "FULL NODE":
        node["class"] = "NODE"
    node["transparency_operator"] = (
        "YES" if _parse_bool(node.get("transparency_operator", "NO"), default=False) else "NO"
    )
    node.pop("full_operator", None)
    merged["kill_node"] = _parse_bool(merged["kill_node"], default=True)
    merged["check_signed_in"] = False
    return merged


def _state_from_legacy_files():
    state = _clone(DEFAULT_STATE)
    legacy_node = _read_legacy_text("files/node_class.txt").splitlines()
    if legacy_node:
        legacy_class = legacy_node[0].strip() or "NODE"
        state["node"]["class"] = "NODE" if legacy_class == "FULL NODE" else legacy_class
    if len(legacy_node) > 1:
        state["node"]["run_on_startup"] = legacy_node[1].strip() or "NO"
    if len(legacy_node) > 2:
        state["node"]["run_in_background"] = legacy_node[2].strip() or "NO"

    kill_node = _read_legacy_text("files/kill_node.txt")
    if kill_node != "":
        state["kill_node"] = _parse_bool(kill_node, default=True)

    state["my_public_ip"] = _read_legacy_text("files/my_public_ip.txt").strip()
    state["spam_protection"] = _read_legacy_text("files/spam_protection.txt")
    return _merge_state(state)


def ensure_runtime_files():
    for directory in runtime_dirs():
        Path(directory).mkdir(parents=True, exist_ok=True)
    state_path = runtime_state_path()
    wallet_path = wallet_generation_path()
    passphrase_path = passphrase_request_path()
    if state_path.exists():
        _write_json(state_path, _merge_state(_read_json(state_path, DEFAULT_STATE)))
    else:
        initial_state = _state_from_legacy_files() if not _network_namespace() else DEFAULT_STATE
        _write_json(state_path, initial_state)
    if not wallet_path.exists():
        _write_json(wallet_path, DEFAULT_WALLET_GENERATION)
    if not passphrase_path.exists():
        _write_json(passphrase_path, DEFAULT_PASSPHRASE_REQUEST)


def read_state():
    if not runtime_state_path().exists():
        ensure_runtime_files()
    return _merge_state(_read_json(runtime_state_path(), DEFAULT_STATE))


def write_state(state):
    _write_json(runtime_state_path(), _merge_state(state))


def read_node_config():
    node = read_state()["node"]
    return (
        str(node.get("class", "NODE")),
        str(node.get("run_on_startup", "NO")),
        str(node.get("run_in_background", "NO")),
    )


def read_node_operator_enabled():
    node = read_state()["node"]
    return "YES" if _parse_bool(node.get("transparency_operator", "NO"), default=False) else "NO"


def write_node_config(
    node_class, run_on_startup, run_in_background, transparency_operator=None, **legacy_options
):
    state = read_state()
    node = state["node"]
    if transparency_operator is None:
        transparency_operator = legacy_options.pop("full_operator", None)
    if legacy_options:
        unexpected = ", ".join(sorted(legacy_options))
        raise TypeError(f"unexpected node config option(s): {unexpected}")
    if transparency_operator is None:
        transparency_operator = node.get("transparency_operator", "NO")
    state["node"] = {
        "class": str(node_class),
        "run_on_startup": str(run_on_startup),
        "run_in_background": str(run_in_background),
        "transparency_operator": (
            "YES" if _parse_bool(transparency_operator, default=False) else "NO"
        ),
    }
    write_state(state)


def get_kill_node():
    return read_state()["kill_node"]


def set_kill_node(value):
    state = read_state()
    state["kill_node"] = bool(value)
    write_state(state)


def get_check_signed_in():
    return False


def set_check_signed_in(_value):
    state = read_state()
    state["check_signed_in"] = False
    write_state(state)


def toggle_check_signed_in():
    set_check_signed_in(False)
    return False


def get_public_ip():
    return str(read_state().get("my_public_ip", "")).strip()


def set_public_ip(value):
    state = read_state()
    state["my_public_ip"] = str(value).strip()
    write_state(state)


def _wallet_generation_from_legacy():
    payload = _read_legacy_text("files/hashing.txt")
    if not payload:
        return _clone(DEFAULT_WALLET_GENERATION)
    return wallet_generation_from_payload(payload)


def wallet_generation_from_payload(payload):
    lines = str(payload).splitlines()
    data = _clone(DEFAULT_WALLET_GENERATION)
    if lines:
        data["address"] = lines[0].strip()
    if len(lines) > 1:
        data["private_key"] = lines[1].strip()
    if len(lines) > 2:
        data["public_key"] = lines[2].strip()
    data["bills"] = [line.rstrip("\n") for line in wallet_bill_lines(lines)]
    return data


def is_wallet_bill_line(line):
    parts = str(line).strip().split()
    if not parts:
        return False
    display_id = parts[0].lstrip("-")
    value, separator, index = display_id.partition("x")
    return separator == "x" and value.isdigit() and bool(index)


def wallet_bill_start_index(lines):
    lines = list(lines or [])
    if len(lines) <= 3:
        return len(lines)
    return 3 if is_wallet_bill_line(lines[3]) else 4


def wallet_bill_lines(lines):
    lines = list(lines or [])
    return lines[wallet_bill_start_index(lines) :]


is_wallet_token_line = is_wallet_bill_line
wallet_token_start_index = wallet_bill_start_index
wallet_token_lines = wallet_bill_lines


# Keep generated wallet secrets in memory until encryption consumes them.
def write_wallet_generation(
    address, private_key, public_key, passphrase="", bills=None, tokens=None
):
    global _WALLET_GENERATION
    if bills is None and tokens is not None:
        bills = tokens
    _WALLET_GENERATION = {
        "schema": 1,
        "address": str(address).strip(),
        "private_key": str(private_key).strip(),
        "public_key": str(public_key).strip(),
        "passphrase": "",
        "bills": list(bills or []),
    }
    _write_json(wallet_generation_path(), DEFAULT_WALLET_GENERATION)


# Load generated wallet material into memory without persisting plaintext secrets.
def write_wallet_generation_from_payload(payload):
    global _WALLET_GENERATION
    _WALLET_GENERATION = wallet_generation_from_payload(payload)
    _write_json(wallet_generation_path(), DEFAULT_WALLET_GENERATION)


def read_wallet_generation():
    if _WALLET_GENERATION is not None:
        return _clone(_WALLET_GENERATION)
    path = wallet_generation_path()
    if not path.exists():
        ensure_runtime_files()
    data = _read_json(path, DEFAULT_WALLET_GENERATION)
    merged = _clone(DEFAULT_WALLET_GENERATION)
    if isinstance(data, dict):
        merged.update(data)
    merged["bills"] = _bill_lines_from_wallet_data(merged)
    merged.pop("tokens", None)
    return merged


def clear_wallet_generation():
    global _WALLET_GENERATION
    _WALLET_GENERATION = None
    _write_json(wallet_generation_path(), DEFAULT_WALLET_GENERATION)


def set_wallet_generation_passphrase(passphrase):
    global _WALLET_GENERATION
    data = read_wallet_generation()
    data["passphrase"] = ""
    _WALLET_GENERATION = data
    _write_json(wallet_generation_path(), DEFAULT_WALLET_GENERATION)


def wallet_generation_lines(include_passphrase=False):
    data = read_wallet_generation()
    lines = [
        str(data.get("address", "")).strip(),
        str(data.get("private_key", "")).strip(),
        str(data.get("public_key", "")).strip(),
    ]
    bills = _bill_lines_from_wallet_data(data)
    if include_passphrase or data.get("passphrase") or bills:
        lines.append(str(data.get("passphrase", "")).strip())
    lines.extend(str(line).rstrip("\n") for line in bills)
    return [line + "\n" for line in lines if line != ""]


def wallet_generation_payload():
    data = read_wallet_generation()
    required = ("address", "private_key", "public_key", "passphrase")
    if any(not str(data.get(key, "")).strip() for key in required):
        raise ValueError("wallet generation JSON is missing required wallet fields")
    lines = [
        str(data["address"]).strip(),
        str(data["private_key"]).strip(),
        str(data["public_key"]).strip(),
        str(data["passphrase"]).strip(),
    ]
    lines.extend(str(line).rstrip("\n") for line in _bill_lines_from_wallet_data(data))
    return "\n".join(lines) + "\n"


def wallet_generation_secret_payload():
    data = read_wallet_generation()
    required = ("address", "private_key", "public_key")
    if any(not str(data.get(key, "")).strip() for key in required):
        raise ValueError("wallet generation JSON is missing required wallet fields")
    lines = [
        str(data["address"]).strip(),
        str(data["private_key"]).strip(),
        str(data["public_key"]).strip(),
    ]
    lines.extend(str(line).rstrip("\n") for line in _bill_lines_from_wallet_data(data))
    return "\n".join(lines) + "\n"


def write_passphrase_request(passphrase, address):
    global _PASSPHRASE_REQUEST
    _PASSPHRASE_REQUEST = {
        "schema": 1,
        "passphrase": str(passphrase),
        "address": str(address).strip(),
    }
    _write_json(passphrase_request_path(), DEFAULT_PASSPHRASE_REQUEST)


def read_passphrase_request():
    if _PASSPHRASE_REQUEST is not None:
        return _clone(_PASSPHRASE_REQUEST)
    path = passphrase_request_path()
    if not path.exists():
        legacy = (
            [] if _network_namespace() else _read_legacy_text("files/passphrase.txt").splitlines()
        )
        if legacy:
            return {
                "schema": 1,
                "passphrase": legacy[0],
                "address": legacy[1].strip() if len(legacy) > 1 else "",
            }
        ensure_runtime_files()
    data = _read_json(path, DEFAULT_PASSPHRASE_REQUEST)
    merged = _clone(DEFAULT_PASSPHRASE_REQUEST)
    if isinstance(data, dict):
        merged.update(data)
    return merged


def clear_passphrase_request():
    global _PASSPHRASE_REQUEST
    _PASSPHRASE_REQUEST = None
    _write_json(passphrase_request_path(), DEFAULT_PASSPHRASE_REQUEST)


def consume_passphrase_request():
    request = read_passphrase_request()
    clear_passphrase_request()
    return request


def wallet_address_from_name(name):
    value = Path(name).name
    if value.startswith(WALLET_ENCRYPTED_PREFIX):
        value = value[len(WALLET_ENCRYPTED_PREFIX) :]
    elif value.startswith(WALLET_DECRYPTED_PREFIX):
        value = value[len(WALLET_DECRYPTED_PREFIX) :]
    for suffix in (".json", ".txt"):
        if value.endswith(suffix):
            value = value[: -len(suffix)]
            break
    return value


def encrypted_wallet_path(address):
    return wallet_dir() / f"{WALLET_ENCRYPTED_PREFIX}{address}.json"


def decrypted_wallet_path(address):
    return wallet_dir() / f"{WALLET_DECRYPTED_PREFIX}{address}.json"


def _iter_wallet_files(prefix):
    current_wallet_dir = wallet_dir()
    if not current_wallet_dir.exists():
        return []
    files = []
    for path in current_wallet_dir.iterdir():
        if (
            path.is_file()
            and path.name.startswith(prefix)
            and path.suffix.lower() in {".json", ".txt"}
        ):
            files.append(path)
    return sorted(files)


def iter_encrypted_wallet_files():
    return _iter_wallet_files(WALLET_ENCRYPTED_PREFIX)


def iter_decrypted_wallet_files():
    files = _iter_wallet_files(WALLET_DECRYPTED_PREFIX)
    existing = {wallet_address_from_name(path.name) for path in files}
    for address in sorted(_DECRYPTED_WALLETS):
        if address not in existing:
            files.append(decrypted_wallet_path(address))
    return sorted(files)


def _payload_json(address, payload):
    lines = str(payload).splitlines()
    return {
        "format": "IND_UNLOCKED_SESSION",
        "address": address,
        "private_key": lines[1].strip() if len(lines) > 1 else "",
        "public_key": lines[2].strip() if len(lines) > 2 else "",
        "bills": [line.rstrip("\n") for line in wallet_bill_lines(lines)],
        "payload": str(payload),
    }


def write_decrypted_wallet(address, payload):
    if isinstance(payload, bytes):
        payload = payload.decode("utf-8")
    address = str(address).strip()
    _DECRYPTED_WALLETS[address] = str(payload)
    for path in (
        decrypted_wallet_path(address),
        wallet_dir() / f"{WALLET_DECRYPTED_PREFIX}{address}.txt",
    ):
        try:
            if path.exists():
                size = path.stat().st_size
                with open(path, "r+b") as handle:
                    handle.write(b"\x00" * size)
                    handle.flush()
                    os.fsync(handle.fileno())
                path.unlink()
        except OSError:
            pass


def read_decrypted_wallet_payload(path):
    path = Path(path)
    address = wallet_address_from_name(path.name)
    if address in _DECRYPTED_WALLETS:
        return _DECRYPTED_WALLETS[address]
    if path.suffix.lower() == ".json":
        data = _read_json(path, {})
        if isinstance(data, dict) and "payload" in data:
            return str(data.get("payload", ""))
        if isinstance(data, dict):
            lines = [
                str(data.get("address", "")).strip(),
                str(data.get("private_key", "")).strip(),
                str(data.get("public_key", "")).strip(),
                str(data.get("passphrase", "")).strip(),
            ]
            lines.extend(str(line).rstrip("\n") for line in _bill_lines_from_wallet_data(data))
            return "\n".join(line for line in lines if line != "") + "\n"
        return ""
    return _read_legacy_text(path)


def read_decrypted_wallet_lines(path):
    return read_decrypted_wallet_payload(path).splitlines(keepends=True)


def write_decrypted_wallet_lines(path, lines):
    path = Path(path)
    address = wallet_address_from_name(path.name)
    payload = "".join(line if str(line).endswith("\n") else str(line) + "\n" for line in lines)
    write_decrypted_wallet(address, payload)
    if path.suffix.lower() == ".txt":
        with contextlib.suppress(FileNotFoundError):
            path.unlink()


def clear_decrypted_wallet(address):
    _DECRYPTED_WALLETS.pop(str(address).strip(), None)


def clear_decrypted_wallets():
    _DECRYPTED_WALLETS.clear()


def write_encrypted_wallet(address, salt_b64, ciphertext):
    if isinstance(salt_b64, bytes):
        salt_b64 = salt_b64.decode("ascii")
    if isinstance(ciphertext, bytes):
        ciphertext = ciphertext.decode("ascii")
    _write_json(
        encrypted_wallet_path(address),
        {
            "format": "INDW1",
            "address": str(address).strip(),
            "cipher": "Fernet",
            "kdf": "PBKDF2-HMAC-SHA3-256",
            "iterations": 1000000,
            "salt": salt_b64,
            "ciphertext": ciphertext,
        },
    )


def write_encrypted_wallet_record(record):
    address = str(record.get("address", "")).strip()
    if not address:
        raise ValueError("encrypted wallet record is missing address")
    _write_json(encrypted_wallet_path(address), record)


def read_encrypted_wallet_record(path):
    path = Path(path)
    if path.suffix.lower() == ".json":
        return _read_json(path, {})
    return {}


def read_encrypted_wallet_bytes(path, prefix=b"INDW1:"):
    path = Path(path)
    if path.suffix.lower() == ".json":
        data = _read_json(path, {})
        if isinstance(data, dict) and data.get("format") == "INDW1":
            return (
                prefix
                + str(data.get("salt", "")).encode("ascii")
                + b":"
                + str(data.get("ciphertext", "")).encode("ascii")
            )
        return b""
    try:
        return path.read_bytes()
    except FileNotFoundError:
        return b""


def remove_encrypted_wallet(address):
    for path in (
        encrypted_wallet_path(address),
        wallet_dir() / f"{WALLET_ENCRYPTED_PREFIX}{address}.txt",
    ):
        with contextlib.suppress(FileNotFoundError):
            path.unlink()


def transaction_files():
    current_transaction_dir = transaction_dir()
    if not current_transaction_dir.exists():
        return []
    return sorted(
        path
        for path in current_transaction_dir.iterdir()
        if path.is_file()
        and path.name.startswith("transaction_")
        and path.suffix.lower() in {".json", ".txt"}
    )


def has_pending_transactions():
    return bool(transaction_files())


def _transaction_index(path):
    stem = Path(path).stem
    try:
        return int(stem.split("_", 1)[1])
    except (IndexError, ValueError):
        return 0


def next_transaction_path():
    next_index = max([_transaction_index(path) for path in transaction_files()] or [0]) + 1
    return transaction_dir() / f"transaction_{next_index}.json"


def write_transaction_message(message):
    path = next_transaction_path()
    data = json.loads(message) if isinstance(message, str) else message
    _write_json(path, data)
    return path


def read_transaction_message(path):
    path = Path(path)
    if path.suffix.lower() == ".json":
        return _read_json(path, {})
    return _read_legacy_text(path)


# Return a Windows-safe peer-cache filename stem for an IP literal.
def peer_file_stem(peer):
    peer = str(peer).strip()
    try:
        ip = ipaddress.ip_address(peer)
    except ValueError:
        safe = "".join(char if char.isalnum() or char in {"-", "_", "."} else "_" for char in peer)
        return safe or "peer"
    if ip.version == 4:
        return ip.compressed
    return "ipv6_" + ip.exploded.replace(":", "-")


def peer_path(ip, version="2"):
    return peer_root() / str(version) / f"{peer_file_stem(ip)}.json"


def write_peer(ip, version="2"):
    _write_json(
        peer_path(ip, version),
        {
            "schema": 1,
            "ip": str(ip).strip(),
            "version": str(version),
            "added_at": int(time.time()),
        },
    )
