import base64
import hashlib
import json
import os
import socket
import struct
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import settings as ind_settings
from . import token as ind_token

PROTOCOL_NAME = "INDN1_X25519_ChaCha20Poly1305_SHA256"
HELLO_PREFIX = b"INDN1 "
MAX_HANDSHAKE_LINE_BYTES = 256
FRAME_HEADER_BYTES = 4
AEAD_TAG_BYTES = 16
NOISE_PRIVATE_KEY_PATH = Path("files/noise_private_key.json")
NOISE_PUBLIC_KEY_PATH = Path("files/noise_public_key.json")
NOISE_PEER_KEY_DIR = Path("files/noise_peers")


# Raised when the encrypted node transport cannot be established.
class TransportError(ind_token.TokenError):
    pass


# Raised when a known peer presents a different transport key.
class PeerKeyMismatch(TransportError):
    pass


def _b64(raw):
    return base64.b64encode(raw).decode("ascii")


def _unb64(text):
    return base64.b64decode(text.encode("ascii"), validate=True)


def _public_bytes(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _private_bytes(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _peer_key_path(peer_ip):
    safe = peer_ip.replace(":", "_").replace("/", "_").replace("\\", "_")
    return _network_path(NOISE_PEER_KEY_DIR) / (safe + ".json")


def _network_path(path):
    path = Path(path)
    namespace = ind_settings.network_runtime_namespace()
    if not namespace or path.is_absolute():
        return path
    parts = path.parts
    if parts and parts[0] == "files":
        return Path("files") / namespace / Path(*parts[1:])
    return path


def _legacy_text_path(path):
    path = Path(path)
    if path.suffix == ".json":
        return path.with_suffix(".txt")
    return path


def _write_key_json(path, field, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix != ".json":
        path.write_text(value + "\n", encoding="ascii")
        return
    tmp_path = path.with_name(path.name + ".tmp")
    tmp_path.write_text(
        json.dumps({field: value}, sort_keys=True, indent=2, ensure_ascii=True) + "\n",
        encoding="ascii",
    )
    os.replace(tmp_path, path)


def _read_key_json_or_legacy(path, field):
    path = Path(path)
    if path.exists():
        if path.suffix == ".json":
            try:
                data = json.loads(path.read_text(encoding="ascii"))
                return str(data.get(field, "")).strip()
            except (json.JSONDecodeError, OSError):
                return ""
        return path.read_text(encoding="ascii").strip()
    legacy_path = _legacy_text_path(path)
    if legacy_path != path and legacy_path.exists():
        return legacy_path.read_text(encoding="ascii").strip()
    return ""


# Create the node's long-term X25519 transport keypair if it is missing.
def ensure_transport_keypair():
    private_path = _network_path(NOISE_PRIVATE_KEY_PATH)
    public_path = _network_path(NOISE_PUBLIC_KEY_PATH)
    peer_key_dir = _network_path(NOISE_PEER_KEY_DIR)
    private_path.parent.mkdir(parents=True, exist_ok=True)
    peer_key_dir.mkdir(parents=True, exist_ok=True)
    existing_private = _read_key_json_or_legacy(private_path, "private_key")
    existing_public = _read_key_json_or_legacy(public_path, "public_key")
    if existing_private and existing_public:
        if not private_path.exists():
            _write_key_json(private_path, "private_key", existing_private)
        if not public_path.exists():
            _write_key_json(public_path, "public_key", existing_public)
        return
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    _write_key_json(private_path, "private_key", _b64(_private_bytes(private_key)))
    _write_key_json(public_path, "public_key", _b64(_public_bytes(public_key)))


# Load the node's long-term X25519 transport private key.
def load_static_private_key():
    ensure_transport_keypair()
    raw = _unb64(_read_key_json_or_legacy(_network_path(NOISE_PRIVATE_KEY_PATH), "private_key"))
    return x25519.X25519PrivateKey.from_private_bytes(raw)


# Return the node's long-term X25519 transport public key bytes.
def load_static_public_key_bytes():
    ensure_transport_keypair()
    return _unb64(_read_key_json_or_legacy(_network_path(NOISE_PUBLIC_KEY_PATH), "public_key"))


# Return whether an incoming connection starts with the IND encrypted transport.
def is_noise_hello(first_packet):
    return first_packet.startswith(HELLO_PREFIX)


# Pin first-seen transport keys and reject unexpected key changes later.
def verify_or_pin_peer_key(peer_ip, public_key_bytes):
    if not peer_ip:
        return
    _network_path(NOISE_PEER_KEY_DIR).mkdir(parents=True, exist_ok=True)
    key_path = _peer_key_path(peer_ip)
    encoded = _b64(public_key_bytes)
    previous = _read_key_json_or_legacy(key_path, "public_key")
    if not previous:
        _write_key_json(key_path, "public_key", encoded)
        return
    if previous != encoded:
        if ind_settings.reject_peer_key_changes():
            raise PeerKeyMismatch("peer transport key changed")
        _write_key_json(key_path, "public_key", encoded)


def _read_line(conn, initial=b"", limit=MAX_HANDSHAKE_LINE_BYTES):
    buffer = bytearray(initial)
    while b"\n" not in buffer:
        if len(buffer) > limit:
            raise TransportError("transport handshake line is too large")
        part = conn.recv(128)
        if not part:
            break
        buffer.extend(part)
    if b"\n" not in buffer:
        raise TransportError("incomplete transport handshake")
    line, extra = bytes(buffer).split(b"\n", 1)
    if extra:
        raise TransportError("unexpected bytes after transport handshake")
    if len(line) > limit:
        raise TransportError("transport handshake line is too large")
    return line


def _derive_keys(
    client_eph_pub, server_static_pub, server_eph_pub, shared_static, shared_ephemeral
):
    transcript = b"|".join((b"INDN1", client_eph_pub, server_static_pub, server_eph_pub))
    salt = hashlib.sha256(transcript).digest()
    material = shared_static + shared_ephemeral
    key_material = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        info=PROTOCOL_NAME.encode("ascii"),
    ).derive(material)
    return key_material[:32], key_material[32:]


def _recv_exact(conn, size):
    received = bytearray()
    while len(received) < size:
        part = conn.recv(size - len(received))
        if not part:
            raise TransportError("encrypted transport frame ended early")
        received.extend(part)
    return bytes(received)


# Small encrypted session for one IND node request and response.
class TransportSession:
    def __init__(self, send_key, recv_key):
        self.send_key = send_key
        self.recv_key = recv_key
        self.send_counter = 0
        self.recv_counter = 0

    def _nonce(self, counter):
        return counter.to_bytes(12, "little")

    def send_text(self, conn, data, max_plaintext_bytes):
        raw = data.encode("utf-8")
        if len(raw) > int(max_plaintext_bytes):
            raise TransportError("encrypted transport payload is too large")
        nonce = self._nonce(self.send_counter)
        self.send_counter += 1
        ciphertext = ChaCha20Poly1305(self.send_key).encrypt(nonce, raw, None)
        conn.sendall(struct.pack(">I", len(ciphertext)) + ciphertext)

    def recv_text(self, conn, max_plaintext_bytes):
        header = _recv_exact(conn, FRAME_HEADER_BYTES)
        ciphertext_size = struct.unpack(">I", header)[0]
        max_ciphertext = int(max_plaintext_bytes) + AEAD_TAG_BYTES
        if ciphertext_size <= AEAD_TAG_BYTES or ciphertext_size > max_ciphertext:
            raise TransportError("encrypted transport frame is too large")
        ciphertext = _recv_exact(conn, ciphertext_size)
        nonce = self._nonce(self.recv_counter)
        self.recv_counter += 1
        plaintext = ChaCha20Poly1305(self.recv_key).decrypt(nonce, ciphertext, None)
        if len(plaintext) > int(max_plaintext_bytes):
            raise TransportError("encrypted transport payload is too large")
        return plaintext.decode("utf-8")


# Start an IND encrypted transport session as the connecting peer.
def client_handshake(conn, peer_ip=None):
    client_eph_private = x25519.X25519PrivateKey.generate()
    client_eph_pub = _public_bytes(client_eph_private.public_key())
    conn.sendall(HELLO_PREFIX + _b64(client_eph_pub).encode("ascii") + b"\n")

    line = _read_line(conn)
    if not line.startswith(HELLO_PREFIX):
        raise TransportError("peer does not speak IND encrypted transport")
    parts = line[len(HELLO_PREFIX) :].split()
    if len(parts) != 2:
        raise TransportError("malformed transport server hello")
    server_static_pub = _unb64(parts[0].decode("ascii"))
    server_eph_pub = _unb64(parts[1].decode("ascii"))
    if len(server_static_pub) != 32 or len(server_eph_pub) != 32:
        raise TransportError("malformed transport public key")
    verify_or_pin_peer_key(peer_ip, server_static_pub)

    server_static_key = x25519.X25519PublicKey.from_public_bytes(server_static_pub)
    server_eph_key = x25519.X25519PublicKey.from_public_bytes(server_eph_pub)
    shared_static = client_eph_private.exchange(server_static_key)
    shared_ephemeral = client_eph_private.exchange(server_eph_key)
    client_to_server, server_to_client = _derive_keys(
        client_eph_pub,
        server_static_pub,
        server_eph_pub,
        shared_static,
        shared_ephemeral,
    )
    return TransportSession(client_to_server, server_to_client)


# Accept an IND encrypted transport session as the listening node.
def server_handshake(conn, first_packet):
    line = _read_line(conn, first_packet)
    if not line.startswith(HELLO_PREFIX):
        raise TransportError("not an IND encrypted transport hello")
    client_eph_pub = _unb64(line[len(HELLO_PREFIX) :].decode("ascii").strip())
    if len(client_eph_pub) != 32:
        raise TransportError("malformed transport client key")

    static_private = load_static_private_key()
    server_static_pub = load_static_public_key_bytes()
    server_eph_private = x25519.X25519PrivateKey.generate()
    server_eph_pub = _public_bytes(server_eph_private.public_key())
    conn.sendall(
        HELLO_PREFIX
        + _b64(server_static_pub).encode("ascii")
        + b" "
        + _b64(server_eph_pub).encode("ascii")
        + b"\n"
    )

    client_eph_key = x25519.X25519PublicKey.from_public_bytes(client_eph_pub)
    shared_static = static_private.exchange(client_eph_key)
    shared_ephemeral = server_eph_private.exchange(client_eph_key)
    client_to_server, server_to_client = _derive_keys(
        client_eph_pub,
        server_static_pub,
        server_eph_pub,
        shared_static,
        shared_ephemeral,
    )
    return TransportSession(server_to_client, client_to_server)


# Send one encrypted IND node request and return its encrypted response.
def request(addr, indicator, data, peer_ip=None, timeout=4):
    if len(data.encode("utf-8")) > ind_token.MAX_WIRE_DECOMPRESSED_BYTES:
        raise TransportError("request payload is too large")
    client = socket.create_connection(addr, timeout=timeout)
    try:
        client.settimeout(timeout)
        session = client_handshake(client, peer_ip=peer_ip)
        session.send_text(
            client,
            indicator + data,
            ind_token.MAX_WIRE_DECOMPRESSED_BYTES + 1,
        )
        return session.recv_text(client, ind_token.MAX_WIRE_DECOMPRESSED_BYTES)
    finally:
        client.close()


# Send one encrypted IND node request and close after the frame is written.
def send_no_response(addr, indicator, data, peer_ip=None, timeout=4):
    data = str(data)
    if len(data.encode("utf-8")) > ind_token.MAX_WIRE_DECOMPRESSED_BYTES:
        raise TransportError("request payload is too large")
    client = socket.create_connection(addr, timeout=timeout)
    try:
        client.settimeout(timeout)
        session = client_handshake(client, peer_ip=peer_ip)
        session.send_text(
            client,
            indicator + data,
            ind_token.MAX_WIRE_DECOMPRESSED_BYTES + 1,
        )
        try:
            client.shutdown(socket.SHUT_WR)
        except OSError:
            pass
    finally:
        client.close()
