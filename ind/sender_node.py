import os
import random
import socket
import time
import threading
import ipaddress
import requests
import json
from pathlib import Path
from . import runtime as runtime_json
from . import settings as ind_settings
from . import token as ind_token
from . import transport as ind_transport

already_tried = []
PORT = 8888
MAX_PEERS_PER_IPV4_C_BLOCK = 3
DEFAULT_DIVERSE_PEER_SAMPLE = 12
DNS_SEED_REFRESH_SECONDS = 3600
MAX_DNS_SEED_RESULTS = 128

RUNTIME_DIRS = runtime_json.RUNTIME_DIRS
_last_dns_seed_refresh = 0


def node_port():
    return ind_settings.node_port()


def _runtime_path(path):
    path = Path(path)
    parts = path.parts
    if parts and parts[0] == "ip_folder":
        return runtime_json.peer_root() / Path(*parts[1:])
    return path


def _read_text(path):
    try:
        with open(_runtime_path(path), 'r') as handle:
            return handle.read()
    except FileNotFoundError:
        return ''


def _list_dir(path):
    path = _runtime_path(path)
    try:
        return os.listdir(path)
    except FileNotFoundError:
        os.makedirs(path, exist_ok=True)
        return []


def _valid_ipv4(value):
    try:
        ip = ipaddress.ip_address(value)
        return (
            ip.version == 4
            and ip.is_global
            and not ip.is_loopback
            and not ip.is_private
            and not ip.is_multicast
            and not ip.is_reserved
            and not ip.is_unspecified
            and not ip.is_link_local
        )
    except Exception:
        return False


def _peer_files(path):
    peers = []
    for item in _list_dir(path):
        ip = _peer_ip(item)
        if item.endswith(('.json', '.txt')) and _valid_ipv4(ip):
            peers.append(item)
    return peers


def _ipv4_c_block(value):
    parts = value.split('.')
    if len(parts) != 4:
        return None
    return '.'.join(parts[:3])


def _peer_ip(item):
    if item.endswith('.json'):
        return item[:-5]
    if item.endswith('.txt'):
        return item[:-4]
    return item


def _configured_peer_servers():
    try:
        return ind_settings.peer_ping_servers()
    except Exception:
        return []


def _configured_dns_seed_hosts():
    try:
        return ind_settings.dns_seed_hosts()
    except Exception:
        return []


def resolve_dns_seed_hosts(seed_hosts=None, limit=MAX_DNS_SEED_RESULTS):
    """Resolve DNS seed hostnames into globally-routable IPv4 node hints."""

    seed_hosts = _configured_dns_seed_hosts() if seed_hosts is None else list(seed_hosts)
    peers = []
    seen = set()
    for seed_host in seed_hosts:
        seed_host = str(seed_host).strip()
        if not seed_host:
            continue
        try:
            records = socket.getaddrinfo(seed_host, node_port(), family=socket.AF_INET, type=socket.SOCK_STREAM)
        except Exception:
            continue
        for _family, _socktype, _proto, _canonname, sockaddr in records:
            ip = str(sockaddr[0]).strip()
            if _valid_ipv4(ip) and ip not in seen:
                seen.add(ip)
                peers.append(ip)
                if len(peers) >= int(limit):
                    return peers
    return peers


def refresh_dns_seed_peers(seed_hosts=None, version='2'):
    """Resolve configured DNS seeds and store their IPs as ordinary peer hints."""

    ensure_runtime_files()
    added = []
    for ip in resolve_dns_seed_hosts(seed_hosts=seed_hosts):
        if add_peer(ip, version=version):
            added.append(ip)
    return added


def maybe_refresh_dns_seed_peers(now=None, force=False):
    """Refresh DNS seeds at most hourly unless explicitly forced."""

    global _last_dns_seed_refresh
    now = int(time.time() if now is None else now)
    if not force and now - _last_dns_seed_refresh < DNS_SEED_REFRESH_SECONDS:
        return []
    _last_dns_seed_refresh = now
    return refresh_dns_seed_peers()


def _with_configured_peers(peers):
    try:
        maybe_refresh_dns_seed_peers()
    except Exception:
        pass
    seen = set()
    result = []
    for peer in list(peers) + _peer_files('ip_folder/2') + _configured_peer_servers():
        peer = str(peer).strip()
        if peer and peer not in seen:
            seen.add(peer)
            result.append(peer)
    return result


def _existing_peer_block_count(block):
    count = 0
    for folder in ('ip_folder/1', 'ip_folder/2'):
        for item in _peer_files(folder):
            if _ipv4_c_block(_peer_ip(item)) == block:
                count += 1
    return count


def add_peer(ip, version='2'):
    """Add a routable peer while limiting concentration in one IPv4 /24."""

    if version not in ('1', '2') or not _valid_ipv4(ip):
        return False
    block = _ipv4_c_block(ip)
    target = runtime_json.peer_path(ip, version)
    if not os.path.exists(target) and _existing_peer_block_count(block) >= MAX_PEERS_PER_IPV4_C_BLOCK:
        return False
    runtime_json.write_peer(ip, version)
    return True


def diverse_peer_sample(peers, limit=DEFAULT_DIVERSE_PEER_SAMPLE):
    """Sample peers across IPv4 blocks to avoid leaning on one network segment."""

    by_block = {}
    for item in peers:
        ip = _peer_ip(item)
        if not _valid_ipv4(ip):
            continue
        block = _ipv4_c_block(ip)
        by_block.setdefault(block, []).append(item)
    for items in by_block.values():
        random.shuffle(items)
    blocks = list(by_block)
    random.shuffle(blocks)
    selected = []
    while blocks and len(selected) < int(limit):
        next_blocks = []
        for block in blocks:
            items = by_block[block]
            if items and len(selected) < int(limit):
                selected.append(items.pop())
            if items:
                next_blocks.append(block)
        blocks = next_blocks
    return selected


def ensure_runtime_files():
    """Create runtime folders, state files, and local transport keypairs."""

    runtime_json.ensure_runtime_files()
    ind_transport.ensure_transport_keypair()


def connect(indicator, data, ipnl):
    """Send one encrypted request to a sampled peer and return its plaintext reply."""

    ensure_runtime_files()
    ipnl = diverse_peer_sample(ipnl, limit=max(DEFAULT_DIVERSE_PEER_SAMPLE, len(ipnl)))
    if not ipnl:
        return 'n'
    if len(data.encode('utf-8')) > ind_token.MAX_WIRE_DECOMPRESSED_BYTES:
        return 'n'
    start_time = int(time.time())
    while int(time.time()) - start_time <= 20:
        if random.randrange(1000) == 9:
            already_tried.clear()
        SERVER = _peer_ip(random.choice(ipnl))
        ADDR = (SERVER, node_port())
        try:
            if SERVER not in already_tried:
                try:
                    timeout = ind_settings.peer_request_timeout_seconds()
                    return ind_transport.request(ADDR, indicator, data, peer_ip=SERVER, timeout=timeout)
                except ind_transport.PeerKeyMismatch:
                    already_tried.append(SERVER)
                    return 'n'
                except Exception:
                    continue
        except :
            if SERVER not in already_tried:
                already_tried.append(SERVER)
    return 'n'



def public_ip():
    """Discover the public IPv4 address without making the peer network the first dependency."""

    try:
        try:
            try:
                my_ip = requests.get('https://www.wikipedia.org').headers['X-Client-IP']
                return my_ip
            except:
                my_ip = requests.get('https://checkip.amazonaws.com').text.strip()
                return my_ip
        except:
            ipnl = _with_configured_peers(_peer_files('ip_folder/1') + _peer_files('ip_folder/2'))
            my_ip = connect('x', '', ipnl)
            if my_ip != 'n' and my_ip:
                return my_ip
    except:
        return
    

def send_bills():
    """Validate queued wallet gossip locally, then broadcast it to sampled peers."""

    ensure_runtime_files()
    ipnl1 = diverse_peer_sample(_peer_files('ip_folder/1'), limit=6)
    ipnl2 = _with_configured_peers(diverse_peer_sample(_peer_files('ip_folder/2'), limit=12))
    store = ind_token.INDLocalStore()
    for transaction_path in runtime_json.transaction_files():
        tm = runtime_json.read_transaction_message(transaction_path)
        try:
            result = store.ingest_message(tm)
            proof = result.get("conflict_proof")
            if proof:
                broadcast_message(proof)
        except Exception:
            os.remove(transaction_path)
            continue
        wire_message = ind_token.pack_wire_message(tm)
        threading.Thread(target=connect, args=('b', wire_message, ipnl1)).start()
        for _ in range(2):
            threading.Thread(target=connect, args=('b', wire_message, ipnl2)).start()
            time.sleep(0.1)
        os.remove(transaction_path)


def broadcast_message(message):
    """Broadcast a protocol message after converting it to the current wire format."""

    ensure_runtime_files()
    raw = ind_token.pack_wire_message(message)
    ipnl1 = diverse_peer_sample(_peer_files('ip_folder/1'), limit=6)
    ipnl2 = _with_configured_peers(diverse_peer_sample(_peer_files('ip_folder/2'), limit=12))
    if ipnl1:
        threading.Thread(target=connect, args=('b', raw, ipnl1)).start()
    for _ in range(2):
        if ipnl2:
            threading.Thread(target=connect, args=('b', raw, ipnl2)).start()
            time.sleep(0.1)


def _parse_peer_messages(raw):
    if not raw or raw == 'n':
        return []
    try:
        decoded = json.loads(raw)
        if isinstance(decoded, list):
            return decoded
        if isinstance(decoded, dict):
            return [decoded]
    except Exception:
        return []
    return []


def check_validity(serial_num_list):
    """Return locally settled token records for wallet display ids or token ids."""

    store = ind_token.INDLocalStore()
    store.finalize_pending(buffer_seconds=ind_settings.finality_buffer_seconds())
    verified = []
    for item in serial_num_list:
        token = store.get_token(item) or store.get_token_by_display_id(item)
        if not token:
            continue
        try:
            state = ind_token.verify_token(token)
            confidence = store.token_confidence(state.token_id, expected_owner=state.owner_address, min_settled_seconds=0)
            if confidence["accepted"]:
                verified.append((state.display_id, state.owner_address, str(state.sequence)))
        except Exception:
            continue
    return verified


def update_ip_list():
    """Refresh the local peer cache from bootstrap and ordinary nodes."""

    maybe_refresh_dns_seed_peers(force=True)

    def new_main_ip():
        comparison_ip = []
        main_ips = _peer_files('ip_folder/1')
        def thrd():
            new_main = connect('u', 'main ip', main_ips)
            comparison_ip.append(new_main)
        for _ in range(len(main_ips)):
            threading.Thread(target=thrd).start()
        time.sleep(10)
        try:
            new_ip = random.choice([ip for ip in comparison_ip if ip != 'n'])
            add_peer(str(new_ip), '1')
        except:
            pass

    if random.randint(0, 27) == 3:
        threading.Thread(target=new_main_ip).start()

    ipnl = _with_configured_peers(_peer_files('ip_folder/2'))
    list_ips = connect('u', '', ipnl)

    for ip in list_ips.splitlines():
        try:
            if ipaddress.ip_address(ip).version == 4:
                add_peer(str(ip), '2')
        except:
            pass


def receive_bills():
    """Pull wallet-addressed gossip, sign receipts, and import settled tokens."""

    ensure_runtime_files()
    ipnl = _with_configured_peers(_peer_files('ip_folder/1') + _peer_files('ip_folder/2'))
    store = ind_token.INDLocalStore()
    for wallet_path in runtime_json.iter_decrypted_wallet_files():
        if wallet_path.name.startswith('wallet_decrypted'):
            wallet = runtime_json.read_decrypted_wallet_lines(wallet_path)
            address = wallet[0].strip()
            private_key = wallet[1].strip()
            public_key = wallet[2].strip()
            full_messages = store.messages_for_recipient(address)

            def thrd_recv():
                msg = connect('r', address, ipnl)
                full_messages.extend(_parse_peer_messages(msg))
            for iteration in range(5):
                threading.Thread(target=thrd_recv).start()
            time.sleep(5)

            for message in full_messages:
                try:
                    result = store.ingest_message(message)
                    proof = result.get("conflict_proof")
                    if proof:
                        broadcast_message(proof)
                    if message.get("type") == ind_token.TRANSFER_ANNOUNCEMENT_TYPE:
                        state = ind_token.verify_token(message["token"])
                        if state.owner_address == address:
                            receipt = ind_token.create_receipt_announcement(message["token"], private_key, public_key)
                            store.ingest_message(receipt)
                            broadcast_message(receipt)
                except Exception:
                    pass

            store.finalize_pending(buffer_seconds=ind_settings.finality_buffer_seconds())
            wallet_ids = {line.split()[0].lstrip('-') for line in runtime_json.wallet_token_lines(wallet) if line.split()}
            settled = store.token_records_for_owner(address, settled_only=True)
            updated_wallet = list(wallet)
            for record in settled:
                if record["display_id"] not in wallet_ids:
                    updated_wallet.append(record["display_id"] + ' ' + str(record["sequence"]) + ' ' + str(int(time.time())) + '\n')
                    wallet_ids.add(record["display_id"])
            runtime_json.write_decrypted_wallet_lines(wallet_path, updated_wallet)


def ask_for_luck():
    """Disable the legacy faucet path; IND supply now exists only at genesis."""

    return False
