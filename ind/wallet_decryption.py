import base64
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from . import runtime as runtime_json
from . import wallet_crypto


WALLET_V1_PREFIX = b'INDW1:'
LEGACY_WALLET_SALT = b'w\x8a\xb3\x97d\x17D\xba\x86\xcc\xea\x9a\x11\\=\xe2'


def _derive_key(password, salt):
    """Derive the legacy Fernet key used by pre-INDW2 wallet files."""

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA3_256(),
        length=32,
        salt=salt,
        iterations=1000000,
        backend=default_backend(),
    )
    return base64.urlsafe_b64encode(kdf.derive(password))


def _decrypt_legacy_payload(file_read, password):
    """Decrypt current legacy wallet files and the older fixed-salt format."""

    if file_read.startswith(WALLET_V1_PREFIX):
        salt_b64, encrypted_file = file_read[len(WALLET_V1_PREFIX):].split(b':', 1)
        salt = base64.urlsafe_b64decode(salt_b64)
        return Fernet(_derive_key(password, salt)).decrypt(encrypted_file)
    return Fernet(_derive_key(password, LEGACY_WALLET_SALT)).decrypt(file_read)


def secure_delete(path):
    """Best-effort overwrite and removal for temporary decrypted wallet files."""

    try:
        size = os.path.getsize(path)
        with open(path, 'r+b') as handle:
            handle.write(b'\x00' * size)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        pass
    try:
        os.remove(path)
    except Exception:
        pass


def _clear_plaintext_wallet_files():
    for wallet_path in runtime_json.iter_decrypted_wallet_files():
        if wallet_path.exists() and wallet_path.name.startswith('wallet_decrypted'):
            secure_delete(wallet_path)


def clear_plaintext_wallet_files(clear_memory=False):
    """Remove temporary plaintext wallet files and optionally clear unlocked sessions."""

    _clear_plaintext_wallet_files()
    if clear_memory:
        runtime_json.clear_decrypted_wallets()
        wallet_crypto.clear_all_session_mwks()


def _decrypt_indw2(record, password):
    decrypted_file, mwk = wallet_crypto.decrypt_wallet_record(
        record,
        password,
        wrapper_types=(wallet_crypto.PASSWORD_WRAPPER,),
        return_mwk=True,
    )
    address = str(record["address"]).strip()
    wallet_crypto.set_session_mwk(address, mwk)
    wallet_crypto.zeroize(bytearray(mwk))
    return decrypted_file


def wallet_decrypt(passphrase=None, address=None):
    """Unlock the selected wallet into process memory after passphrase entry."""

    if passphrase is None or address is None:
        request = runtime_json.consume_passphrase_request()
        passphrase = request["passphrase"]
        address = request["address"]
    password = str(passphrase).encode('utf-8')
    address = str(address).strip()
    clear_plaintext_wallet_files()
    for wallet_path in runtime_json.iter_encrypted_wallet_files():
        if runtime_json.wallet_address_from_name(wallet_path.name) != address:
            continue
        try:
            record = runtime_json.read_encrypted_wallet_record(wallet_path)
            if record.get("format") == wallet_crypto.FORMAT:
                decrypted_file = _decrypt_indw2(record, password)
            else:
                file_read = runtime_json.read_encrypted_wallet_bytes(wallet_path, prefix=WALLET_V1_PREFIX)
                decrypted_file = _decrypt_legacy_payload(file_read, password)
            if decrypted_file.decode('utf-8').startswith(address):
                runtime_json.write_decrypted_wallet(address, decrypted_file)
                return True
        except Exception:
            return False
    return False
