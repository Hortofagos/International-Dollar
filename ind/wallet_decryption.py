import logging
import os

from . import runtime as runtime_json
from . import wallet_crypto

logger = logging.getLogger(__name__)


# Best-effort overwrite and removal for temporary decrypted wallet files.
def secure_delete(path):
    try:
        size = os.path.getsize(path)
        with open(path, "r+b") as handle:
            handle.write(b"\x00" * size)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception as exc:
        logger.debug("could not overwrite temporary wallet file %s: %s", path, exc)
    try:
        os.remove(path)
    except Exception as exc:
        logger.debug("could not remove temporary wallet file %s: %s", path, exc)


def _clear_plaintext_wallet_files():
    for wallet_path in runtime_json.iter_decrypted_wallet_files():
        if wallet_path.exists() and wallet_path.name.startswith("wallet_decrypted"):
            secure_delete(wallet_path)


# Remove temporary plaintext wallet files and optionally clear unlocked sessions.
def clear_plaintext_wallet_files(clear_memory=False):
    _clear_plaintext_wallet_files()
    if clear_memory:
        runtime_json.clear_decrypted_wallets()
        wallet_crypto.clear_all_session_mwks()


def _decrypt_indw3(record, password):
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


# Unlock the selected V3 wallet into process memory after passphrase entry.
def wallet_decrypt(passphrase=None, address=None):
    if passphrase is None or address is None:
        request = runtime_json.consume_passphrase_request()
        passphrase = request["passphrase"]
        address = request["address"]
    password = str(passphrase).encode("utf-8")
    address = str(address).strip()
    clear_plaintext_wallet_files()
    for wallet_path in runtime_json.iter_encrypted_wallet_files():
        if runtime_json.wallet_address_from_name(wallet_path.name) != address:
            continue
        try:
            record = runtime_json.read_encrypted_wallet_record(wallet_path)
            if record.get("format") != wallet_crypto.FORMAT:
                return False
            decrypted_file = _decrypt_indw3(record, password)
            if decrypted_file.decode("utf-8").startswith(address):
                runtime_json.write_decrypted_wallet(address, decrypted_file)
                return True
        except Exception:
            return False
    return False
