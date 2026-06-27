from . import runtime as runtime_json
from . import wallet_crypto

WALLET_V3_FORMAT = wallet_crypto.FORMAT
PasswordPolicyError = wallet_crypto.PasswordPolicyError


# Create a new INDW3 wallet: payload encrypted by MWK, MWK wrapped by password.
def wallet_encrypt(wallet_password=None, recovery_phrase=None, wallet_name=None):
    wallet = runtime_json.read_wallet_generation()
    password = wallet_password
    if password is None:
        password = str(wallet.get("passphrase", ""))
    address = str(wallet["address"]).strip()
    payload = runtime_json.wallet_generation_secret_payload().encode("utf-8")
    record = wallet_crypto.create_wallet_record(
        address,
        payload,
        str(password),
        recovery_phrase=recovery_phrase,
    )
    display_name = runtime_json.normalize_wallet_name(
        wallet.get("wallet_name", "") if wallet_name is None else wallet_name
    )
    if display_name:
        record["wallet_name"] = display_name
    runtime_json.write_encrypted_wallet_record(record)
    return record


# Persist changes to an already unlocked INDW3 wallet without storing the password.
def wallet_reencrypt_unlocked(address, payload):
    address = str(address).strip()
    mwk = wallet_crypto.get_session_mwk(address)
    if mwk is None:
        raise wallet_crypto.WalletCryptoError("wallet is not unlocked in this process")
    for wallet_path in runtime_json.iter_encrypted_wallet_files():
        if runtime_json.wallet_address_from_name(wallet_path.name) != address:
            continue
        record = runtime_json.read_encrypted_wallet_record(wallet_path)
        if record.get("format") != WALLET_V3_FORMAT:
            raise wallet_crypto.WalletCryptoError("unlocked re-encryption requires INDW3")
        updated = wallet_crypto.update_wallet_payload(record, str(payload).encode("utf-8"), mwk)
        runtime_json.write_encrypted_wallet_record(updated)
        return updated
    raise FileNotFoundError(f"encrypted wallet not found for {address}")
