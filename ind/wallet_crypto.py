import base64
import json
import os
import secrets
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id


FORMAT = "INDW2"
VERSION = 2
MWK_BYTES = 32
SALT_BYTES = 16
NONCE_BYTES = 12
ARGON2_MEMORY_COST_KIB = 256 * 1024
ARGON2_ITERATIONS = 3
ARGON2_PARALLELISM = 4
PASSWORD_WRAPPER = "password"
RECOVERY_PHRASE_WRAPPER = "recovery_phrase"
PASSKEY_WRAPPER = "passkey_prf"

_SESSION_MWKS = {}


class WalletCryptoError(Exception):
    pass


class PasswordPolicyError(ValueError):
    pass


@dataclass(frozen=True)
class Argon2Params:
    memory_cost_kib: int = ARGON2_MEMORY_COST_KIB
    iterations: int = ARGON2_ITERATIONS
    parallelism: int = ARGON2_PARALLELISM


DEFAULT_ARGON2_PARAMS = Argon2Params()


def _b64e(value):
    return base64.urlsafe_b64encode(bytes(value)).decode("ascii")


def _b64d(value):
    return base64.urlsafe_b64decode(str(value).encode("ascii"))


def zeroize(value):
    try:
        for index in range(len(value)):
            value[index] = 0
    except Exception:
        pass


def _json_clone(value):
    return json.loads(json.dumps(value))


def _payload_aad(address):
    return f"{FORMAT}:payload:{address}".encode("utf-8")


def _wrapper_aad(address, wrapper_type, salt_b64):
    return f"{FORMAT}:mwk-wrapper:{address}:{wrapper_type}:{salt_b64}".encode("utf-8")


def _derive_argon2id(secret, salt, params):
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    kdf = Argon2id(
        salt=salt,
        length=MWK_BYTES,
        iterations=params.iterations,
        lanes=params.parallelism,
        memory_cost=params.memory_cost_kib,
    )
    return kdf.derive(secret)


def _encrypt_aesgcm(key, plaintext, aad):
    nonce = os.urandom(NONCE_BYTES)
    ciphertext = AESGCM(bytes(key)).encrypt(nonce, bytes(plaintext), aad)
    return {
        "cipher": "AES-256-GCM",
        "nonce": _b64e(nonce),
        "ciphertext": _b64e(ciphertext),
    }


def _decrypt_aesgcm(key, box, aad):
    if box.get("cipher") != "AES-256-GCM":
        raise WalletCryptoError("unsupported wallet cipher")
    return AESGCM(bytes(key)).decrypt(_b64d(box["nonce"]), _b64d(box["ciphertext"]), aad)


def _fallback_password_score(password):
    text = str(password)
    if len(text) < 10:
        return 0
    classes = sum(
        bool(check(text))
        for check in (
            str.islower,
            str.isupper,
            str.isdigit,
            lambda value: any(not char.isalnum() for char in value),
        )
    )
    score = 1
    if len(text) >= 12:
        score += 1
    if len(text) >= 16:
        score += 1
    if classes >= 3:
        score += 1
    if text.lower() in {"password", "walletpassword", "internationaldollar"}:
        score = 0
    return min(score, 4)


def validate_wallet_password(password):
    text = str(password)
    if len(text) < 10:
        raise PasswordPolicyError("Wallet password must be at least 10 characters.")
    try:
        from zxcvbn import zxcvbn

        score = int(zxcvbn(text).get("score", 0))
    except Exception:
        score = _fallback_password_score(text)
    if score < 3:
        raise PasswordPolicyError("Wallet password is too easy to guess. Use a longer mixed phrase.")


def _wrapper_from_secret(address, wrapper_type, secret, mwk, params, expires_at=None):
    salt = os.urandom(SALT_BYTES)
    salt_b64 = _b64e(salt)
    key = bytearray(_derive_argon2id(secret, salt, params))
    try:
        box = _encrypt_aesgcm(key, mwk, _wrapper_aad(address, wrapper_type, salt_b64))
    finally:
        zeroize(key)
    wrapper = {
        "type": wrapper_type,
        "kdf": "Argon2id",
        "memory_cost_kib": params.memory_cost_kib,
        "iterations": params.iterations,
        "parallelism": params.parallelism,
        "salt": salt_b64,
        **box,
    }
    if expires_at is not None:
        wrapper["expires_at"] = int(expires_at)
    return wrapper


def _unwrap_with_secret(address, wrapper, secret):
    if wrapper.get("kdf") != "Argon2id":
        raise WalletCryptoError("unsupported wallet KDF")
    params = Argon2Params(
        memory_cost_kib=int(wrapper["memory_cost_kib"]),
        iterations=int(wrapper["iterations"]),
        parallelism=int(wrapper["parallelism"]),
    )
    salt_b64 = str(wrapper["salt"])
    key = bytearray(_derive_argon2id(secret, _b64d(salt_b64), params))
    try:
        return _decrypt_aesgcm(key, wrapper, _wrapper_aad(address, wrapper["type"], salt_b64))
    finally:
        zeroize(key)


def create_wallet_record(address, wallet_payload, wallet_password, recovery_phrase=None, kdf_params=None):
    validate_wallet_password(wallet_password)
    params = kdf_params or DEFAULT_ARGON2_PARAMS
    address = str(address).strip()
    mwk = bytearray(os.urandom(MWK_BYTES))
    try:
        wrappers = [
            _wrapper_from_secret(address, PASSWORD_WRAPPER, wallet_password, mwk, params),
        ]
        if recovery_phrase:
            wrappers.append(
                _wrapper_from_secret(address, RECOVERY_PHRASE_WRAPPER, recovery_phrase, mwk, params)
            )
        return {
            "format": FORMAT,
            "version": VERSION,
            "address": address,
            "created_at": int(time.time()),
            "mwk": {
                "bytes": MWK_BYTES,
                "storage": "wrapped-only",
            },
            "payload": _encrypt_aesgcm(mwk, wallet_payload, _payload_aad(address)),
            "wrappers": wrappers,
        }
    finally:
        zeroize(mwk)


def decrypt_wallet_record(record, secret, wrapper_types=(PASSWORD_WRAPPER,), return_mwk=False):
    if not isinstance(record, dict) or record.get("format") != FORMAT:
        raise WalletCryptoError("unsupported wallet format")
    address = str(record["address"]).strip()
    now = int(time.time())
    failures = []
    for wrapper in record.get("wrappers", []):
        if wrapper.get("type") not in wrapper_types:
            continue
        expires_at = wrapper.get("expires_at")
        if expires_at is not None and int(expires_at) < now:
            continue
        try:
            mwk = _unwrap_with_secret(address, wrapper, secret)
            payload = _decrypt_aesgcm(mwk, record["payload"], _payload_aad(address))
            if return_mwk:
                return payload, mwk
            zeroize(bytearray(mwk))
            return payload
        except (InvalidTag, WalletCryptoError, KeyError, ValueError) as exc:
            failures.append(exc)
    raise WalletCryptoError("wallet secret did not unlock any allowed wrapper")


def update_wallet_payload(record, wallet_payload, mwk):
    if not isinstance(record, dict) or record.get("format") != FORMAT:
        raise WalletCryptoError("unsupported wallet format")
    updated = _json_clone(record)
    address = str(updated["address"]).strip()
    updated["payload"] = _encrypt_aesgcm(mwk, wallet_payload, _payload_aad(address))
    updated["updated_at"] = int(time.time())
    return updated


def rotate_password(record, current_password, new_password, grace_days=30):
    validate_wallet_password(new_password)
    payload, mwk = decrypt_wallet_record(record, current_password, return_mwk=True)
    try:
        updated = _json_clone(record)
        now = int(time.time())
        grace_until = now + int(grace_days * 24 * 60 * 60)
        for wrapper in updated.get("wrappers", []):
            if wrapper.get("type") == PASSWORD_WRAPPER and "expires_at" not in wrapper:
                wrapper["expires_at"] = grace_until
                wrapper["grace_reason"] = "previous_password"
        updated["wrappers"].append(
            _wrapper_from_secret(
                str(updated["address"]).strip(),
                PASSWORD_WRAPPER,
                new_password,
                mwk,
                DEFAULT_ARGON2_PARAMS,
            )
        )
        updated["updated_at"] = now
        _decrypt_aesgcm(mwk, updated["payload"], _payload_aad(updated["address"]))
        return updated, payload, grace_until
    finally:
        zeroize(bytearray(mwk))


def set_session_mwk(address, mwk):
    clear_session_mwk(address)
    _SESSION_MWKS[str(address).strip()] = bytearray(mwk)


def get_session_mwk(address):
    value = _SESSION_MWKS.get(str(address).strip())
    if value is None:
        return None
    return bytes(value)


def clear_session_mwk(address):
    key = str(address).strip()
    value = _SESSION_MWKS.pop(key, None)
    if value is not None:
        zeroize(value)


def clear_all_session_mwks():
    for address in list(_SESSION_MWKS):
        clear_session_mwk(address)


def generate_recovery_phrase(word_count=8):
    try:
        from mnemonic import Mnemonic
    except Exception as exc:
        raise RuntimeError("Install the mnemonic package to generate BIP-39 recovery phrases.") from exc
    words = Mnemonic("english").wordlist
    return " ".join(secrets.choice(words) for _ in range(int(word_count)))
