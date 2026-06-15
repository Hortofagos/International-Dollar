import base64
import hashlib
import os

import ecdsa

from . import keys_v3
from . import runtime as runtime_json
from . import token as ind_token


# Generate one IND wallet address and secp256k1 keypair.
def generate_legacy_keypair():
    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1, hashfunc=hashlib.sha3_256)
    vk = sk.get_verifying_key()
    private_key = base64.b85encode(sk.to_string()).decode("utf-8")
    public_key = base64.b85encode(vk.to_string()).decode("utf-8")
    address = ind_token.address_from_public_key(public_key)
    return address, private_key, public_key


def generate_keypair():
    """Generate one default IND wallet address/keypair.

    V3 x3 Ed25519 wallets are the default. Set IND_LEGACY_WALLET_KEYS=1 only
    for explicit V1/V2 development compatibility.
    """

    if os.environ.get("IND_LEGACY_WALLET_KEYS", "").strip().lower() in {"1", "true", "yes"}:
        return generate_legacy_keypair()
    return keys_v3.generate_keypair()


# Compatibility wrapper for older callers expecting list output.
def hash_func(stop):
    address, private_key, public_key = generate_keypair()
    stop.append(address)
    stop.append(private_key)
    stop.append(public_key)


# Generate a wallet address/keypair into the runtime wallet-generation slot.
def main():
    address, private_key, public_key = generate_keypair()
    runtime_json.write_wallet_generation(address, private_key, public_key)


if __name__ == "__main__":
    main()
