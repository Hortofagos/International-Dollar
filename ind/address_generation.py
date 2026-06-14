import hashlib
import ecdsa
import base64

from . import runtime as runtime_json
from . import token as ind_token


def generate_keypair():
    """Generate one IND wallet address and secp256k1 keypair."""

    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1, hashfunc=hashlib.sha3_256)
    vk = sk.get_verifying_key()
    private_key = base64.b85encode(sk.to_string()).decode("utf-8")
    public_key = base64.b85encode(vk.to_string()).decode("utf-8")
    address = ind_token.address_from_public_key(public_key)
    return address, private_key, public_key


def hash_func(stop):
    """Compatibility wrapper for older callers expecting list output."""

    address, private_key, public_key = generate_keypair()
    stop.append(address)
    stop.append(private_key)
    stop.append(public_key)


def main():
    """Generate a wallet address/keypair into the runtime wallet-generation slot."""

    address, private_key, public_key = generate_keypair()
    runtime_json.write_wallet_generation(address, private_key, public_key)


if __name__ == "__main__":
    main()
