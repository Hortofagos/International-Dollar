from . import keys_v3
from . import runtime as runtime_json


def generate_keypair():
    """Generate one default V3 IND wallet address/keypair."""

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
