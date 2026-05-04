import time
import hashlib
import ecdsa
from multiprocessing import Process, Manager, cpu_count
import base64

from . import runtime as runtime_json
from . import token as ind_token


def hash_func(stop):
    """Generate vanity IND wallet keys until one worker finds a matching address."""

    while True:
        if stop:
            break
        sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1, hashfunc=hashlib.sha3_256)
        vk = sk.get_verifying_key()
        sk_string = sk.to_string()
        vk_string = vk.to_string()
        sk_base85 = base64.b85encode(sk_string).decode('utf-8')
        vk_base85 = base64.b85encode(vk_string).decode('utf-8')
        addr = ind_token.address_from_public_key(vk_base85)
        stop.append(addr)
        stop.append(sk_base85)
        stop.append(vk_base85)


def main():
    """Generate a wallet address/keypair into the runtime wallet-generation slot."""

    with Manager() as manager:
        st = manager.list()
        cpu = cpu_count()
        p = Process(target=hash_func, args=(st, )).start()
        p2 = Process(target=hash_func, args=(st,)).start()
        p3 = Process(target=hash_func, args=(st,)).start()
        p4 = Process(target=hash_func, args=(st,)).start()
        p5 = Process(target=hash_func, args=(st,)).start()
        p6 = Process(target=hash_func, args=(st,)).start()
        p7 = Process(target=hash_func, args=(st,)).start()
        p8 = Process(target=hash_func, args=(st,)).start()
        hash_func(st)
        time.sleep(0.2)
        runtime_json.write_wallet_generation(st[0], st[1], st[2])


if __name__ == "__main__":
    main()
