import time
import hashlib
import base58
import ecdsa
from multiprocessing import Process, Manager, cpu_count
import base64


def hash_func(stop):
    while True:
        if stop:
            break
        sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1, hashfunc=hashlib.sha3_256)
        vk = sk.get_verifying_key()
        #signing key
        sk_string = sk.to_string()
        #verifying key
        vk_string = vk.to_string()
        #encode the keys in base85
        sk_base85 = base64.b85encode(sk_string).decode('utf-8')
        vk_base85 = base64.b85encode(vk_string).decode('utf-8')
        #hash the verifying key (public_key) in sha3_256
        sha = hashlib.sha3_256(str(vk_base85).encode('utf-8')).digest()
        #encode the hash in base58
        sha_encode = base58.b58encode(sha).decode('utf-8')
        #slice the sha3_256 hash at 30 characters and check if it starts and ends with 'x'
        #if it does not start and end with 'x', the loop continues
        addr = sha_encode[:30]
        if addr.startswith('x') and addr.endswith('x'):
            stop.append(addr)
            stop.append(sk_base85)
            stop.append(vk_base85)


if __name__ == "__main__":
    with Manager() as manager:
        st = manager.list()
        cpu = cpu_count()
        #8 seperate processes using up 8 cores
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
        #write the final hashed address in hashing.txt
        #this address starts and ends with 'x'
        with open('files/hashing.txt', 'w') as hashx:
            hashx.seek(0)
            hashx.truncate()
            hashx.write(st[0] + '\n' + st[1] + '\n' + st[2] + '\n')
