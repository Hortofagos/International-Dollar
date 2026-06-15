import base64
import hashlib

import ecdsa


def verify_ecdsa(ds, d, pk):
    try:
        public_key_decode = base64.b85decode(pk)
        vk = ecdsa.VerifyingKey.from_string(
            public_key_decode, curve=ecdsa.SECP256k1, hashfunc=hashlib.sha3_256
        )
        signature_decode = base64.b85decode(ds)
        vk.verify(signature_decode, d.encode('utf-8'))
        return 'valid'
    except (ValueError, ecdsa.BadSignatureError, ecdsa.MalformedPointError):
        return 'not valid'
