import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet


def wallet_encrypt():
    with open('hashing.txt', 'r') as ha:
        h_pass = ha.readlines()
    password = h_pass[3].strip().encode('utf-8')
    salt = b'w\x8a\xb3\x97d\x17D\xba\x86\xcc\xea\x9a\x11\\=\xe2'
    kdf = PBKDF2HMAC(algorithm=hashes.SHA3_256, length=32, salt=salt, iterations=1000000, backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(password))
    with open('hashing.txt', 'rb') as f:
        file_read = f.read()
    cipher = Fernet(key)
    encrypted_file = cipher.encrypt(file_read)
    with open('wallet_folder\wallet_encrypted_' + h_pass[0].strip() + '.txt', 'wb') as ef:
        ef.write(encrypted_file)
