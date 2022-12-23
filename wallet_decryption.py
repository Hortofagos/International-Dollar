import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import os


def wallet_decrypt():
    with open('passphrase.txt', 'r+') as p:
        passphrase = p.readlines()
        p.seek(0)
        p.truncate()
    password = str(passphrase[0]).strip().encode('utf-8')
    address = str(passphrase[1]).strip()
    salt = b'w\x8a\xb3\x97d\x17D\xba\x86\xcc\xea\x9a\x11\\=\xe2'
    kdf = PBKDF2HMAC(algorithm=hashes.SHA3_256, length=32, salt=salt, iterations=1000000, backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(password))
    cipher = Fernet(key)
    for x in os.listdir('wallet_folder'):
        if x.replace('wallet_encrypted_', '').replace('.txt', '') == address:
            with open('wallet_folder/' + x, 'rb') as f:
                file_read = f.read()
            try:
                decrypted_file = cipher.decrypt(file_read)
                if decrypted_file.decode('utf-8').startswith(address):
                    with open('wallet_folder/wallet_decrypted_' + x[17:], 'wb') as de:
                        de.write(decrypted_file)
                    break
            except:
                break
        elif x.startswith('wallet_decrypted'):
            os.remove('wallet_folder/' + x)
