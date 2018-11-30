import os
import Constants

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

def MyEncrypt(message, key):
    bits = 16;
    backend = default_backend()
    IV = os.urandom(bits)
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(Constants.blockSize).padder()
    padded_data = padder.update(message)
    padded_data += padder.finalize()
    print("padded_data: " + str(padded_data))
    C = encryptor.update(padded_data) + encryptor.finalize()
    return (C, IV)