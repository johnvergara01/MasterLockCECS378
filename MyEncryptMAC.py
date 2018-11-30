import os
import Constants
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes, hmac

def MyEncryptMAC(message, EncKey, HMACKey):
    bits = 16;
    backend = default_backend()
    IV = os.urandom(bits)
    cipher = Cipher(algorithms.AES(EncKey), modes.CBC(IV), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(Constants.blockSize).padder()
    padded_data = padder.update(message)
    padded_data += padder.finalize()
    print("padded_data: " + str(padded_data))
    C = encryptor.update(padded_data) + encryptor.finalize()

    tag = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())
    tag.update(C)
    return (C, IV, tag.finalize())