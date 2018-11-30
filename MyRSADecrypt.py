import MyDecryptMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as RSApad
from cryptography.hazmat.primitives import serialization

def MyRSADecrypt(RSACipher, C, IV, tag, ext, RSA_Privatekey_filepath):
    with open(RSA_Privatekey_filepath, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())
    key = private_key.decrypt(RSACipher, RSApad.OAEP(mgf=RSApad.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    EncKey = key[:32]
    HMACKey = key[-32:]

    MyDecryptMAC.MyDecryptMAC(C, IV, tag, EncKey, HMACKey, ext)