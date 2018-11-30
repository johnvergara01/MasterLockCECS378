import MyFileEncryptMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as RSApad
from cryptography.hazmat.primitives import serialization

def MyRSAEncrypt(filepath, RSA_Publickey_filepath):
    (C, IV, tag, Enckey, HMACKey, ext) = MyFileEncryptMAC.MyFileEncryptMAC(filepath)
    key = Enckey + HMACKey
    with open(RSA_Publickey_filepath, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())
    RSACipher = public_key.encrypt(key, RSApad.OAEP(mgf=RSApad.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return RSACipher, C, IV, tag, ext