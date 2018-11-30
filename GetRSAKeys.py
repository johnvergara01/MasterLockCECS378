import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def getRSAKeys(pubK, privK):
    if(os.path.exists(pubK) and os.path.exists(privK)):
        print("Key files found")
    else:
        private_key = rsa.generate_private_key(public_exponent=65537,key_size=2048,backend=default_backend())
        public_key = private_key.public_key()
        privPEM = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                            format=serialization.PrivateFormat.TraditionalOpenSSL,
                                            encryption_algorithm=serialization.NoEncryption())
        pubPEM = public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
        pubFile=open(pubK, "wb")
        pubFile.write(pubPEM)
        pubFile.close()

        privFile=open(privK, "wb")
        privFile.write(privPEM)
        privFile.close()