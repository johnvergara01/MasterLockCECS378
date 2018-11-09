import os
import os.path
import base64
import json

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding as RSApad
from cryptography.hazmat.primitives import serialization

blockSize = 128

# part 1
def MyEncrypt(message, key):
    bits = 16;
    backend = default_backend()
    IV = os.urandom(bits)
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(blockSize).padder()
    padded_data = padder.update(message)
    padded_data += padder.finalize()
    print("padded_data: " + str(padded_data))
    C = encryptor.update(padded_data) + encryptor.finalize()
    return (C, IV)


def MyFileEncrypt(filepath):
    bits = 32;
    key = os.urandom(bits)
    f = open(filepath, 'r')
    ext = os.path.splitext(filepath)[1]
    message = f.read()
    message = bytes(message.encode('utf8'))
    cipher = MyEncrypt(message, key)
    C = cipher[0]
    IV = cipher[1]
    print("cipher text: " + str(C))
    return (C, IV, key, ext)


def MyDecrypt(C, IV, key, ext):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=backend)
    decryptor = cipher.decryptor()
    output = decryptor.update(C)
    print("decrypt: " + str(output))
    unpadder = padding.PKCS7(blockSize).unpadder()
    output = unpadder.update(output)
    output = output + unpadder.finalize()
    print("unpadded decrypt: " + str(output))
    f = open("decrypt" + ext, 'w+')
    f.write(str(output))
    f.close()


# part 1 test
#print("Part 1 test")
#test = MyFileEncrypt("test.txt")
#MyDecrypt(test[0], test[1], test[2], test[3])


# part 2
# hmac cipher text not message
# how would you combine integrity and confidentiality and why
def MyEncryptMAC(message, EncKey, HMACKey):
    bits = 16;
    backend = default_backend()
    IV = os.urandom(bits)
    cipher = Cipher(algorithms.AES(EncKey), modes.CBC(IV), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(blockSize).padder()
    padded_data = padder.update(message)
    padded_data += padder.finalize()
    print("padded_data: " + str(padded_data))
    C = encryptor.update(padded_data) + encryptor.finalize()

    tag = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())
    tag.update(C)
    return (C, IV, tag.finalize())


def MyFileEncryptMAC(filepath):
    bits = 32
    EncKey = os.urandom(bits)
    HMACKey = os.urandom(bits)
    ext = os.path.splitext(filepath)[1]
    with open(filepath, "rb") as message:
        messageStr = base64.b64encode(message.read())
    message = bytes(messageStr)
    cipher = MyEncryptMAC(message, EncKey, HMACKey)
    C = cipher[0]
    IV = cipher[1]
    tag = cipher[2]
    return (C, IV, tag, EncKey, HMACKey, ext)


def MyDecryptMAC(C, IV, tag, EncKey, HMACKey, ext):
    backend = default_backend()
    h = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())
    h.update(C)
    try:
        h.verify(tag)

        cipher = Cipher(algorithms.AES(EncKey), modes.CBC(IV), backend=backend)
        decryptor = cipher.decryptor()
        output = decryptor.update(C)
        unpadder = padding.PKCS7(blockSize).unpadder()
        string = unpadder.update(output)
        string = string + unpadder.finalize()
        f = open("decryptMAC" + ext, 'wb')
        output = base64.b64decode(string)
        f.write(output)
        f.close()
        with open('decryptMAC.json', 'w') as jsonFile:
            data = (str(C), str(IV), str(tag), str(EncKey), str(HMACKey), ext)
            json.dump(data, jsonFile)
        return output
    except:
        print("Invalid tag")

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

def MyRSAEncrypt(filepath, RSA_Publickey_filepath):
    (C, IV, tag, Enckey, HMACKey, ext) = MyFileEncryptMAC(filepath)
    key = Enckey + HMACKey
    with open(RSA_Publickey_filepath, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())
    RSACipher = public_key.encrypt(key, RSApad.OAEP(mgf=RSApad.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return RSACipher, C, IV, tag, ext

def MyRSADecrypt(RSACipher, C, IV, tag, ext, RSA_Privatekey_filepath):
    with open(RSA_Privatekey_filepath, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())
    key = private_key.decrypt(RSACipher, RSApad.OAEP(mgf=RSApad.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    EncKey = key[:32]
    HMACKey = key[-32:]

    MyDecryptMAC(C, IV, tag, EncKey, HMACKey, ext)


#test = MyFileEncryptMAC("thumb.jpg")
#MyDecryptMAC(test[0], test[1], test[2], test[3], test[4], test[5])
getRSAKeys("MasterLockRSAPublicKey.pem", "MasterLockRSAPrivateKey.pem")
RSAenc = MyRSAEncrypt("thumb.jpg", "MasterLockRSAPublicKey.pem")
MyRSADecrypt(RSAenc[0], RSAenc[1], RSAenc[2], RSAenc[3], RSAenc[4], "MasterLockRSAPrivateKey.pem")