import Constants
import base64
import json

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes, hmac

def MyDecryptMAC(C, IV, tag, EncKey, HMACKey, ext):
    backend = default_backend()
    h = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())
    h.update(C)
    try:
        h.verify(tag)

        cipher = Cipher(algorithms.AES(EncKey), modes.CBC(IV), backend=backend)
        decryptor = cipher.decryptor()
        output = decryptor.update(C)
        unpadder = padding.PKCS7(Constants.blockSize).unpadder()
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