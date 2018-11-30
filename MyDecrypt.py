import Constants
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes, hmac

def MyDecrypt(C, IV, key, ext):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=backend)
    decryptor = cipher.decryptor()
    output = decryptor.update(C)
    print("decrypt: " + str(output))
    unpadder = padding.PKCS7(Constants.blockSize).unpadder()
    output = unpadder.update(output)
    output = output + unpadder.finalize()
    print("unpadded decrypt: " + str(output))
    f = open("decrypt" + ext, 'w+')
    f.write(str(output))
    f.close()