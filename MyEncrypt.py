import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def MyEncrypt(message, key):
	backend = default_backend()
	IV = os.urandom(16)
	cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=backend)
	encryptor = cipher.encryptor()
	buf = bytearray(len(message) + 127)
	len_encrypted = encryptor.update_into(message, buf)
	C = bytes(buf[:len_encrypted]) + encryptor.finalize()
	return (C, IV)
#make object to pad, make sure its PKCS7 use that to pad, no magic numbers

def MyFileEncrypt(filepath):
	key = os.urandom(32)
	f = open(filepath, 'r')
	ext = os.path.splitext(filepath)[1]
	message = f.read()
	message = bytes(message.encode('utf8'))
	cipher = MyEncrypt(message, key)
	C = cipher[0]
	IV = cipher[1]
	return (C, IV, key, ext)

def MyDecrypt(C, IV, key, ext):
	backend = default_backend()
	cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=backend)
	decryptor = cipher.decryptor()
	buf = bytearray(len(C) + 127)
	len_decrypted = decryptor.update_into(C, buf)
	output = bytes(buf[:len_decrypted]) + decryptor.finalize()
	f = open("decrypt" + ext, 'w+')
	f.write(str(output))

test = MyFileEncrypt("test.txt")
MyDecrypt(test[0], test[1], test[2], test[3])










# def MyEncryptMAC(message, EncKey, HMACKey):
# 	backend = default_backend()
# 	IV = os.urandom(16)
# 	cipher = Cipher(algorithms.AES(EncKey), modes.CBC(IV), backend=backend)
# 	encryptor = cipher.encryptor()
# 	buf = bytearray(len(message) + 127)
# 	len_encrypted = encryptor.update_into(message, buf)
# 	C = bytes(buf[:len_encrypted]) + encryptor.finalize()
#
# 	tag = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())
# 	tag.update(C)
# 	tag.finalize()
# 	return(C, IV, tag)
#
# def MyFileEncryptMAC(filepath):
# 	EncKey = os.urandom(32)
# 	HMACKey = os.urandom(32)
# 	f = open(filepath, 'r')
# 	ext = os.path.splitext(filepath)[1]
# 	message = f.read()
# 	message = bytes(message.encode('utf8'))
# 	cipher = MyEncryptMAC(message, EncKey, HMACKey)
# 	C = cipher[0]
# 	IV = cipher[1]
# 	tag = cipher[2]
# 	return(C, IV, tag, EncKey, HMACKey, ext)
#
# def MyDecryptMAC(C, IV, tag, EncKey, HMACKey, ext):
# 	backend = default_backend()
# 	h = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())
# 	h.update(C)
# 	h.verify(C)
# 	h = h.finalize()
#
# 	cipher = Cipher(algorithms.AES(EncKey), modes.CBC(IV), backend=backend)
# 	decryptor = cipher.decryptor()
# 	buf = bytearray(len(C) + 127)
# 	len_decrypted = decryptor.update_into(C, buf)
# 	output = bytes(buf[:len_decrypted]) + decryptor.finalize()
# 	f = open("decryptMAC" + ext, 'w+')
# 	f.write(str(output))
#
# test = MyFileEncryptMAC("test.txt")
# MyDecryptMAC(test[0], test[1], test[2], test[3], test[4], test[5])