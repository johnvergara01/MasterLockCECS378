import os
import base64
import json

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes, hmac

blockSize = 128

#part 1
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

#part 1 test
print("Part 1 test")
test = MyFileEncrypt("test.txt")
MyDecrypt(test[0], test[1], test[2], test[3])

#part 2
#hmac cipher text not message
#how would you combine integrity and confidentiality and why
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
	return(C, IV, tag.finalize())

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
	return(C, IV, tag, EncKey, HMACKey, ext)

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
	except:
		print("Invalid tag")
	with open('decryptMAC.json', 'w') as jsonFile:
		data = (str(C), str(IV), str(tag), str(EncKey), str(HMACKey), ext)
		json.dump(data, jsonFile)

test = MyFileEncryptMAC("thumb.jpg")
MyDecryptMAC(test[0], test[1], test[2], test[3], test[4], test[5])