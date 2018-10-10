import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import(Cipher, algorithms,modes)



def Myencrypt(message,key):
	IV = os.random(2)
	encryptor = Cipher(algorithms.AES(key),modes.GCM(IV),backend=default_backend()).encryptor()
	C = encryptor.update(message) + encryptor.finalize()
	
	return (C,IV)

def MyfileEncrypt(filepath):
	key = os.random(4)
	
	f= open(filepath,'r+')
	message = f.read()
	ext = os.path.splitext(filepath)
	f=close()
	enc = Myencrypt(message,key)
	
	return(C,IV,key,ext)

def Mydecrypt(C,IV,key,ext):
	
	
	

