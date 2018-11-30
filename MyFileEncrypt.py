import MyEncrypt
import os

def MyFileEncrypt(filepath):
    bits = 32
    key = os.urandom(bits)
    f = open(filepath, 'r')
    ext = os.path.splitext(filepath)[1]
    message = f.read()
    message = bytes(message.encode('utf8'))
    cipher = MyEncrypt.MyEncrypt(message, key)
    C = cipher[0]
    IV = cipher[1]
    print("cipher text: " + str(C))
    return (C, IV, key, ext)