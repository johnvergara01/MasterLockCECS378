import os
import MyEncryptMAC
import base64

def MyFileEncryptMAC(filepath):
    bits = 32
    EncKey = os.urandom(bits)
    HMACKey = os.urandom(bits)
    ext = os.path.splitext(filepath)[1]
    with open(filepath, "rb") as message:
        messageStr = base64.b64encode(message.read())
    message = bytes(messageStr)
    cipher = MyEncryptMAC.MyEncryptMAC(message, EncKey, HMACKey)
    C = cipher[0]
    IV = cipher[1]
    tag = cipher[2]
    return (C, IV, tag, EncKey, HMACKey, ext)