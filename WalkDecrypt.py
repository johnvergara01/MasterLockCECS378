import MyRSADecrypt
import os
import json
import base64

def WalkDecrypt(dir):
    for dirName, subdirList, fileList in os.walk(dir):
        for i in fileList:
            if ".json" in i:
                with open(dir+"/"+i) as f:
                    data=json.load(f)
                    #RSACipher = base64.b64encode(data["RSACipher"])
                    RSACipher = str.encode(data["RSACipher"])
                    #C = base64.b64encode(data["C"])
                    C = str.encode((data["C"]))
                    #IV = base64.b64encode(data["IV"])
                    IV = str.encode(data["IV"])
                    #tag = base64.b64encode(data["tag"])
                    tag = str.encode(data["tag"])
                MyRSADecrypt.MyRSADecrypt(RSACipher, C, IV, tag, data["ext"], dir+"/PrivateKey.pem")
