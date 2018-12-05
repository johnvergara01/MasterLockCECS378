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
                    RSACipher = base64.b64decode(data["RSACipher"])
                    #RSACipher = bytes(data["RSACipher"], encoding='ascii')
                    C = base64.b64decode(data["C"])
                    IV = base64.b64decode(data["IV"])
                    tag = base64.b64decode(data["tag"])
                    #C = str.encode((data["C"]))
                    #IV = str.encode(data["IV"])
                    #tag = str.encode(data["tag"])
                restore = MyRSADecrypt.MyRSADecrypt(RSACipher, C, IV, tag, data["ext"], dir+"/PrivateKey.pem")
                filename = os.path.splitext(dir+"/"+i)[0]
                f = open(filename+data["ext"], 'w')
                f.write(restore.decode('ascii'))
                os.remove(dir+"/"+i)
                os.remove(dir+"/PrivateKey.pem")