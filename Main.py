import GetRSAKeys
import MyRSAEncrypt
import MyRSADecrypt
import Walk
import WalkDecrypt
import os

def main():
    Walk.Walk(r"C:\Users\johnv\Downloads\TestFolder")
    WalkDecrypt.WalkDecrypt(r"C:\Users\johnv\Downloads\TestFolder")

if __name__ == '__main__':main()