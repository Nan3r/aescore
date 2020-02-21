#coding:utf-8

import base64,zlib,time,hashlib
from Crypto.Cipher import AES

class AESCipher:
    def __init__(self, IV=False, Key=False):
        #key is hash256.digest
        self.BS = 16
        self.IV = IV if IV else self.generateIV()
        self.Key = Key if Key else hashlib.md5(str(self.IV)).hexdigest()

    def generateIV(self):
        return hashlib.md5(str(time.time())).hexdigest()[:self.BS]

    def encrypt( self, raw):
        pad = lambda s: s + (self.BS - len(s) % self.BS) * chr(self.BS - len(s) % self.BS)
        raw = pad(raw)
        cipher = AES.new(self.Key, AES.MODE_CBC, self.IV)
        return base64.b64encode(zlib.compress(self.IV+cipher.encrypt(raw)))

    def decrypt( self, enc ):
        unpad = lambda s: s[0:-ord(s[-1])]
        IV,enc = zlib.decompress(base64.b64decode(enc))[:self.BS],zlib.decompress(base64.b64decode(enc))[self.BS:]
        Key = hashlib.md5(str(IV)).hexdigest()
        cipher = AES.new(Key, AES.MODE_CBC, IV)
        return unpad(cipher.decrypt(enc))

'''       
a = AESCipher()
print a.encrypt('aesencrypt')
print a.decrypt('eJwLCk90y3VPiSz3NfUIyfRKd76yyKDQXnxm8y8uI531xl4AvycLyw==')
'''