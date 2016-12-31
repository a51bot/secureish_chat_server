#"borrowed" from http://stackoverflow.com/questions/12524994/encrypt-decrypt-using-pycrypto-aes-256

import base64
from Crypto.Cipher import AES
from Crypto import Random
import hashlib, binascii

def create_password_hash(password, salt):
    dk = hashlib.pbkdf2_hmac('sha256', bytes(password), bytes(salt), 10000)
    return binascii.hexlify(dk)

BS=16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-ord(s[-1])]

class AESCipher(object):
    def __init__( self, key ):
        self.key = hashlib.sha256(key.encode('utf-8')).digest()
        #self.key = key

    def encrypt( self, raw ):
        if len(raw) != 0: #if no data is passed in return nothing
            raw = pad(raw)
            iv = Random.new().read( AES.block_size )
            cipher = AES.new( self.key, AES.MODE_CBC, iv )
            return base64.b64encode( iv + cipher.encrypt( raw ) )
        return ""

    def decrypt(self, enc):
        if len(enc) != 0: #if no data is passed in return nothing
            #print "got_to_decrypt: "+enc
            enc = base64.b64decode(enc)
            iv = enc[:16]
            cipher = AES.new(self.key, AES.MODE_CBC, iv )
            return unpad(cipher.decrypt( enc[16:] ))
        return ""
#a = AESCipher("test")
#enc = a.encrypt("test")
#print enc
#print a.decrypt(enc)
