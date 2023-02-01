#!/usr/bin/env python2

from Crypto.Util.number import *
from Crypto.Util.strxor import *
def encrypt(plaintext, key):

    ciphertext = []
    for i in range(0, len(plaintext)):
        ciphertext.append(ord(plaintext[i]) ^ ord(key[i%len(key)])) 

    return ''.join(map(chr, ciphertext))

decrypt = encrypt

'''
I'll give you a sample of how this works:

Plaintext: 
"Here is a sample. Pay close attention!"

Ciphertext: (encoded in hex)
2e0c010d46000048074900090b191f0d484923091f491004091a1648071d070d081d1a070848

Flag: (encoded in hex, encrypted with the same key)
0005120f1d111c1a3900003712011637080c0437070c0015


'''
flag = long_to_bytes(0x0005120f1d111c1a3900003712011637080c0437070c0015)
plain = b"Here is a sample. Pay close attention!"
cipher = long_to_bytes(0x2e0c010d46000048074900090b191f0d484923091f491004091a1648071d070d081d1a070848)

key = strxor(plain, cipher)

print(decrypt(flag.decode(), 'fish'))



# idk what I was doing wrong, but this solved it for me: https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')XOR(%7B'option':'UTF8','string':'fish'%7D,'Standard',false)&input=MDAwNTEyMGYxZDExMWMxYTM5MDAwMDM3MTIwMTE2MzcwODBjMDQzNzA3MGMwMDE1
