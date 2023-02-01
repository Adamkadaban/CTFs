#!/bin/python3
from base64 import *
from Crypto.Util.number import *
from Crypto.PublicKey import RSA
import re

with open('pK.txt') as fin: # open public key
	apK = fin.read()

# Here, I'm fixing the format so it can be more easily read by pycryptodome
fixedKey = '-----BEGIN RSA PUBLIC KEY-----\n'
fixedKey += apK + '\n'
fixedKey += '-----END RSA PUBLIC KEY-----'

pK = RSA.import_key(fixedKey) # now we can import all the values from the public key


n=pK.n
e=pK.e
d=pK.d
p=pK.p

q=pK.q

u=pK.u




with open('nc') as fin: # Here, I'm reading the ciphertext
	cipher = fin.read().rstrip()

unbased = bytes_to_long(b64decode(cipher)) # base64 decode and convert to a number in order to manipulate it

# print(bytes_to_long(unbased))


def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b%a,a)
    return (g, x - (b//a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('No modular inverse')
    return x%m

# now, solve using rsa formulas
phi = (p-1)*(q-1)

m = pow(unbased,d,n)

# convert the message from a number to text
outp = long_to_bytes(m)

# the last few bytes give us the flag
print(outp[-19:].decode('UTF-8'))
