#!/bin/python3
from base64 import *
from Crypto.Util.number import *
from Crypto.PublicKey import RSA
import re

with open('pK.txt') as fin:
	apK = fin.read()

fixedKey = '-----BEGIN RSA PUBLIC KEY-----\n'
fixedKey += apK + '\n'
fixedKey += '-----END RSA PUBLIC KEY-----'

pK = RSA.import_key(fixedKey)


n=pK.n
e=pK.e
d=pK.d
p=pK.p

q=pK.q

u=pK.u

# print(n)


with open('nc') as fin:
	cipher = fin.read().rstrip()

unbased = bytes_to_long(b64decode(cipher))

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


phi = (p-1)*(q-1)

m = pow(unbased,d,n)


outp = long_to_bytes(m)

print(outp[-19:].decode('UTF-8'))
