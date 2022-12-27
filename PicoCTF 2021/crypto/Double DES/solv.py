#!/bin/python3

from Crypto.Cipher import DES
from Crypto.Util.number import *
import itertools
import string
from pwn import *


def pad(msg):
    block_len = 8
    over = len(msg) % block_len
    pad = block_len - over
    return (msg + " " * pad).encode()

'''
GETTING DATA
'''

r = remote('mercury.picoctf.net', 1903)

r.recvline()
flag_c = long_to_bytes(int(r.recvline().rstrip(), 16))

dummyString = 'I am doing a meet in the middle attack'
r.sendline(hex(bytes_to_long(dummyString.encode()))[2:].encode())
m = pad(dummyString)

c = long_to_bytes(int(r.recvline().rstrip().split()[-1],16))


'''
DOING ATTACK
'''

decryptions = {}
encryptions = {}


for key in itertools.product(string.digits, repeat=6):
	key = pad("".join(key))

	cipher = DES.new(key, DES.MODE_ECB)
	decryptions[cipher.decrypt(c)] = key
	encryptions[cipher.encrypt(m)] = key


d_s = set(decryptions)
e_s = set(encryptions)

middle_point = d_s.intersection(e_s).pop()



key1 = decryptions[middle_point]
key2 = encryptions[middle_point]

cipher1 = DES.new(key1, DES.MODE_ECB)
cipher2 = DES.new(key2, DES.MODE_ECB)

flag_m = cipher2.decrypt(cipher1.decrypt(flag_c))

print(flag_m.rstrip())
