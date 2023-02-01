#!/usr/bin/python3 -u
from Crypto.Cipher import DES
import binascii
import itertools
import random
import string


def pad(msg):
    block_len = 8
    over = len(msg) % block_len
    pad = block_len - over
    return (msg + " " * pad).encode()

def generate_key():
    return pad("".join(random.choice(string.digits) for _ in range(6)))


FLAG = open("flag").read().rstrip()
KEY1 = generate_key()
KEY2 = generate_key()


def get_input():
    try:
        res = binascii.unhexlify(input("What data would you like to encrypt? ").rstrip()).decode()
    except:
        res = None
    return res

def double_encrypt(m):
    msg = pad(m)

    cipher1 = DES.new(KEY1, DES.MODE_ECB)
    enc_msg = cipher1.encrypt(msg)
    cipher2 = DES.new(KEY2, DES.MODE_ECB)
    return binascii.hexlify(cipher2.encrypt(enc_msg)).decode()


print("Here is the flag:")
print(double_encrypt(FLAG))

while True:
    inputs = get_input()
    if inputs:
        print(double_encrypt(inputs))
    else:
        print("Invalid input.")

