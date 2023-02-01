#!/bin/python3

from Crypto.Util.number import *

n = long_to_bytes(0x73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d)

for k in range(2**8):
        tmp = ''
        for i in n:
                tmp += chr(i ^ k)
        if 'crypto{' in tmp:
                print(tmp)

