#!/bin/python3

from Crypto.Util.number import *

hexVals = [0x536861646F77, 0x4354467B,0x7368654C4C, 0x2D416E616C79,0x7369732D, 0x646F6E337D]

s = b"".join([long_to_bytes(i) for i in hexVals])

print(s.decode('UTF-8'))


