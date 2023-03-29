#!/bin/python3
from Crypto.Util.number import *

def msb(b):
	return b >> 7

with open('Ninja-and-Prince-Genji-Ukiyoe-Utagawa-Kunisada.flag.png', 'rb') as fin:
	img = fin.read()

bits = ""

for b in img:
	bits += str(msb(b))

newImgBytes = []

for i in range(0, len(bits), 8):
	print(chr(int("0b" + bits[i:i + 8], 2)))

