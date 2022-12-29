#!/bin/python3

from Crypto.Util.number import *
import itertools
from pwn import xor

c = long_to_bytes(0x57657535570c1e1c612b3468106a18492140662d2f5967442a2960684d28017931617b1f3637)

random_strs = [b'break it', b'ever', b'and you will never', b'is absolutely impenetrable', b'my encryption method']

for combo in range(2**len(random_strs)):
	for i, s in enumerate(random_strs):
		if (combo >> i) & 1:
			c = xor(c, s)

	# this indicates that the 4th option has a key of 'Africa!'
	# print(xor(c, b'picoCTF'))

	m = xor(c, b'Africa!')

	if b'picoCTF' in m:
		print(m.decode())
