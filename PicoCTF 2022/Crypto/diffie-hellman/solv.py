#!/bin/python3
from Crypto.Util.number import *

s = "H98A9W_H6UM8W_6A_9_D6C_5ZCI9C8I_CB5EJHB6"


a = 7 # private
b = 3 # private

p = 13
g = 5

y = (g ** a) % p # recieved public key
x = (g ** b) % p # recieved public key

# symmetric shared key
k_a = (y ** a) % p
k_b = (x ** b) % p

assert(k_a == k_b)

chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
n = k_a
o = ''
for i in s:
	if i=="_":
		o += "_"
	else:
		o += chars[(chars.index(i) - k_a) % len(chars)]
print(f'picoCTF{{{o}}}')

