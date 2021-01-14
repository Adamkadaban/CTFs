#!/bin/python3

from Crypto.Util.number import *

unbase = long_to_bytes(0x0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104)

knownString = b'crypto{'

pwd = ""

for l in range(1,50):
	try:
		pwd = bytes(unbase[i] ^ knownString[i] for i in range(l))
	except:
		pass

# pwd ends up being 'myXORke', but that gives an output of 'crypto{%r~n-LQCnAUaY6ifjtJJMvXeb_lGja'
# That's nonsense, so we assume that the password is actually 'myXORkey'

pwd = b'myXORkey'

pwdLength = len(pwd)

flag = bytes(unbase[i] ^ pwd[i%pwdLength] for i in range(len(unbase)))

print(flag.decode('UTF-8'))
