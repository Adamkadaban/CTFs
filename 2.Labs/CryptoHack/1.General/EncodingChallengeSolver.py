#!/bin/python3

from pwn import *
from Crypto.Util import number as nb
import binascii
from string import ascii_lowercase as lower
from string import ascii_uppercase as upper
import base64


r = remote('socket.cryptohack.org', 13377, level = 'debug')


def f(s):
	return s.decode('UTF-8')

def rot13(s):
	o = ""
	for i in s:
		character = ord(i)
		if i=="_":
			o += "_"
		elif i.islower():
			character -= 97
			character = (character + 13)%26
			o += lower[character]
		else:
			character -= 65
			character = (character + 13)%26
			o += upper[character]

	return o

def utf8(s):
	nums = s.split(", ")
	o = "".join([chr(int(i)) for i in nums])
	return o


def base64D(s):
	o = base64.b64decode(s)
	return f(o)

def bigint(s):
	o = nb.long_to_bytes(int(s, 16))
	return f(o)

def hexD(s):
	o = binascii.unhexlify(s)
	return f(o)

def outp(s):
	o = '{"decoded": "'
	o += s
	o += '"}\n'
	return o


while True:
	line = r.recvline()
	line = f(line)
	if "encoded" in line:
		encStrIndex = line.index("encoded")
		encoded = line[encStrIndex + len("encoded:  "):-2]
		encoded = encoded[1:-1]

		s = ""
		if "bigint" in line:
			s = bigint(encoded)
		elif "hex" in line:
			s = hexD(encoded)
		elif "rot13" in line:
			s = rot13(encoded)
		elif "utf-8" in line:
			s = utf8(encoded)
		elif "base64" in line:
			s = base64D(encoded)
		else:
			print("you messed up")
			print(line)

		r.sendline(outp(s))
	if "flag" in line:
		print("I GOT THE FLAG!!")
		print(line)
		break