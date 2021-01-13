# Encoding

## ASCII
* We just have to convert numbers to their ascii representations

```python3
nums = [99, 114, 121, 112, 116, 111, 123, 65, 83, 67, 73, 73, 95, 112, 114, 49, 110, 116, 52, 98, 108, 51, 125]
s = "".join([chr(i) for i in nums])
print(s)
```
* This gives us the flag: `crypto{ASCII_pr1nt4bl3}`

## Hex
* We can decode hex by typing the following in the terminal:
	* `echo "63727970746f7b596f755f77696c6c5f62655f776f726b696e675f776974685f6865785f737472696e67735f615f6c6f747d" | xxd -r -p`
	* This gives us the flag `crypto{You_will_be_working_with_hex_strings_a_lot}`

## Base64
* We can encode base64 by typing the following in the terminal:
	* `echo "72bca9b68fc16ac7beeb8f849dca1d8a783e8acf9679bf9269f7bf" | xxd -r -p | base64`
	* This gives us the flag `crypto/Base+64+Encoding+is+Web+Safe/`

## Bytes and Big Integers
* The following code will turn the integer into text:

```python3
from Crypto.Util import number # do `apt install python3-pycryptodome` if you haven't yet

in = 11515195063862318899931685488813747395775516287289682636499965282714637259206269

d = number.long_to_bytes(in)

print(d.decode('UTF-8'))
```

* This gives us the flag `crypto{3nc0d1n6_4ll_7h3_w4y_d0wn}`

## Encoding Challenge
* Running `nc socket.cryptohack.org 13377` connects us to a challenge that gives us a json object with something to decode
	* Solutions should be sent in the format `{"decoded": <answer>}`
* Doing it manually would take too long, so we can automate it:
```python3
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
```

* We then get the flag `crypto{3nc0d3_d3c0d3_3nc0d3}` (you may have to run it a few times for it to work)

