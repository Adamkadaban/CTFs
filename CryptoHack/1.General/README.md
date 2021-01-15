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

# XOR

## XOR Starter
* The XOR operator is universally known as `^`
* We can write some code to xor each letter
```
#!/bin/python3

o = "label"

s = ""

for i in o:
        s += chr(ord(i)^13)

print("crypto{"+s+"}")

```
* The flag is `crypto{aloha}`

### XOR Properties
* **Important Properties:**
```
Commutative: A ⊕ B = B ⊕ A
Associative: A ⊕ (B ⊕ C) = (A ⊕ B) ⊕ C
Identity: A ⊕ 0 = A
Self-Inverse: A ⊕ A = 0
```

* XOR is associative, which is very important for this problem
* We can use what they give us to solve that by converting the hex into integers and turning the integer into bytes to get the string



```python3
#!/bin/python3

import binascii
from pwn import xor
from Crypto.Util import number as n

'''
KEY1 = a6c8b6733c9b22de7bc0253266a3867df55acde8635e19c73313
KEY2 ^ KEY1 = 37dcb292030faa90d07eec17e3b1c6d8daf94c35d4c9191a5e1e
KEY2 ^ KEY3 = c1545756687e7573db23aa1c3452a098b71a7fbf0fddddde5fc1
FLAG ^ KEY1 ^ KEY3 ^ KEY2 = 04ee9855208a2cd59091d04767ae47963170d1660df7f56f5faf
'''
key1 = int("a6c8b6733c9b22de7bc0253266a3867df55acde8635e19c73313",16)

key2_key1 = int("37dcb292030faa90d07eec17e3b1c6d8daf94c35d4c9191a5e1e",16)

key2_key3 = int("c1545756687e7573db23aa1c3452a098b71a7fbf0fddddde5fc1",16)

flag_key1_key3_key2 = int("04ee9855208a2cd59091d04767ae47963170d1660df7f56f5faf",16)

flagLong = flag_key1_key3_key2 ^ key1 ^ key2_key3

flag = n.long_to_bytes(flagLong)

print(flag.decode('UTF-8'))
```
* The flag is `crypto{x0r_i5_ass0c1at1v3}`

## Favorite Byte

* We just have to loop through all the possible bytes and decode the hex with that

```python3
from Crypto.Util.number import *

n = long_to_bytes(0x73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d)

for k in range(2**8):
	tmp = ''
	for i in n:
		tmp += chr(i ^ k)
	if 'crypto{' in tmp:
		print(tmp)

```
* The flag is `crypto{0x10_15_my_f4v0ur173_by7e}`

## You either know, XOR you don't
* Here, we just have to use the fact that we already know the first few letters of the flag to figure out what the key used to encrypt was
	* Then, we can use that key to get the original string

```python3
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


```
* The flag is `crypto{1f_y0u_Kn0w_En0uGH_y0u_Kn0w_1t_4ll}`


## Lemur XOR
* Here, we just have to XOR each of the pixels in both the images
* [This](https://www.diffchecker.com/image-diff/) website works decently well for that

* Here's the code to do it that uses python's image manipulation library:

```python3
#!/bin/python3

from PIL import Image

lemur = Image.open("lemur.png")
flag = Image.open("flag.png")

lemurPixels = lemur.load()
flagPixels = flag.load()

XORdImage = Image.new(mode = "RGB", size = lemur.size)

for i in range(lemur.size[0]):
	for j in range(lemur.size[1]):
		l = lemurPixels[i,j]
		f = flagPixels[i,j]

		r = l[0] ^ f[0]
		g = l[1] ^ f[1]
		b = l[2] ^ f[2]

		XORdImage.putpixel((i,j), (r,g,b))

XORdImage.save("XORdImage.png")
```
* Looking at the image, the flag is `crypto{X0Rly_n0t!}`

# Mathematics

## Greatest Common Divisor
* The Euclidean algorithm is a very fast way of getting the greatest common divisor of 2 numbers
	* It can be implemented very easily with a short recursive function:

```python3
def gcd(a,b):
	if b==0:
		return a
	return gcd(b, a%b)

print(gcd(66528, 52920))
```
* The flag is `1512`

## Extended GCD
* Extended GCD can be implemented in a very similar way as above

```python3
def egcd(a,b):
	if a==0:
		return (b,0,1)
	g,y,x = egcd(b%1,1)
	return (g, x - (b//a) * y, y)

egcd(26513,32321)
```
* The flag is crypto{10245,-8404)

## Modular Arithmetic 1
* This can be tested very simply
* `11 ≡ a mod 6` translates to `11 % 6 = a`
* `8146798528947 ≡ b mod 17` translates to `8146798528947 % 17 = b`

```python3
a = 11 % 6

b = 8146798528947 % 17

print(max(a,b))
```
* The flag is `4`

## Modular Arithmetic 2
* Fermat's little theorem states that given a prime number p, `p | a^p -a`

* This is typically represented as `a^p ≡ a (mod p)` or `a**p % p = a%p`
* A variation of that is that `a^(p-1) ≡ 1 (mod p), given gcd(a,p)=1`
* We can use this for the problem:
```
3^17 % 17 must be 3
7^16 % 17 must be 1

Following,
273246787654^65536 % 65537 must be 1

```
* The flag is `1`

## Modular Inverting

