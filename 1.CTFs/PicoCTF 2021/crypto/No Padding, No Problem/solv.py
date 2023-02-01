#!/bin/python3

from pwn import *
from random import randint
from Crypto.Util.number import *

r = remote('mercury.picoctf.net', 30048)

r.recvuntil('n: ')
n = int(r.recvuntil('\n').rstrip())

r.recvuntil('e: ')
e = int(r.recvuntil('\n').rstrip())

r.recvuntil('text: ')
c = int(r.recvuntil('\n').rstrip())

def serverDecrypt(s):
	r.sendline(str(s))
	r.recvuntil('go: ')
	o = r.recvuntil('\n').rstrip()

	return int(o)


randomValue = randint(1,100) # just to show you can pick anything

knownValue = pow(randomValue,e,n)

# unpadded RSA is [homomorphic](https://en.wikipedia.org/wiki/Homomorphic_encryption), which means:
# encrypted(m1) * encrypted(m2) = encrypted(m1 * m2) = ((m1**e) * (m2**e)) mod n = (m1 * m2)**e mod n

myMessage = c * knownValue
SERVER_DECRYPTED_myMessage = serverDecrypt(myMessage)


# Because unpadded RSA is homomorphic, we can get the individual message:
individualDecryptedMessage = SERVER_DECRYPTED_myMessage // randomValue

flag = long_to_bytes(individualDecryptedMessage)

print(flag.decode('UTF-8'))