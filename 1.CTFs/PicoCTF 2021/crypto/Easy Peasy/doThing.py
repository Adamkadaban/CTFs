#!/bin/python3
from pwn import *

encryptedFlag = "5b 1e 56 4b 6e 41 5c 0e 39 4e 04 01 38 4b 08 55 3a 4e 5c 59 7b 6d 4a 5c 5a 68 4d 50 01 3d 6e 4b".split()

context.log_level = 'error'




for c in range(ord('!'), ord('~')+2):
	r = remote('mercury.picoctf.net', 20266)
	
	found = "".join([":","(","x","3","V","'","x","R","X","\x7f","X","y","\\","/","T","-","x","-","x","!","x","o","x","\x7f","x","y","X","[","f"])
	print(found)
	r.recvuntil("encrypt?")
	r.sendline(found)

	r.recvuntil("encrypt?")
	r.sendline(chr(c))
	r.recvuntil('go!\n')
	got = r.recvuntil('\n').rstrip()
	print(chr(c), str(got))
	r.close()


