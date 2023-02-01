#!/bin/python3
from pwn import *


print("CTRL+C when the script stops outputting things to get the flag")
r = remote('ctf.hackucf.org', 10102)
r.recvuntil('seconds!')
vals = []
while(True):
	try:
		n = str(r.recvuntil('Repeat: '))
		print(n)
		if "Value" not in n:
			print("a")
			r.sendline(vals[0]+"\n")
			r.interactive()
		x = n.split(' ') # split on space
		num = x[1].split("\\")[0] # get number
		vals.append(num)
		r.sendline(num+"\n")
	except:
		print("B")
		r.sendline(vals[0]+"\n")
		r.interactive()
