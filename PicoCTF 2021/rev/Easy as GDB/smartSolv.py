#!/bin/python3
from pwn import *
context.log_level = 'error'

p = process('gdb')
p.recvuntil(b'gef')
p.sendline(b'set disable-randomization on')
p.recvuntil(b'gef')
p.sendline(b'file ./brute')
p.recvuntil(b'gef')
p.sendline(b'start')
p.recvuntil(b'gef')
p.sendline(b'b *0x565559a7')
p.recvuntil(b'gef')
flag = b'picoCTF{'
while b"}" not in flag:
	for c in range(33,127):
		p.sendline(b'run')
		p.recvuntil(b'program')
		print(flag + chr(c).encode())
		p.sendline(flag + chr(c).encode())
		p.recvuntil('Legend')
		p.recvuntil(b'gef')
		# p.recv()
		p.sendline(b'x/x $ebp-0x14')
		p.recvuntil(b'0xffff')
		ln = p.recv()
		# print(ln)
		# print("*"*40)
		# print(p.recvline())
		count = int(ln.split(b'\t')[1].split(b'\n')[0], 16)
		if(count > len(flag)):
			flag += chr(c).encode()
			print(flag)
			break
