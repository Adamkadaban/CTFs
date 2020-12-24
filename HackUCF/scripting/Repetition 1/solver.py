from pwn import *

r = remote('ctf.hackucf.org', 10101)
r.recvuntil('seconds!')
while(True):
	try:
		n = str(r.recvuntil('Repeat: '))
		if "Value" not in n:
			r.interactive()
		x = n.split(' ') # split on space
		num = x[1].split("\\")[0] # get number
		r.sendline(num+"\n")
	except:
		r.interactive()
