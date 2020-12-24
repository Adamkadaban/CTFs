from pwn import *

r = remote("ctf.hackucf.org", 10104)

r.recvuntil('return!')
while(True):
	try:
		l = r.recv().lstrip()
		print(l)
		if b"=" in l:
			eq = l[:-3]
			eq = eq.replace(b"/", b"//")
			print(eq, "=", int(eval(eq)))
			r.sendline(str(int(eval(eq))))
			r.sendline("\n")
	except:
		exit()
