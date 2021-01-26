#!/bin/python3

import os, re, string


lower = string.ascii_lowercase
upper = string.ascii_uppercase

shift = 23 # duh bc he was stabbed 23 times

x = os.popen('strings img1.jpg').read().split('\n') # get strings output

ogFlag = x[-2] # get original flag

ogFlag = ogFlag[ogFlag.index("{")+1:-1] # string "flag{" part

# print(ogFlag)

newFlag = ""

for i in ogFlag:
	if i in lower:
		newFlag += lower[(lower.index(i) + 26) % shift]
	elif i in upper:
		newFlag += upper[(upper.index(i) + 26) % shift]
	else:
		newFlag += i

print(f'shadowCTF{{{newFlag}}}')
