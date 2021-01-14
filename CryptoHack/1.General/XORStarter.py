#!/bin/python3

o = "label"

s = ""

for i in o:
	s += chr(ord(i)^13)

print("crypto{"+s+"}")


