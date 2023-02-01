#!/bin/python3
with open('enc') as fin:
	encoded = fin.read().rstrip()

def enc(flag):
	s = ""
	for i in range(0,len(flag),2):
		s += chr( (ord(flag[i]) << 8) + ord(flag[i + 1]) )
	return s


# print(encoded)


decoded = ""

for w in encoded:
	for i in range(33,127):
		for j in range(33,127):
			if (i << 8) + j == ord(w):
				decoded += chr(i) + chr(j)
print(decoded)