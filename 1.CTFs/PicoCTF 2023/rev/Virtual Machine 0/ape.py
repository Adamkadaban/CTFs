from Crypto.Util.number import *


input = 39722847074734820757600524178581224432297292490103995905682815333550839577



for div in range(1,40*65):
	for offset in range(-40*65,40*65):
		out = long_to_bytes((input // div) + offset)
		if b'ctf' in out:
			print(out)


