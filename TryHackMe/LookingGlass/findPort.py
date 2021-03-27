#!/bin/python3
import os


ip = '10.10.156.153'

lo = 9000

hi = 14000

s = ""

while hi - lo > 1 :
	mid =  (hi + lo)//2
	print(f'Trying port {mid}')
	s = os.popen(f'ssh {ip} -p {mid} -oStrictHostKeyChecking=no $h uptime').read().rstrip()
	if s == "Lower":
		lo = mid
	elif s == "Higher":
		hi = mid
	else:
		print(s)
		print(f"Found the port!!! {mid}")
		break
