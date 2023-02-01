#!/bin/python3
import os
x = os.popen('strings tay.jpg').read() # get strings output

b64 = x.split("\n")[-2] # last output of strings is a base64 encoded string

flag = os.popen(f'echo "{b64}" | base64 -d').read() # decode the string
print(flag)
