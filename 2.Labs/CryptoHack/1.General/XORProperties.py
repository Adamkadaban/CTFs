#!/bin/python3

import binascii
from pwn import xor
from Crypto.Util import number as n

'''
KEY1 = a6c8b6733c9b22de7bc0253266a3867df55acde8635e19c73313
KEY2 ^ KEY1 = 37dcb292030faa90d07eec17e3b1c6d8daf94c35d4c9191a5e1e
KEY2 ^ KEY3 = c1545756687e7573db23aa1c3452a098b71a7fbf0fddddde5fc1
FLAG ^ KEY1 ^ KEY3 ^ KEY2 = 04ee9855208a2cd59091d04767ae47963170d1660df7f56f5faf
'''
key1 = int("a6c8b6733c9b22de7bc0253266a3867df55acde8635e19c73313",16)

key2_key1 = int("37dcb292030faa90d07eec17e3b1c6d8daf94c35d4c9191a5e1e",16)

key2_key3 = int("c1545756687e7573db23aa1c3452a098b71a7fbf0fddddde5fc1",16)

flag_key1_key3_key2 = int("04ee9855208a2cd59091d04767ae47963170d1660df7f56f5faf",16)

flagLong = flag_key1_key3_key2 ^ key1 ^ key2_key3

flag = n.long_to_bytes(flagLong)

print(flag.decode('UTF-8'))