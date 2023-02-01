#!/bin/python3
import base64

unbase = base64.b64decode('CVtQFwJcAFRFHAlUVRUdXQUHERgMVlMVSgoPUhUdDg4DRRpfAEw=')

knownString = b"flag{"
pwdLength = 5

pwd = bytes(unbase[i] ^ knownString[i] for i in range(pwdLength))


flag = bytes(unbase[i] ^ pwd[i%pwdLength] for i in range(len(unbase)))



print(f'password is {pwd.decode("utf-8")}')
print(flag.decode('utf-8'))
