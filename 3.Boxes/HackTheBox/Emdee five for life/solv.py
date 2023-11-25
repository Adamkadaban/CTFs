#!/bin/python3

import requests
import re
import hashlib

url = 'http://142.93.32.153:32119/'

# send initial post requests a bunch of times to get captcha

r = requests.session()

t = r.get(url).text

s = t.split('h3')[1].split('>')[1].split('<')[0]

m = hashlib.md5(s.encode()).hexdigest()

data = {'hash':m}

t = r.post(url, data=data).text

print(t)
