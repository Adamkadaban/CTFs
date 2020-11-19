### IP
`10.10.148.40`


# Enumeration
`nmap -sC -sV 10.10.148.40 -o LazyAdmin.nmap`
```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-14 02:57 EST
Nmap scan report for 10.10.148.40
Host is up (0.12s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 49:7c:f7:41:10:43:73:da:2c:e6:38:95:86:f8:e0:f0 (RSA)
|   256 2f:d7:c4:4c:e8:1b:5a:90:44:df:c0:63:8c:72:ae:55 (ECDSA)
|_  256 61:84:62:27:c6:c3:29:17:dd:27:45:9e:29:cb:90:5e (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.23 seconds
```
* Going to the website, it looks like the default apache page
	* Let's try to find out more about the site
### Gobuster
`gobuster dir -u http://10.10.148.40/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -o gobusterScan.txt`
```
/content (Status: 301)
/server-status (Status: 403)
```
* `/server-status` is a 403, so I'm not interested in that. `content` looks like a redirect though... should be interesting
* let's do a second one for good measure:
`gobuster dir -u http://10.10.148.40/ -w /usr/share/wordlists/dirb/common.txt -t 50 -o gobusterScan2.txt`
```
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.148.40/
[+] Threads:        50
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/11/14 03:45:44 Starting gobuster
===============================================================
/.htpasswd (Status: 403)
/.htaccess (Status: 403)
/content (Status: 301)
/.hta (Status: 403)
/index.html (Status: 200)
/server-status (Status: 403)
===============================================================
2020/11/14 03:45:59 Finished
===============================================================
```
* Nope. Just more 403s and stuff we've had before



* Okay... since `/content` is really the only useful directory here... let's run a scan on that

`gobuster dir -u http://10.10.148.40/ -w /usr/share/wordlists/dirb/common.txt -t 50 -o gobusterScan3.txt`
```
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.148.40/content/
[+] Threads:        50
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/11/14 03:58:00 Starting gobuster
===============================================================
/_themes (Status: 301)
/.htpasswd (Status: 403)
/as (Status: 301)
/attachment (Status: 301)
/.hta (Status: 403)
/.htaccess (Status: 403)
/images (Status: 301)
/inc (Status: 301)
/index.php (Status: 200)
/js (Status: 301)
===============================================================
2020/11/14 03:58:15 Finished
===============================================================
```
* `/as` looks like a login page!
* `/js` and `/inc` also might have some interesting stuff
### Nikto
`nikto -host 10.10.148.40`

```
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.148.40
+ Target Hostname:    10.10.148.40
+ Target Port:        80
+ Start Time:         2020-11-14 03:02:55 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Server may leak inodes via ETags, header found with file /, inode: 2c39, size: 59878d86c765e, mtime: gzip
+ Allowed HTTP Methods: POST, OPTIONS, GET, HEAD 
+ OSVDB-3233: /icons/README: Apache default file found.
+ 7889 requests: 0 error(s) and 7 item(s) reported on remote host
+ End Time:           2020-11-14 03:27:19 (GMT-5) (1464 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```
* smh 25 minutes of nikto and nothing useful
