### IP
`10.10.91.105`

# Recon
### nmap
`nmap -sC -sV 10.10.91.105 -oN init.nmap`
```
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-10 02:34 EDT
Nmap scan report for 10.10.91.105
Host is up (0.17s latency).
Not shown: 997 filtered ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
|   3072 de:5b:0e:b5:40:aa:43:4d:2a:83:31:14:20:77:9c:a1 (RSA)
|   256 f4:b5:a6:60:f4:d1:bf:e2:85:2e:2e:7e:5f:4c:ce:38 (ECDSA)
|_  256 29:e6:61:09:ed:8a:88:2b:55:74:f2:b7:33:ae:df:c8 (ED25519)
80/tcp open  http    Apache httpd 2.4.37 ((centos))
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.37 (centos)
|_http-title: Overpass Hosting
Service Info: OS: Unix

```

### gobuster
* We can look through the website for subdirectories with gobuster:
`gobuster dir -u http://10.10.91.105/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o root.dirs`
```
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.91.105/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/07/10 02:36:32 Starting gobuster in directory enumeration mode
===============================================================
/backups              (Status: 301) [Size: 236] [--> http://10.10.91.105/backups/]

```
* `/backups` has a `backup.zip` that we can download and unzip.
	* Once we do this, we get a PGP private key and an encrypted file
	* We can add the key to GPG with `gpg --import priv.key` and can decrypt the file with `gpg CustomerDetails.xlsx.gpg`

* Once we open the file with `libreoffice CustomerDetails.xlsx`, we get the following:
'''
| Customer Name   | Username       | Password          | Credit card number  | CVC |
|-----------------|----------------|-------------------|---------------------|-----|
| Par. A. Doxx    | paradox        | ShibesAreGreat123 | 4111 1111 4555 1142 | 432 |
| 0day Montgomery | 0day           | OllieIsTheBestDog | 5555 3412 4444 1115 | 642 |
| Muir Land       | muirlandoracle | A11D0gsAreAw3s0me | 5103 2219 1119 9245 | 737 |
'''
* In the main webpage, we can see that `paradox` and `muirlandoracle` are employees at the company, so we can try their passwords to ssh in

# Connecting
### ssh
* `ssh paradox@10.10.91.105`
