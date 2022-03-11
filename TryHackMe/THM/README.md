### IP
`10.10.203.227`

# Recon

### nmap
`nmap 10.10.203.227 -sC -sV -oN init.nmap`
```
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-22 02:22 EST
Nmap scan report for 10.10.203.227
Host is up (0.099s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 79:5f:11:6a:85:c2:08:24:30:6c:d4:88:74:1b:79:4d (RSA)
|   256 af:7e:3f:7e:b4:86:58:83:f1:f6:a2:54:a6:9b:ba:ad (ECDSA)
|_  256 26:25:b0:7b:dc:3f:b2:94:37:12:5d:cd:06:98:c7:9f (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works! If you see this add 'te...
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```
* The http site is just the apache2 default page
	* It indicates that the os is ubuntu
	* The source also shows the following text:
```
<title>Apache2 Ubuntu Default Page: It works! If you see this add 'team.thm' to your hosts!</title>

```
* Thus, add the line `10.10.203.227	team.thm` to `/etc/hosts`

### gobuster
`gobuster dir -u http://team.thm/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`
```

```

# Exploitation
* 