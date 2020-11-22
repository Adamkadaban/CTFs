### IP
`10.10.10.152`

# Recon

### nmap
`nmap -sC -sV Netmon.nmap`
```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-22 02:53 EST
Nmap scan report for 10.10.10.152
Host is up (0.049s latency).
Not shown: 995 closed ports
PORT    STATE SERVICE      VERSION
21/tcp  open  ftp          Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 02-02-19  11:18PM                 1024 .rnd
| 02-25-19  09:15PM       <DIR>          inetpub
| 07-16-16  08:18AM       <DIR>          PerfLogs
| 02-25-19  09:56PM       <DIR>          Program Files
| 02-02-19  11:28PM       <DIR>          Program Files (x86)
| 02-03-19  07:08AM       <DIR>          Users
|_02-25-19  10:49PM       <DIR>          Windows
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp  open  http         Indy httpd 18.1.37.13946 (Paessler PRTG bandwidth monitor)
|_http-server-header: PRTG/18.1.37.13946
| http-title: Welcome | PRTG Network Monitor (NETMON)
|_Requested resource was /index.htm
|_http-trane-info: Problem with XML parsing of /evox/about
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 3m26s, deviation: 0s, median: 3m25s
|_smb-os-discovery: ERROR: Script execution failed (use -d to debug)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-11-22T07:57:26
|_  start_date: 2020-11-22T07:55:18

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.26 seconds

```
* Looks like nmap found an ftp server and automatically showed us the directories
* We also have a web server running Indy httpd
* We also have smb running

# Exploitation

### ftp
* This one was super easy. 
* We can log in to the server with `ftp 10.10.10.152`. 
	We can log in anonymously with the `anonymous` username and no password
* Once we cd to `/Users/Public`
* Now, we can download the file with `get user.txt`. 
* After that, we can just cat it on our own machine to get the user flag: `dd58ce67b49e15105e88096c8d9255a5`

### PRTG
* I did some digging and found [this](https://www.reddit.com/r/sysadmin/comments/835dai/prtg_exposes_domain_accounts_and_passwords_in/) reddit post, which explains that old version of PRTG store credentials in plaintext at `C:\ProgramData\Paessler\PRTG Network Monitor\PRTG Configuration.old.bak`

	* Downloading that file on the ftp server and runnning get on it will give us a file, which when examined a bit gives us this: 
```xml
   </dbcredentials>
            <dbpassword>
	      <!-- User: prtgadmin -->
	      PrTg@dmin2018
            </dbpassword>
            <dbtimeout>
```
* Username: `prtgadmin`
* Password: `PrTg@dmin2018`

* Unfortunately, this password didn't work so I tried out a couple other years for the password
* `PrTg@dmin2019` worked
	* Strangely it didn't work for me at first and I was getting really frustrated, but when I came back the next day (and I assume the machine was reset), it worked. So maybe reset the machine if you run into the same issue

* Now we can log in!
