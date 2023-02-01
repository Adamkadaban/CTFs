### IP
`10.10.137.94`

# Enumeration


### nmap

`nmap -sC -sV 10.10.137.94 -oN init.nmap`
```
Nmap scan report for 10.10.137.94
Host is up (0.12s latency).
Not shown: 999 closed ports
PORT   STATE    SERVICE VERSION
80/tcp filtered http
```
Only port 80 is open.

I also ran a full port-scan here, but nothing else showed up. For a while, I was doing directory scanning and subdomain enumeration, which also didn't really find anything.

### Nikto

I typically never run Nikto, but my scanning wasn't showing anything, and neither were burp or my manual webpage exploration.

`nikto -h http://10.10.137.94`
```
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          10.10.114.122
+ Target Hostname:    10.10.114.122
+ Target Port:        80
+ Start Time:         2022-12-10 23:27:48 (GMT-5)
---------------------------------------------------------------------------
+ Server: No banner retrieved
+ Retrieved x-powered-by header: PHP/8.1.0-dev
+ The anti-clickjacking X-Frame-Options header is not present.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ OSVDB-44056: /sips/sipssys/users/a/admin/user: SIPS v0.2.2 allows user account info (including password) to be retrieved remotely.
+ OSVDB-27071: /phpimageview.php?pic=javascript:alert(8754): PHP Image View 1.0 is vulnerable to Cross Site Scripting (XSS).  http://www.cert.org/advisories/CA-2000-02.html.
+ OSVDB-3931: /myphpnuke/links.php?op=MostPopular&ratenum=[script]alert(document.cookie);[/script]&ratetype=percent: myphpnuke is vulnerable to Cross Site Scripting (XSS). http://www.cert.org/advisories/CA-2000-02.html.
+ /modules.php?op=modload&name=FAQ&file=index&myfaq=yes&id_cat=1&categories=%3Cimg%20src=javascript:alert(9456);%3E&parent_id=0: Post Nuke 0.7.2.3-Phoenix is vulnerable to Cross Site Scripting (XSS). http://www.cert.org/advisories/CA-2000-02.html.
+ /modules.php?letter=%22%3E%3Cimg%20src=javascript:alert(document.cookie);%3E&op=modload&name=Members_List&file=index: Post Nuke 0.7.2.3-Phoenix is vulnerable to Cross Site Scripting (XSS). http://www.cert.org/advisories/CA-2000-02.html.
+ OSVDB-4598: /members.asp?SF=%22;}alert(223344);function%20x(){v%20=%22: Web Wiz Forums ver. 7.01 and below is vulnerable to Cross Site Scripting (XSS). http://www.cert.org/advisories/CA-2000-02.html.
+ OSVDB-2946: /forum_members.asp?find=%22;}alert(9823);function%20x(){v%20=%22: Web Wiz Forums ver. 7.01 and below is vulnerable to Cross Site Scripting (XSS). http://www.cert.org/advisories/CA-2000-02.html.
+ OSVDB-3092: /demo/: This might be interesting...
+ OSVDB-18114: /reports/rwservlet?server=repserv+report=/tmp/hacker.rdf+destype=cache+desformat=PDF:  Oracle Reports rwservlet report Variable Arbitrary Report Executable Execution
+ 6544 items checked: 24 error(s) and 11 item(s) reported on remote host
+ End Time:           2022-12-10 23:56:23 (GMT-5) (1715 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

```

Here, we can see a header titled `X-Powered-By` with the contents `PHP/8.1.0-dev`

It looks like this version of PHP is vulnerable to Remote Code Execution through a backdoor.

I looked up an exploit with searchsploit and downloaded it with
	`searchsploit -m php/webapps/49933.py`

Running this exploit and entering the hostname gets us a reverse shell.

For some reason I couldn't change directories, so I used `ls /` to see that the `flag.txt` was in `/flag.txt`: `flag{4127d0530abf16d6d23973e3df8dbecb}`