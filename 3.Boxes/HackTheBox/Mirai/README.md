### IP
`10.10.10.48`
# Recon
### nmap
`nmap -sC -sV 10.10.10.48 -oN init.nmap`
```
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-27 21:38 EDT
Nmap scan report for 10.10.10.48
Host is up (0.050s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.7p1 Debian 5+deb8u3 (protocol 2.0)
| ssh-hostkey: 
|   1024 aa:ef:5c:e0:8e:86:97:82:47:ff:4a:e5:40:18:90:c5 (DSA)
|   2048 e8:c1:9d:c5:43:ab:fe:61:23:3b:d7:e4:af:9b:74:18 (RSA)
|   256 b6:a0:78:38:d0:c8:10:94:8b:44:b2:ea:a0:17:42:2b (ECDSA)
|_  256 4d:68:40:f7:20:c4:e5:52:80:7a:44:38:b8:a2:a7:52 (ED25519)
53/tcp open  domain  dnsmasq 2.76
| dns-nsid: 
|_  bind.version: dnsmasq-2.76
80/tcp open  http    lighttpd 1.4.35
|_http-server-header: lighttpd/1.4.35
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.04 seconds

```
* I wasn't able to access port 80, so I did a more comprehensive scan:
`nmap -sC -sV 10.10.10.48 --min-rate 10000 -p-`
```
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-27 21:41 EDT
Warning: 10.10.10.48 giving up on port because retransmission cap hit (10).
Verbosity Increased to 1.
Completed Service scan at 21:41, 11.17s elapsed (6 services on 1 host)
NSE: Script scanning 10.10.10.48.
Initiating NSE at 21:41
Completed NSE at 21:42, 8.20s elapsed
Initiating NSE at 21:42
Completed NSE at 21:42, 0.22s elapsed
Initiating NSE at 21:42
Completed NSE at 21:42, 0.00s elapsed
Nmap scan report for 10.10.10.48
Host is up (0.052s latency).
Not shown: 63659 closed ports, 1870 filtered ports
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 6.7p1 Debian 5+deb8u3 (protocol 2.0)
| ssh-hostkey: 
|   1024 aa:ef:5c:e0:8e:86:97:82:47:ff:4a:e5:40:18:90:c5 (DSA)
|   2048 e8:c1:9d:c5:43:ab:fe:61:23:3b:d7:e4:af:9b:74:18 (RSA)
|   256 b6:a0:78:38:d0:c8:10:94:8b:44:b2:ea:a0:17:42:2b (ECDSA)
|_  256 4d:68:40:f7:20:c4:e5:52:80:7a:44:38:b8:a2:a7:52 (ED25519)
53/tcp    open  domain  dnsmasq 2.76
| dns-nsid: 
|_  bind.version: dnsmasq-2.76
80/tcp    open  http    lighttpd 1.4.35
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
|_http-server-header: lighttpd/1.4.35
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
1657/tcp  open  upnp    Platinum UPnP 1.0.5.13 (UPnP/1.0 DLNADOC/1.50)
32400/tcp open  http    Plex Media Server httpd
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Server returned status 401 but no WWW-Authenticate header.
|_http-cors: HEAD GET POST PUT DELETE OPTIONS
|_http-favicon: Plex
|_http-title: Unauthorized
32469/tcp open  upnp    Platinum UPnP 1.0.5.13 (UPnP/1.0 DLNADOC/1.50)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
Initiating NSE at 21:42
Completed NSE at 21:42, 0.00s elapsed
Initiating NSE at 21:42
Completed NSE at 21:42, 0.00s elapsed
Initiating NSE at 21:42
Completed NSE at 21:42, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 44.06 seconds
           Raw packets sent: 233946 (10.294MB) | Rcvd: 63990 (2.560MB)

```
* Port `32400` gives a website
	* I looking at some vulnerabilities here, but nothing popped up.
		* Instead, lets look back at port 80

### gobuster
* Since there is nothing initially for port 80, lets scan to see if anything else is there
`gobuster dir -u http://10.10.10.48/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`
```
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.48/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/03/27 22:25:43 Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 301) [Size: 0] [--> http://10.10.10.48/admin/]
/versions             (Status: 200) [Size: 13]                               
                                                                             
===============================================================
2021/03/27 22:45:00 Finished
===============================================================

```
* We can see an `/admin` page, which takes us to a pi.hole login

# SSH
* Based on the pi.hole, we can guess that the device running on ssh is a raspberry pi
	* Using default credentials of `pi:raspberry` works
	* We can log in with `ssh pi@10.10.10.48`

* `cat /home/pi/Desktop/user.txt` gives us the user flag: `ff837707441b257a20e32199d7c8838d`

# Privesc
* `sudo -l` shows us that we can run all commands as root.
	* `sudo su` gives us root

# Forensics
* Trying to `cat /root/root.txt` doesn't give us the root flag, but rather the following:
```
I lost my original root.txt! I think I may have a backup on my USB stick...
``` 
* We can look for the usb stick by just typing `mount`, which gives the following output:
```bash
sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)
proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)
tmpfs on /run type tmpfs (rw,nosuid,relatime,size=102396k,mode=755)
/dev/sda1 on /lib/live/mount/persistence/sda1 type iso9660 (ro,noatime)
/dev/loop0 on /lib/live/mount/rootfs/filesystem.squashfs type squashfs (ro,noatime)
tmpfs on /lib/live/mount/overlay type tmpfs (rw,relatime)
/dev/sda2 on /lib/live/mount/persistence/sda2 type ext4 (rw,noatime,data=ordered)
aufs on / type aufs (rw,noatime,si=a467153b,noxino)
devtmpfs on /dev type devtmpfs (rw,nosuid,size=10240k,nr_inodes=58955,mode=755)
securityfs on /sys/kernel/security type securityfs (rw,nosuid,nodev,noexec,relatime)
tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)
devpts on /dev/pts type devpts (rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000)
tmpfs on /run/lock type tmpfs (rw,nosuid,nodev,noexec,relatime,size=5120k)
tmpfs on /sys/fs/cgroup type tmpfs (ro,nosuid,nodev,noexec,mode=755)
cgroup on /sys/fs/cgroup/systemd type cgroup (rw,nosuid,nodev,noexec,relatime,xattr,release_agent=/lib/systemd/systemd-cgroups-agent,name=systemd)
pstore on /sys/fs/pstore type pstore (rw,nosuid,nodev,noexec,relatime)
cgroup on /sys/fs/cgroup/cpuset type cgroup (rw,nosuid,nodev,noexec,relatime,cpuset)
cgroup on /sys/fs/cgroup/cpu,cpuacct type cgroup (rw,nosuid,nodev,noexec,relatime,cpu,cpuacct)
cgroup on /sys/fs/cgroup/devices type cgroup (rw,nosuid,nodev,noexec,relatime,devices)
cgroup on /sys/fs/cgroup/freezer type cgroup (rw,nosuid,nodev,noexec,relatime,freezer)
cgroup on /sys/fs/cgroup/net_cls,net_prio type cgroup (rw,nosuid,nodev,noexec,relatime,net_cls,net_prio)
cgroup on /sys/fs/cgroup/blkio type cgroup (rw,nosuid,nodev,noexec,relatime,blkio)
cgroup on /sys/fs/cgroup/perf_event type cgroup (rw,nosuid,nodev,noexec,relatime,perf_event)
systemd-1 on /proc/sys/fs/binfmt_misc type autofs (rw,relatime,fd=22,pgrp=1,timeout=300,minproto=5,maxproto=5,direct)
debugfs on /sys/kernel/debug type debugfs (rw,relatime)
mqueue on /dev/mqueue type mqueue (rw,relatime)
hugetlbfs on /dev/hugepages type hugetlbfs (rw,relatime)
tmpfs on /tmp type tmpfs (rw,nosuid,nodev,relatime)
/dev/sdb on /media/usbstick type ext4 (ro,nosuid,nodev,noexec,relatime,data=ordered)
tmpfs on /run/user/999 type tmpfs (rw,nosuid,nodev,relatime,size=51200k,mode=700,uid=999,gid=997)
tmpfs on /run/user/1000 type tmpfs (rw,nosuid,nodev,relatime,size=51200k,mode=700,uid=1000,gid=1000)
```
* We can see a `/dev/sdb` mounted on `/media/usbstick`

* Here, there is a file called `damnit.txt` with the following text: 
```
Do you know if there is any way to get them back?

-James
```
* To do the forensics locally, we can first turn the device into an image with `dd if=/dev/sdb/ -of=/dev/usb.image`
	* We can then download this with `python3 -m http.server 8080` remotely and `wget http://10.10.10.48:8080/usb.image` locally

* first tried to cat out the device with `strings usb.image | egrep [a-f0-9]{32}`
* This gives us the strings on the block device, which gives us the root flag: `3d3e483143ff12ec505d026fa13e020b`


