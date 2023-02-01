Note: I have placed by ctfchallenge cookie string in an environment variable called `ctfc`

# Enumeration

## gobuster dir

### root directory

`gobuster dir -u http://www.vulnlawyers.co.uk/ -w /usr/share/wordlists/ctf/content.txt -t 1 -c $ctfc --delay .1s`
```
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://www.vulnlawyers.co.uk/
[+] Method:                  GET
[+] Threads:                 1
[+] Delay:                   100ms
[+] Wordlist:                /usr/share/wordlists/ctf/content.txt
[+] Negative Status codes:   404
[+] Cookies:                 $ctfc
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2022/12/19 07:01:52 Starting gobuster in directory enumeration mode
===============================================================
/css                  (Status: 301) [Size: 178] [--> http://www.vulnlawyers.co.uk/css/]
/denied               (Status: 401) [Size: 1020]
/images               (Status: 301) [Size: 178] [--> http://www.vulnlawyers.co.uk/images/]
/js                   (Status: 301) [Size: 178] [--> http://www.vulnlawyers.co.uk/js/]
/login                (Status: 302) [Size: 1119] [--> /denied]
===============================================================
2022/12/19 07:23:52 Finished
===============================================================
```
`/login` redirects us to `/denied` because our IP is wrong

## subfinder
`subfinder -d vulnlawyers.co.uk`
```
[INF] Loading provider config from '/root/.config/subfinder/provider-config.yaml'
[INF] Enumerating subdomains for 'vulnlawyers.co.uk'
www.vulnlawyers.co.uk
data.vulnlawyers.co.uk
api.vulnlawyers.co.uk
vulnlawyers.co.uk
[INF] Found 4 subdomains for 'vulnlawyers.co.uk' in 13 seconds 907 milliseconds
```
`data.vulnbegin.co.uk` has a flag
`api.vulnbegin.co.uk` appears to show the same thing as the data subdomain
