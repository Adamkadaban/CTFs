# Day 1
* We can go onto the website and regsiter/login.
* Once we do that, viewing the cookies shows us a hexidecimal value named "auth"
* We can decode that with `echo <hex_string> | xxd -r -p`
* We want to log in to "santa", so let's switch our user for that with the following command:
* `echo <hex_string> | xxd -r -p | sed s/<your_username>/santa/g | xxd -p`
* Once we replace the value of the previous cookie with the new one in the "Applications->Cookies" section on chrome developer tools, we get authenticated as santa and can turn on all the controls
* The flag is `THM{MjY0Yzg5NTJmY2Q1NzM1NjBmZWFhYmQy}` 
