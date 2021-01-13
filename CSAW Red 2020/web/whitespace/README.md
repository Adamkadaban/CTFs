# whitespace (200pt)

> I think I handled the authentication correctly here... (this challenge resets its database every 60 seconds)
[http://web.red.csaw.io:5002](http://web.red.csaw.io:5002/)

The name of the challenge gives it away. If you search up “whitespace login vulnerability” on google, this CVE comes up: [https://nvd.nist.gov/vuln/detail/CVE-2020-7245](https://nvd.nist.gov/vuln/detail/CVE-2020-7245)

1. If we look at the source code, we find that when we register, our session username is set to whatever username we typed:

    ![whitespace%20(200pt)%209bc5cb994d874ce5a54f2aeeee529bc4/Untitled_1.png](whitespace%20(200pt)%209bc5cb994d874ce5a54f2aeeee529bc4/Untitled_1.png)

2. However, when we login, our session username is the **stripped** version of our username:

    ![whitespace%20(200pt)%209bc5cb994d874ce5a54f2aeeee529bc4/Untitled_2.png](whitespace%20(200pt)%209bc5cb994d874ce5a54f2aeeee529bc4/Untitled_2.png)

    - **.strip()** basically removes all the spaces in the end and beginning of a string. For example:

        ![whitespace%20(200pt)%209bc5cb994d874ce5a54f2aeeee529bc4/Untitled_3.png](whitespace%20(200pt)%209bc5cb994d874ce5a54f2aeeee529bc4/Untitled_3.png)

3. Now we can register the account " admin" with password “max” so when its stripped, we will be “admin” account in the website:

    ![whitespace%20(200pt)%209bc5cb994d874ce5a54f2aeeee529bc4/Untitled_4.png](whitespace%20(200pt)%209bc5cb994d874ce5a54f2aeeee529bc4/Untitled_4.png)

    - **MAKE SURE IT SAYS WELCOME WHEN YOU REGISTER**
4. Now if we open a Google Chrome tab in our own Windows host (not Kali) and go into the website and quickly sign in with our credentials as before, we will get the flag:
5. The flag is flag{gotta_make_sure_you_handle_the_whitespace!}

- Unfortunately, which challenges like this where a lot of people are modifying the server at the same time, it can be difficult to get the login on the first try.
- Let's write a python scrip to do it for us:

    ```python
    #!/bin/env python2
    import requests

    s = requests.Session()

    data = {"username": "admin ", "password": "AAAA"}

    payload = {"username": "admin ", "password": "AAAA"}

    r = s.post("http://web.red.csaw.io:5002/register", data=data)

    r1 = s.post("http://web.red.csaw.io:5002/login", data=payload)

    q1 = s.get("http://web.red.csaw.io:5002/")

    print(q1.text)
    ```