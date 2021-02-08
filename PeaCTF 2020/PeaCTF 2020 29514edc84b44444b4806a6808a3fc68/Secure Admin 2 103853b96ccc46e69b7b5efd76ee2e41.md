# Secure Admin 2

> This admin panel is now secured and hardened.

1. Go to the website they give you
2. The SQL login is now "hardened", so we can assume they're filtering the input
3. Let's try something else
4. When we submit something to the login page, a request cookie called "_auth" is sent

    ![Secure%20Admin%202%20103853b96ccc46e69b7b5efd76ee2e41/Untitled.png](Secure%20Admin%202%20103853b96ccc46e69b7b5efd76ee2e41/Untitled.png)

    - Let's see what the value means
5. It looks like base64... lets try decoding it

    ![Secure%20Admin%202%20103853b96ccc46e69b7b5efd76ee2e41/Untitled%201.png](Secure%20Admin%202%20103853b96ccc46e69b7b5efd76ee2e41/Untitled%201.png)

6. Strangely, it still looks like base64. Let's try decoding that

    ![Secure%20Admin%202%20103853b96ccc46e69b7b5efd76ee2e41/Untitled%202.png](Secure%20Admin%202%20103853b96ccc46e69b7b5efd76ee2e41/Untitled%202.png)

    - Awesome.
7. Now lets enter in our own version of the auth value, but change it to true
    - double base64 encode "admin:true" to get WVdSdGFXNDZkSEoxWlE9PQ==
8. Let's open burpsuite and turn on the proxy.
    - turn intercept on
    - type in random credentials into the webpage

    ![Secure%20Admin%202%20103853b96ccc46e69b7b5efd76ee2e41/Untitled%203.png](Secure%20Admin%202%20103853b96ccc46e69b7b5efd76ee2e41/Untitled%203.png)

    - Let's change their auth value to our new one and click "forward"

    ![Secure%20Admin%202%20103853b96ccc46e69b7b5efd76ee2e41/Untitled%204.png](Secure%20Admin%202%20103853b96ccc46e69b7b5efd76ee2e41/Untitled%204.png)

9. The flag is peaCTF{101416d2-16cc-4915-a04d-78c087e3b083}