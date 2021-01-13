# Traefik (250pt)

> hint: Try to learn how traefik routes requests. Reddit is NOT a part of the challenge. Do not attack reddit.
[http://web.red.csaw.io:5006](http://web.red.csaw.io:5006/)

# Burp Suite

1. Lets learn about Traefik and how it works:

    ![Traefik%20(250pt)%20a77bcf0db2e54cae87eeafb5c7bc58f1/Untitled_1.png](Traefik%20(250pt)%20a77bcf0db2e54cae87eeafb5c7bc58f1/Untitled_1.png)

    - So based on certain rules, we get a certain service.
2. Let’s check the docker-compose.yml file and see if we find something that could help us out:

    ![Traefik%20(250pt)%20a77bcf0db2e54cae87eeafb5c7bc58f1/Untitled_2.png](Traefik%20(250pt)%20a77bcf0db2e54cae87eeafb5c7bc58f1/Untitled_2.png)

3. We find out this section about our flag. If we look at labels, it seems that the entry point is through http, so we must use http to connect to it. And the rule is that the **Host** = flag
4. Set up Burp Suite. Make sure you allow the Intercept to intercept Server Responses. Then head into [http://web.red.csaw.io:5006/](http://web.red.csaw.io:5006/) and intercept the request:

    ![Traefik%20(250pt)%20a77bcf0db2e54cae87eeafb5c7bc58f1/Untitled_3.png](Traefik%20(250pt)%20a77bcf0db2e54cae87eeafb5c7bc58f1/Untitled_3.png)

5. Let’s change the **Host** to “flag” just like in the docker-compose.yml file and see what happens:

    ![Traefik%20(250pt)%20a77bcf0db2e54cae87eeafb5c7bc58f1/Untitled_4.png](Traefik%20(250pt)%20a77bcf0db2e54cae87eeafb5c7bc58f1/Untitled_4.png)

6. After we send the request, we get this:

    ![Traefik%20(250pt)%20a77bcf0db2e54cae87eeafb5c7bc58f1/Untitled_5.png](Traefik%20(250pt)%20a77bcf0db2e54cae87eeafb5c7bc58f1/Untitled_5.png)

7. The flag is flag{81rD5_@RnT_r3@1!!!!!}

# Curl

1. Looking at the yaml file, we can see a container named "flag"
2. Let's use curl to get it

    ```bash
    curl -H Host:flag http://web.red.csaw.io:5006/
    ```

3. The flag is flag{81rD5_@RnT_r3@1!!!!!}