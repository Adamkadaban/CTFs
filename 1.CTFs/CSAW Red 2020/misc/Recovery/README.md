> Alice forgot her throwaway email address, but she has a packet capture of her traffic. Can you help her recover it? To get the flag, answer a question about this traffic on the server here: nc [web.red.csaw.io](http://web.red.csaw.io/) 5018

# Strings method

1. run strings on the file & grep the email

    ```bash
    strings recovery.data | grep mail.com
    ```

2. Look for the email with Alice's name

    ```bash
    strings recovery.data | grep mail.com | alice
    ```

    - The email is `alice_test@hotmail.com`
3. Type the email into the nc

    ```markdown
    echo alice_test@hotmail.com | nc web.red.csaw.io 5018
    ```

4. The flag is flag{W1r3sh4rk,TCPfl0w,gr3p,57r1n95--7h3y'r3_4ll_f0r3n51c5_700l5}
