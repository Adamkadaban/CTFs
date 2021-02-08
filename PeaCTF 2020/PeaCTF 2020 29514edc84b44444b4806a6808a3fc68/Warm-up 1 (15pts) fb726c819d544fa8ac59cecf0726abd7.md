# Warm-up 1 (15pts)

> Log into the ssh service with username peactf and password peactf2020.
Hmm... how to I search for a string recursively on Linux?

1. Log in with the ip and port they give:

    ```bash
    ssh peactf@45.32.128.108 -p 28083
    # then type in the password (peactf2020)
    ```

2. We see a directory... lets cd into it

    ![Warm-up%200%20(10pts)%207feefa2e25aa444ba698dc475af663fd/Untitled.png](Warm-up%200%20(10pts)%207feefa2e25aa444ba698dc475af663fd/Untitled.png)

3. There's too many directories to even hope to look through
    - All of them have even more subdirectories

        ![Warm-up%201%20(15pts)%20fb726c819d544fa8ac59cecf0726abd7/Untitled.png](Warm-up%201%20(15pts)%20fb726c819d544fa8ac59cecf0726abd7/Untitled.png)

4. Let's recursively look through the folders and cat out any files

    ```bash
    # ls -LR | cat | grep peaCTF
    # for some reason, the above command didn't work, so i used this:
    find  -exec cat {} \; | cat | grep pea
    ```

5. After some errors, the flag is highlighted

    ![Warm-up%201%20(15pts)%20fb726c819d544fa8ac59cecf0726abd7/Untitled%201.png](Warm-up%201%20(15pts)%20fb726c819d544fa8ac59cecf0726abd7/Untitled%201.png)

6. The flag is peaCTF{51e1de7c-6606-42c2-8621-96c62f56bd83}