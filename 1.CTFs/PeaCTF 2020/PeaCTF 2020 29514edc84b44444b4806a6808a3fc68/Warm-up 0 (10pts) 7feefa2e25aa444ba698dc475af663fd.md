# Warm-up 0 (10pts)

> These are a series of introductory problems on basic Linux skills.
Log into the ssh service with username peactf and password peactf2020. What's on the server?

1. Log in with the ip and port they give:

    ```bash
    ssh peactf@45.32.128.108 -p 28083
    # then type in the password (peactf2020)
    ```

2. We see a directory... lets cd into it

    ![Warm-up%200%20(10pts)%207feefa2e25aa444ba698dc475af663fd/Untitled.png](Warm-up%200%20(10pts)%207feefa2e25aa444ba698dc475af663fd/Untitled.png)

3. There's too many directories to even hope to look through
    - All of them have even more subdirectories

        ![Warm-up%200%20(10pts)%207feefa2e25aa444ba698dc475af663fd/Untitled%201.png](Warm-up%200%20(10pts)%207feefa2e25aa444ba698dc475af663fd/Untitled%201.png)

4. Let's recursively look through the folders and cat out any files

    ```bash
    ls -LR | cat | grep peaCTF
    ```

5. The flag is peaCTF{67f7b551-159b-49ef-b39e-6ddc2031bb1c}