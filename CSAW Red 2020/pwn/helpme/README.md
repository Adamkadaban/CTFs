# helpme (50pt)

> A young'un like you must be a tech whiz. Can you show me how to use this here computer? (This is a 64 bit program)
nc [pwn.red.csaw.io](http://pwn.red.csaw.io/) 5002

[This is a very helpful video. This challenge wouldn’t have been possible without it.](https://www.youtube.com/watch?v=yH8kzOkA_vw&ab_channel=JohnHammond)

1. Let’s run **helpme** and see what it does:

    ![helpme%20(50pt)%2043499b6a52c944a694574dc84eb178aa/Untitled_1.png](helpme%20(50pt)%2043499b6a52c944a694574dc84eb178aa/Untitled_1.png)

2. Let’s check it out in Ghidra and see what we can find. Oh look, there’s some type of function that calls /bin/sh. Maybe we can overflow the **return instruction pointer (RIP)** to call that?

    ![helpme%20(50pt)%2043499b6a52c944a694574dc84eb178aa/Untitled_2.png](helpme%20(50pt)%2043499b6a52c944a694574dc84eb178aa/Untitled_2.png)

3. If we look at the main function, we see that our input has a limited size of 32 bytes, so 32 characters:

    ![helpme%20(50pt)%2043499b6a52c944a694574dc84eb178aa/Untitled_3.png](helpme%20(50pt)%2043499b6a52c944a694574dc84eb178aa/Untitled_3.png)

4. Let’s try to overflow the RIP:

    ![helpme%20(50pt)%2043499b6a52c944a694574dc84eb178aa/Untitled_4.png](helpme%20(50pt)%2043499b6a52c944a694574dc84eb178aa/Untitled_4.png)

5. If we send 8 bytes above our limit, we see that there is no response “Hmm… Well that didn’t work”, but also no “Segmentation fault”. So we will go with 40 as our input right before we overwrite the **RIP**
6. Let’s look for the pointer address of the **binsh** function:

    ![helpme%20(50pt)%2043499b6a52c944a694574dc84eb178aa/Untitled_5.png](helpme%20(50pt)%2043499b6a52c944a694574dc84eb178aa/Untitled_5.png)

7. In little endian, that is ‘\x62\x11\x40\x00’
8. Let’s try to add that to our input and see what we get:

    ```bash
    (python -c "print('A'*40 + '\x62\x11\x40\x00' )"; cat) | nc pwn.red.csaw.io 5002
    ```

    ![helpme%20(50pt)%2043499b6a52c944a694574dc84eb178aa/Untitled_6.png](helpme%20(50pt)%2043499b6a52c944a694574dc84eb178aa/Untitled_6.png)

9. It looks like we create a shell, but it dies immediately. Let’s try to capture it with this **cat** trick:

    ![helpme%20(50pt)%2043499b6a52c944a694574dc84eb178aa/Untitled_7.png](helpme%20(50pt)%2043499b6a52c944a694574dc84eb178aa/Untitled_7.png)

10. It works! We get the shell, then we **cat flag.txt**, and we get the flag
11. Let’s do this on the server now:

    ![helpme%20(50pt)%2043499b6a52c944a694574dc84eb178aa/Untitled_8.png](helpme%20(50pt)%2043499b6a52c944a694574dc84eb178aa/Untitled_8.png)

12. The flag is flag{U_g07_5h311!_wh4t_A_h4xor!}