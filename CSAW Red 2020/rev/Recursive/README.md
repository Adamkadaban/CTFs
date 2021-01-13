# Recursive (150pt)

> Onions have layers. Recursions have layers.
nc [rev.red.csaw.io](http://rev.red.csaw.io/) 5000

# Brute Force

1. Let’s run **recursive:**

    ![Recursive%20(150pt)%20aff63dae22b04ae59b697cbd870c4f89/Untitled_1.png](Recursive%20(150pt)%20aff63dae22b04ae59b697cbd870c4f89/Untitled_1.png)

2. So we need to guess a number until we get it right. Now, I took the bruteforce approach. This can be done with a quick script to go through all answers, or an angr script.
    - Because the program asks for only numbers (and we assume it wants a number), we decide to only input those numbers.
3. We can write a **bash** script to bruteforce all the possible numbers and in the end find out the flag:

    ```
    #!/bin/bash
    #Make sure you have a flag.txt with a distinct phrase or letter so you can grep it after (Mine was "This is the flag{}!")

    #Loops from 1-99999, where num represents the value it is at the moment
    for num in `seq 1 99999`; do
    # It prints the value "num" into our text file, which holds all the outputs (the >> just means to add to the next line | > means to overwrite the whole file)
    echo $num >> results.txt
    # Prints the value of num and pipes it into the recursive function.
    # Then we remove any lines that have "Enter" or "not it" in them with grep -v.
    # In the end, if it's not the flag, it puts nothing into the results.txt, otherwise it puts the flag.
    echo $num | ./recursive | grep -v 'Enter\|not it'>> results.txt
    done

    # After the loop, we print the line number of the line that contains "flag" in it.
    # Then we subtract one from the line number to discover the secret number and we print it :)
    $line = grep -n flag results.txt
    echo $line-1
    ```

    - Just me mindful, this will take a few minutes to run.
4. We end up getting the value to be 11*2**7
    - Type this into the netcat:

    ```bash
    python -c 'print(11*2**7)' | nc rev.red.csaw.io 5000
    ```

5. The flag is flag{r3Curs1Ve_Rev3rSe}

# Reverse Engineering

1. Opening the binary in a decompiler, we can see the following code:

    ![Recursive%20(150pt)%20aff63dae22b04ae59b697cbd870c4f89/Untitled.png](Recursive%20(150pt)%20aff63dae22b04ae59b697cbd870c4f89/Untitled.png)

2. First, we see v10 being modified by f(). Let's check what that function does.

    ![Recursive%20(150pt)%20aff63dae22b04ae59b697cbd870c4f89/Untitled%201.png](Recursive%20(150pt)%20aff63dae22b04ae59b697cbd870c4f89/Untitled%201.png)

3. Here, we can tell that if a1 is not 0, we return that value
    - tbh, I'm too lazy to go through all of the recursive calls, but just make sure you realize ++*a2 modifies the variable outside of the function and that the function makes a bunch of recursive calls