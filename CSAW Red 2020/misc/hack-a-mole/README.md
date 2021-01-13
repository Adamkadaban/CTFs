# hack-a-mole (250pt)

> Welcome to Hack-a-Mole, the hacker version of Whack-a-Mole! Beat all the levels to claim your flag. nc [web.red.csaw.io](http://web.red.csaw.io/) 5016

1. Lets take a look at the challenge:
    - When we connect to the server, it looks like a whack a mole game (makes sense)

        ![hack-a-mole%20(250pt)%208d902fed191c41fd9226378d386d19ed/Untitled.png](hack-a-mole%20(250pt)%208d902fed191c41fd9226378d386d19ed/Untitled.png)

    - However, the grid gets larger as you progress

        ![hack-a-mole%20(250pt)%208d902fed191c41fd9226378d386d19ed/Untitled%201.png](hack-a-mole%20(250pt)%208d902fed191c41fd9226378d386d19ed/Untitled%201.png)

    - The time you get to input also gets shorter
    - There are also some distractors.... all things to keep in mind

        ![hack-a-mole%20(250pt)%208d902fed191c41fd9226378d386d19ed/Untitled%202.png](hack-a-mole%20(250pt)%208d902fed191c41fd9226378d386d19ed/Untitled%202.png)

2. This is just a coding challenge. Input the correct row and column quickly enough to get the points
3. Use pwn.remote() to get inputs and send outputs

    ```python
    '''
    hackamole.py
    '''
    from pwn import *
    import re

    p = remote('web.red.csaw.io', 5016)
    p.recvline()
    box_width = 17
    box_height = 8
    divider_chars = ['0', '|', "*", ' ', 'O', '-', '.', '+', "@", "#", '[', ']']
    nope = ['']
    hard_part = False
    right_in_a_row = 0
    flag_inc = False
    while True:
        content = p.recvuntil("(row col):").decode('utf-8')
        if "Score: 9950" in content:
            flag_inc = True
        print(content)
        content = content.split('\n')[2:] # get rid of score and whitespace
        start_count = False
        counter = 1

        print("Started finding num spaces between boxes")
        for i, line in enumerate(content):
            print(line)
            if line.strip() == '' and start_count:
                print("Added one to count")
                counter += 1
            elif line.strip() == '':
                print("Started count")
                start_count = True
            elif start_count: # its not a newline and we already started counting
                spaces_vertical = counter
                print("Got vertical spaces")
                break
        '''
        spaces_horizantal = 0
        for i, char in enumerate(content[2]): # just choose a line that's not the first line of a box divider or whitespace
            if i >= box_width - 1: # check if we reached the first whitespace after the edge of the first box
                spaces_horizantal += 1
            if char != " " and spaces_horizantal > 0: # check if we started counting already and break if we reached the border of the next box
                break
        print(f"Horizantal spaces: {spaces_horizantal} Vertical spaces: {spaces_vertical}")
        '''
        if not hard_part:
            spaces_horizantal = 2
        else:
            spaces_horizantal = int(input("Enter the number of horizantal spaces: "))
            spaces_vertical = int(input("Enter the number of vertical spaces: "))
        try:
            for i, line in enumerate(content):
                for i2, char in enumerate(line):
                    if not char in divider_chars and " ___ " in line and char == "_":
                        # account for space below box
                        row = str(int(i / (box_height + spaces_vertical)))
                        # 17 + 2 to account for spaces between boxes and the divider of the next box
                        col = str(int(i2 / (17 + spaces_horizantal)))
                        payload = f"{row} {col}"
                        print(payload)
                        p.sendline(payload)
                        raise Exception("found")
        except:
            pass
        result = p.recvline()
        print(result)
        if result != b' Whack!\n':
            hard_part = True
        else:
            right_in_a_row += 1
        if right_in_a_row > 1:
            hard_part = False
        if flag_inc:
            p.interactive()
    p.interactive()
    ```

4. If the code doesn't work, try running it again a couple times

    ![hack-a-mole%20(250pt)%208d902fed191c41fd9226378d386d19ed/Untitled%203.png](hack-a-mole%20(250pt)%208d902fed191c41fd9226378d386d19ed/Untitled%203.png)

5. The flag is flag{Wh4t3v3r_d1d_th3_p00r_m0l3_d0_t0_y0u?}