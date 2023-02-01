> Greetings, employee #9458. Please ensure that our DRM software is sufficiently secure.
nc [rev.red.csaw.io](http://rev.red.csaw.io/) 5004
## Addendum:
* While looking at this a year later, I realized all this program is doing is a string compare with the correct password.
* This can be solved much easier in one of two ways:

### 1. GDB
* This is the end of the disassembly of the function that checks the password:
```
   0x000000000000124d <+216>:	xor    edx,eax
   0x000000000000124f <+218>:	mov    eax,DWORD PTR [rbp-0x4]
   0x0000000000001252 <+221>:	cdqe   
   0x0000000000001254 <+223>:	mov    BYTE PTR [rbp+rax*1-0x80],dl
   0x0000000000001258 <+227>:	add    DWORD PTR [rbp-0x4],0x1
   0x000000000000125c <+231>:	mov    eax,DWORD PTR [rbp-0x4]
   0x000000000000125f <+234>:	cmp    eax,0x18
   0x0000000000001262 <+237>:	jbe    0x121a <trademark+165>
   0x0000000000001264 <+239>:	lea    rdx,[rbp-0x80]
   0x0000000000001268 <+243>:	mov    rax,QWORD PTR [rbp-0x88]
   0x000000000000126f <+250>:	mov    rsi,rdx
   0x0000000000001272 <+253>:	mov    rdi,rax
   0x0000000000001275 <+256>:	call   0x1060 <strcmp@plt>
   0x000000000000127a <+261>:	test   eax,eax
   0x000000000000127c <+263>:	sete   al
   0x000000000000127f <+266>:	movzx  eax,al
   0x0000000000001282 <+269>:	leave  
   0x0000000000001283 <+270>:	ret   
```
* `strcmp` compares `rsi` and `rdi` when we call the function, so all we have to do is break at offset 256 and print the contents of the rsi or rdx register:
```
b *trademark + 256
run
RandomFillerString
x/s $rsi
```

### 2. ltrace
* `ltrace` is a utility that shows us library calls (like strcmp)
* When we run `ltrace ./proprietary` and input a random string, it shows us what is being compared and gives us the flag:
```
puts("Welcome to FlagGiver\342\204\242 Enterpri"...Welcome to FlagGiver™ Enterprises' FlagGiver™!

) = 52
puts("Please input the Password\342\204\242 to "...Please input the Password™ to recieve™ a Flag™:

) = 55
fgets(randomFillerString
"randomFillerString\n", 25, 0x7f60335069a0) = 0x7ffecccf0300
strcmp("randomFillerString\n", "mvsvds~l}tvem&xxbcabfai{") = 5
puts("Sorry\342\204\242, that was the Wrong\342\204\242 "...Sorry™, that was the Wrong™ Password™.
) = 45
+++ exited (status 0) +++
```

## Original writeup:
1. To analyze the program, open it up in Ghidra
2. Use Ghidra to determine the locations of 
3. Use an angr script to bruteforce the correct input:
    - Make sure to set up a virtual environment first:

    ```bash
    apt-get install python3-venv
    python3 -m venv angr
    source angr/bin/activate
    python -m pip install angr
    ```

    ```python
    '''
    solver.py
    '''
    import angr
    import claripy

    max_flag_length = 40

    base_address = 0x00100000 # first location of the program

    success_address = 0x0010134d # where the success function is called
    failure_address = 0x0010135b # all the fails

    proj = angr.Project('./proprietary', main_opts={"base_addr":base_address})

    # BVS means a (symbolic, bit vector)
    flag_chars = [claripy.BVS(f'flag{i}', 8) for i in range(max_flag_length)]

    # BVV means a (value, bit vector)
    # b'' turns the character into a byte 
    flag = claripy.Concat(*flag_chars + [claripy.BVV(b'\n')]) # add \n in order to allow input to be accepted

    state = proj.factory.full_init_state(
    	args=['./proprietary'],
    	add_options = angr.options.unicorn,
    	stdin = flag
    )
    for c in flag_chars:
    	state.solver.add(c >= ord('!'))
    	state.solver.add(c <= ord('~'))

    simmgr = proj.factory.simulation_manager(state)
    simmgr.explore(find=success_address)

    if len(simmgr.found)>0:
    	for found in simmgr.found:
    		print(found.posix.dumps(0))
    else:
    	print("found nothing")
    ```

    - We get the correct input as `mvsvds~l}tvem&xxbcabfai{!!!!!!!!!!!!!!!!`
4. Use that input on the nc to get the flag

    ```bash
    echo 'mvsvds~l}tvem&xxbcabfai{!!!!!!!!!!!!!!!!' | nc rev.red.csaw.io 5004 
    ```

5. The flag is flag{fr3e_n_0p1n_so@rce_xd}
