> Greetings, employee #9458. Please ensure that our DRM software is sufficiently secure.
nc [rev.red.csaw.io](http://rev.red.csaw.io/) 5004

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
