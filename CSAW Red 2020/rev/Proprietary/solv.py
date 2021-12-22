#!/bin/python3
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
