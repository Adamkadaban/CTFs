#!/bin/python3
import angr
import claripy

proj = angr.Project('./checkpass', main_opts={'base_addr': 0}, auto_load_libs=False)

arg = claripy.BVS('arg', 8*100)

state = proj.factory.entry_state(args=['./checkpass', arg])
simgr = proj.factory.simulation_manager(state)
simgr.explore(avoid=[0x00139dc8,0x00139db7])
print("len(simgr.found) = {}".format(len(simgr.found)))

if len(simgr.found) > 0:
    s = simgr.found[0]
    print("argv[1] = {!r}".format(s.solver.eval(arg, cast_to=bytes)))
    print("stdin = {!r}".format(s.posix.dumps(0)))