#!/usr/bin/env python3
import angr

binaryName = "chall"
winAddress = [] # can be array of ints or single int
loseAddress = []

p = angr.Project(binaryName)
simgr = p.factory.simulation_manager(p.factory.full_init_state())
simgr.explore(find=0x00101319, avoid=0x00101306)

print(simgr.found[0].posix.dumps(0))
