#!/usr/bin/env python3
import angr
import claripy

proj = angr.Project("./brute")

state = proj.factory.entry_state()


simgr = proj.factory.simulation_manager(state)
simgr.explore(find = lambda newState: b"Correct!" in newState.posix.dumps(1))

simgr.found[0] # will give us the state

print(simgr.found[0].posix.dumps(0)) # stdin that gives us the correct stdout
