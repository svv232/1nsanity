#!/usr/bin/env python
import angr

def main():
    proj = angr.Project("./obfuscated")
    find = [0x4007e0]
    avoid = [0x401dde]
    
    state = proj.factory.blank_state(addr=0x401cc0)
    sm = proj.factory.simulation_manager(state)
    ex = sm.explore(find = find, avoid = avoid)
    
    final = ex.found[0]
    flag = final.posix.dumps(0)
    print(flag.rstrip('\x00'))
    
 
if "__main__" == __name__:
    main()
