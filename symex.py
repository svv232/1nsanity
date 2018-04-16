#!/usr/bin/env python
import angr

def main():
    proj = angr.Project("./test")
    find = [0x400761]
    avoid = [0x400770]
    
    state = proj.factory.blank_state(addr=0x400640)
    sm = proj.factory.simulation_manager(state)
    ex = sm.explore(find = find, avoid = avoid)
    
    final = ex.found[0]
    flag = final.posix.dumps(0)
    print(flag.rstrip('\x00'))
    
 
if "__main__" == __name__:
    main()
