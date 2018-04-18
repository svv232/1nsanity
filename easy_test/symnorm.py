#!/usr/bin/env python
import angr

def main():
    proj = angr.Project("./normal")
    find = [0x40096a]
    avoid = [0x400971]
    
    state = proj.factory.blank_state(addr=0x4008ef)
    sm = proj.factory.simulation_manager(state)
    ex = sm.explore(find = find, avoid = avoid)
    
    final = ex.found[0]
    flag = final.posix.dumps(0)
    print(flag.rstrip('\x00'))
    
 
if "__main__" == __name__:
    main()
