#!/usr/bin/env python
from manticore import Manticore
from pwn import *

m = Manticore("./normal")
e = ELF("./normal")
exit = e.symbols["exit"]

buffer_addr = None
buffer_size = 15

@m.hook(0x4009a4)
def hook(state):
    state.cpu.EIP = 0x4009c1

@m.hook(0x4009c8)
def hook(state):
    global buffer_addr;
    sym_buff = state.new_symbolic_buffer(buffer_size)
    buffer_addr = state.cpu.RDI
    state.cpu.write_bytes(buffer_addr, sym_buff)
    
@m.hook(exit)
def hook(state):
    state.abandon()

@m.hook(0x400981)
def hook(state):
    res = "".join(map(chr, state.solve_buffer(buffer_addr, buffer_size)))
    print(res)
    state.abandon()

m.run()
