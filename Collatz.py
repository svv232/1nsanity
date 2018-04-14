#!/usr/bin/env python
from random import randint
def collatz(n):
    print(n)
    while(n != 1): 
        if n & 1 == 1:
            n *= 3
            n += 1
        else:
            n /= 2
        print(n)

collatz(randint(0,2500))
