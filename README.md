# Description:
1nsanity is a LLVM pass that obfuscates against symbolic execution. It includes mathematical obfuscation, bogus
control flow injection, and tacks on additional complexity to switch cases and branch instructions. It also includes
infinite loop traps along with the use of the Collatz Conjecture as an opaque predicate. Included are challenges
solved with both Angr and Manticore along with solve times both before and after obfuscation. A variety of test cases
were used ranging from basic ctf challenges to a simple unix shell.

# Example:

Here is an example of a C program

```
int main(){
  int f = 986;
  while (f != 1){
      printf("%d\n", f);
      if ((f & 1) == 1){
          f *= 3;
          f += 1;
       }
       else{
          f /= 2;
       }
    }
  return f;
}
```

### Before Obfuscation:
Binary Size:  8.0K:

#### CFG in function main:
![main cfg](https://github.com/svv232/1nsanity/blob/master/images/norm.png)

### After Obfuscation:


Obfuscated Binary Size:  8.0K:	 
![main cfg](https://github.com/svv232/1nsanity/blob/master/images/obf.png)

#### CFG in function main:


### Solve Times with Manticore:
#### [Manticore Challenge](https://github.com/svv232/1nsanity/blob/master/manticore_tests/manticore_challenge/mant_chal.c)

##### [Solver for mant_chal.c](https://github.com/svv232/1nsanity/blob/master/manticore_tests/manticore_challenge/symnorm.py)

Size: 12K:
=====NORMAL=====:
real	0m43.738s: 
user	0m43.274s: 
sys	0m0.977s: 
=====NORMAL=====: 

##### [Solver for obfuscated mant_chal.c](https://github.com/svv232/1nsanity/blob/master/manticore_tests/manticore_challenge/symobf.py): 
Size: 16K: 
===OBFUSCATED=====: 
real	16m42.648s: 
user	16m34.412s: 
sys	0m22.461s: 
===OBFUSCATED=====: 

### Solve Times with Angr: 
#### [Angr Challenge](https://github.com/svv232/1nsanity/tree/master/angr_tests/checker_ctf): 

##### [Solver for recruit.c](https://github.com/svv232/1nsanity/blob/master/angr_tests/checker_ctf/symnorm.py): 
Size: 12K: 
-----NORMAL------: 
real	1m17.714s: 
user	1m3.453s: 
sys	0m14.607s: 
-----NORMAL-------: 

##### [Solver for obfuscated recruit.c](https://github.com/svv232/1nsanity/blob/master/angr_tests/checker_ctf/symobf.py): 
Size: 20K: 
----OBFUSCATED----: 
real   10m34.944s: 
user    10m17.969s: 
sys 0m17.233s: 
----OBFUSCATED----: 

# Further Work: 
- Number Detection: 
- Symbolic input detection: 
- Cause fork on every byte of symbolic input: 
