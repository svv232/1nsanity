CC = clang-3.9 
CPP = clang++-3.9
OPT = opt-3.9
LLVMDIS = llvm-dis-3.9
LLVMCONFIG=llvm-config-3.9
CFLAGS += -Wall -fno-rtti -fcolor-diagnostics 
OUT = test

all: bc pass check clean

bc: test.bc

pass: Insanity.so

%.bc: %.c
	$(CC) -m32 -emit-llvm -c $< -o $@ 
	$(LLVMDIS) $@

%.so: %.cpp
	$(CPP) -fPIC -shared $< -o $@ -std=c++14 `$(LLVMCONFIG) --cxxflags` $(CFLAGS)

check:
	$(OPT) -load ./Insanity.so -1nsanity test.bc -o out.bc
	$(CPP) -o test out.bc -m32

clean:
	rm -rf *.bc *.ll *.so *.dwo
