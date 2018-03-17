#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Pass.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/Support/raw_ostream.h"
#include <time.h>
using namespace llvm;

namespace {
    struct Insanity: public FunctionPass {
        
        static char ID;
        Insanity(): FunctionPass(ID) {}
        virtual bool runOnFunction(Function &F) override;
        Value * intToVal(const int integer, Instruction * I) const;
        bool bad(Instruction &I) const;
        void unfold(Instruction * I, Instruction * prev);
        void dumpAll(BasicBlock * B) const;
    };

bool Insanity::bad(Instruction &I) const{
    switch (I.getOpcode()){
    case Instruction::Store: {
       return true;
        }
    }
    return false;
}

Value * Insanity::intToVal(const int integer, Instruction *I) const {
    return ConstantInt::get(Type::getInt32Ty(I -> getContext()), integer);
}

void Insanity::unfold(Instruction *I, Instruction * prev) {
    unsigned original = 
        dyn_cast<ConstantInt>(prev -> getOperand(0)) -> getSExtValue();
        
    srand(time(0));

    unsigned random = rand();
    
    prev -> setOperand(0,intToVal(random, prev));

    Value * xored = intToVal(random ^ original ,I);
    
    IRBuilder<> * builder = new IRBuilder<>(I);
    
    Value * alloc = 
        builder -> CreateAlloca(Type::getInt32Ty(I -> getContext()));

    builder -> CreateStore(xored, alloc);

    Value * lval = 
        builder -> CreateLoad(alloc, true);

    Value * rval = 
        builder -> CreateLoad(prev -> getOperand(1), true);

    Value * xorRes = builder -> CreateXor(lval, rval);

    builder -> CreateStore(xorRes, prev -> getOperand(1));
}

bool Insanity::runOnFunction(Function &F){
	
	//inst_iterator I = inst_begin(F), E = inst_end(F);
    bool flag = false;
    Instruction * prev;
	//for (; I != E ; ++I) {
    for (auto &B : F){
        for (auto &I: B){
		if (flag){
            flag = false;
			unfold(&I, prev);
        }
        if (bad(I)){
            flag = true;
            prev = &I;
        }
        }
    dumpAll(&B);
    }
	return true;
}

void Insanity::dumpAll(BasicBlock * B) const{
    for (const auto &I : *B){
        I.dump();
    }
}
}

char Insanity::ID = 0;
static RegisterPass<Insanity> X("1nsanity","1nsaneBof");
