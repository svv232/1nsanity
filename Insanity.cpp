#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Pass.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/Support/raw_ostream.h"
#include <vector>

using namespace llvm;

namespace {
    struct Insanity: public FunctionPass {
        
        static char ID;
        Insanity(): FunctionPass(ID) {}
        virtual bool runOnFunction(Function &F) override;
        Value * obfuscate(Instruction * I);
        void dumpAll(Function &F) const;
        void clean_up(std::vector<Instruction*>& clean);
        void replaceAll(Instruction * I, Value * V);
        Value * valNeg(Value * oper);

    };

Value * Insanity::valNeg(Value * oper){
    auto cint = dyn_cast<ConstantInt>(oper);
    return ConstantInt::get(oper -> getContext()
            ,-(cint -> getValue()));
}

void Insanity::replaceAll(Instruction * I, Value * V){
    BasicBlock::iterator iter(I);
    Value * repl = dyn_cast<Value>(I);
    for (;iter != I -> getParent() -> end(); ++iter){
        for (size_t i = 0; i < iter -> getNumOperands(); ++i){
            if (iter -> getOperand(i) == repl)
                iter -> setOperand(i, V);
        }
    }
}

void Insanity::clean_up(std::vector<Instruction*>& clean){
    for (auto& I: clean){I -> eraseFromParent();}
}

Value * Insanity::obfuscate(Instruction * I){
    IRBuilder <> * builder = new IRBuilder<>(I);
    //Value * ope2 = valNeg(I -> getOperand(1)); 
    return builder -> CreateSub(I -> getOperand(0), 
            I -> getOperand(1),"tmp"); 
}

bool Insanity::runOnFunction(Function &F){
    auto I = inst_begin(F), E = inst_end(F);
    bool modified = false;
    std::vector<Instruction *> trash;
    for(; I != E; ++I){
        switch(I -> getOpcode()){
            case(Instruction::Add): {
                auto& ins = *I;
                replaceAll(&ins, obfuscate(&ins));
                trash.push_back(&ins);
                modified = true;
            }
            }
        }
    clean_up(trash);
    dumpAll(F);
    return modified;
}

void Insanity::dumpAll(Function &F) const{
    for (const auto &B : F){
        for (const auto &I : B){
            I.dump();
        }
    }
}
}

char Insanity::ID = 0;
static RegisterPass<Insanity> X("1nsanity","1nsaneBof");
