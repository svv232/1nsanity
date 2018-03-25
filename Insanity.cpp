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
        Value * obfuscateAdd(Instruction * I);
        Value * obfuscateXor(Instruction * I);
        Value * obfuscateOr(Instruction * I); 
        Value * obfuscateAnd(Instruction * I); 
        Value * obfuscateSub(Instruction * I);  
        void dumpAll(Function &F) const;
        void clean_up(std::vector<Instruction*>& clean);
        Value * intToVal(const int intgr, 
                Instruction * I);
        void replaceAll(Instruction * I, Value * V);
    };

Value * Insanity::intToVal(const int intgr, 
        Instruction * I){
    return ConstantInt::get(
            Type::getInt32Ty(I -> getContext()),intgr);
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

Value * Insanity::obfuscateAdd(Instruction * I){
    IRBuilder <> * builder = new IRBuilder<>(I);
    Value * op1 = I -> getOperand(0);
    Value * op2 = I -> getOperand(1);
    op2 = builder -> CreateSub(intToVal(0,I), op2); 
    return builder -> CreateSub(op1, op2); 
}

Value * Insanity::obfuscateXor(Instruction * I){
    IRBuilder <> * builder = new IRBuilder<>(I);
    Value * op1 = I -> getOperand(0);
    Value * op2 = I -> getOperand(1); 
    Value * negOp1=builder 
        -> CreateXor(intToVal(-1, I), op1);
    Value* andRes1=builder -> CreateAnd(negOp1, op2);
    Value * negOp2=builder
        -> CreateXor(intToVal(-1, I), op2);
    Value * andRes2=builder -> CreateAnd(op1 ,negOp2);
    return builder -> CreateOr(andRes1, andRes2);
}

Value * Insanity::obfuscateOr(Instruction * I){
    IRBuilder <> * builder = new IRBuilder<>(I);
    Value * op1 = I -> getOperand(0);
    Value * op2 = I -> getOperand(1);
    Value * andRes = builder -> CreateAnd(op1, op2);
    Value * xorRes = builder -> CreateXor(op1, op2);
    return builder -> CreateOr(andRes, xorRes);
}


Value * Insanity::obfuscateAnd(Instruction * I){
    IRBuilder <> * builder = new IRBuilder<>(I);
    Value * op1 = I -> getOperand(0);
    Value * op2 = I -> getOperand(1);
    Value * negOp1 = builder -> CreateXor(op2, 
            intToVal(-1, I));
    Value * xorRes = builder -> CreateXor(op1, negOp1);
    return builder -> CreateAnd(xorRes, op1);
}

Value * Insanity::obfuscateSub(Instruction * I){
    IRBuilder <> * builder = new IRBuilder<>(I);
    Value * op1 = I -> getOperand(0);
    Value * op2 = I -> getOperand(1);
    op2 = builder -> CreateSub(intToVal(0,I), op2); 
    return builder -> CreateAdd(op1, op2); 
}

bool Insanity::runOnFunction(Function &F){
    auto I = inst_begin(F), E = inst_end(F);
    bool modified = false;
    std::vector<Instruction *> trash;
    for(; I != E; ++I){
        switch(I -> getOpcode()){
            case(Instruction::Add): {
                auto& ins = *I;
                replaceAll(&ins, obfuscateAdd(&ins));
                trash.push_back(&ins);
                modified = true;
                break;
            }
            case(Instruction::Xor): {
                auto& ins = *I;
                replaceAll(&ins, obfuscateXor(&ins));
                trash.push_back(&ins);
                modified = true;
                break;
            }
            case(Instruction::Or): {
                auto& ins = *I;
                replaceAll(&ins, obfuscateOr(&ins));
                trash.push_back(&ins);
                modified = true;
                break;
            }
            case(Instruction::And): {
                auto& ins = *I;
                replaceAll(&ins, obfuscateAnd(&ins));
                trash.push_back(&ins);
                modified = true;
                break;
            }
            case(Instruction::Sub): {
                auto& ins = *I;
                replaceAll(&ins, obfuscateSub(&ins));
                trash.push_back(&ins);
                modified = true;
                break;
            }
        }
        }
    clean_up(trash);
    dumpAll(F);
    return modified;
}

void Insanity::dumpAll(Function &F) const{
    for (const auto &B : F)
        for (const auto &I : B)
            I.dump();
}
}

char Insanity::ID = 0;
static RegisterPass<Insanity> X("1nsanity","Insanity");
