#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Pass.h"
#include "llvm/IR/InstIterator.h"

#include <unordered_set>
#include <vector>

using namespace llvm;

//gets fgets read

namespace {
    struct Insanity: public FunctionPass {
        
        static char ID;
        Insanity(): FunctionPass(ID) {}
        virtual bool runOnFunction(Function &F) override;
        void dumpAll(const BasicBlock &B) const;
    };

bool Insanity::runOnFunction(Function &F){
    for (auto &B: F)
        dumpAll(B);
    return true;
}

void Insanity::dumpAll(const BasicBlock &B) const{
    for (const auto &I : B){
        I.dump();
    }
}

}

char Insanity::ID = 0;
static RegisterPass<Insanity> X("1nsanity","1nsaneBof");
