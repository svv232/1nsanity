#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"

#include <stdlib.h>
#include <time.h>
#include <unordered_set>
#include <vector>

using namespace llvm;

namespace {
struct Insanity : public FunctionPass {
  static char ID;
  Insanity() : FunctionPass(ID) {}
  virtual bool runOnFunction(Function &F) override;
  Value *obfuscateAdd(Instruction *I);
  Value *obfuscateXor(Instruction *I);
  Value *obfuscateOr(Instruction *I);
  Value *obfuscateAnd(Instruction *I);
  Value *obfuscateSub(Instruction *I);
  Value *obfuscateBr(BranchInst *I, Value *V,
                     std::unordered_set<BasicBlock *> &blacklist);
  void dumpAll(Function &F) const;
  void clean_up(std::vector<Instruction *> &clean);
  Value *intToVal(const int intgr, Instruction *I);
  Value *intToVal(const int intgr, LLVMContext &C);
  void replaceAll(Instruction *I, Value *V);
  Value *insertHailStoneQuery(int n, Instruction *I);
  Function *generateHailStone(Instruction *I);
};

Value *Insanity::intToVal(const int intgr, Instruction *I) {
  return ConstantInt::get(Type::getInt32Ty(I->getContext()), intgr);
}
Value *Insanity::intToVal(const int intgr, LLVMContext &C) {
  return ConstantInt::get(Type::getInt32Ty(C), intgr);
}
void Insanity::replaceAll(Instruction *I, Value *V) {
  BasicBlock::iterator iter(I);
  Value *repl = dyn_cast<Value>(I);
  for (; iter != I->getParent()->end(); ++iter) {
    for (size_t i = 0; i < iter->getNumOperands(); ++i) {
      if (iter->getOperand(i) == repl)
        iter->setOperand(i, V);
    }
  }
}

Function *Insanity::generateHailStone(Instruction *I) {
  Module *mod = I->getModule();
  Constant *c =
      mod->getOrInsertFunction("hailstone", Type::getInt32Ty(mod->getContext()),
                               Type::getInt32Ty(mod->getContext()), nullptr);
  Function *hailStone = cast<Function>(c);
  hailStone->setCallingConv(CallingConv::C);
  Function::arg_iterator args = hailStone->arg_begin();
  Value *n_arg = &*args++;
  n_arg->setName("hailStoneN");

  BasicBlock *entry = BasicBlock::Create(I->getContext(), "entry", hailStone);
  BasicBlock *prequel = BasicBlock::Create(I->getContext(), "prql", hailStone);
  BasicBlock *even = BasicBlock::Create(I->getContext(), "even", hailStone);
  BasicBlock *odd = BasicBlock::Create(I->getContext(), "odd", hailStone);
  BasicBlock *ret = BasicBlock::Create(I->getContext(), "ret", hailStone);
  BasicBlock *loop = BasicBlock::Create(I->getContext(), "loop", hailStone);

  Value *one = intToVal(1, mod->getContext());
  Value *two = intToVal(2, mod->getContext());
  Value *three = intToVal(3, mod->getContext());

  IRBuilder<> *builder = new IRBuilder<>(entry);
  Value *space = builder->CreateAlloca(Type::getInt32Ty(mod->getContext()));
  builder->CreateStore(n_arg, space);
  builder->CreateBr(prequel);

  builder->SetInsertPoint(prequel);
  Value *brCond = builder->CreateICmpEQ(builder->CreateLoad(space), one);
  builder->CreateCondBr(brCond, ret, loop);

  builder->SetInsertPoint(loop);
  Value *checker = builder->CreateLoad(space);
  Value *res = builder->CreateAnd(checker, one);
  Value *cond = builder->CreateICmpEQ(res, one);
  builder->CreateCondBr(cond, odd, even);

  builder->SetInsertPoint(odd);
  Value *oddChecker = builder->CreateLoad(space);
  Value *store = builder->CreateAdd(builder->CreateMul(oddChecker, three), one);
  builder->CreateStore(store, space);
  builder->CreateBr(prequel);

  builder->SetInsertPoint(even);
  Value *evenChecker = builder->CreateLoad(space);
  Value *evenStore = builder->CreateUDiv(evenChecker, two);
  builder->CreateStore(evenStore, space);
  builder->CreateBr(prequel);

  builder->SetInsertPoint(ret);
  Value *retVal = builder->CreateLoad(space);
  builder->CreateRet(retVal);

  return hailStone;
}

Value *Insanity::insertHailStoneQuery(int n, Instruction *I) {
  Function *hailStone = generateHailStone(I);
  IRBuilder<> *builder = new IRBuilder<>(I);
  return builder->CreateCall(hailStone, intToVal(n, I));
}

void Insanity::clean_up(std::vector<Instruction *> &clean) {
  for (auto &I : clean) {
    I->eraseFromParent();
  }
}

Value *Insanity::obfuscateAdd(Instruction *I) {
  IRBuilder<> *builder = new IRBuilder<>(I);
  Value *op1 = I->getOperand(0);
  Value *op2 = I->getOperand(1);
  op2 = builder->CreateSub(intToVal(0, I), op2);
  return builder->CreateSub(op1, op2);
}

Value *Insanity::obfuscateXor(Instruction *I) {
  IRBuilder<> *builder = new IRBuilder<>(I);
  Value *op1 = I->getOperand(0);
  Value *op2 = I->getOperand(1);
  Value *negOp1 = builder->CreateXor(intToVal(-1, I), op1);
  Value *andRes1 = builder->CreateAnd(negOp1, op2);
  Value *negOp2 = builder->CreateXor(intToVal(-1, I), op2);
  Value *andRes2 = builder->CreateAnd(op1, negOp2);
  return builder->CreateOr(andRes1, andRes2);
}

Value *Insanity::obfuscateOr(Instruction *I) {
  IRBuilder<> *builder = new IRBuilder<>(I);
  Value *op1 = I->getOperand(0);
  Value *op2 = I->getOperand(1);
  Value *andRes = builder->CreateAnd(op1, op2);
  Value *xorRes = builder->CreateXor(op1, op2);
  return builder->CreateOr(andRes, xorRes);
}

Value *Insanity::obfuscateAnd(Instruction *I) {
  IRBuilder<> *builder = new IRBuilder<>(I);
  Value *op1 = I->getOperand(0);
  Value *op2 = I->getOperand(1);
  Value *negOp1 = builder->CreateXor(op2, intToVal(-1, I));
  Value *xorRes = builder->CreateXor(op1, negOp1);
  return builder->CreateAnd(xorRes, op1);
}

Value *Insanity::obfuscateSub(Instruction *I) {
  IRBuilder<> *builder = new IRBuilder<>(I);
  Value *op1 = I->getOperand(0);
  Value *op2 = I->getOperand(1);
  op2 = builder->CreateSub(intToVal(0, I), op2);
  return builder->CreateAdd(op1, op2);
}

Value *Insanity::obfuscateBr(BranchInst *I, Value *extra,
                             std::unordered_set<BasicBlock *> &blacklist) {
  if (I->isConditional()) {
    Value *cond = I->getOperand(0);

    auto zero_32 = ConstantInt::get(Type::getInt32Ty(I->getContext()), 0);
    auto one_32 = ConstantInt::get(Type::getInt32Ty(I->getContext()), 1);
    auto two_32 = ConstantInt::get(Type::getInt32Ty(I->getContext()), 2);
    auto three_32 = ConstantInt::get(Type::getInt32Ty(I->getContext()), 3);
    auto six_32 = ConstantInt::get(Type::getInt32Ty(I->getContext()), 6);

    auto one_1 = ConstantInt::get(Type::getInt1Ty(I->getContext()), 1);
    auto zero_1 = ConstantInt::get(Type::getInt1Ty(I->getContext()), 0);

    BasicBlock *op2 = dyn_cast<BasicBlock>(I->getOperand(1));
    BasicBlock *op3 = dyn_cast<BasicBlock>(I->getOperand(2));
    BasicBlock *trap =
        BasicBlock::Create(I->getContext(), "trap", I->getFunction());

    BasicBlock *trap2 =
        BasicBlock::Create(I->getContext(), "trap2", I->getFunction());

    IRBuilder<> *trapBuilder = new IRBuilder<>(trap);
    auto special = trapBuilder->CreateZExt(trapBuilder->CreateAnd(cond, one_1),
                                           Type::getInt32Ty(I->getContext()));

    auto sw = trapBuilder->CreateSwitch(special, trap2, 3);
    sw->addCase(one_32, trap);
    sw->addCase(zero_32, op2);
    sw->addCase(six_32, op3);

    trapBuilder->SetInsertPoint(trap2);
    Value *tr = trapBuilder->CreateAnd(extra, intToVal(rand() % 150, I));
    Value *ch = trapBuilder->CreateXor(three_32, tr);
    Value *teen = trapBuilder->CreateMul(ch, six_32);
    Value *sw2 = trapBuilder->CreateMul(teen, intToVal(8, I));
    auto spCond = trapBuilder->CreateICmpUGT(intToVal(rand() % 95, I), sw2);

    auto tr2 = trapBuilder->CreateSwitch(spCond, op2);
    tr2->addCase(one_1, trap);
    tr2->addCase(zero_1, op3);

    IRBuilder<> *builder = new IRBuilder<>(I);

    auto longCon = cast<ConstantInt>(
        builder->CreateZExt(cond, Type::getInt32Ty(I->getContext())));

    auto switcher = builder->CreateSwitch(longCon, trap, 3);
    switcher->addCase(one_32, trap2);
    switcher->addCase(three_32, op2);
    switcher->addCase(two_32, op3);

    return switcher;
  } else {
    auto zero_32 = ConstantInt::get(Type::getInt32Ty(I->getContext()), 0);
    auto one_32 = ConstantInt::get(Type::getInt32Ty(I->getContext()), 1);
    auto two_32 = ConstantInt::get(Type::getInt32Ty(I->getContext()), 2);

    BasicBlock *op1 = dyn_cast<BasicBlock>(I->getOperand(0));
    BasicBlock *loop =
        BasicBlock::Create(I->getContext(), "loop", I->getFunction());
    BasicBlock *flatten =
        BasicBlock::Create(I->getContext(), "flatten", I->getFunction());
    BasicBlock *conditional =
        BasicBlock::Create(I->getContext(), "conditional", I->getFunction());
    BasicBlock *trap =
        BasicBlock::Create(I->getContext(), "second_trap", I->getFunction());
    BasicBlock *trueVal =
        BasicBlock::Create(I->getContext(), "true", I->getFunction());
    BasicBlock *falseVal =
        BasicBlock::Create(I->getContext(), "false", I->getFunction());

    blacklist.insert(loop);
    blacklist.insert(flatten);
    blacklist.insert(conditional);
    blacklist.insert(trap);
    blacklist.insert(trueVal);
    blacklist.insert(falseVal);

    IRBuilder<> *builder = new IRBuilder<>(loop);
    LLVMContext &c = I->getContext();

    Value *space = builder->CreateAlloca(Type::getInt32Ty(c));
    Value *predicate = builder->CreateAlloca(Type::getInt32Ty(c));
    builder->CreateStore(extra, predicate);
    builder->CreateStore(intToVal(0, c), space);
    builder->CreateBr(flatten);

    builder->SetInsertPoint(flatten);
    Value *swCase = builder->CreateLoad(space);
    auto switcher = builder->CreateSwitch(swCase, trap, 3);
    switcher->addCase(zero_32, conditional);
    switcher->addCase(one_32, op1);
    switcher->addCase(two_32, trap);

    builder->SetInsertPoint(conditional);
    Value *condition = builder->CreateICmpUGT(builder->CreateLoad(predicate),
                                              intToVal(421, c));
    builder->CreateCondBr(condition, trueVal, falseVal);

    builder->SetInsertPoint(trueVal);
    builder->CreateStore(one_32, space);
    builder->CreateBr(flatten);

    builder->SetInsertPoint(falseVal);
    builder->CreateStore(two_32, space);
    builder->CreateBr(flatten);

    builder->SetInsertPoint(trap);
    auto newSwitcher =
        builder->CreateSwitch(builder->CreateLoad(space), trap, 2);
    newSwitcher->addCase(zero_32, trap);
    newSwitcher->addCase(two_32, op1);

    IRBuilder<> *official = new IRBuilder<>(I);
    return official->CreateBr(loop);
  }
}

bool Insanity::runOnFunction(Function &F) {
  auto I = inst_begin(F), E = inst_end(F);
  bool modified = false;
  std::vector<Instruction *> trash;
  std::unordered_set<BasicBlock *> blacklist;
  if (I->getFunction() != generateHailStone(&*I)) {
    for (; I != E; ++I) {
      switch (I->getOpcode()) {
      case (Instruction::Add): {
        auto &ins = *I;
        replaceAll(&ins, obfuscateAdd(&ins));
        trash.push_back(&ins);
        modified = true;
        break;
      }
      case (Instruction::Xor): {
        auto &ins = *I;
        replaceAll(&ins, obfuscateXor(&ins));
        trash.push_back(&ins);
        modified = true;
        break;
      }
      case (Instruction::Or): {
        auto &ins = *I;
        replaceAll(&ins, obfuscateOr(&ins));
        trash.push_back(&ins);
        modified = true;
        break;
      }
      case (Instruction::And): {
        auto &ins = *I;
        replaceAll(&ins, obfuscateAnd(&ins));
        trash.push_back(&ins);
        modified = true;
        break;
      }
      case (Instruction::Sub): {
        auto &ins = *I;
        replaceAll(&ins, obfuscateSub(&ins));
        trash.push_back(&ins);
        modified = true;
        break;
      }
      case (Instruction::Br): {
        auto &ins = *I;
        BranchInst *br = cast<BranchInst>(&ins);
        if (blacklist.find(br->getParent()) == blacklist.end()) {
          if (br->isConditional()) {
            srand(time(0));
            int n = rand();
            Value *retVal = insertHailStoneQuery(n, &ins);
            obfuscateBr(br, retVal, blacklist);
          } else {
            obfuscateBr(br, intToVal(rand() % 420, &ins), blacklist);
          }
          trash.push_back(br);
          modified = true;
        }
        break;
      }
      }
    }
    clean_up(trash);
    dumpAll(F);
  }
  return modified;
}
void Insanity::dumpAll(Function &F) const {
  for (const auto &B : F)
    for (const auto &I : B)
      I.dump();
}
}

char Insanity::ID = 0;
static RegisterPass<Insanity> X("1nsanity", "Insanity");
