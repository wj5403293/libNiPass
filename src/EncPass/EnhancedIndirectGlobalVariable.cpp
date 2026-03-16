#include "EncPass/EnhancedIndirectGlobalVariable.h"
#include "EncPass/EncryptUtils.h"
#include "CryptoUtils.h"
#include "llvm/Support/Debug.h"

#define DEBUG_TYPE "enhancedindirectgv"

#include <random>

using namespace llvm;

namespace ni_pass {

// 多态解密：3 种等价解密变体（2 密钥 XOR-SUB 方案，与 4-key 方案不同）
static Value *emitDecrypt(IRBuilder<> &IRB, Value *EncPtr,
                          const GVEncInfo &Info, IntegerType *intType,
                          LLVMContext &Ctx) {
  auto *i8ptr = Type::getInt8Ty(Ctx)->getPointerTo();
  Value *AsInt = IRB.CreatePtrToInt(EncPtr, intType);

  Value *K2 = emitSplitKey(IRB, Info.key2, intType);
  Value *K1 = emitSplitKey(IRB, Info.key1, intType);

  Value *Step1, *DecInt;

  switch (Info.variant) {
  case 0: // 标准: SUB → XOR
    Step1 = IRB.CreateSub(AsInt, K2);
    DecInt = IRB.CreateXor(Step1, K1);
    break;
  case 1: { // NEG+ADD 替代 SUB
    Value *NegK2 = IRB.CreateNeg(K2);
    Step1 = IRB.CreateAdd(AsInt, NegK2);
    DecInt = IRB.CreateXor(Step1, K1);
    break;
  }
  case 2: { // XOR-NOT-NOT 恒等式
    Step1 = IRB.CreateSub(AsInt, K2);
    Value *NotK1 = IRB.CreateNot(K1);
    DecInt = IRB.CreateNot(IRB.CreateXor(Step1, NotK1));
    break;
  }
  default:
    Step1 = IRB.CreateSub(AsInt, K2);
    DecInt = IRB.CreateXor(Step1, K1);
    break;
  }

  return IRB.CreateIntToPtr(DecInt, i8ptr);
}

// === Pass 入口 ===

PreservedAnalyses EnhancedIndirectGlobalVariablePass::run(Module &M,
                                                           ModuleAnalysisManager &AM) {
  if (this->flag) {
    LLVM_DEBUG(dbgs() << "\033[1;36m[EnhancedIndirectGV] force.run\033[0m\n");
  }

  bool changed = false;
  for (Function &Fn : M) {
    if (!toObfuscate(flag, &Fn, "eigv"))
      continue;
    if (Options && Options->skipFunction(Fn.getName()))
      continue;

    LLVMContext &Ctx = Fn.getContext();

    GVNumbering.clear();
    GlobalVariables.clear();
    GVKeys.clear();

    LowerConstantExpr(Fn);
    NumberGlobalVariable(Fn);

    if (GlobalVariables.empty())
      continue;

    LLVM_DEBUG(dbgs() << "\033[1;36m[EnhancedIndirectGV] Function : " << Fn.getName()
                      << "\033[0m\n");
    changed = true;

    const DataLayout &DL = Fn.getParent()->getDataLayout();
    unsigned pointerSize = DL.getPointerSize();
    IntegerType *intType = Type::getInt32Ty(Ctx);
    if (pointerSize == 8)
      intType = Type::getInt64Ty(Ctx);

    ConstantInt *Zero = ConstantInt::get(intType, 0);
    auto *i8ptr = Type::getInt8Ty(Ctx)->getPointerTo();

    GlobalVariable *GVars = getIndirectGlobalVariables(Fn, intType);
    uint64_t indexKey = cryptoutils->get_uint64_t();

    for (inst_iterator I = inst_begin(Fn), E = inst_end(Fn); I != E; ++I) {
      Instruction *Inst = &*I;
      // 跳过异常处理和调用指令
      if (isa<LandingPadInst>(Inst) || isa<CleanupPadInst>(Inst) ||
          isa<CatchPadInst>(Inst) || isa<CatchReturnInst>(Inst) ||
          isa<CatchSwitchInst>(Inst) || isa<ResumeInst>(Inst) ||
          isa<CallInst>(Inst))
        continue;

      if (PHINode *PHI = dyn_cast<PHINode>(Inst)) {
        for (unsigned int i = 0; i < PHI->getNumIncomingValues(); ++i) {
          Value *val = PHI->getIncomingValue(i);
          if (GlobalVariable *GV = dyn_cast<GlobalVariable>(val)) {
            if (GVNumbering.count(GV) == 0)
              continue;

            Instruction *IP = PHI->getIncomingBlock(i)->getTerminator();
            IRBuilder<> IRB(IP);

            // 索引混淆
            unsigned realIdx = GVNumbering[GV];
            uint64_t encodedIdx = realIdx ^ indexKey;
            Value *EncodedIdxVal = ConstantInt::get(intType, encodedIdx);
            Value *IdxKeyVal = emitSplitKey(IRB, indexKey, intType);
            Value *RealIdxVal = IRB.CreateXor(EncodedIdxVal, IdxKeyVal);

            Value *GEP = IRB.CreateGEP(GVars->getValueType(), GVars,
                                        {Zero, RealIdxVal});
            LoadInst *EncPtr =
                IRB.CreateLoad(i8ptr, GEP, GV->getName());

            // 多层解密
            const GVEncInfo &Info = GVKeys[GV];
            Value *DecPtr = emitDecrypt(IRB, EncPtr, Info, intType, Ctx);
            DecPtr = IRB.CreateBitCast(DecPtr, GV->getType());
            DecPtr->setName("EIndGV0_");
            PHI->setIncomingValue(i, DecPtr);
          }
        }
      } else {
        for (User::op_iterator op = Inst->op_begin(); op != Inst->op_end();
             ++op) {
          if (GlobalVariable *GV = dyn_cast<GlobalVariable>(*op)) {
            if (GVNumbering.count(GV) == 0)
              continue;

            IRBuilder<> IRB(Inst);

            unsigned realIdx = GVNumbering[GV];
            uint64_t encodedIdx = realIdx ^ indexKey;
            Value *EncodedIdxVal = ConstantInt::get(intType, encodedIdx);
            Value *IdxKeyVal = emitSplitKey(IRB, indexKey, intType);
            Value *RealIdxVal = IRB.CreateXor(EncodedIdxVal, IdxKeyVal);

            Value *GEP = IRB.CreateGEP(GVars->getValueType(), GVars,
                                        {Zero, RealIdxVal});
            LoadInst *EncPtr =
                IRB.CreateLoad(i8ptr, GEP, GV->getName());

            const GVEncInfo &Info = GVKeys[GV];
            Value *DecPtr = emitDecrypt(IRB, EncPtr, Info, intType, Ctx);
            DecPtr = IRB.CreateBitCast(DecPtr, GV->getType());
            DecPtr->setName("EIndGV1_");
            Inst->replaceUsesOfWith(GV, DecPtr);
          }
        }
      }
    }
  }

  return changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}

// === 收集全局变量 ===

void EnhancedIndirectGlobalVariablePass::NumberGlobalVariable(Function &F) {
  for (inst_iterator I = inst_begin(F), E = inst_end(F); I != E; ++I) {
    for (User::op_iterator op = (*I).op_begin(); op != (*I).op_end(); ++op) {
      Value *val = *op;
      if (GlobalVariable *GV = dyn_cast<GlobalVariable>(val)) {
        if (!GV->isThreadLocal() && GVNumbering.count(GV) == 0 &&
            !GV->isDLLImportDependent()) {
          GVNumbering[GV] = GlobalVariables.size();
          GlobalVariables.push_back((GlobalVariable *)val);
        }
      }
    }
  }
}

// === 构建加密全局变量指针表（per-entry 独立密钥，多层加密）===
// 表初始化为原始指针，通过 constructor 函数在运行时做 XOR+ADD 加密

GlobalVariable *EnhancedIndirectGlobalVariablePass::getIndirectGlobalVariables(
    Function &F, IntegerType *intType) {
  // 随机化表名，确保不碰撞
  std::string GVName;
  do {
    GVName = ".eigv_" + std::to_string(cryptoutils->get_uint32_t());
  } while (F.getParent()->getNamedGlobal(GVName));

  LLVMContext &Ctx = F.getContext();
  Module *M = F.getParent();
  auto *i8ptr = Type::getInt8Ty(Ctx)->getPointerTo();

  std::vector<Constant *> Elements;
  for (auto *GVar : GlobalVariables) {
    // 为每个全局变量生成独立密钥
    GVEncInfo Info;
    Info.key1 = cryptoutils->get_uint64_t();
    Info.key2 = cryptoutils->get_uint64_t();
    Info.variant = cryptoutils->get_range(0, 3);
    GVKeys[GVar] = Info;

    // 表初始化为原始指针
    Constant *CE = ConstantExpr::getBitCast(GVar, i8ptr);
    Elements.push_back(CE);
  }

  ArrayType *ATy = ArrayType::get(i8ptr, Elements.size());
  Constant *CA = ConstantArray::get(ATy, ArrayRef<Constant *>(Elements));
  GlobalVariable *GV = new GlobalVariable(*M, ATy, false,
                           GlobalValue::LinkageTypes::PrivateLinkage, CA, GVName);
  appendToCompilerUsed(*M, {GV});

  // 生成 constructor 函数：运行时对表做 (ptrtoint ^ key1) + key2 加密
  std::string CtorName;
  do {
    CtorName = ".eigv_init_" + std::to_string(cryptoutils->get_uint32_t());
  } while (M->getFunction(CtorName));
  FunctionType *CtorTy = FunctionType::get(Type::getVoidTy(Ctx), false);
  Function *CtorFn = Function::Create(CtorTy, GlobalValue::InternalLinkage,
                                       CtorName, M);
  BasicBlock *Entry = BasicBlock::Create(Ctx, "", CtorFn);
  IRBuilder<> IRB(Entry);

  ConstantInt *Zero = ConstantInt::get(intType, 0);
  for (unsigned idx = 0; idx < GlobalVariables.size(); ++idx) {
    GlobalVariable *GVar = GlobalVariables[idx];
    const GVEncInfo &Info = GVKeys[GVar];

    Value *Idx = ConstantInt::get(intType, idx);
    Value *GEP = IRB.CreateGEP(ATy, GV, {Zero, Idx});
    Value *Loaded = IRB.CreateLoad(i8ptr, GEP);

    // 加密: stored = inttoptr( (ptrtoint(ptr) ^ key1) + key2 )
    Value *AsInt = IRB.CreatePtrToInt(Loaded, intType);
    Value *Xored = IRB.CreateXor(AsInt, ConstantInt::get(intType, Info.key1));
    Value *Added = IRB.CreateAdd(Xored, ConstantInt::get(intType, Info.key2));
    Value *Encrypted = IRB.CreateIntToPtr(Added, i8ptr);

    IRB.CreateStore(Encrypted, GEP);
  }
  IRB.CreateRetVoid();

  appendToGlobalCtors(*M, CtorFn, 65535);

  return GV;
}

} // namespace ni_pass
