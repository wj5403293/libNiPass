#include "EncPass/EnhancedIndirectCall.h"
#include "EncPass/EncryptUtils.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/Debug.h"
#include "CryptoUtils.h"

#define DEBUG_TYPE "enhancedindirectcall"

#if LLVM_VERSION_MAJOR > 10
#include "compat/CallSite.h"
#else
#include "llvm/IR/CallSite.h"
#endif

using namespace llvm;

namespace ni_pass {

// === Pass 入口 ===

PreservedAnalyses EnhancedIndirectCallPass::run(Function &F,
                                                 FunctionAnalysisManager &FAM) {
  if (toObfuscate(flag, &F, "eicall")) {
    LLVM_DEBUG(dbgs() << "\033[1;36m[EnhancedIndirectCall] Function : " << F.getName()
                      << "\033[0m\n");
    doEnhancedIndirectCall(F);
    return PreservedAnalyses::none();
  }
  return PreservedAnalyses::all();
}

// === 收集被调用函数 ===

void EnhancedIndirectCallPass::NumberCallees(Function &F) {
  for (auto &BB : F) {
    for (auto &I : BB) {
      if (dyn_cast<CallInst>(&I)) {
        CallSite CS(&I);
        Function *Callee = CS.getCalledFunction();
        if (Callee == nullptr)
          continue;
        if (Callee->isIntrinsic())
          continue;
        CallSites.push_back((CallInst *)&I);
        if (CalleeNumbering.count(Callee) == 0) {
          CalleeNumbering[Callee] = Callees.size();
          Callees.push_back(Callee);
        }
      }
    }
  }
}

// === 构建加密函数指针表（per-entry 独立密钥，多层加密）===
// 编译时直接用 ConstantExpr 计算加密值，无需 constructor

GlobalVariable *EnhancedIndirectCallPass::getIndirectCallees(Function &F,
                                                              IntegerType *intType) {
  // 随机化表名，确保不碰撞
  std::string GVName;
  do {
    GVName = ".eic_" + std::to_string(cryptoutils->get_uint32_t());
  } while (F.getParent()->getNamedGlobal(GVName));

  LLVMContext &Ctx = F.getContext();
  Module *M = F.getParent();
  auto *i8ptr = Type::getInt8Ty(Ctx)->getPointerTo();

  std::vector<Constant *> Elements;
  for (auto *Callee : Callees) {
    // 为每个 callee 生成 4 个独立密钥
    CalleeEncInfo Info;
    Info.key1 = cryptoutils->get_uint64_t();
    Info.key2 = cryptoutils->get_uint64_t();
    Info.key3 = cryptoutils->get_uint64_t();
    Info.key4 = cryptoutils->get_uint64_t();
    Info.variant = cryptoutils->get_range(0, 3);
    CalleeKeys[Callee] = Info;

    // 编译时加密: combined = (key1 ^ key2) + (key3 ^ key4)
    //            stored = inttoptr( ptrtoint(ptr) + combined )
    Constant *CE = ConstantExpr::getBitCast(Callee, i8ptr);
    Constant *AsInt = ConstantExpr::getPtrToInt(CE, intType);
    uint64_t combinedKey = (Info.key1 ^ Info.key2) + (Info.key3 ^ Info.key4);
    Constant *Added = ConstantExpr::getAdd(AsInt, ConstantInt::get(intType, combinedKey));
    Constant *Encrypted = ConstantExpr::getIntToPtr(Added, i8ptr);
    Elements.push_back(Encrypted);
  }

  ArrayType *ATy = ArrayType::get(i8ptr, Elements.size());
  Constant *CA = ConstantArray::get(ATy, ArrayRef<Constant *>(Elements));
  GlobalVariable *GV = new GlobalVariable(*M, ATy, false,
                           GlobalValue::LinkageTypes::PrivateLinkage, CA, GVName);
  appendToCompilerUsed(*M, {GV});

  return GV;
}

// === 核心替换逻辑 ===

bool EnhancedIndirectCallPass::doEnhancedIndirectCall(Function &Fn) {
  if (Options && Options->skipFunction(Fn.getName()))
    return false;

  LLVMContext &Ctx = Fn.getContext();

  CalleeNumbering.clear();
  Callees.clear();
  CallSites.clear();
  CalleeKeys.clear();

  NumberCallees(Fn);

  if (Callees.empty())
    return false;

  const DataLayout &DL = Fn.getParent()->getDataLayout();
  unsigned pointerSize = DL.getPointerSize();
  IntegerType *intType = Type::getInt32Ty(Ctx);
  if (pointerSize == 8)
    intType = Type::getInt64Ty(Ctx);

  ConstantInt *Zero = ConstantInt::get(intType, 0);
  auto *i8ptr = Type::getInt8Ty(Ctx)->getPointerTo();

  // 构建加密表（内部生成 per-entry 密钥）
  GlobalVariable *Targets = getIndirectCallees(Fn, intType);

  // 每函数独立的索引混淆密钥
  uint64_t indexKey = cryptoutils->get_uint64_t();

  for (auto CI : CallSites) {
    CallBase *CB = CI;
    Function *Callee = CB->getCalledFunction();
    FunctionType *FTy = CB->getFunctionType();
    IRBuilder<> IRB(CB);

    // --- 索引混淆 ---
    unsigned realIdx = CalleeNumbering[Callee];
    uint64_t encodedIdx = realIdx ^ indexKey;
    Value *EncodedIdxVal = ConstantInt::get(intType, encodedIdx);
    Value *IdxKeyVal = emitSplitKey(IRB, indexKey, intType);
    Value *RealIdxVal = IRB.CreateXor(EncodedIdxVal, IdxKeyVal);

    Value *GEP = IRB.CreateGEP(Targets->getValueType(), Targets,
                                {Zero, RealIdxVal});
    LoadInst *EncPtr = IRB.CreateLoad(i8ptr, GEP, CI->getName());

    // --- 多层解密（随机变体）---
    const CalleeEncInfo &Info = CalleeKeys[Callee];
    Value *DecPtr = emitDecrypt4Key(IRB, EncPtr, Info, intType, Ctx);

    // --- 替换调用目标 ---
    Value *FnPtr = IRB.CreateBitCast(DecPtr, FTy->getPointerTo());
    FnPtr->setName("ECall_" + Callee->getName());
    CB->setCalledOperand(FnPtr);
  }

  return true;
}

} // namespace ni_pass
