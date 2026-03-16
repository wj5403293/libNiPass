#include "EncPass/EnhancedIndirectBranch.h"
#include "EncPass/EncryptUtils.h"
#include "CryptoUtils.h"
#include "Utils.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"

#define DEBUG_TYPE "enhancedindirectbranch"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/LowerSwitch.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include <unordered_set>

using namespace llvm;

// 命令行选项：是否使用基于栈的间接跳转方式
static cl::opt<bool>
    EIBRUseStack("eibr-use-stack", cl::init(true), cl::NotHidden,
                 cl::desc("[EnhancedIndirectBranch]Stack-based indirect jumps"));

namespace ni_pass {

// === 模块初始化：收集 BB、创建全局加密表 ===

bool EnhancedIndirectBranchPass::initialize(Module &M) {
  // 先对所有待混淆函数运行 LowerSwitchPass
  PassBuilder PB;
  FunctionAnalysisManager FAM;
  FunctionPassManager FPM;
  PB.registerFunctionAnalyses(FAM);
  FPM.addPass(LowerSwitchPass());

  LLVMContext &Ctx = M.getContext();
  auto *i8ptr = Type::getInt8Ty(Ctx)->getPointerTo();
  const DataLayout &DL = M.getDataLayout();
  unsigned pointerSize = DL.getPointerSize();
  IntegerType *intType = Type::getInt32Ty(Ctx);
  if (pointerSize == 8)
    intType = Type::getInt64Ty(Ctx);

  // 收集所有非入口 BB
  SmallVector<BasicBlock *, 64> AllBBs;
  unsigned idx = 0;

  for (Function &F : M) {
#if LLVM_VERSION_MAJOR >= 18
    if (F.getSection().starts_with(".init.text") ||
        F.getSection().starts_with(".exit.text"))
      continue;
#else
    if (F.getSection().startswith(".init.text") ||
        F.getSection().startswith(".exit.text"))
      continue;
#endif
    if (!toObfuscate(flag, &F, "eibr"))
      continue;

    to_obf_funcs.insert(&F);
    FPM.run(F, FAM);

    for (BasicBlock &BB : F) {
#if LLVM_VERSION_MAJOR <= 12
      bool isFirst = (&BB == &F.getEntryBlock());
#else
      bool isFirst = BB.isEntryBlock();
#endif
      if (!isFirst) {
        indexmap[&BB] = idx++;
        AllBBs.push_back(&BB);
      }
    }
  }

  if (AllBBs.empty()) {
    this->initialized = true;
    return false;
  }

  // 创建全局表（编译时直接用 ConstantExpr 计算加密值）
  std::string GVName = ".eibr_" + std::to_string(cryptoutils->get_uint32_t());
  std::vector<Constant *> Elements;
  for (BasicBlock *BB : AllBBs) {
    // 为每个 BB 生成 4 个独立密钥
    BBEncInfo Info;
    Info.key1 = cryptoutils->get_uint64_t();
    Info.key2 = cryptoutils->get_uint64_t();
    Info.key3 = cryptoutils->get_uint64_t();
    Info.key4 = cryptoutils->get_uint64_t();
    Info.variant = cryptoutils->get_range(0, 3);
    BBKeys[BB] = Info;

    // 编译时加密: combined = (key1 ^ key2) + (key3 ^ key4)
    //            stored = inttoptr( ptrtoint(ptr) + combined )
    Constant *BA = BlockAddress::get(BB->getParent(), BB);
    Constant *CE = ConstantExpr::getBitCast(BA, i8ptr);
    Constant *AsInt = ConstantExpr::getPtrToInt(CE, intType);
    uint64_t combinedKey = (Info.key1 ^ Info.key2) + (Info.key3 ^ Info.key4);
    Constant *Added = ConstantExpr::getAdd(AsInt, ConstantInt::get(intType, combinedKey));
    Constant *Encrypted = ConstantExpr::getIntToPtr(Added, i8ptr);
    Elements.push_back(Encrypted);
  }

  ArrayType *ATy = ArrayType::get(i8ptr, Elements.size());
  Constant *CA = ConstantArray::get(ATy, ArrayRef<Constant *>(Elements));
  GlobalTable = new GlobalVariable(M, ATy, false,
                                   GlobalValue::LinkageTypes::PrivateLinkage,
                                   CA, GVName);
  appendToCompilerUsed(M, {GlobalTable});

  // 为每个函数生成独立 indexKey
  for (Function *F : to_obf_funcs)
    funcIndexKeys[F] = cryptoutils->get_uint64_t();

  this->initialized = true;
  return true;
}

// === Pass 入口 ===

PreservedAnalyses EnhancedIndirectBranchPass::run(Function &F,
                                                   FunctionAnalysisManager &FAM) {
  Module *M = F.getParent();

  if (!this->initialized)
    initialize(*M);

  if (to_obf_funcs.find(&F) == to_obf_funcs.end())
    return PreservedAnalyses::all();

  LLVM_DEBUG(dbgs() << "\033[1;36m[EnhancedIndirectBranch] Function : " << F.getName()
                    << "\033[0m\n");

  LLVMContext &Ctx = M->getContext();
  const DataLayout &DL = M->getDataLayout();
  unsigned pointerSize = DL.getPointerSize();
  IntegerType *intType = Type::getInt32Ty(Ctx);
  if (pointerSize == 8)
    intType = Type::getInt64Ty(Ctx);

  Type *Int8PtrTy = Type::getInt8Ty(Ctx)->getPointerTo();
  Value *zero = ConstantInt::get(intType, 0);

  // 获取函数特定的栈使用选项
  bool useStack = EIBRUseStack;
  toObfuscateBoolOption(&F, "eibr_use_stack", &useStack);

  uint64_t indexKey = funcIndexKeys[&F];

  // 收集所有分支指令
  SmallVector<BranchInst *, 32> BIs;
  for (Instruction &Inst : instructions(F))
    if (BranchInst *BI = dyn_cast<BranchInst>(&Inst))
      BIs.emplace_back(BI);

  IRBuilder<NoFolder> IRBEntry(&F.getEntryBlock().front());

  for (BranchInst *BI : BIs) {
    if (useStack &&
        IRBEntry.GetInsertPoint() != F.getEntryBlock().begin())
      IRBEntry.SetInsertPoint(F.getEntryBlock().getTerminator());

    IRBuilder<NoFolder> IRBBI(BI);

    // 收集分支目标（跳过入口块）
    SmallVector<BasicBlock *, 2> BBs;
#if LLVM_VERSION_MAJOR <= 12
    if (BI->isConditional() && (BI->getSuccessor(1) != &F.getEntryBlock()))
      BBs.emplace_back(BI->getSuccessor(1));
    if (BI->getSuccessor(0) != &F.getEntryBlock())
      BBs.emplace_back(BI->getSuccessor(0));
#else
    if (BI->isConditional() && !BI->getSuccessor(1)->isEntryBlock())
      BBs.emplace_back(BI->getSuccessor(1));
    if (!BI->getSuccessor(0)->isEntryBlock())
      BBs.emplace_back(BI->getSuccessor(0));
#endif

    if (BBs.empty())
      continue;

    GlobalVariable *LoadFrom = nullptr;

    if (BI->isConditional() ||
        indexmap.find(BI->getSuccessor(0)) == indexmap.end()) {
      // === 条件分支 / 目标不在全局表 → 创建局部加密表 ===
      std::vector<Constant *> LocalElements;
      std::vector<BBEncInfo> LocalKeys;
      for (BasicBlock *BB : BBs) {
        BBEncInfo Info;
        Info.key1 = cryptoutils->get_uint64_t();
        Info.key2 = cryptoutils->get_uint64_t();
        Info.key3 = cryptoutils->get_uint64_t();
        Info.key4 = cryptoutils->get_uint64_t();
        Info.variant = cryptoutils->get_range(0, 3);
        LocalKeys.push_back(Info);

        // 编译时加密: combined = (key1 ^ key2) + (key3 ^ key4)
        Constant *BA = BlockAddress::get(BB->getParent(), BB);
        Constant *CE = ConstantExpr::getBitCast(BA, Int8PtrTy);
        Constant *AsInt = ConstantExpr::getPtrToInt(CE, intType);
        uint64_t combinedKey = (Info.key1 ^ Info.key2) + (Info.key3 ^ Info.key4);
        Constant *Added = ConstantExpr::getAdd(AsInt, ConstantInt::get(intType, combinedKey));
        Constant *Encrypted = ConstantExpr::getIntToPtr(Added, Int8PtrTy);
        LocalElements.push_back(Encrypted);
      }

      ArrayType *LocalATy = ArrayType::get(Int8PtrTy, LocalElements.size());
      Constant *LocalCA =
          ConstantArray::get(LocalATy, ArrayRef<Constant *>(LocalElements));
      std::string LocalName =
          ".eibr_local_" + std::to_string(cryptoutils->get_uint32_t());
      LoadFrom = new GlobalVariable(*M, LocalATy, false,
                                     GlobalValue::LinkageTypes::PrivateLinkage,
                                     LocalCA, LocalName);
      appendToCompilerUsed(*M, {LoadFrom});

      // 条件分支：index = zext(condition)；无条件分支：index = 0
      Value *zext;
      if (BI->isConditional()) {
        Value *condition = BI->getCondition();
        zext = IRBBI.CreateZExt(condition, intType);
      } else {
        zext = ConstantInt::get(intType, 0);
      }

      Value *LocalIndex;
      if (useStack) {
        AllocaInst *LoadFromAI = IRBEntry.CreateAlloca(LoadFrom->getType());
        IRBEntry.CreateStore(LoadFrom, LoadFromAI);
        AllocaInst *condAI = IRBEntry.CreateAlloca(intType);
        IRBBI.CreateStore(zext, condAI);

        LoadInst *LILoadFrom =
            IRBBI.CreateLoad(LoadFrom->getType(), LoadFromAI);
        Value *condLoad = IRBBI.CreateLoad(intType, condAI);
        Value *GEP = IRBBI.CreateGEP(LoadFrom->getValueType(), LILoadFrom,
                                      {zero, condLoad});
        LocalIndex = condLoad;
        Value *EncPtr = IRBBI.CreateLoad(Int8PtrTy, GEP);

        // 根据 index 选择对应的密钥解密
        // 条件分支只有 0/1 两个索引，用 select 选择密钥
        const BBEncInfo &Info0 = LocalKeys[0];
        const BBEncInfo &Info1 = LocalKeys.size() > 1 ? LocalKeys[1] : Info0;
        Value *DecPtr0 = emitDecrypt4Key(IRBBI, EncPtr, Info0, intType, Ctx);
        Value *DecPtr1 = emitDecrypt4Key(IRBBI, EncPtr, Info1, intType, Ctx);
        Value *IsZero = IRBBI.CreateICmpEQ(condLoad, zero);
        Value *DecPtr = IRBBI.CreateSelect(IsZero, DecPtr0, DecPtr1);

        IndirectBrInst *indirBr = IndirectBrInst::Create(DecPtr, BBs.size());
        for (BasicBlock *BB : BBs)
          indirBr->addDestination(BB);
        ReplaceInstWithInst(BI, indirBr);
      } else {
        Value *GEP = IRBBI.CreateGEP(LoadFrom->getValueType(), LoadFrom,
                                      {zero, zext});
        Value *EncPtr = IRBBI.CreateLoad(Int8PtrTy, GEP);

        const BBEncInfo &Info0 = LocalKeys[0];
        const BBEncInfo &Info1 = LocalKeys.size() > 1 ? LocalKeys[1] : Info0;
        Value *DecPtr0 = emitDecrypt4Key(IRBBI, EncPtr, Info0, intType, Ctx);
        Value *DecPtr1 = emitDecrypt4Key(IRBBI, EncPtr, Info1, intType, Ctx);
        Value *IsZero = IRBBI.CreateICmpEQ(zext, zero);
        Value *DecPtr = IRBBI.CreateSelect(IsZero, DecPtr0, DecPtr1);

        IndirectBrInst *indirBr = IndirectBrInst::Create(DecPtr, BBs.size());
        for (BasicBlock *BB : BBs)
          indirBr->addDestination(BB);
        ReplaceInstWithInst(BI, indirBr);
      }
    } else {
      // === 无条件分支 → 使用全局表 ===
      BasicBlock *Target = BI->getSuccessor(0);
      unsigned realIdx = indexmap[Target];
      uint64_t encodedIdx = realIdx ^ indexKey;

      Value *EncodedIdxVal = ConstantInt::get(intType, encodedIdx);
      Value *IdxKeyVal = emitSplitKey(IRBBI, indexKey, intType);
      Value *RealIdxVal = IRBBI.CreateXor(EncodedIdxVal, IdxKeyVal);

      if (useStack) {
        AllocaInst *LoadFromAI = IRBEntry.CreateAlloca(GlobalTable->getType());
        IRBEntry.CreateStore(GlobalTable, LoadFromAI);
        AllocaInst *idxAI = IRBEntry.CreateAlloca(intType);
        IRBBI.CreateStore(RealIdxVal, idxAI);

        LoadInst *LILoadFrom =
            IRBBI.CreateLoad(GlobalTable->getType(), LoadFromAI);
        Value *idxLoad = IRBBI.CreateLoad(intType, idxAI);
        Value *GEP = IRBBI.CreateGEP(GlobalTable->getValueType(), LILoadFrom,
                                      {zero, idxLoad});
        Value *EncPtr = IRBBI.CreateLoad(Int8PtrTy, GEP);

        const BBEncInfo &Info = BBKeys[Target];
        Value *DecPtr = emitDecrypt4Key(IRBBI, EncPtr, Info, intType, Ctx);

        IndirectBrInst *indirBr = IndirectBrInst::Create(DecPtr, BBs.size());
        for (BasicBlock *BB : BBs)
          indirBr->addDestination(BB);
        ReplaceInstWithInst(BI, indirBr);
      } else {
        Value *GEP = IRBBI.CreateGEP(GlobalTable->getValueType(), GlobalTable,
                                      {zero, RealIdxVal});
        Value *EncPtr = IRBBI.CreateLoad(Int8PtrTy, GEP);

        const BBEncInfo &Info = BBKeys[Target];
        Value *DecPtr = emitDecrypt4Key(IRBBI, EncPtr, Info, intType, Ctx);

        IndirectBrInst *indirBr = IndirectBrInst::Create(DecPtr, BBs.size());
        for (BasicBlock *BB : BBs)
          indirBr->addDestination(BB);
        ReplaceInstWithInst(BI, indirBr);
      }
    }
  }

  shuffleBasicBlocks(F);
  return PreservedAnalyses::none();
}

// 随机打乱函数中基本块的顺序
void EnhancedIndirectBranchPass::shuffleBasicBlocks(Function &F) {
  SmallVector<BasicBlock *, 32> blocks;
  for (BasicBlock &block : F) {
#if LLVM_VERSION_MAJOR <= 12
    if (&block != &F.getEntryBlock())
      blocks.emplace_back(&block);
#else
    if (!block.isEntryBlock())
      blocks.emplace_back(&block);
#endif
  }

  if (blocks.size() < 2)
    return;

  // Fisher-Yates 洗牌
  for (size_t i = blocks.size() - 1; i > 0; i--)
    std::swap(blocks[i], blocks[cryptoutils->get_range(i + 1)]);

  BasicBlock *prev = &F.getEntryBlock();
  for (BasicBlock *block : blocks) {
    block->moveAfter(prev);
    prev = block;
  }
}

} // namespace ni_pass
