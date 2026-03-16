#ifndef LLVM_ENHANCED_INDIRECT_GLOBAL_VARIABLE_H
#define LLVM_ENHANCED_INDIRECT_GLOBAL_VARIABLE_H

#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include "CryptoUtils.h"
#include "ObfuscationOptions.h"
#include "Utils.h"

using namespace llvm;

namespace ni_pass {

// 每个全局变量的独立加密信息
struct GVEncInfo {
  uint64_t key1;     // XOR 密钥
  uint64_t key2;     // ADD 偏移密钥
  uint32_t variant;  // 解密模板选择器 (0/1/2)
};

class EnhancedIndirectGlobalVariablePass
    : public PassInfoMixin<EnhancedIndirectGlobalVariablePass> {
public:
  bool flag;
  ObfuscationOptions *Options;
  std::map<GlobalVariable *, unsigned> GVNumbering;
  std::vector<GlobalVariable *> GlobalVariables;
  std::map<GlobalVariable *, GVEncInfo> GVKeys;

  EnhancedIndirectGlobalVariablePass(bool flag) {
    this->flag = flag;
    this->Options = new ObfuscationOptions;
  }

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);
  void NumberGlobalVariable(Function &F);
  GlobalVariable *getIndirectGlobalVariables(Function &F, IntegerType *intType);
  static bool isRequired() { return true; }
};

} // namespace ni_pass

#endif // LLVM_ENHANCED_INDIRECT_GLOBAL_VARIABLE_H
