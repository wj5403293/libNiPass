#ifndef PASS_REGISTRY_H
#define PASS_REGISTRY_H

#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"


using namespace llvm;

namespace ni_pass {

/**
 * @brief 统一注册所有Pass
 * 
 * 该文件用于统一注册所有Pass，避免链接时的符号冲突。
 * 当有多个Pass时，如果每个Pass都定义自己的llvmGetPassPluginInfo函数，
 * 会导致链接时的符号冲突。通过这个文件，我们可以统一注册所有Pass。
 * 
 * 使用方法:
 * 1. 在每个Pass的实现文件中，不要定义llvmGetPassPluginInfo函数
 * 2. 在PassRegistry.cpp中定义llvmGetPassPluginInfo函数，并注册所有Pass
 */
class PassRegistry {
public:
  /**
   * 注册所有Pass到PassBuilder
   * @param PB PassBuilder实例
   */
  static void registerAllPasses(llvm::PassBuilder &PB);

  /**
   * 注册模块Pass
   * @param PB PassBuilder实例
   */
  static void registerModulePasses(llvm::PassBuilder &PB);

  /**
   * 注册函数Pass
   * @param PB PassBuilder实例
   */
  static void registerFunctionPasses(llvm::ModulePassManager &MPM);

  /**
   * 注册解析回调Pass
   * @param PB PassBuilder实例
   */
  static void registerPipelineParsingCallbacks(llvm::PassBuilder &PB);
};

} // namespace ni_pass

#endif // PASS_REGISTRY_H 