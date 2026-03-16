#ifndef FLATTENING_ENHANCED_H
#define FLATTENING_ENHANCED_H

#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Pass.h"
#include <vector>

namespace ni_pass {

class FlatteningEnhanced : public llvm::PassInfoMixin<FlatteningEnhanced> {
public:
    FlatteningEnhanced(bool flag) : flag(flag) {}

    llvm::PreservedAnalyses run(llvm::Module &M, llvm::ModuleAnalysisManager &AM);

    static bool isRequired() { return true; }

private:
    bool flag;

    // 获取函数中的所有基本块
    std::vector<llvm::BasicBlock *> *getBlocks(llvm::Function *function, std::vector<llvm::BasicBlock *> *lists);

    // 获取唯一的随机数
    unsigned int getUniqueNumber(std::vector<unsigned int> *rand_list);

    // 对函数进行平坦化增强
    void DoFlatteningEnhanced(llvm::Function *f);
};

// 创建FlatteningEnhanced Pass的工厂函数
FlatteningEnhanced *createFlatteningEnhanced(bool flag);

} // namespace ni_pass

#endif // FLATTENING_ENHANCED_H
