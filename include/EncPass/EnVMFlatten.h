#ifndef EN_VM_FLATTEN_H
#define EN_VM_FLATTEN_H

#include "llvm/IR/PassManager.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/CFG.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/SmallSet.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/Utils/Cloning.h"

#include "Utils.h"
#include "CryptoUtils.h"

#include <vector>
#include <map>
#include <algorithm>
#include <queue>
#include <cstdio>

namespace ni_pass {

/// 控制流图节点
struct EnNode {
    unsigned int value;
    EnNode *bb1, *bb2;
    llvm::BasicBlock *data;
};

/// 虚拟机指令
struct EnVMInst {
    unsigned int type;
    unsigned int op1, op2;
};

/// 多态指令类型映射 —— 每个函数随机生成不同的编码
struct VMTypeMap {
    unsigned int RunBlock;
    unsigned int JmpBoring;
    unsigned int JmpSelect;
    unsigned int VmNop;
};

/// 增强版 VM 平坦化 Pass
class EnVMFlattenPass : public llvm::PassInfoMixin<EnVMFlattenPass> {
public:
    bool flag;
    EnVMFlattenPass(bool flag = true) : flag(flag) {}

    llvm::PreservedAnalyses run(llvm::Function &F, llvm::FunctionAnalysisManager &FAM);
    static llvm::StringRef name() { return "EnVMFlatten"; }

private:
    // 每函数随机状态
    VMTypeMap currentTypeMap;
    uint32_t currentOperandKey;

    // 随机化指令类型编码
    VMTypeMap generateTypeMap();

    // 基本块收集
    std::vector<llvm::BasicBlock *> *getBlocks(llvm::Function *function, std::vector<llvm::BasicBlock *> *lists);

    // 生成不重复随机数（使用 cryptoutils）
    unsigned int getUniqueNumber(std::vector<unsigned int> *rand_list);

    // 节点/指令创建
    EnNode *newNode(unsigned int value);
    EnVMInst *newInst(unsigned int type, unsigned int op1, unsigned int op2);

    // 值逃逸检测
    bool valueEscapes(llvm::Instruction *Inst);

    // 指令生成
    void create_node_inst(std::vector<EnVMInst *> *all_inst, std::map<EnNode *, unsigned int> *inst_map, EnNode *node);
    void gen_inst(std::vector<EnVMInst *> *all_inst, std::map<EnNode *, unsigned int> *inst_map, EnNode *node);
    EnNode *findBBNode(llvm::BasicBlock *bb, std::vector<EnNode *> *all_node);
    void dump_inst(std::vector<EnVMInst *> *all_inst);

    // 增强：dummy 指令插入，返回新的起始偏移
    unsigned int insertDummyInstructions(std::vector<EnVMInst *> *all_inst);

    // 增强：操作数 XOR 编码
    void encodeOperands(std::vector<EnVMInst *> *all_inst);

    // 主函数
    void DoFlatten(llvm::Function *f);
};

std::unique_ptr<llvm::PassInfoMixin<EnVMFlattenPass>> createEnVMFlatten(bool flag = true);

} // namespace ni_pass

#endif // EN_VM_FLATTEN_H
