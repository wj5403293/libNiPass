#include "EncPass/FlatteningEnhanced.h"
#include "CryptoUtils.h"
#include "Utils.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/Local.h"

#define DEBUG_TYPE "flatteningenhanced"
#include <list>
#include <map>
#include <utility>
#include <vector>

using namespace llvm;

namespace ni_pass {

// ============================================================
// 编译时非线性哈希：用于累积 key_map
// ============================================================
static uint32_t nonlinearHash(uint32_t current, uint32_t input) {
    current ^= input;
    current *= 0x9E3779B9u;
    current = (current << 13) | (current >> 19);
    current += 0xDEADBEEFu;
    return current;
}

// ============================================================
// 运行时非线性哈希 IR 序列（等价于编译时 nonlinearHash）
// ============================================================
static Value *emitNonlinearHashIR(IRBuilder<> &irb, Value *current, Value *input) {
    // current ^= input
    Value *xored = irb.CreateXor(current, input);
    // current *= 0x9E3779B9u
    Value *muled = irb.CreateMul(xored, irb.getInt32(0x9E3779B9u));
    // rotl(current, 13) = (current << 13) | (current >> 19)
    Value *shl = irb.CreateShl(muled, 13);
    Value *shr = irb.CreateLShr(muled, 19);
    Value *rotl = irb.CreateOr(shl, shr);
    // current += 0xDEADBEEFu
    return irb.CreateAdd(rotl, irb.getInt32(0xDEADBEEFu));
}

// ============================================================
// XOR 等价表达式：随机选择一种变体替代 a ^ b
// (a ^ b) == (a | b) - (a & b)
// (a ^ b) == (a + b) - 2*(a & b)
// (a ^ b) == (a & ~b) | (~a & b)
// (a ^ b) == ~(~a ^ b) ... 双重否定展开
// ============================================================
static Value *emitObfuscatedXor(IRBuilder<> &irb, Value *a, Value *b) {
    uint32_t variant = cryptoutils->get_range(4);
    switch (variant) {
    case 0: {
        // (a | b) - (a & b)
        Value *orVal = irb.CreateOr(a, b);
        Value *andVal = irb.CreateAnd(a, b);
        return irb.CreateSub(orVal, andVal);
    }
    case 1: {
        // (a + b) - 2*(a & b)
        Value *addVal = irb.CreateAdd(a, b);
        Value *andVal = irb.CreateAnd(a, b);
        Value *doubled = irb.CreateShl(andVal, 1);
        return irb.CreateSub(addVal, doubled);
    }
    case 2: {
        // (a & ~b) | (~a & b)
        Value *notB = irb.CreateNot(b);
        Value *notA = irb.CreateNot(a);
        Value *left = irb.CreateAnd(a, notB);
        Value *right = irb.CreateAnd(notA, b);
        return irb.CreateOr(left, right);
    }
    default: {
        // ~(~(a ^ b)) 展开为 ~(~a ^ ~b) ... 再 NOT
        // 实际用: NOT( (a XNOR b) ) = NOT( NOT(a^b) ) 但多加一层运算
        // 这里用: (a | b) & (~a | ~b) 也等价于 a ^ b
        Value *orVal = irb.CreateOr(a, b);
        Value *notA = irb.CreateNot(a);
        Value *notB = irb.CreateNot(b);
        Value *orNot = irb.CreateOr(notA, notB);
        return irb.CreateAnd(orVal, orNot);
    }
    }
}

// ============================================================
// Pass 入口
// ============================================================
PreservedAnalyses FlatteningEnhanced::run(Module &M, ModuleAnalysisManager& AM) {
    bool changed = false;
    for (Function &f : M) {
        if (ni_pass::toObfuscate(flag, &f, "enfla")) {
            LLVM_DEBUG(dbgs() << "\033[1;32m[FlatteningEnhanced] Function: " << f.getName() << "\033[0m\n");
            DoFlatteningEnhanced(&f);
            changed = true;
        }
    }
    return changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}

std::vector<BasicBlock *> *
FlatteningEnhanced::getBlocks(Function *function, std::vector<BasicBlock *> *lists) {
    lists->clear();
    for (BasicBlock &basicBlock : *function)
        lists->push_back(&basicBlock);
    return lists;
}

unsigned int FlatteningEnhanced::getUniqueNumber(std::vector<unsigned int> *rand_list) {
    unsigned int num = cryptoutils->get_uint32_t();
    while (true) {
        bool state = true;
        for (auto n = rand_list->begin(); n != rand_list->end(); n++)
            if (*n == num) {
                state = false;
                break;
            }
        if (state)
            break;
        num = cryptoutils->get_uint32_t();
    }
    return num;
}

// ============================================================
// 核心：增强平坦化
// ============================================================
void FlatteningEnhanced::DoFlatteningEnhanced(Function *f) {
    // --- 将 InvokeInst 降级为 CallInst + BranchInst ---
    {
        SmallVector<BasicBlock *, 8> invokeBlocks;
        for (BasicBlock &BB : *f)
            if (isa<InvokeInst>(BB.getTerminator()))
                invokeBlocks.push_back(&BB);
        for (BasicBlock *BB : invokeBlocks)
            removeUnwindEdge(BB);
        if (!invokeBlocks.empty())
            removeUnreachableBlocks(*f);
    }

    std::vector<BasicBlock *> origBB;
    getBlocks(f, &origBB);
    if (origBB.size() <= 1)
        return;

    BasicBlock *oldEntry = &f->getEntryBlock();
    BranchInst *firstBr = nullptr;
    if (isa<BranchInst>(oldEntry->getTerminator()))
        firstBr = cast<BranchInst>(oldEntry->getTerminator());
    BasicBlock *firstbb = oldEntry->getTerminator()->getSuccessor(0);

    // 分割第一个基本块
    BasicBlock::iterator iter = oldEntry->end();
    iter--;
    if (oldEntry->size() > 1)
        iter--;
    BasicBlock *splited = oldEntry->splitBasicBlock(iter, Twine("FirstBB"));
    firstbb = splited;
    origBB.insert(origBB.begin(), splited);

    // 生成上下文信息，为每个块生成密钥
    IRBuilder<> irb(&*oldEntry->getFirstInsertionPt());
    Value *visitedArray =
        irb.CreateAlloca(irb.getInt8Ty(), irb.getInt32(origBB.size()));
    Value *keyArray =
        irb.CreateAlloca(irb.getInt32Ty(), irb.getInt32(origBB.size()));
    irb.CreateMemSet(visitedArray, irb.getInt8(0), origBB.size(), MaybeAlign(0));
    irb.CreateMemSet(keyArray, irb.getInt8(0), origBB.size() * 4, MaybeAlign(0));

    int idx = 0;
    std::vector<unsigned int> key_list;
    DominatorTree tree(*f);
    std::map<BasicBlock *, unsigned int> key_map;
    std::map<BasicBlock *, unsigned int> index_map;

    // 初始化密钥映射
    for (auto b = origBB.begin(); b != origBB.end(); b++) {
        unsigned int num = getUniqueNumber(&key_list);
        key_list.push_back(num);
        key_map[*b] = 0;
    }

    // 构建支配关系和密钥（编译时用 nonlinearHash 累积）
    // 运行时：在每个块末尾内联密钥更新（无条件写入，用 select 避免 split）
    for (auto b = origBB.begin(); b != origBB.end(); b++, idx++) {
        BasicBlock *block = *b;
        std::vector<unsigned int> domIndices;
        int i = 0;

        for (auto bb = origBB.begin(); bb != origBB.end(); bb++, i++) {
            BasicBlock *block0 = *bb;
            if (block0 != block && tree.dominates(block, block0)) {
                domIndices.push_back(i);
                key_map[block0] = nonlinearHash(key_map[block0], key_list[idx]);
            }
        }

        // 在每个块末尾内联密钥更新逻辑（替代 updateFunc 调用）
        irb.SetInsertPoint(block->getTerminator());
        Value *ptr =
            irb.CreateGEP(irb.getInt8Ty(), visitedArray, irb.getInt32(idx));
        Value *visited = irb.CreateLoad(irb.getInt8Ty(), ptr);
        Type *i32Ty = Type::getInt32Ty(f->getContext());

        if (!domIndices.empty()) {
            // visited == 0 时才需要更新，用 select 避免分支
            Value *isFirst = irb.CreateICmpEQ(visited, irb.getInt8(0));

            for (unsigned int domIdx : domIndices) {
                Value *gepKey = irb.CreateGEP(i32Ty, keyArray, irb.getInt32(domIdx));
                Value *keyVal = irb.CreateLoad(i32Ty, gepKey);
                Value *updated = emitNonlinearHashIR(irb, keyVal, irb.getInt32(key_list[idx]));
                // 如果是首次访问则写入更新值，否则保持原值
                Value *chosen = irb.CreateSelect(isFirst, updated, keyVal);
                irb.CreateStore(chosen, gepKey);
            }
        }

        irb.CreateStore(irb.getInt8(1), ptr);
        index_map[block] = idx;
    }

    // ============================================================
    // 准备 switch 调度器
    // ============================================================
    BasicBlock *newEntry = oldEntry;
    BasicBlock *loopBegin =
        BasicBlock::Create(f->getContext(), "LoopBegin", f, newEntry);
    BasicBlock *defaultCase =
        BasicBlock::Create(f->getContext(), "DefaultCase", f, newEntry);
    BasicBlock *loopEnd =
        BasicBlock::Create(f->getContext(), "LoopEnd", f, newEntry);

    newEntry->moveBefore(loopBegin);

    BranchInst::Create(loopEnd, defaultCase);
    BranchInst::Create(loopBegin, loopEnd);
    newEntry->getTerminator()->eraseFromParent();
    BranchInst::Create(loopBegin, newEntry);

    AllocaInst *switchVar =
        new AllocaInst(Type::getInt32Ty(f->getContext()), 0, Twine("switchVar"),
                       newEntry->getTerminator());

    LoadInst *swValue =
        new LoadInst(Type::getInt32Ty(f->getContext()), switchVar, "cmd", loopBegin);

    SwitchInst *sw = SwitchInst::Create(swValue, defaultCase, 0, loopBegin);

    std::vector<unsigned int> rand_list;
    unsigned int startNum = 0;

    // 将基本块放入 switch 结构
    for (auto b = origBB.begin(); b != origBB.end(); b++) {
        BasicBlock *block = *b;
        unsigned int num = getUniqueNumber(&rand_list);
        rand_list.push_back(num);

        if (block == newEntry)
            continue;

        block->moveBefore(loopEnd);

        if (block == firstbb)
            startNum = num;

        ConstantInt *numCase =
            cast<ConstantInt>(ConstantInt::get(sw->getCondition()->getType(), num));
        sw->addCase(numCase, block);
    }

    // 设置入口值
    ConstantInt *startVal = cast<ConstantInt>(ConstantInt::get(
        sw->getCondition()->getType(), startNum));
    new StoreInst(startVal, switchVar, newEntry->getTerminator());

    // ============================================================
    // 插入虚假 switch case（2~5 个）
    // ============================================================
    unsigned int numBogus = cryptoutils->get_range(2, 6);
    for (unsigned int bi = 0; bi < numBogus; bi++) {
        unsigned int bogusNum = getUniqueNumber(&rand_list);
        rand_list.push_back(bogusNum);

        BasicBlock *bogusBB =
            BasicBlock::Create(f->getContext(), "bogusCase", f, loopEnd);
        IRBuilder<> bogusIrb(bogusBB);

        // 生成看起来真实的计算：load keyArray → xor → store switchVar
        Type *i32Ty = Type::getInt32Ty(f->getContext());
        unsigned int fakeIdx = cryptoutils->get_range(origBB.size());
        Value *gepKey = bogusIrb.CreateGEP(i32Ty, keyArray, bogusIrb.getInt32(fakeIdx));
        Value *keyVal = bogusIrb.CreateLoad(i32Ty, gepKey);
        uint32_t fakeConst = cryptoutils->get_uint32_t();
        Value *fakeXor = bogusIrb.CreateXor(keyVal, bogusIrb.getInt32(fakeConst));
        bogusIrb.CreateStore(fakeXor, switchVar);
        bogusIrb.CreateBr(loopEnd);

        ConstantInt *bogusCase =
            cast<ConstantInt>(ConstantInt::get(sw->getCondition()->getType(), bogusNum));
        sw->addCase(bogusCase, bogusBB);
    }

    // ============================================================
    // 处理后继：用 emitObfuscatedXor 替代直接 XOR
    // ============================================================
    for (auto b = origBB.begin(); b != origBB.end(); b++) {
        BasicBlock *block = *b;
        irb.SetInsertPoint(block);

        if (block == newEntry)
            continue;

        if (!isa<BranchInst>(*block->getTerminator()))
            continue;

        if (block->getTerminator()->getNumSuccessors() == 1) {
            BasicBlock *succ = block->getTerminator()->getSuccessor(0);
            ConstantInt *caseNum = sw->findCaseDest(succ);

            if (caseNum == nullptr) {
                unsigned int num = getUniqueNumber(&rand_list);
                rand_list.push_back(num);
                caseNum = cast<ConstantInt>(
                    ConstantInt::get(sw->getCondition()->getType(), num));
            }

            unsigned int fixNum =
                caseNum->getValue().getZExtValue() ^ key_map[block];
            block->getTerminator()->eraseFromParent();

            irb.SetInsertPoint(block);
            Type *i32Ty = Type::getInt32Ty(f->getContext());
            Value *gepKey = irb.CreateGEP(i32Ty, keyArray, irb.getInt32(index_map[block]));
            Value *keyVal = irb.CreateLoad(i32Ty, gepKey);

            Value *obfXor = emitObfuscatedXor(
                irb, keyVal,
                ConstantInt::get(sw->getCondition()->getType(), fixNum));
            irb.CreateStore(obfXor, switchVar);
            BranchInst::Create(loopEnd, block);

        } else if (block->getTerminator()->getNumSuccessors() == 2) {
            BasicBlock *succTrue = block->getTerminator()->getSuccessor(0);
            BasicBlock *succFalse = block->getTerminator()->getSuccessor(1);
            ConstantInt *numTrue = sw->findCaseDest(succTrue);
            ConstantInt *numFalse = sw->findCaseDest(succFalse);

            if (numTrue == nullptr) {
                unsigned int num = getUniqueNumber(&rand_list);
                rand_list.push_back(num);
                numTrue = cast<ConstantInt>(
                    ConstantInt::get(sw->getCondition()->getType(), num));
            }
            if (numFalse == nullptr) {
                unsigned int num = getUniqueNumber(&rand_list);
                rand_list.push_back(num);
                numFalse = cast<ConstantInt>(
                    ConstantInt::get(sw->getCondition()->getType(), num));
            }

            unsigned int fixNumTrue =
                numTrue->getValue().getZExtValue() ^ key_map[block];
            unsigned int fixNumFalse =
                numFalse->getValue().getZExtValue() ^ key_map[block];

            BranchInst *oldBr = cast<BranchInst>(block->getTerminator());
            SelectInst *select = SelectInst::Create(
                oldBr->getCondition(),
                ConstantInt::get(sw->getCondition()->getType(), fixNumTrue),
                ConstantInt::get(sw->getCondition()->getType(), fixNumFalse),
                Twine("choice"), block->getTerminator());

            block->getTerminator()->eraseFromParent();

            irb.SetInsertPoint(block);
            Type *i32Ty = Type::getInt32Ty(f->getContext());
            Value *gepKey = irb.CreateGEP(i32Ty, keyArray, irb.getInt32(index_map[block]));
            Value *keyVal = irb.CreateLoad(i32Ty, gepKey);

            Value *obfXor = emitObfuscatedXor(irb, keyVal, select);
            irb.CreateStore(obfXor, switchVar);
            BranchInst::Create(loopEnd, block);
        }
    }

    ni_pass::fixStack(f);
}

FlatteningEnhanced *createFlatteningEnhanced(bool flag) {
    return new FlatteningEnhanced(flag);
}

} // end namespace ni_pass
