//===----------------------------------------------------------------------===//
// SubstituteImpl.cpp - 实现各种算术和逻辑指令的替换方法
// 本文件提供了多种等价但更复杂的指令序列，用于替换简单的算术和逻辑运算
//===----------------------------------------------------------------------===//

#include "SubstituteImpl.h"
#include "CryptoUtils.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/NoFolder.h"

using namespace llvm;

namespace ni_pass {
namespace SubstituteImpl {

// 定义每种操作的替换方法数量
#define NUMBER_ADD_SUBST 7  // 加法替换方法数量
#define NUMBER_SUB_SUBST 6  // 减法替换方法数量
#define NUMBER_AND_SUBST 6  // 与操作替换方法数量
#define NUMBER_OR_SUBST 6   // 或操作替换方法数量
#define NUMBER_XOR_SUBST 6  // 异或操作替换方法数量
#define NUMBER_MUL_SUBST 2  // 乘法替换方法数量

// 前置声明
static BinaryOperator *buildNor(Value *a, Value *b, Instruction *insertBefore);
static BinaryOperator *buildNand(Value *a, Value *b, Instruction *insertBefore);

// 加法操作的替换方法声明
static void addNeg(BinaryOperator *bo);            // 使用减负数
static void addDoubleNeg(BinaryOperator *bo);      // 使用双重取反
static void addRand(BinaryOperator *bo);           // 使用随机数偏移
static void addRand2(BinaryOperator *bo);          // 使用另一种随机数偏移
static void addSubstitution(BinaryOperator *bo);   // 使用位操作替换
static void addSubstitution2(BinaryOperator *bo);  // 使用位或和位与
static void addSubstitution3(BinaryOperator *bo);  // 使用位异或和位与

// 减法操作的替换方法声明
static void subNeg(BinaryOperator *bo);            // 使用加负数
static void subRand(BinaryOperator *bo);           // 使用随机数偏移
static void subRand2(BinaryOperator *bo);          // 使用另一种随机数偏移
static void subSubstitution(BinaryOperator *bo);   // 使用位操作替换
static void subSubstitution2(BinaryOperator *bo);  // 使用位操作和乘法
static void subSubstitution3(BinaryOperator *bo);  // 使用位补码特性

// 与操作的替换方法声明
static void andSubstitution(BinaryOperator *bo);    // 使用位异或和位操作
static void andSubstitution2(BinaryOperator *bo);   // 使用位或和位异或非
static void andSubstitution3(BinaryOperator *bo);   // 使用加法和补码特性
static void andSubstitutionRand(BinaryOperator *bo); // 使用随机数和位操作
static void andNor(BinaryOperator *bo);             // 使用NOR门实现
static void andNand(BinaryOperator *bo);            // 使用NAND门实现

// 或操作的替换方法声明
static void orSubstitution(BinaryOperator *bo);    // 使用位与和位异或
static void orSubstitution2(BinaryOperator *bo);   // 使用加法和位操作
static void orSubstitution3(BinaryOperator *bo);   // 使用加法和补码特性
static void orSubstitutionRand(BinaryOperator *bo); // 使用随机数和位操作
static void orNor(BinaryOperator *bo);             // 使用NOR门实现
static void orNand(BinaryOperator *bo);            // 使用NAND门实现

// 异或操作的替换方法声明
static void xorSubstitution(BinaryOperator *bo);    // 使用位与和位或
static void xorSubstitution2(BinaryOperator *bo);   // 使用加法和位与
static void xorSubstitution3(BinaryOperator *bo);   // 使用位操作和减法
static void xorSubstitutionRand(BinaryOperator *bo); // 使用随机数和位操作
static void xorNor(BinaryOperator *bo);             // 使用NOR门实现
static void xorNand(BinaryOperator *bo);            // 使用NAND门实现

// 乘法操作的替换方法声明
static void mulSubstitution(BinaryOperator *bo);   // 使用位操作和加法
static void mulSubstitution2(BinaryOperator *bo);  // 使用另一种位操作和加法

// 各种操作类型的替换函数指针数组，存储所有可用的替换方法
static void (*funcAdd[NUMBER_ADD_SUBST])(BinaryOperator *bo) = {
    &addNeg,          &addDoubleNeg,     &addRand,         &addRand2,
    &addSubstitution, &addSubstitution2, &addSubstitution3};
static void (*funcSub[NUMBER_SUB_SUBST])(BinaryOperator *bo) = {
    &subNeg,          &subRand,          &subRand2,
    &subSubstitution, &subSubstitution2, &subSubstitution3};
static void (*funcAnd[NUMBER_AND_SUBST])(BinaryOperator *bo) = {
    &andSubstitution,     &andSubstitution2, &andSubstitution3,
    &andSubstitutionRand, &andNor,           &andNand};
static void (*funcOr[NUMBER_OR_SUBST])(BinaryOperator *bo) = {
    &orSubstitution,     &orSubstitution2, &orSubstitution3,
    &orSubstitutionRand, &orNor,           &orNand};
static void (*funcXor[NUMBER_XOR_SUBST])(BinaryOperator *bo) = {
    &xorSubstitution,     &xorSubstitution2, xorSubstitution3,
    &xorSubstitutionRand, &xorNor,           &xorNand};
static void (*funcMul[NUMBER_MUL_SUBST])(BinaryOperator *bo) = {
    &mulSubstitution, &mulSubstitution2};

// 实现 ~(a | b) 或 ~a & ~b 等价逻辑
static BinaryOperator *buildNor(Value *a, Value *b, Instruction *insertBefore) {
  switch (cryptoutils->get_range(2)) {
  case 0: {
    // 实现方式1: ~(a | b)
    BinaryOperator *op =
        BinaryOperator::Create(Instruction::Or, a, b, "", insertBefore);
    op = BinaryOperator::CreateNot(op, "", insertBefore);
    return op;
  }
  case 1: {
    // 实现方式2: ~a & ~b (摩根定律)
    BinaryOperator *nota = BinaryOperator::CreateNot(a, "", insertBefore);
    BinaryOperator *notb = BinaryOperator::CreateNot(b, "", insertBefore);
    BinaryOperator *op =
        BinaryOperator::Create(Instruction::And, nota, notb, "", insertBefore);
    return op;
  }
  default:
    llvm_unreachable("wtf?");
  }
}

// 实现 ~(a & b) 或 ~a | ~b 等价逻辑
static BinaryOperator *buildNand(Value *a, Value *b,
                                 Instruction *insertBefore) {
  switch (cryptoutils->get_range(2)) {
  case 0: {
    // 实现方式1: ~(a & b)
    BinaryOperator *op =
        BinaryOperator::Create(Instruction::And, a, b, "", insertBefore);
    op = BinaryOperator::CreateNot(op, "", insertBefore);
    return op;
  }
  case 1: {
    // 实现方式2: ~a | ~b (摩根定律)
    BinaryOperator *nota = BinaryOperator::CreateNot(a, "", insertBefore);
    BinaryOperator *notb = BinaryOperator::CreateNot(b, "", insertBefore);
    BinaryOperator *op =
        BinaryOperator::Create(Instruction::Or, nota, notb, "", insertBefore);
    return op;
  }
  default:
    llvm_unreachable("wtf?");
  }
}

// a + b 替换为 b - (-a)
// 实现: a + b => b - (-a)
static void addNeg(BinaryOperator *bo) {
  // 使用0-x代替-x
  Constant *zero = ConstantInt::get(bo->getType(), 0);
  BinaryOperator *op = BinaryOperator::Create(
      Instruction::Sub, zero, bo->getOperand(1), "", bo);
  op = BinaryOperator::Create(Instruction::Sub, bo->getOperand(0), op, "", bo);
  bo->replaceAllUsesWith(op);
}

// a + b 替换为 -(-a + (-b))
// 实现: a + b => -(-a + (-b))
static void addDoubleNeg(BinaryOperator *bo) {
  // 使用0-x代替-x
  Constant *zero = ConstantInt::get(bo->getType(), 0);
  BinaryOperator *op = BinaryOperator::Create(
      Instruction::Sub, zero, bo->getOperand(0), "", bo);
  BinaryOperator *op2 = BinaryOperator::Create(
      Instruction::Sub, zero, bo->getOperand(1), "", bo);
  op = BinaryOperator::Create(Instruction::Add, op, op2, "", bo);
  op = BinaryOperator::Create(Instruction::Sub, zero, op, "", bo);
  bo->replaceAllUsesWith(op);
}

// a + b 替换为使用随机数的等价序列
// 实现: (a + r) + b - r
static void addRand(BinaryOperator *bo) {
  // 生成随机常量
  ConstantInt *co = (ConstantInt *)ConstantInt::get(
      bo->getType(), cryptoutils->get_uint64_t());
  // 步骤1: a + r
  BinaryOperator *op =
      BinaryOperator::Create(Instruction::Add, bo->getOperand(0), co, "", bo);
  // 步骤2: (a + r) + b
  op = BinaryOperator::Create(Instruction::Add, op, bo->getOperand(1), "", bo);
  // 步骤3: ((a + r) + b) - r
  op = BinaryOperator::Create(Instruction::Sub, op, co, "", bo);
  // 替换原始指令
  bo->replaceAllUsesWith(op);
}

// a + b 替换为另一种使用随机数的等价序列
// 实现: (a - r) + b + r
static void addRand2(BinaryOperator *bo) {
  // 生成随机常量
  ConstantInt *co = (ConstantInt *)ConstantInt::get(
      bo->getType(), cryptoutils->get_uint64_t());
  // 步骤1: a - r
  BinaryOperator *op =
      BinaryOperator::Create(Instruction::Sub, bo->getOperand(0), co, "", bo);
  // 步骤2: (a - r) + b
  op = BinaryOperator::Create(Instruction::Add, op, bo->getOperand(1), "", bo);
  // 步骤3: ((a - r) + b) + r
  op = BinaryOperator::Create(Instruction::Add, op, co, "", bo);
  // 替换原始指令
  bo->replaceAllUsesWith(op);
}

// a + b 替换为使用位操作和补码特性的等价序列
// 实现: a + b => a - ~b - 1 (利用补码特性: -x = ~x + 1)
static void addSubstitution(BinaryOperator *bo) {
  // 创建常量1
  Constant *co = ConstantInt::get(bo->getType(), 1);
  // 步骤1: ~b (对b取反)
  BinaryOperator *op = BinaryOperator::CreateNot(bo->getOperand(1), "", bo);
  // 步骤2: -1 (对常量1取负)
  Constant *minusOne = ConstantInt::get(bo->getType(), (uint64_t)-1);
  // 步骤3: ~b - 1
  op = BinaryOperator::Create(Instruction::Sub, op, minusOne, "", bo);
  // 步骤4: a - (~b - 1) = a - ~b + 1 = a + b
  op = BinaryOperator::Create(Instruction::Sub, bo->getOperand(0), op, "", bo);
  // 替换原始指令
  bo->replaceAllUsesWith(op);
}

// a + b 替换为使用位或和位与的等价序列
// 实现: a + b => (a | b) + (a & b) (位级加法定理)
static void addSubstitution2(BinaryOperator *bo) {
  BinaryOperator *op = BinaryOperator::Create(
      Instruction::And, bo->getOperand(0), bo->getOperand(1), "", bo);
  BinaryOperator *op1 = BinaryOperator::Create(
      Instruction::Or, bo->getOperand(0), bo->getOperand(1), "", bo);
  op = BinaryOperator::Create(Instruction::Add, op, op1, "", bo);
  bo->replaceAllUsesWith(op);
}

// a + b 替换为使用位异或和位与的等价序列
// 实现: a + b => (a ^ b) + (a & b) * 2
static void addSubstitution3(BinaryOperator *bo) {
  ConstantInt *co = (ConstantInt *)ConstantInt::get(bo->getType(), 2);
  BinaryOperator *op = BinaryOperator::Create(
      Instruction::And, bo->getOperand(0), bo->getOperand(1), "", bo);
  op = BinaryOperator::Create(Instruction::Mul, op, co, "", bo);
  BinaryOperator *op1 = BinaryOperator::Create(
      Instruction::Xor, bo->getOperand(0), bo->getOperand(1), "", bo);
  op = BinaryOperator::Create(Instruction::Add, op1, op, "", bo);
  bo->replaceAllUsesWith(op);
}

// a + b 替换为 b - (-a)
// 实现: a + b => b - (-a)
static void subNeg(BinaryOperator *bo) {
  // 使用0-x代替-x
  Constant *zero = ConstantInt::get(bo->getType(), 0);
  BinaryOperator *op = BinaryOperator::Create(
      Instruction::Sub, zero, bo->getOperand(1), "", bo);
  op = BinaryOperator::Create(Instruction::Add, bo->getOperand(0), op, "", bo);
  bo->replaceAllUsesWith(op);
}

// a + b 替换为使用随机数的等价序列
// 实现: (a + r) + b - r
static void subRand(BinaryOperator *bo) {
  ConstantInt *co = (ConstantInt *)ConstantInt::get(
      bo->getType(), cryptoutils->get_uint64_t());
  BinaryOperator *op =
      BinaryOperator::Create(Instruction::Add, bo->getOperand(0), co, "", bo);
  op = BinaryOperator::Create(Instruction::Sub, op, bo->getOperand(1), "", bo);
  op = BinaryOperator::Create(Instruction::Sub, op, co, "", bo);
  bo->replaceAllUsesWith(op);
}

// a + b 替换为另一种使用随机数的等价序列
// 实现: (a - r) + b + r
static void subRand2(BinaryOperator *bo) {
  ConstantInt *co = (ConstantInt *)ConstantInt::get(
      bo->getType(), cryptoutils->get_uint64_t());
  BinaryOperator *op =
      BinaryOperator::Create(Instruction::Sub, bo->getOperand(0), co, "", bo);
  op = BinaryOperator::Create(Instruction::Sub, op, bo->getOperand(1), "", bo);
  op = BinaryOperator::Create(Instruction::Add, op, co, "", bo);
  bo->replaceAllUsesWith(op);
}

// a - b 替换为使用位操作和补码特性的等价序列
// 实现: a - b => (b & ~a) - (~b & a)
static void subSubstitution(BinaryOperator *bo) {
  BinaryOperator *op1 = BinaryOperator::CreateNot(bo->getOperand(0), "", bo);
  BinaryOperator *op =
      BinaryOperator::Create(Instruction::And, op1, bo->getOperand(1), "", bo);
  op1 = BinaryOperator::CreateNot(bo->getOperand(1), "", bo);
  BinaryOperator *op2 =
      BinaryOperator::Create(Instruction::And, bo->getOperand(0), op1, "", bo);
  op = BinaryOperator::Create(Instruction::Sub, op2, op, "", bo);
  bo->replaceAllUsesWith(op);
}

// a - b 替换为使用位操作和乘法特性的等价序列
// 实现: a - b => (2 * (b & ~a)) - (b ^ a)
static void subSubstitution2(BinaryOperator *bo) {
  ConstantInt *co = (ConstantInt *)ConstantInt::get(bo->getType(), 2);
  BinaryOperator *op1 = BinaryOperator::Create(
      Instruction::Xor, bo->getOperand(0), bo->getOperand(1), "", bo);
  BinaryOperator *op = BinaryOperator::CreateNot(bo->getOperand(1), "", bo);
  op = BinaryOperator::Create(Instruction::And, bo->getOperand(0), op, "", bo);
  op = BinaryOperator::Create(Instruction::Mul, co, op, "", bo);
  op = BinaryOperator::Create(Instruction::Sub, op, op1, "", bo);
  bo->replaceAllUsesWith(op);
}

// a - b 替换为使用位补码特性的等价序列
// 实现: a - b => b + ~a + 1
static void subSubstitution3(BinaryOperator *bo) {
  ConstantInt *co = (ConstantInt *)ConstantInt::get(bo->getType(), 1);
  BinaryOperator *op1 = BinaryOperator::CreateNot(bo->getOperand(1), "", bo);
  BinaryOperator *op =
      BinaryOperator::Create(Instruction::Add, bo->getOperand(0), op1, "", bo);
  op = BinaryOperator::Create(Instruction::Add, op, co, "", bo);
  bo->replaceAllUsesWith(op);
}

// a & b 替换为使用位异或和位操作的等价序列
// 实现: a & b => (b ^ ~a) & b
static void andSubstitution(BinaryOperator *bo) {
  BinaryOperator *op = BinaryOperator::CreateNot(bo->getOperand(1), "", bo);
  BinaryOperator *op1 =
      BinaryOperator::Create(Instruction::Xor, bo->getOperand(0), op, "", bo);
  op = BinaryOperator::Create(Instruction::And, op1, bo->getOperand(0), "", bo);
  bo->replaceAllUsesWith(op);
}

// a & b 替换为使用位或和位异或非的等价序列
// 实现: a & b => (b | a) & ~(b ^ a)
static void andSubstitution2(BinaryOperator *bo) {
  BinaryOperator *op1 = BinaryOperator::Create(
      Instruction::Xor, bo->getOperand(0), bo->getOperand(1), "", bo);
  op1 = BinaryOperator::CreateNot(op1, "", bo);
  BinaryOperator *op = BinaryOperator::Create(
      Instruction::Or, bo->getOperand(0), bo->getOperand(1), "", bo);
  op = BinaryOperator::Create(Instruction::And, op, op1, "", bo);
  bo->replaceAllUsesWith(op);
}

// a & b 替换为使用加法和补码特性的等价序列
// 实现: a & b => (~b | a) + (b + 1)
static void andSubstitution3(BinaryOperator *bo) {
  ConstantInt *co = (ConstantInt *)ConstantInt::get(bo->getType(), 1);
  BinaryOperator *op1 =
      BinaryOperator::Create(Instruction::Add, bo->getOperand(0), co, "", bo);
  BinaryOperator *op = BinaryOperator::CreateNot(bo->getOperand(0), "", bo);
  op = BinaryOperator::Create(Instruction::Or, op, bo->getOperand(1), "", bo);
  op = BinaryOperator::Create(Instruction::Add, op, op1, "", bo);
  bo->replaceAllUsesWith(op);
}

// a & b 替换为使用随机数和位操作的等价序列
// 实现: a & b => ~(~a | ~b) & (r | ~r)
static void andSubstitutionRand(BinaryOperator *bo) {
  ConstantInt *co = (ConstantInt *)ConstantInt::get(
      bo->getType(), cryptoutils->get_uint64_t());
  BinaryOperator *op = BinaryOperator::CreateNot(bo->getOperand(0), "", bo);
  BinaryOperator *op1 = BinaryOperator::CreateNot(bo->getOperand(1), "", bo);
  BinaryOperator *opr = BinaryOperator::CreateNot(co, "", bo);
  BinaryOperator *opa =
      BinaryOperator::Create(Instruction::Or, op, op1, "", bo);
  opr = BinaryOperator::Create(Instruction::Or, co, opr, "", bo);
  op = BinaryOperator::CreateNot(opa, "", bo);
  op = BinaryOperator::Create(Instruction::And, op, opr, "", bo);
  bo->replaceAllUsesWith(op);
}

// a & b 替换为使用NOR门实现的等价序列
// 实现: a & b => Nor(Nor(a, a), Nor(b, b))
static void andNor(BinaryOperator *bo) {
  BinaryOperator *noraa = buildNor(bo->getOperand(0), bo->getOperand(0), bo);
  BinaryOperator *norbb = buildNor(bo->getOperand(1), bo->getOperand(1), bo);
  bo->replaceAllUsesWith(buildNor(noraa, norbb, bo));
}

// a & b 替换为使用NAND门实现的等价序列
// 实现: a & b => Nand(Nand(a, b), Nand(a, b))
static void andNand(BinaryOperator *bo) {
  BinaryOperator *nandab = buildNand(bo->getOperand(0), bo->getOperand(1), bo);
  BinaryOperator *nandab2 = buildNand(bo->getOperand(0), bo->getOperand(1), bo);
  bo->replaceAllUsesWith(buildNand(nandab, nandab2, bo));
}

// a | b 替换为使用位与和位异或的等价序列
// 实现: a | b => (b & c) | (b ^ c)
static void orSubstitution(BinaryOperator *bo) {
  BinaryOperator *op = BinaryOperator::Create(
      Instruction::And, bo->getOperand(0), bo->getOperand(1), "", bo);
  BinaryOperator *op1 = BinaryOperator::Create(
      Instruction::Xor, bo->getOperand(0), bo->getOperand(1), "", bo);
  op = BinaryOperator::Create(Instruction::Or, op, op1, "", bo);
  bo->replaceAllUsesWith(op);
}

// a | b 替换为使用加法和位操作的等价序列
// 实现: a | b => a + (a ^ b) - (b & ~a)
static void orSubstitution2(BinaryOperator *bo) {
  BinaryOperator *op1 = BinaryOperator::CreateNot(bo->getOperand(1), "", bo);
  op1 =
      BinaryOperator::Create(Instruction::And, bo->getOperand(0), op1, "", bo);
  BinaryOperator *op = BinaryOperator::Create(
      Instruction::Xor, bo->getOperand(0), bo->getOperand(1), "", bo);
  op = BinaryOperator::Create(Instruction::Add, bo->getOperand(0), op, "", bo);
  op = BinaryOperator::Create(Instruction::Sub, op, op1, "", bo);
  bo->replaceAllUsesWith(op);
}

// a | b 替换为使用加法和补码特性的等价序列
// 实现: a | b => a + c + 1 + ~(c & b)
static void orSubstitution3(BinaryOperator *bo) {
  ConstantInt *co = (ConstantInt *)ConstantInt::get(bo->getType(), 1);
  BinaryOperator *op1 = BinaryOperator::Create(
      Instruction::And, bo->getOperand(1), bo->getOperand(0), "", bo);
  op1 = BinaryOperator::CreateNot(op1, "", bo);
  BinaryOperator *op = BinaryOperator::Create(
      Instruction::Add, bo->getOperand(0), bo->getOperand(1), "", bo);
  op = BinaryOperator::Create(Instruction::Add, op, co, "", bo);
  op = BinaryOperator::Create(Instruction::Add, op, op1, "", bo);
  bo->replaceAllUsesWith(op);
}

// a | b 替换为使用随机数和位操作的等价序列
// 实现: a | b => (((~a & r) | (a & ~r)) ^ ((~b & r) | (b & ~r))) | (~(~a | ~b) & (r | ~r))
static void orSubstitutionRand(BinaryOperator *bo) {
  ConstantInt *co = (ConstantInt *)ConstantInt::get(
      bo->getType(), cryptoutils->get_uint64_t());
  BinaryOperator *op = BinaryOperator::CreateNot(bo->getOperand(0), "", bo);
  BinaryOperator *op1 = BinaryOperator::CreateNot(bo->getOperand(1), "", bo);
  BinaryOperator *op2 = BinaryOperator::CreateNot(co, "", bo);
  BinaryOperator *op3 =
      BinaryOperator::Create(Instruction::And, op, co, "", bo);
  BinaryOperator *op4 =
      BinaryOperator::Create(Instruction::And, bo->getOperand(0), op2, "", bo);
  BinaryOperator *op5 =
      BinaryOperator::Create(Instruction::And, op1, co, "", bo);
  BinaryOperator *op6 =
      BinaryOperator::Create(Instruction::And, bo->getOperand(1), op2, "", bo);
  op3 = BinaryOperator::Create(Instruction::Or, op3, op4, "", bo);
  op4 = BinaryOperator::Create(Instruction::Or, op5, op6, "", bo);
  op5 = BinaryOperator::Create(Instruction::Xor, op3, op4, "", bo);
  op3 = BinaryOperator::Create(Instruction::Or, op, op1, "", bo);
  op3 = BinaryOperator::CreateNot(op3, "", bo);
  op4 = BinaryOperator::Create(Instruction::Or, co, op2, "", bo);
  op4 = BinaryOperator::Create(Instruction::And, op3, op4, "", bo);
  op = BinaryOperator::Create(Instruction::Or, op5, op4, "", bo);
  bo->replaceAllUsesWith(op);
}

// a | b 替换为使用NOR门实现的等价序列
// 实现: a | b => Nor(Nor(a, b), Nor(a, b))
static void orNor(BinaryOperator *bo) {
  BinaryOperator *norab = buildNor(bo->getOperand(0), bo->getOperand(1), bo);
  BinaryOperator *norab2 = buildNor(bo->getOperand(0), bo->getOperand(1), bo);
  BinaryOperator *op = buildNor(norab, norab2, bo);
  bo->replaceAllUsesWith(op);
}

// a | b 替换为使用NAND门实现的等价序列
// 实现: a | b => Nand(Nand(a, a), Nand(b, b))
static void orNand(BinaryOperator *bo) {
  BinaryOperator *nandaa = buildNand(bo->getOperand(0), bo->getOperand(0), bo);
  BinaryOperator *nandbb = buildNand(bo->getOperand(1), bo->getOperand(1), bo);
  BinaryOperator *op = buildNand(nandaa, nandbb, bo);
  bo->replaceAllUsesWith(op);
}

// a ^ b 替换为使用位与和位或的等价序列
// 实现: a ^ b => (~a & b) | (a & ~b)
static void xorSubstitution(BinaryOperator *bo) {
  BinaryOperator *op = BinaryOperator::CreateNot(bo->getOperand(0), "", bo);
  op = BinaryOperator::Create(Instruction::And, bo->getOperand(1), op, "", bo);
  BinaryOperator *op1 = BinaryOperator::CreateNot(bo->getOperand(1), "", bo);
  op1 =
      BinaryOperator::Create(Instruction::And, bo->getOperand(0), op1, "", bo);
  op = BinaryOperator::Create(Instruction::Or, op, op1, "", bo);
  bo->replaceAllUsesWith(op);
}

// a ^ b 替换为使用加法和位与的等价序列
// 实现: a ^ b => (b + c) - 2 * (b & c)
static void xorSubstitution2(BinaryOperator *bo) {
  ConstantInt *co = (ConstantInt *)ConstantInt::get(bo->getType(), 2);
  BinaryOperator *op1 = BinaryOperator::Create(
      Instruction::And, bo->getOperand(0), bo->getOperand(1), "", bo);
  op1 = BinaryOperator::Create(Instruction::Mul, co, op1, "", bo);
  BinaryOperator *op = BinaryOperator::Create(
      Instruction::Add, bo->getOperand(0), bo->getOperand(1), "", bo);
  op = BinaryOperator::Create(Instruction::Sub, op, op1, "", bo);
  bo->replaceAllUsesWith(op);
}

// a ^ b 替换为使用位操作和减法的等价序列
// 实现: a ^ b => b - (2 * (c & ~(b ^ c)) - c)
static void xorSubstitution3(BinaryOperator *bo) {
  ConstantInt *co = (ConstantInt *)ConstantInt::get(bo->getType(), 2);
  BinaryOperator *op1 = BinaryOperator::Create(
      Instruction::Xor, bo->getOperand(0), bo->getOperand(1), "", bo);
  op1 = BinaryOperator::CreateNot(op1, "", bo);
  op1 =
      BinaryOperator::Create(Instruction::And, bo->getOperand(1), op1, "", bo);
  op1 = BinaryOperator::Create(Instruction::Mul, co, op1, "", bo);
  op1 =
      BinaryOperator::Create(Instruction::Sub, op1, bo->getOperand(1), "", bo);
  BinaryOperator *op =
      BinaryOperator::Create(Instruction::Sub, bo->getOperand(0), op1, "", bo);
  bo->replaceAllUsesWith(op);
}

// a ^ b 替换为使用随机数和位操作的等价序列
// 实现: a ^ b => (~a & r | a & ~r) ^ (~b & r | b & ~r)
static void xorSubstitutionRand(BinaryOperator *bo) {
  ConstantInt *co = (ConstantInt *)ConstantInt::get(
      bo->getType(), cryptoutils->get_uint64_t());
  BinaryOperator *op = BinaryOperator::CreateNot(bo->getOperand(0), "", bo);
  op = BinaryOperator::Create(Instruction::And, co, op, "", bo);
  BinaryOperator *opr = BinaryOperator::CreateNot(co, "", bo);
  BinaryOperator *op1 =
      BinaryOperator::Create(Instruction::And, bo->getOperand(0), opr, "", bo);
  BinaryOperator *op2 = BinaryOperator::CreateNot(bo->getOperand(1), "", bo);
  op2 = BinaryOperator::Create(Instruction::And, op2, co, "", bo);
  BinaryOperator *op3 =
      BinaryOperator::Create(Instruction::And, bo->getOperand(1), opr, "", bo);
  op = BinaryOperator::Create(Instruction::Or, op, op1, "", bo);
  op1 = BinaryOperator::Create(Instruction::Or, op2, op3, "", bo);
  op = BinaryOperator::Create(Instruction::Xor, op, op1, "", bo);
  bo->replaceAllUsesWith(op);
}

// a ^ b 替换为使用NOR门实现的等价序列
// 实现: a ^ b => Nor(Nor(Nor(a, a), Nor(b, b)), Nor(a, b))
static void xorNor(BinaryOperator *bo) {
  BinaryOperator *noraa = buildNor(bo->getOperand(0), bo->getOperand(0), bo);
  BinaryOperator *norbb = buildNor(bo->getOperand(1), bo->getOperand(1), bo);
  BinaryOperator *nornoraanorbb = buildNor(noraa, norbb, bo);
  BinaryOperator *norab = buildNor(bo->getOperand(0), bo->getOperand(1), bo);
  BinaryOperator *op = buildNor(nornoraanorbb, norab, bo);
  bo->replaceAllUsesWith(op);
}

// a ^ b 替换为使用NAND门实现的等价序列
// 实现: a ^ b => Nand(Nand(Nand(a, a), b), Nand(a, Nand(b, b)))
static void xorNand(BinaryOperator *bo) {
  BinaryOperator *nandaa = buildNand(bo->getOperand(0), bo->getOperand(0), bo);
  BinaryOperator *nandnandaab = buildNand(nandaa, bo->getOperand(1), bo);
  BinaryOperator *nandbb = buildNand(bo->getOperand(1), bo->getOperand(1), bo);
  BinaryOperator *nandanandbb = buildNand(bo->getOperand(0), nandbb, bo);
  BinaryOperator *op = buildNand(nandnandaab, nandanandbb, bo);
  bo->replaceAllUsesWith(op);
}

// a * b 替换为使用位操作和加法的等价序列
// 实现: a * b => (((b | c) * (b & c)) + ((b & ~c) * (c & ~b)))
static void mulSubstitution(BinaryOperator *bo) {
  BinaryOperator *op1 = BinaryOperator::CreateNot(bo->getOperand(0), "", bo);
  op1 =
      BinaryOperator::Create(Instruction::And, bo->getOperand(1), op1, "", bo);
  BinaryOperator *op2 = BinaryOperator::CreateNot(bo->getOperand(1), "", bo);
  op2 =
      BinaryOperator::Create(Instruction::And, bo->getOperand(0), op2, "", bo);
  BinaryOperator *op =
      BinaryOperator::Create(Instruction::Mul, op2, op1, "", bo);
  op1 = BinaryOperator::Create(Instruction::And, bo->getOperand(0),
                               bo->getOperand(1), "", bo);
  op2 = BinaryOperator::Create(Instruction::Or, bo->getOperand(0),
                               bo->getOperand(1), "", bo);
  BinaryOperator *op3 =
      BinaryOperator::Create(Instruction::Mul, op2, op1, "", bo);
  op = BinaryOperator::Create(Instruction::Add, op3, op, "", bo);
  bo->replaceAllUsesWith(op);
}

// a * b 替换为使用另一种位操作和加法的等价序列
// 实现: a * b => (((b | c) * (b & c)) + ((~(b | ~c)) * (b & ~c)))
static void mulSubstitution2(BinaryOperator *bo) {
  BinaryOperator *op1 = BinaryOperator::CreateNot(bo->getOperand(1), "", bo);
  BinaryOperator *op2 =
      BinaryOperator::Create(Instruction::And, bo->getOperand(0), op1, "", bo);
  BinaryOperator *op3 =
      BinaryOperator::Create(Instruction::Or, bo->getOperand(0), op1, "", bo);
  op3 = BinaryOperator::CreateNot(op3, "", bo);
  op3 = BinaryOperator::Create(Instruction::Mul, op3, op2, "", bo);
  BinaryOperator *op4 = BinaryOperator::Create(
      Instruction::And, bo->getOperand(0), bo->getOperand(1), "", bo);
  BinaryOperator *op5 = BinaryOperator::Create(
      Instruction::Or, bo->getOperand(0), bo->getOperand(1), "", bo);
  op5 = BinaryOperator::Create(Instruction::Mul, op5, op4, "", bo);
  BinaryOperator *op =
      BinaryOperator::Create(Instruction::Add, op5, op3, "", bo);
  bo->replaceAllUsesWith(op);
}

// SubstituteImpl类的实现，为每种操作随机选择一种替换方法
void substituteAdd(BinaryOperator *bo) {
  // 随机选择一种加法替换方法
  (*funcAdd[cryptoutils->get_range(NUMBER_ADD_SUBST)])(bo);
}
void substituteSub(BinaryOperator *bo) {
  // 随机选择一种减法替换方法
  (*funcSub[cryptoutils->get_range(NUMBER_SUB_SUBST)])(bo);
}
void substituteAnd(BinaryOperator *bo) {
  // 随机选择一种与操作替换方法
  (*funcAnd[cryptoutils->get_range(NUMBER_AND_SUBST)])(bo);
}
void substituteOr(BinaryOperator *bo) {
  // 随机选择一种或操作替换方法
  (*funcOr[cryptoutils->get_range(NUMBER_OR_SUBST)])(bo);
}
void substituteXor(BinaryOperator *bo) {
  // 随机选择一种异或操作替换方法
  (*funcXor[cryptoutils->get_range(NUMBER_XOR_SUBST)])(bo);
}
void substituteMul(BinaryOperator *bo) {
  // 随机选择一种乘法替换方法
  (*funcMul[cryptoutils->get_range(NUMBER_MUL_SUBST)])(bo);
}

} // namespace SubstituteImpl
} // namespace ni_pass
