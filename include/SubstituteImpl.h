#ifndef _SUBSTITUTE_IMPL_H
#define _SUBSTITUTE_IMPL_H

#include "llvm/IR/InstrTypes.h"

using namespace llvm;

namespace ni_pass {

namespace SubstituteImpl {

void substituteAdd(BinaryOperator *bo);
void substituteSub(BinaryOperator *bo);
void substituteAnd(BinaryOperator *bo);
void substituteOr(BinaryOperator *bo);
void substituteXor(BinaryOperator *bo);
void substituteMul(BinaryOperator *bo);

} // namespace SubstituteImpl

} // namespace ni_pass

#endif
