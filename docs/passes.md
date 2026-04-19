# NiPass 混淆 Pass 详解

本文档详细介绍 NiPass 中每个混淆 Pass 的原理、技术实现和安全特性。

---

## 1. EnhancedStringEncryption（增强字符串加密）

**开关**: `-enstrenc` | **注解**: `enstrenc` / `noenstrenc`

### 原理

将编译产物中的明文字符串在编译期加密存储，运行时按需解密到独立的 DecryptSpace，函数返回时自动清零，防止内存 dump 提取。

### 技术特性

- **多层异构加密** — 每个字符串随机选择以下模式之一：
  - `XOR_ONLY`: `enc = val ^ K1`
  - `XOR_SUB`: `enc = (val ^ K1) - K2`
  - `XOR_ADD`: `enc = (val ^ K1) + K2`
  - `XOR_ADD_XOR`: `enc = ((val ^ K1) + K2) ^ K3`
- **XOR 密钥混淆** — 解密循环中的 XOR 操作通过 SubstituteImpl 替换为等价复杂表达式，增加逆向分析难度
- **GV/BB/指令名随机化** — 消除符号特征匹配；新生成的私有全局变量使用随机但非空的名字，避免污染 `llvm.compiler.used`
- **每函数独立副本** — 取消跨函数共享，同一字符串在不同函数中使用不同密钥
- **DecryptSpace 生命周期管理** — 函数返回前自动清零解密缓冲区

### 命令行参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-enstrcry_prob` | 100 | 每个元素被加密的概率 (%) |
| `-enstrcry_subxor_prob` | 50 | XOR 操作被替换为复杂表达式的概率 (%) |
| `-enstrcry_cleanup` | true | 函数返回时是否清零 DecryptSpace |

---

## 2. FlatteningEnhanced（增强控制流平坦化）

**开关**: `-enfla` | **注解**: `enfla` / `noenfla`

### 原理

将函数的原始控制流图（CFG）打散为 switch-case 结构，所有基本块在同一层级由一个调度变量驱动跳转，破坏原始的分支/循环结构，使反编译器难以恢复高层逻辑。

### 技术特性

- **非线性哈希调度** — 状态变量通过非线性哈希函数 `(XOR → MUL 0x9E3779B9 → ROTL 13 → ADD 0xDEADBEEF)` 计算下一跳，而非简单赋值，防止模式匹配还原
- **按支配链顺序派生 key_map** — 编译期状态密钥按 `entry -> ... -> idom` 顺序累积，与运行时 key 更新顺序保持一致，避免 dispatcher 落入默认分支死循环
- **XOR 等价表达式混淆** — 调度逻辑中的 XOR 操作随机替换为 4 种等价变体：
  - `(a | b) - (a & b)`
  - `(a + b) - 2*(a & b)`
  - `(a & ~b) | (~a & b)`
  - `~(~a ^ b)` 双重否定展开
- **随机化 case 值** — 每个基本块的 case 标签使用密码学安全随机数生成
- **显式 case 映射维护** — 对后继块统一维护 `BasicBlock -> case` 映射，避免出现“生成了 fixNum 但目标块未注册到 switch”的无效状态

---

## 3. EnVMFlatten（增强 VM 平坦化）

**开关**: `-envmf` | **注解**: `envmf` / `noenvmf`

### 原理

将函数的控制流编译为自定义虚拟机字节码，运行时由一个解释器循环（dispatcher）逐条执行。相比普通平坦化，VM 化引入了额外的间接层，使静态分析必须先理解 VM 语义才能还原逻辑。

### 技术特性

- **多态指令编码** — 每个函数随机生成不同的指令类型映射（`VMTypeMap`），同一语义指令在不同函数中编码不同
  - `RunBlock` — 执行基本块
  - `JmpBoring` — 无条件跳转
  - `JmpSelect` — 条件跳转
  - `VmNop` — 空操作（干扰分析）
- **Dummy 指令插入** — 在字节码序列中插入无效指令，增加字节码体积和分析噪声
- **操作数 XOR 编码** — 字节码中的操作数经过 XOR 密钥编码，运行时解码后使用
- **字节码 XOR 加密** — 整个字节码数组可进一步加密存储

---

## 4. EnhancedIndirectCall（增强间接调用）

**开关**: `-eicall` | **注解**: `eicall` / `noeicall`

### 原理

将函数中的直接调用（`call @func`）替换为通过加密函数指针表的间接调用。编译时将目标函数地址加密存入全局表，运行时从表中取出并解密后再调用。

### 技术特性

- **Per-entry 独立密钥** — 每个被调用函数拥有 4 个独立的 64 位密钥（`key1~key4`）
- **4 密钥 XOR-ADD 混合加密** —
  - 编译时：`combined = (key1 ^ key2) + (key3 ^ key4)`，`stored = ptr + combined`
  - 运行时：重建 `combined`，`ptr = stored - combined`
- **3 种多态解密变体** — 每个 entry 随机选择：
  - 变体 0：标准 XOR + ADD 重建，SUB 解密
  - 变体 1：NOT-XOR 恒等式重建，NEG 替代 SUB
  - 变体 2：OR-AND 分解 XOR，NOT 恒等式解密
- **密钥拆分** — 每个密钥在运行时拆分为 2~3 个部分通过 XOR 合成，增加提取难度
- **随机化表名** — 全局表名使用随机后缀，防止符号匹配

---

## 5. EnhancedIndirectGlobalVariable（增强间接全局变量）

**开关**: `-eigv` | **注解**: `eigv` / `noeigv`

### 原理

将函数中对全局变量的直接引用替换为通过加密指针表的间接访问。编译时将全局变量地址经过 XOR + ADD 加密存入表中，运行时解密后再访问，隐藏代码与数据之间的交叉引用关系。

### 技术特性

- **Per-entry 独立密钥** — 每个全局变量拥有独立的 `key1`（XOR 密钥）和 `key2`（ADD 偏移密钥）
- **2 密钥 XOR-ADD 加密** —
  - 编译时：`stored = (ptr ^ key1) + key2`
  - 运行时：`ptr = (stored - key2) ^ key1`
- **3 种多态解密变体** — 每个 entry 随机选择：
  - 变体 0：标准 SUB → XOR
  - 变体 1：NEG + ADD 替代 SUB
  - 变体 2：XOR-NOT-NOT 恒等式 `~(val ^ ~key) == val ^ key`
- **密钥拆分** — 运行时密钥拆分为 2~3 个部分通过 XOR 合成
- **Per-function 作用域** — 每个函数独立收集和编号全局变量，生成独立的加密表

---

## 6. EnhancedIndirectBranch（增强间接分支）

**开关**: `-eibr` | **注解**: `eibr` / `noeibr`

### 原理

将函数内的条件/无条件分支替换为通过加密基本块地址表的间接跳转。编译时将所有非入口基本块的地址加密存入全局表，运行时解密后通过 `indirectbr` 指令跳转，破坏 CFG 的静态可分析性。

### 技术特性

- **Per-BB 独立密钥** — 每个基本块拥有 4 个独立的 64 位密钥（`key1~key4`）
- **4 密钥 XOR-ADD 混合加密** — 与 EnhancedIndirectCall 共享 `emitDecrypt4Key` 模板：
  - 编译时：`combined = (key1 ^ key2) + (key3 ^ key4)`，`stored = ptr + combined`
  - 运行时：重建 `combined`，`ptr = stored - combined`
- **3 种多态解密变体** — 同 EnhancedIndirectCall
- **索引混淆** — 每个函数拥有独立的 `funcIndexKey`，基本块索引经过 XOR 混淆后存储
- **基本块乱序（BB Shuffle）** — 混淆后对函数内基本块重新排列，破坏原始布局顺序
- **栈模式间接跳转** — 可选通过 `-eibr-use-stack` 启用基于栈的间接跳转方式（默认开启）
- **LowerSwitch 前置** — 自动将 switch 指令降级为 if-else 链后再处理

---

## 加密基础设施

以上 Pass 共享以下底层加密工具：

### EncryptUtils（加密工具模板）

- **`emitSplitKey`** — 将单个密钥拆分为 2~3 个随机部分，运行时通过 XOR 合成还原，防止密钥被直接提取
- **`emitDecrypt4Key`** — 4 密钥 XOR-ADD 多态解密模板，被 EnhancedIndirectCall 和 EnhancedIndirectBranch 共用

### CryptoUtils

- 提供密码学安全的随机数生成（`get_uint32_t`、`get_uint64_t`、`get_range`）
- 所有密钥、case 值、表名后缀均由此生成

### SubstituteImpl

- 将简单的算术/逻辑运算替换为语义等价的复杂表达式
- 被 EnhancedStringEncryption 用于混淆解密循环中的 XOR 操作

---

## Pass 执行顺序

在 `PassRegistry` 中，各 Pass 按以下顺序注册执行：

```
1. EnhancedStringEncryption  (Module Pass)  — 字符串加密
2. EnVMFlatten               (Function Pass) — VM 平坦化
3. EnhancedIndirectCall       (Function Pass) — 间接调用
4. EnhancedIndirectBranch     (Function Pass) — 间接分支
5. FlatteningEnhanced         (Module Pass)  — 控制流平坦化
6. EnhancedIndirectGlobalVariable (Module Pass) — 间接全局变量
```

> 字符串加密最先执行以确保密文 GV 已就位；间接全局变量最后执行以覆盖前序 Pass 产生的新全局引用。
