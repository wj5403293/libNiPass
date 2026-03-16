# NiPass - Enhanced LLVM Obfuscation Passes

基于 LLVM 19 的增强混淆 Pass 集合。

## 构建

```bash
mkdir build && cd build
cmake ..
cmake --build .
```

产物：`lib/libNiPass-<version>.so`

## Pass 列表

| 开关 | 注解名 | 说明 |
|------|--------|------|
| `-enstrenc` | `enstrenc` | 增强字符串加密 |
| `-enfla` | `enfla` | 增强控制流平坦化 |
| `-envmf` | `envmf` | 增强 VM 平坦化 |
| `-eicall` | `eicall` | 增强间接调用 |
| `-eigv` | `eigv` | 增强间接全局变量 |
| `-eibr` | `eibr` | 增强间接分支 |

## 使用方式

### 方式一：命令行全局开关

使用 `-fplugin` 加载插件，通过 `-mllvm` 传递开关，对所有函数生效。

```bash
# 开启字符串加密 + 平坦化
clang-19 -fplugin=./lib/libNiPass-19.1.1.so -O1 \
  -mllvm -enstrenc -mllvm -enfla \
  test.c -o test

# 开启全部 pass
clang-19 -fplugin=./lib/libNiPass-19.1.1.so -O1 \
  -mllvm -enstrenc -mllvm -enfla -mllvm -envmf \
  -mllvm -eicall -mllvm -eigv -mllvm -eibr \
  test.c -o test
```

> 注意：必须用 `-fplugin` 而非 `-fpass-plugin`，后者加载时机晚于命令行解析，`-mllvm` 开关无法识别。

### 方式二：函数注解驱动

使用 `-fpass-plugin` 加载插件，通过 `__attribute__((annotate(...)))` 逐函数控制。

```c
// 对该函数开启字符串加密
__attribute__((annotate("enstrenc")))
void secret_func() {
    const char *key = "my_secret_key";
    printf("%s\n", key);
}

// 对该函数开启 VM 平坦化
__attribute__((annotate("envmf")))
int compute(int x) {
    if (x > 10) return x * 2;
    return x + 1;
}

// 不加注解的函数不会被混淆
int normal(int x) {
    return x + 1;
}
```

```bash
clang-19 -fpass-plugin=./lib/libNiPass-19.1.1.so -O1 test.c -o test
```

### 方式三：命令行 + 注解混合

用 `-fplugin` + `-mllvm` 设置全局默认，再用注解逐函数覆盖：

- 注解 `enstrenc` → 强制开启（即使全局未开）
- 注解 `noenstrenc` → 强制关闭（即使全局已开）

```bash
# 全局开启字符串加密，但个别函数可用 noenstrenc 关闭
clang-19 -fplugin=./lib/libNiPass-19.1.1.so -O1 \
  -mllvm -enstrenc \
  test.c -o test
```

```c
// 全局已开启 enstrenc，此函数强制关闭
__attribute__((annotate("noenstrenc")))
void skip_this() { ... }
```

## CMake 集成

项目提供了 CMake 脚本（`testarm64/CMakeLists.txt`）用于 Android ARM64 交叉编译，支持通过 CMake 变量切换两种插件加载模式。

### CMake 变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `ENABLE_OBFUSCATION` | `ON` | 是否启用 NiPass 混淆 |
| `NIPASS_LIB` | `../lib/libNiPass-19.0.0.so` | NiPass 插件路径 |
| `PLUGIN_MODE` | `fpass-plugin` | 插件加载模式：`fpass-plugin`（注解驱动）或 `fplugin`（全局开关） |
| `NIPASS_PASSES` | `-enstrenc;-enfla` | 方式一的 `-mllvm` 开关列表，仅 `fplugin` 模式生效 |

### 方式一：全局开关（fplugin）

通过 `-fplugin` 加载插件，`-mllvm` 传递开关，对所有函数生效：

```bash
cmake -S testarm64 -B build \
  -DPLUGIN_MODE=fplugin \
  -DNIPASS_PASSES="-enstrenc;-enfla"
cmake --build build -j$(nproc)
```

开启全部 pass：

```bash
cmake -S testarm64 -B build \
  -DPLUGIN_MODE=fplugin \
  -DNIPASS_PASSES="-enstrenc;-enfla;-envmf;-eicall;-eigv;-eibr"
cmake --build build -j$(nproc)
```

### 方式二：注解驱动（fpass-plugin）

通过 `-fpass-plugin` 加载插件，由源码中的 `__attribute__((annotate(...)))` 逐函数控制：

```bash
cmake -S testarm64 -B build \
  -DPLUGIN_MODE=fpass-plugin
cmake --build build -j$(nproc)
```

### 不启用混淆（对照组）

```bash
cmake -S testarm64 -B build \
  -DENABLE_OBFUSCATION=OFF
cmake --build build -j$(nproc)
```

### 自定义插件路径

```bash
cmake -S testarm64 -B build \
  -DNIPASS_LIB=/path/to/libNiPass-19.0.0.so
```

> CMake 脚本内部使用 `SHELL:` 前缀确保每个 `-mllvm <pass>` 参数正确配对，避免被 CMake 去重合并。

## 作者

Made By Ni-QiuQiu
