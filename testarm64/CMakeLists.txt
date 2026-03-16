cmake_minimum_required(VERSION 3.18)


# ----------------------------------------------------------------------------
# NDK 路径配置
# ----------------------------------------------------------------------------
# 优先使用环境变量 ANDROID_NDK，否则使用默认路径
if(NOT DEFINED ANDROID_NDK)
    if(WIN32)
        # Windows 默认路径，可以通过 -DANDROID_NDK=<路径> 覆盖
        set(CMAKE_ANDROID_NDK "D:/ndkollvm/android-ndk-r27c-windows/android-ndk-r27c" 
            CACHE PATH "Android NDK path")
    else()
        # Linux 默认路径
        set(CMAKE_ANDROID_NDK "/home/qiu/Android/android-ndk-r28c" 
            CACHE PATH "Android NDK path")
    endif()
else()
    set(CMAKE_ANDROID_NDK ${ANDROID_NDK})
endif()

# 设置 Android 工具链
set(CMAKE_SYSTEM_NAME ANDROID)
set(CMAKE_TOOLCHAIN_FILE ${CMAKE_ANDROID_NDK}/build/cmake/android.toolchain.cmake)

# Android 平台配置
set(CMAKE_ANDROID_ARCH_ABI arm64-v8a)
set(ANDROID_ABI arm64-v8a)
set(ANDROID_PLATFORM android-26)
set(ANDROID_NDK ${CMAKE_ANDROID_NDK})


# ============================================================================
# 项目定义
# ============================================================================
project(NiPassTestARM64)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
set(CMAKE_CXX_STANDARD 23)

# ============================================================================
# NiPass 插件配置
# ============================================================================
set(NIPASS_LIB "${CMAKE_SOURCE_DIR}/../lib/libNiPass-19.0.0.so"
    CACHE FILEPATH "Path to NiPass plugin .so")

# 是否启用混淆（默认开启）
option(ENABLE_OBFUSCATION "Enable NiPass obfuscation" ON)

# 插件加载模式: "fpass-plugin" (方式二，注解驱动) 或 "fplugin" (方式一，全局开关)
set(PLUGIN_MODE "fpass-plugin" CACHE STRING "Plugin loading mode: fpass-plugin or fplugin")

# 方式一全局开关列表（仅 fplugin 模式生效）
set(NIPASS_PASSES "-enstrenc;-enfla" CACHE STRING "NiPass -mllvm passes for fplugin mode")

if(ENABLE_OBFUSCATION AND EXISTS "${NIPASS_LIB}")
    message(STATUS "NiPass plugin: ${NIPASS_LIB}")
    message(STATUS "Plugin mode: ${PLUGIN_MODE}")
    if(PLUGIN_MODE STREQUAL "fplugin")
        # 方式一：-fplugin + -mllvm 全局开关
        add_compile_options(-fplugin=${NIPASS_LIB})
        foreach(pass ${NIPASS_PASSES})
            add_compile_options("SHELL:-mllvm ${pass}")
        endforeach()
        message(STATUS "Global passes: ${NIPASS_PASSES}")
    else()
        # 方式二：-fpass-plugin 注解驱动
        add_compile_options(-fpass-plugin=${NIPASS_LIB})
    endif()
elseif(ENABLE_OBFUSCATION)
    message(WARNING "NiPass plugin not found: ${NIPASS_LIB}, building without obfuscation")
endif()

# ============================================================================
# 测试目标
# ============================================================================
# 基础测试 - 覆盖各类混淆场景
add_executable(test_nipass test.c)
target_compile_options(test_nipass PRIVATE -O1)

# 生产级测试 - 模拟真实 native 库场景
add_executable(test_production test_production.c)
target_compile_options(test_production PRIVATE -O1)

# STL 测试 - 容器/算法/智能指针/variant
add_executable(test_stl test_stl.cpp)
target_compile_options(test_stl PRIVATE -O1)

# 模板元编程测试 - CRTP/SFINAE/表达式模板/策略模式
add_executable(test_template test_template.cpp)
target_compile_options(test_template PRIVATE -O1)

# 注解子选项测试 - 方式二注解驱动的子配置选项
add_executable(test_annotate test_annotate.c)
target_compile_options(test_annotate PRIVATE -O1)
