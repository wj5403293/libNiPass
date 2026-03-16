#!/bin/bash
# NiPass ARM64 远程 LLDB 调试脚本
# 使用 NDK lldb + lldb-server 进行远程调试
#
# 用法:
#   ./remote_debug.sh                          # 调试 test_nipass_obf
#   ./remote_debug.sh test_production_obf      # 调试指定二进制
#   ./remote_debug.sh -s <serial> <binary>     # 指定设备
#   ./remote_debug.sh --setup-only             # 仅部署 lldb-server，不启动调试
#   ./remote_debug.sh --cleanup                # 清理设备上的调试文件

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="${SCRIPT_DIR}/bin"
DEVICE_DIR="/data/local/tmp/nipass_debug"

# NDK 路径
NDK_ROOT="/home/qiu/Android/android-ndk-r28c"
NDK_LLVM="${NDK_ROOT}/toolchains/llvm/prebuilt/linux-x86_64"
LLDB="${NDK_LLVM}/bin/lldb.sh"
LLDB_SERVER_LOCAL="${NDK_LLVM}/lib/clang/19/lib/linux/aarch64/lldb-server"

# 调试端口
DEBUG_PORT=12345

# 解析参数
ADB_SERIAL=""
BINARY_NAME=""
SETUP_ONLY=false
CLEANUP=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        -s)
            ADB_SERIAL="$2"
            shift 2
            ;;
        --setup-only)
            SETUP_ONLY=true
            shift
            ;;
        --cleanup)
            CLEANUP=true
            shift
            ;;
        *)
            BINARY_NAME="$1"
            shift
            ;;
    esac
done
BINARY_NAME="${BINARY_NAME:-test_nipass_obf}"

# adb 命令封装
ADB="adb"
if [ -n "$ADB_SERIAL" ]; then
    ADB="adb -s $ADB_SERIAL"
fi

check_prerequisites() {
    # 检查 lldb
    if [ ! -f "$LLDB" ]; then
        echo "[ERROR] LLDB not found: $LLDB"
        echo "  请检查 NDK 路径是否正确"
        exit 1
    fi

    # 检查 lldb-server
    if [ ! -f "$LLDB_SERVER_LOCAL" ]; then
        echo "[ERROR] lldb-server not found: $LLDB_SERVER_LOCAL"
        exit 1
    fi

    # 检查设备
    if ! $ADB devices 2>/dev/null | grep -qw "device"; then
        echo "[ERROR] 没有连接的设备"
        exit 1
    fi

    local dev=$($ADB shell getprop ro.product.model 2>/dev/null | tr -d '\r')
    local abi=$($ADB shell getprop ro.product.cpu.abi 2>/dev/null | tr -d '\r')
    echo "  设备: ${dev} (${abi})"
}

setup_device() {
    echo "[1/3] 部署 lldb-server 到设备..."
    $ADB shell "mkdir -p ${DEVICE_DIR}" 2>/dev/null

    # 检查设备上是否已有 lldb-server
    if $ADB shell "[ -f ${DEVICE_DIR}/lldb-server ]" 2>/dev/null; then
        echo "  lldb-server 已存在，跳过推送"
    else
        $ADB push "$LLDB_SERVER_LOCAL" "${DEVICE_DIR}/lldb-server" 2>&1 | sed 's/^/  /'
        $ADB shell "chmod 755 ${DEVICE_DIR}/lldb-server"
    fi
}

push_binary() {
    local local_bin="${BIN_DIR}/${BINARY_NAME}"
    if [ ! -f "$local_bin" ]; then
        echo "[ERROR] 二进制文件不存在: $local_bin"
        echo "  可用文件:"
        ls -1 "${BIN_DIR}/" 2>/dev/null | sed 's/^/    /'
        exit 1
    fi

    echo "[2/3] 推送测试二进制 ${BINARY_NAME}..."
    $ADB push "$local_bin" "${DEVICE_DIR}/${BINARY_NAME}" 2>&1 | sed 's/^/  /'
    $ADB shell "chmod 755 ${DEVICE_DIR}/${BINARY_NAME}"
}

start_debug_session() {
    echo "[3/3] 启动远程调试..."
    echo ""

    # 杀掉旧的 lldb-server 进程
    $ADB shell "pkill -f lldb-server" 2>/dev/null || true
    sleep 0.5

    # 在设备上启动 lldb-server（platform 模式）
    echo "  在设备上启动 lldb-server (端口 ${DEBUG_PORT})..."
    $ADB shell "${DEVICE_DIR}/lldb-server platform --listen '*:${DEBUG_PORT}' --server" &
    LLDB_SERVER_PID=$!
    sleep 1

    # 设置 adb 端口转发
    $ADB forward tcp:${DEBUG_PORT} tcp:${DEBUG_PORT}

    echo ""
    echo "========================================"
    echo "  远程调试环境已就绪"
    echo "========================================"
    echo ""
    echo "  目标二进制: ${BINARY_NAME}"
    echo "  设备路径:   ${DEVICE_DIR}/${BINARY_NAME}"
    echo "  调试端口:   ${DEBUG_PORT}"
    echo ""
    echo "  正在启动 LLDB..."
    echo ""

    # 创建 LLDB 初始化命令文件
    local lldb_cmds=$(mktemp /tmp/lldb_cmds.XXXXXX)
    cat > "$lldb_cmds" <<EOF
platform select remote-android
platform connect connect://localhost:${DEBUG_PORT}
platform settings -w ${DEVICE_DIR}
target create ${BIN_DIR}/${BINARY_NAME}
breakpoint set --name main
process launch --stop-at-entry
EOF

    echo "  LLDB 命令文件: $lldb_cmds"
    echo "  内容:"
    sed 's/^/    /' "$lldb_cmds"
    echo ""

    # 启动 LLDB
    "$LLDB" --source "$lldb_cmds"

    # 清理
    rm -f "$lldb_cmds"
    kill $LLDB_SERVER_PID 2>/dev/null || true
    $ADB forward --remove tcp:${DEBUG_PORT} 2>/dev/null || true
}

cleanup() {
    echo "清理设备上的调试文件..."
    $ADB shell "pkill -f lldb-server" 2>/dev/null || true
    $ADB shell "rm -rf ${DEVICE_DIR}" 2>/dev/null || true
    $ADB forward --remove-all 2>/dev/null || true
    echo "  清理完成"
}

# 主流程
echo "========================================"
echo "  NiPass ARM64 远程 LLDB 调试"
echo "========================================"
check_prerequisites

if [ "$CLEANUP" = true ]; then
    cleanup
    exit 0
fi

setup_device

if [ "$SETUP_ONLY" = true ]; then
    echo ""
    echo "  lldb-server 已部署到 ${DEVICE_DIR}/lldb-server"
    echo "  手动启动: adb shell '${DEVICE_DIR}/lldb-server platform --listen *:${DEBUG_PORT} --server'"
    exit 0
fi

push_binary
start_debug_session
