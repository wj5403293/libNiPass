#!/bin/bash
# NiPass ARM64 设备测试脚本
# 通过 adb 推送二进制到 Android 设备执行，带 timeout 防止死循环
#
# 用法:
#   ./run_test.sh                # 测试混淆版本
#   ./run_test.sh plain          # 测试未混淆版本
#   ./run_test.sh both           # 两个版本都测试并对比
#   ./run_test.sh -s <serial>    # 指定设备序列号
#   ./run_test.sh -t 5           # 指定单个程序超时时间（秒）

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="${SCRIPT_DIR}/bin"
DEVICE_DIR="/data/local/tmp/nipass_test"

# 设备上执行超时时间（秒）
TIMEOUT="${TIMEOUT_SECONDS:-10}"

TARGETS="test_nipass test_annotate test_production test_stl test_template"

# 解析参数
ADB_SERIAL=""
MODE=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -s)
            ADB_SERIAL="$2"
            shift 2
            ;;
        -t|--timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        *)
            MODE="$1"
            shift
            ;;
    esac
done
MODE="${MODE:-obf}"

if ! [[ "$TIMEOUT" =~ ^[0-9]+$ ]] || [ "$TIMEOUT" -le 0 ]; then
    echo "[ERROR] Timeout must be a positive integer, got: ${TIMEOUT}"
    exit 1
fi

# adb 命令封装
ADB="adb"
if [ -n "$ADB_SERIAL" ]; then
    ADB="adb -s $ADB_SERIAL"
fi

check_device() {
    if ! $ADB devices 2>/dev/null | grep -qw "device"; then
        echo "[ERROR] No device connected."
        echo "  Check 'adb devices' output."
        exit 1
    fi
    local dev
    dev=$($ADB shell getprop ro.product.model 2>/dev/null | tr -d '\r')
    local abi
    abi=$($ADB shell getprop ro.product.cpu.abi 2>/dev/null | tr -d '\r')
    echo "  Device: ${dev} (${abi})"
    if [[ "$abi" != arm64* ]]; then
        echo "[WARN] Device ABI is '${abi}', expected arm64-v8a"
    fi
}

# 推送并执行单个二进制
run_on_device() {
    local local_bin="$1"
    local remote_name="$2"
    local label="$3"

    if [ ! -f "$local_bin" ]; then
        echo "[ERROR] Binary not found: $local_bin"
        echo "  Run './build.sh ${MODE}' first."
        return 1
    fi

    local remote_bin="${DEVICE_DIR}/${remote_name}"

    echo ""
    echo "----------------------------------------"
    echo "  ${label}"
    echo "----------------------------------------"

    # 创建目录 & 推送
    $ADB shell "mkdir -p ${DEVICE_DIR}" 2>/dev/null
    echo "  Pushing $(basename "$local_bin") -> ${remote_bin}"
    $ADB push "$local_bin" "$remote_bin" 2>&1 | sed 's/^/  /'
    $ADB shell "chmod 755 ${remote_bin}"

    # 带 timeout 执行
    echo "  Running (timeout=${TIMEOUT}s)..."
    echo ""

    local exit_code=0
    $ADB shell "timeout ${TIMEOUT} ${remote_bin}" 2>&1 || exit_code=$?

    echo ""
    if [ $exit_code -eq 124 ]; then
        echo "  [TIMEOUT] Process killed after ${TIMEOUT}s - possible infinite loop!"
        return 1
    elif [ $exit_code -ne 0 ]; then
        echo "  [FAIL] Exit code: ${exit_code}"
        return 1
    else
        echo "  [PASS] Exit code: 0"
    fi
    return 0
}

cleanup_device() {
    echo ""
    echo "Cleaning up device..."
    $ADB shell "rm -rf ${DEVICE_DIR}" 2>/dev/null || true
}

# 汇总结果
print_summary() {
    local total="$1"
    local passed="$2"
    local failed="$3"

    echo ""
    echo "========================================"
    echo "  Results: ${passed}/${total} passed, ${failed} failed"
    echo "========================================"

    if [ "$failed" -gt 0 ]; then
        return 1
    fi
}

run_targets() {
    local suffix="$1"
    local label_suffix="$2"

    for t in $TARGETS; do
        local local_bin="${BIN_DIR}/${t}${suffix}"
        local remote_name="${t}${suffix}"
        local label="${t} (${label_suffix})"

        if run_on_device "$local_bin" "$remote_name" "$label"; then
            PASSED=$((PASSED + 1))
        else
            FAILED=$((FAILED + 1))
        fi
    done
}

echo "========================================"
echo "  NiPass ARM64 Device Test"
echo "========================================"
echo "  Timeout: ${TIMEOUT}s per binary"
check_device

TOTAL=0
PASSED=0
FAILED=0

case "$MODE" in
    obf)
        TOTAL=5
        run_targets "" "obfuscated"
        ;;
    plain)
        TOTAL=5
        run_targets "" "plain"
        ;;
    both)
        TOTAL=10
        for t in $TARGETS; do
            if [ ! -f "${BIN_DIR}/${t}_plain" ] || [ ! -f "${BIN_DIR}/${t}_obf" ]; then
                echo ""
                echo "[ERROR] Missing ${t}_plain or ${t}_obf. Run './build.sh both' first."
                exit 1
            fi
        done

        run_targets "_plain" "plain"
        run_targets "_obf" "obfuscated"
        ;;
    *)
        echo "Usage: $0 [-s serial] [-t seconds] [obf|plain|both]"
        exit 1
        ;;
esac

cleanup_device
print_summary "$TOTAL" "$PASSED" "$FAILED"
