#!/usr/bin/env bash
#
# 真机运行时基线采集：启动耗时、内存、code_cache 落盘情况。
#
# 用法：
#   tools/benchmark/bench-runtime.sh <package.name> [activity]
#
# 例：
#   tools/benchmark/bench-runtime.sh com.example.app
#   tools/benchmark/bench-runtime.sh com.example.app com.example.app/.MainActivity
#
# 无设备时打印 skip 并以 0 退出，不阻塞流水线。
#
# 注意：必须对同一个包、同一台设备、同一份 APK 前后对比。
# 升级系统、换设备、加解密具后测得的数字不可与之前比较。

set -euo pipefail

PKG="${1:?用法: bench-runtime.sh <package.name> [activity]}"
ACTIVITY="${2:-$PKG/.MainActivity}"
RUNS="${BENCH_RUNS:-10}"

if ! command -v adb >/dev/null 2>&1; then
    echo "skip:adb 不可用"
    exit 0
fi
if ! adb get-state >/dev/null 2>&1; then
    echo "skip:没有连接的设备"
    exit 0
fi

echo "设备     : $(adb shell getprop ro.product.model | tr -d '\r')"
echo "系统     : Android $(adb shell getprop ro.build.version.release | tr -d '\r') (API $(adb shell getprop ro.build.version.sdk | tr -d '\r'))"
echo "包名     : $PKG"

# ---- 首次安装后的 code_cache（只影响首启，必须先看）----
echo
echo "== code_cache =="
if adb shell run-as "$PKG" ls -l code_cache/ 2>/dev/null; then
    echo "（i11111i111.zip 存在 = 当前走落盘路径）"
else
    echo "code_cache 为空或不可读（API>=29 走 InMemoryDex 时属正常）"
fi

# ---- 冷启动：每次都 force-stop，测的是「按图标到画面出现」----
echo
echo "== 冷启动（$RUNS 次，每次 force-stop）=="
COLD=()
for ((i = 0; i < RUNS; i++)); do
    adb shell am force-stop "$PKG" >/dev/null 2>&1 || true
    sleep 1
    T=$(adb shell am start -W "$ACTIVITY" 2>/dev/null \
        | grep -E "TotalTime" | tr -d '\r' | awk '{print $NF}')
    [[ -n "$T" ]] && COLD+=( "$T" )
done

if (( ${#COLD[@]} == 0 )); then
    echo "未取到 TotalTime，确认 Activity 是否存在：$ACTIVITY"
else
    printf '%s\n' "${COLD[@]}" | sort -n | awk -v n="${#COLD[@]}" '
        { a[NR] = $1 }
        END {
            mid = (NR % 2) ? a[(NR + 1) / 2] : (a[NR / 2] + a[NR / 2 + 1]) / 2
            printf "TotalTime 中位数 : %.0f ms\n", mid
            printf "最小 / 最大      : %d / %d ms\n", a[1], a[NR]
            if (NR > 1 && (a[NR] - a[1]) > mid * 0.15) {
                print "警告             : 样本波动过大，建议增加 BENCH_RUNS"
            }
        }'
    echo "原始值 : ${COLD[*]}"
fi

# ---- 热启动：不 force-stop，走的是另一条路径（不触发类解密）----
echo
echo "== 热启动（3 次，不 force-stop）=="
for ((i = 0; i < 3; i++)); do
    adb shell am start -W "$ACTIVITY" 2>/dev/null \
        | grep -E "TotalTime" | tr -d '\r' | sed 's/^/  /'
done

# ---- 内存 ----
echo
echo "== 内存 =="
adb shell dumpsys meminfo "$PKG" 2>/dev/null \
    | grep -E "TOTAL PSS|Native Heap|Dalvik Heap|TOTAL RSS" | sed 's/^/  /' \
    || echo "  dumpsys meminfo 读取失败"