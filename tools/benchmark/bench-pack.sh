#!/usr/bin/env bash
#
# 打包耗时基准：同一份 APK 连续跑 N 次，取中位数。
#
# 用法：
#   tools/benchmark/bench-pack.sh <apk> [runs] [dpt.jar]
#
# 例：
#   tools/benchmark/bench-pack.sh app.apk
#   tools/benchmark/bench-pack.sh app.apk 7 executable/dpt.jar
#
# 只用 date +%s%N 和 awk，不依赖 bc / hyperfine。
#
# 注意：
#   1. 首次运行含 JVM 预热，默认丢弃第 1 次（见 WARMUP）。
#   2. 输出的是墙钟时间（wall clock），包含 JVM 启动与签名开销。
#   3. 跨机器比较毫无意义，只能同机前后对比。

set -euo pipefail

APK="${1:?用法: bench-pack.sh <apk> [runs] [dpt.jar]}"
RUNS="${2:-5}"
JAR="${3:-executable/dpt.jar}"
WARMUP="${BENCH_WARMUP:-1}"

if [[ ! -f "$JAR" ]]; then
    echo "skip:找不到 $JAR（先跑 ./gradlew build）" >&2
    exit 0
fi
if [[ ! -f "$APK" ]]; then
    echo "skip:找不到 $APK" >&2
    exit 0
fi
if (( RUNS < 1 )); then
    echo "错误:runs 至少为 1" >&2
    exit 1
fi

# 方法数用于归一化，否则不同体量的 APK 之间无法横向比较。
METHOD_COUNT=$(python3 - "$APK" <<'PY'
import sys, zipfile, struct
try:
    with zipfile.ZipFile(sys.argv[1]) as z:
        raw = z.read("classes.dex")
except Exception:
    sys.exit(0)
if len(raw) < 112 or raw[:4] != b"dex\n":
    sys.exit(0)
# header: method_ids_size 位于 0x58，class_defs_size 位于 0x60
print(struct.unpack("<I", raw[0x58:0x5c])[0])
PY
)

OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT

run_once() {
    # dpt.jar 缺 shell-files 时会抛 FileNotFoundException，但进程仍以 exit 0 结束
    # （只往 stderr 打日志，见 AndroidPackage.protect）。所以退出码不可信，
    # 必须校验产物是否真的生成。
    rm -rf "$OUT"
    mkdir -p "$OUT"

    # 注意：这里不能用 `set -e` 的隐式退出。run_once 在函数里 exit 1 时，
    # 命令替换 `$(run_once ...)` 会连带终止整个脚本，导致报错信息打不出来。
    # 所以显式关闭 errexit，由本函数自己控制返回码。
    local start end produced
    set +e
    start=$(date +%s%N)
    java -jar "$JAR" -f "$APK" -o "$OUT" -x >"$OUT.log" 2>&1
    end=$(date +%s%N)
    set -e

    produced=$(find "$OUT" -maxdepth 1 \( -name '*.apk' -o -name '*.aab' \) -print -quit 2>/dev/null || true)
    if [[ -z "$produced" || ! -s "$produced" ]]; then
        {
            echo "错误:加壳未产出文件（第 $1 次）。dpt.jar 关键输出："
            # 异常首行通常是 "xxxException: msg"，比堆栈更有用，故 head -5
            head -5 "$OUT.log" 2>/dev/null | sed 's/^/  /'
            echo "  提示:需要完整 executable/，请先 ./gradlew build 生成 shell-files/"
        } >&2
        return 1
    fi
    echo $(( (end - start) / 1000000 ))   # 毫秒
}

# 预热：让 JIT 把热路径编译完，避免首轮偏慢污染中位数。
for ((w = 0; w < WARMUP; w++)); do
    run_once "预热$((w + 1))" >/dev/null 2>&1 || true
done

TIMES=()
for ((i = 0; i < RUNS; i++)); do
    if ! T="$(run_once "第$((i + 1))次")"; then
        exit 1
    fi
    TIMES+=( "$T" )
done

APK_NAME=$(basename "$APK")
echo "APK      : $APK_NAME"
if [[ -n "$METHOD_COUNT" && "$METHOD_COUNT" -gt 0 ]]; then
    echo "方法数   : $METHOD_COUNT"
fi
echo "样本     : $RUNS 次（已丢弃 $WARMUP 次预热）"
echo "原始耗时 : ${TIMES[*]} ms"
printf '%s\n' "${TIMES[@]}" | sort -n | awk -v mc="${METHOD_COUNT:-0}" -v apk="$APK_NAME" '
    { a[NR] = $1 }
    END {
        mid = (NR % 2) ? a[(NR + 1) / 2] : (a[NR / 2] + a[NR / 2 + 1]) / 2
        printf "最小     : %d ms\n", a[1]
        printf "中位数   : %.0f ms\n", mid
        printf "最大     : %d ms\n", a[NR]
        printf "波动     : %d ms (max-min)\n", a[NR] - a[1]
        if (mc > 0) {
            printf "归一化   : %.3f ms/千方法\n", mid / mc * 1000
        }
        # 波动超过中位数 15% 说明测量环境不稳，这个数字不可信
        if (a[NR] - a[1] > mid * 0.15) {
            print "警告     : 样本波动过大，本次结果不可信，建议增加 runs"
        }
    }'