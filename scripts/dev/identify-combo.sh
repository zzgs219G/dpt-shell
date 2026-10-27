#!/usr/bin/env bash
# identify-combo.sh —— 判断一个 APK 来自哪个模块组合
#
# 为什么需要它：dpt-shell 与 apk-protect-action 是两个仓库，同一个 .apk
# 可能来自完全不同的模块组合，而它们的**故障定位路径完全不同**。
# 接手者必须先能判断产物属于哪一类，否则会往错误方向查。
#
# 三类最基本的组合：
#   ① 只勾 packer（dpt）           —— 验证 dpt 自身三条链
#   ② 全模块（含 packer）          —— 验证联动 + 壳
#   ③ 全模块**不勾 packer**        —— 只有 sigcheck/dex2c/stringenc/envcheck
#                                     产物**不是壳包**，没有 .bitcode/配置/载荷
#
# 用法：
#   scripts/dev/identify-combo.sh <apk>
#
# 退出码：0 总是（信息查询，不是断言）
set -uo pipefail

APK="${1:-}"
[[ -n "$APK" ]] || { echo "用法: $0 <apk>" >&2; exit 2; }
[[ -f "$APK" ]] || { echo "❌ APK 不存在: $APK" >&2; exit 2; }
command -v unzip >/dev/null 2>&1 || { echo "❌ 需要 unzip" >&2; exit 2; }

TMPDE=$(mktemp); TMPD=$(mktemp -d)
trap 'rm -f "$TMPDE"; rm -rf "$TMPD"' EXIT

echo "APK: $(basename "$APK")"
echo "大小: $(du -h "$APK" | cut -f1)"
echo

# ⚠️ 不要用 `unzip -p ... | strings | grep -q`：grep -q 命中后立即退出，
# 会向 unzip 发 SIGPIPE，把整条管道判成失败（实测踩过）。先落临时文件。
count_entry() { unzip -l "$APK" 2>/dev/null | grep -c "$1" || true; }

XIXIN_SO=$(count_entry 'assets/xixin/.*/libxixin\.so')
XIXIN_CFG=$(count_entry 'assets/xixin_config$')
XIXIN_DATA=$(count_entry 'assets/xixin_data$')
LIBNC=$(count_entry 'lib/.*/libnc\.so')

# 壳特征：Manifest 里的 ProxyApplication / ProxyComponentFactory
# （这是 packer 独有 —— dpt 会把 application 改成 ProxyApplication）
PACKER_MANIFEST=0
if unzip -p "$APK" AndroidManifest.xml >"$TMPDE" 2>/dev/null; then
  if strings "$TMPDE" 2>/dev/null | grep -qE 'ProxyApplication|ProxyComponentFactory'; then
    PACKER_MANIFEST=1
  fi
fi

# stringenc 解密桩：用桩骨架的结构不变量（类名每包随机，不能 grep 类名）
STRDEC=0
if unzip -p "$APK" classes.dex >"$TMPDE" 2>/dev/null; then
  if strings "$TMPDE" 2>/dev/null | grep -E 'GAMMA|keyByte|mix64' >/dev/null; then
    STRDEC=1
  fi
fi

# ── 判据汇总 ─────────────────────────────────────────────────────────
echo "── 判据 ──"
printf '  assets/xixin/*/libxixin.so : %s   ← packer 独有\n' "$XIXIN_SO"
printf '  assets/xixin_config        : %s   ← packer 独有\n' "$XIXIN_CFG"
printf '  assets/xixin_data          : %s   ← packer 独有\n' "$XIXIN_DATA"
printf '  Manifest 有 Proxy*         : %s   ← packer 独有\n' "$PACKER_MANIFEST"
printf '  lib/*/libnc.so             : %s   ← sigcheck/dex2c/envcheck\n' "$LIBNC"
printf '  stringenc 桩               : %s\n' "$STRDEC"

IS_PACKER=0
[[ "$XIXIN_SO" -gt 0 && "$PACKER_MANIFEST" -eq 1 ]] && IS_PACKER=1

echo
echo "── 判定 ──"
if [[ "$IS_PACKER" -eq 0 ]]; then
  if [[ "$LIBNC" -eq 0 && "$STRDEC" -eq 0 ]]; then
    echo "→ **未加壳，且无任何模块产物**"
    echo "  可能是原始 APK，或 protect.sh 未成功执行。"
  elif [[ "$STRDEC" -eq 1 ]]; then
    echo "→ **全模块但不勾 packer**（有 stringenc/dex2c/sigcheck，无壳）"
    echo "  ⚠️ 这不是壳包：没有 .bitcode / 配置 / 载荷抽取。"
    echo "  预期：[kl] 日志**不会出现**（壳 so 不存在）；桩仍在业务 dex 里。"
    echo "  测试重点：桩能否正常解密字符串（Java 实现，不依赖 so）。"
  else
    echo "→ **部分模块，不勾 packer**（有 libnc.so，无 stringenc 桩）"
    echo "  常见：仅 sigcheck / 仅 dex2c / sigcheck+dex2c。"
    echo "  预期：[kl] 日志不会出现。"
  fi
  echo
  echo "  ⚠️ 拿这类产物跑 verify-on-device.sh 会因「无 [kl] 日志」判 FAIL ——"
  echo "     那是**预期的**，不是缺陷。该脚本只适用于 packer 产物。"
  exit 0
fi

# 是 packer 产物
if [[ "$LIBNC" -gt 0 && "$STRDEC" -eq 1 ]]; then
  echo "→ **全模块（含 packer + stringenc↔dex2c 联动）**"
  echo "  预期：启动时加载 libnc.so；[kl] derive_rc=0；"
  echo "        桩的 SEED 来自 JniBridge.gseed()（壳提供）。"
elif [[ "$LIBNC" -eq 0 && "$STRDEC" -eq 0 ]]; then
  echo "→ **只勾 packer（dpt）**"
  echo "  预期：[kl] derive_rc=0；无 libnc.so 加载。"
  echo "  价值：dpt 自身缺陷在这个组合下就能复现，与联动无关。"
else
  echo "→ **packer + 部分模块**（libnc=$LIBNC, strdec=$STRDEC）"
fi

# ── 壳 so / 载荷强度 ─────────────────────────────────────────────────
echo
echo "── 壳状态 ──"
if unzip -o -q "$APK" "assets/xixin_data" -d "$TMPD" 2>/dev/null \
   && [[ -f "$TMPD/assets/xixin_data" ]]; then
  python3 - "$TMPD/assets/xixin_data" <<'PY'
import struct, sys
d = open(sys.argv[1], 'rb').read()
try:
    m, v, dc, co, bo, bc, r = struct.unpack_from('<IHHIIII', d, 0)
except struct.error:
    print("  xixin_data 解析失败（不是 v5 载荷）"); raise SystemExit
if m != 0x4F4F4F35:
    print(f"  ❌ magic 不符: 0x{m:08x}"); raise SystemExit
print(f"  xixin_data: version={v} dexCount={dc} blockCount={bc} size={len(d)}")
print(f"  含义：{bc} 个载荷块（业务指令已抽取并加密）")
PY
else
  echo "  无 xixin_data（--plain 模式，或未抽取指令）"
fi

echo
echo "── 下一步 ──"
echo "  scripts/dev/verify-on-device.sh <apk> --device <host:port>"
echo "  判据见 scripts/dev/README.md"
