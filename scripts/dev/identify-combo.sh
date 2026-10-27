#!/usr/bin/env bash
# identify-combo.sh —— 判断一个加壳 APK 是「只勾 dpt」还是「全模块联动」
#
# 为什么需要它：dpt-shell 与 apk-protect-action 是两个仓库，
# 同一个 .apk 产物可能来自完全不同的模块组合，而两者的
# 故障定位路径、测试重点、预期日志都不同。接手者拿到一个 apk
# 必须先能判断它是哪一类。
#
# 用法：
#   scripts/dev/identify-combo.sh <apk>
#
# 退出码：0 总是（这是"信息查询"而非"断言"）
set -uo pipefail

APK="${1:-}"
[[ -n "$APK" ]] || { echo "用法: $0 <apk>" >&2; exit 2; }
[[ -f "$APK" ]] || { echo "❌ APK 不存在: $APK" >&2; exit 2; }

command -v unzip >/dev/null 2>&1 || { echo "❌ 需要 unzip" >&2; exit 2; }

echo "APK: $(basename "$APK")"
echo "大小: $(du -h "$APK" | cut -f1)"
echo

have() { unzip -l "$APK" 2>/dev/null | grep -q "$1"; }
count() { unzip -l "$APK" 2>/dev/null | grep -c "$1" || true; }

# ── 判据 A：壳 so 是否存在（dpt 加壳的标志）──────────────────────────
XIXIN_SO=$(count 'assets/xixin/.*/libxixin\.so')
if [[ "$XIXIN_SO" -eq 0 ]]; then
  echo "❌ 这不是 dpt 加壳产物（没有 assets/xixin/*/libxixin.so）"
  echo "   可能是：未加壳的原包，或 packer 未勾选。"
  exit 0
fi
echo "✅ dpt 已加壳：assets/xixin/*/libxixin.so × $XIXIN_SO"

# ── 判据 B：libnc.so（sigcheck / dex2c / envcheck 的产物）────────────
LIBNC=$(count 'lib/.*/libnc\.so')
# ── 判据 C：stringenc 解密桩（存在即勾了 stringenc）──────────────────
# 桩类名每包随机，不能用类名判断 → 用桩骨架里固定的字段/方法特征。
# 这些是 scripts/string-enc/StrDec.java 的结构不变量，桩随机化不会改。
# ⚠️ 不要写成 `unzip -p ... | strings | grep -q`：grep -q 命中后立即退出，
# 会向 unzip 发 SIGPIPE，在某些 shell 下把整条管道判成失败（实测踩过：
# 全模块包被判成"部分模块"）。先落临时文件再 grep。
STRDEC=0
TMPDE=$(mktemp); trap 'rm -f "$TMPDE"; rm -rf "${TMP:-}"' EXIT
if unzip -p "$APK" classes.dex >"$TMPDE" 2>/dev/null; then
  if strings "$TMPDE" 2>/dev/null | grep -E 'GAMMA|keyByte|mix64' >/dev/null; then
    STRDEC=1
  fi
fi

echo
echo "── 组合识别 ──"
printf '  libnc.so   : %s\n' "$([[ $LIBNC -gt 0 ]] && echo "存在 × $LIBNC（含 sigcheck/dex2c/envcheck）" || echo "不存在")"
printf '  stringenc  : %s\n' "$([[ $STRDEC -eq 1 ]] && echo "有解密桩" || echo "无")"

echo
if [[ "$LIBNC" -eq 0 && "$STRDEC" -eq 0 ]]; then
  echo "→ 判定：**只勾 dpt（packer）**"
  echo "  预期：启动日志有 [kl] derive_rc=0，无 libnc.so 相关加载。"
  echo "  定位价值：dpt 自身缺陷在这个组合下就能复现，与联动无关。"
elif [[ "$LIBNC" -gt 0 && "$STRDEC" -eq 1 ]]; then
  echo "→ 判定：**全模块（含 stringenc↔dex2c 联动）**"
  echo "  预期：启动时先加载 libnc.so，再由壳 so 派生解密；"
  echo "        桩的 SEED 来自 JniBridge.gseed()（壳提供）。"
  echo "  注意：桩名每包随机，不能用固定类名 grep。"
else
  echo "→ 判定：**部分模块**（libnc=$LIBNC, strdec=$STRDEC）"
  echo "  常见组合：仅 sigcheck（有 libnc 无 stringenc）。"
fi

# ── 附：壳 so 载荷强度（顺带核验派生链是否生效）───────────────────────
echo
echo "── 壳 so 状态 ──"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
unzip -o -q "$APK" "assets/xixin_data" -d "$TMP" 2>/dev/null
if [[ -f "$TMP/assets/xixin_data" ]]; then
  python3 - "$TMP/assets/xixin_data" <<'PY'
import struct, sys
d=open(sys.argv[1],'rb').read()
try:
    m,v,dc,co,bo,bc,r = struct.unpack_from('<IHHIIII', d, 0)
except struct.error:
    print("  xixin_data 解析失败（可能不是 v5 载荷）"); raise SystemExit
if m != 0x4F4F4F35:
    print(f"  ❌ magic 不符: 0x{m:08x}"); raise SystemExit
print(f"  xixin_data: version={v} dexCount={dc} blockCount={bc} size={len(d)}")
print(f"  含义：{bc} 个载荷块（业务指令已抽取并加密）")
PY
else
  echo "  无 xixin_data（--plain 模式，或未抽取指令）"
fi

echo
echo "── 想进一步验证？──"
echo "  scripts/dev/verify-on-device.sh <apk> --device <host:port>"
echo "  判据见 scripts/dev/README.md"
