#!/usr/bin/env bash
# verify-apk-static.sh —— 对加壳产物做静态核验（不需要真机）
#
# 这是 dpt-shell 能独立闭环的验证部分：只检查产物里的字节是否符合契约，
# 不涉及运行时行为。真机功能验证由 apk-protect-action 的脚本负责
# （产物是那条流水线出的，dpt 只是被调用方）。
#
# 用法：
#   scripts/dev/verify-apk-static.sh <加壳后.apk>
#
# 退出码：0 全部通过 / 1 有检查项失败 / 2 参数或环境错误
#
# 核验项来源：docs/基线-v1.3.2-真机验证.md §4
set -uo pipefail

APK="${1:-}"
[[ -n "$APK" ]] || { echo "用法: $0 <加壳后.apk>" >&2; exit 2; }
[[ -f "$APK" ]] || { echo "❌ APK 不存在: $APK" >&2; exit 2; }
command -v unzip >/dev/null 2>&1 || { echo "❌ 需要 unzip" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "❌ 需要 python3" >&2; exit 2; }

TMPD=$(mktemp -d); trap 'rm -rf "$TMPD"' EXIT
FAIL=0

# ⚠️ 先把条目清单落盘，不要直接 `unzip -l | grep -q`：
# grep -q 命中即退出 → SIGPIPE 杀掉 unzip → 整条管道判失败
# （实测踩过两次，全模块包被判成"不是壳包"）。
LIST="$TMPD/entries.txt"
unzip -l "$APK" > "$LIST" 2>/dev/null || { echo "❌ 无法读取 APK 条目"; exit 2; }
ok()   { printf '  ✅ %s\n' "$1"; }
bad()  { printf '  ❌ %s\n' "$1"; FAIL=1; }

echo "APK: $(basename "$APK")"
echo "大小: $(du -h "$APK" | cut -f1)"
echo

# ── 0. 是不是壳包 ────────────────────────────────────────────────────
if ! grep -qE 'assets/xixin/[^/]+/libxixin[.]so' "$LIST"; then
  echo "❌ 这不是 dpt 加壳产物（无 assets/xixin/*/libxixin.so）"
  echo "   可能是未加壳的原包，或本次没勾 packer。"
  exit 1
fi

SO_COUNT=$(grep -cE 'assets/xixin/[^/]+/libxixin[.]so' "$LIST" || true)
echo "── 产物结构 ──"
ok "壳 so × $SO_COUNT"
grep -q 'assets/xixin_config' "$LIST" \
  && ok "xixin_config 存在" || bad "xixin_config 缺失（壳会 fail-closed）"

# ── 1. 逐个 ABI 做段级核验 ───────────────────────────────────────────
echo
echo "── 壳 so 段级核验 ──"
unzip -o -q "$APK" 'assets/xixin/*/libxixin.so' -d "$TMPD" 2>/dev/null

python3 - "$TMPD" <<'PY' || FAIL=1
import sys, os, glob, struct, zlib, collections, math

root = sys.argv[1]
sos = sorted(glob.glob(os.path.join(root, 'assets/xixin/*/libxixin.so')))
if not sos:
    print("  ❌ 解压不出壳 so"); raise SystemExit(1)

def sections(d):
    is64 = d[4] == 2
    if is64:
        e = struct.unpack_from('<Q', d, 0x28)[0]
        es = struct.unpack_from('<H', d, 0x3A)[0]
        n  = struct.unpack_from('<H', d, 0x3C)[0]
        si = struct.unpack_from('<H', d, 0x3E)[0]
        OO, OS = 0x18, 0x20
    else:
        e = struct.unpack_from('<I', d, 0x20)[0]
        es = struct.unpack_from('<H', d, 0x2E)[0]
        n  = struct.unpack_from('<H', d, 0x30)[0]
        si = struct.unpack_from('<H', d, 0x32)[0]
        OO, OS = 0x10, 0x14
    rd = (lambda o: struct.unpack_from('<Q', d, o)[0]) if is64 else (lambda o: struct.unpack_from('<I', d, o)[0])
    shstr = rd(e + si * es + OO)
    out = {}
    for i in range(n):
        q = e + i * es
        no = struct.unpack_from('<I', d, q)[0]
        off = rd(q + OO); sz = rd(q + OS)
        p = shstr + no; z = p
        while z < len(d) and d[z] != 0: z += 1
        out[d[p:z].decode('ascii', 'replace')] = (off, sz)
    return out

fail = 0
for so in sos:
    abi = so.split('/')[-2]
    d = open(so, 'rb').read()
    try:
        secs = sections(d)
    except Exception as ex:
        print(f"  ❌ [{abi}] 段表解析失败: {ex}"); fail = 1; continue

    if '.bitcode' not in secs:
        print(f"  ❌ [{abi}] 没有 .bitcode 段"); fail = 1; continue
    boff, bsz = secs['.bitcode']
    blob = d[boff:boff + bsz]

    # 密文判据：熵 > 7.9
    f = collections.Counter(blob)
    ent = -sum(v / len(blob) * math.log2(v / len(blob)) for v in f.values())
    tag = "✅" if ent > 7.9 else "❌"
    print(f"  {tag} [{abi}] .bitcode {bsz}B 熵={ent:.3f}" + ("" if ent > 7.9 else " (应为密文 >7.9)"))
    if ent <= 7.9: fail = 1

    # 哨兵必须已被覆盖（说明没有残留明文 key 载体）
    if b'1234567890abcdef' in d:
        print(f"  ❌ [{abi}] 残留哨兵 1234567890abcdef"); fail = 1

    # .text 可解析（派生链要读它算 CRC）
    if '.text' not in secs:
        print(f"  ❌ [{abi}] 没有 .text 段"); fail = 1
    else:
        toff, tsz = secs['.text']
        crc = zlib.crc32(d[toff:toff + tsz]) & 0xFFFFFFFF
        print(f"  ✅ [{abi}] .text 可解析（CRC32=0x{crc:08x}，运行期同源计算）")

raise SystemExit(fail)
PY

# ── 2. 符号与明文串（防回归）────────────────────────────────────────
echo
echo "── 逆向面回归 ──"
for so in "$TMPD"/assets/xixin/*/libxixin.so; do
  abi=$(basename "$(dirname "$so")")

  # DPT_UNKNOWN_DATA 必须消失（它是旧方案的明文密钥载体）
  if command -v readelf >/dev/null 2>&1; then
    n=$(readelf -sW --dyn-syms "$so" 2>/dev/null | grep -c 'DPT_UNKNOWN_DATA' || true)
    [[ "$n" -eq 0 ]] && ok "[$abi] DPT_UNKNOWN_DATA 已移除" \
                     || bad "[$abi] DPT_UNKNOWN_DATA 仍存在（$n 处）"
    # .comment 不得保留工具链指纹
    n=$(readelf -SW "$so" 2>/dev/null | grep -c '\.comment' || true)
    [[ "$n" -eq 0 ]] && ok "[$abi] .comment 已移除" \
                     || bad "[$abi] .comment 仍存在（泄露 clang/LLD 版本）"
  else
    echo "  ⚠️  [{abi}] 无 readelf，跳过符号检查"
  fi

  # 派生常量不得以明文出现（P2）
  for kw in dpt-sec-v1 dpt-kl-v1 dpt-cfg-v1 dpt-cfg-master; do
    if grep -aq "$kw" "$so" 2>/dev/null; then
      bad "[$abi] 明文串泄漏: $kw"
    fi
  done
  ok "[$abi] 派生常量无明文串"
done

# ── 3. 载荷结构（v5）─────────────────────────────────────────────────
echo
echo "── 载荷结构 ──"
if unzip -o -q "$APK" 'assets/xixin_data' -d "$TMPD" 2>/dev/null \
   && [[ -f "$TMPD/assets/xixin_data" ]]; then
  python3 - "$TMPD/assets/xixin_data" <<'PY' || FAIL=1
import struct, sys
d = open(sys.argv[1], 'rb').read()
try:
    m, v, dc, co, bo, bc, r = struct.unpack_from('<IHHIIII', d, 0)
except struct.error:
    print("  ❌ xixin_data 太短，不是 v5 载荷"); raise SystemExit(1)
if m != 0x4F4F4F35:
    print(f"  ❌ magic 不符: 0x{m:08x}（期望 0x4f4f4f35）"); raise SystemExit(1)
if v != 5:
    print(f"  ❌ 版本 {v}（运行期只接受 5）"); raise SystemExit(1)
print(f"  ✅ version={v} dexCount={dc} blockCount={bc} size={len(d)}")
# 块表边界自检
if bo + bc * 16 > len(d):
    print("  ❌ 块表越界"); raise SystemExit(1)
prev = -1
for i in range(bc):
    ro, rs, cof, cs = struct.unpack_from('<IIII', d, bo + i * 16)
    if cof + cs > len(d):
        print(f"  ❌ block[{i}] 密文越界"); raise SystemExit(1)
    if ro < prev:
        print(f"  ❌ block[{i}] rawOffset 非升序"); raise SystemExit(1)
    prev = ro
print(f"  ✅ {bc} 个块的偏移与长度自洽")
PY
else
  echo "  ⚠️  无 xixin_data（--plain 模式，未抽取指令，属正常）"
fi

# ── 结论 ─────────────────────────────────────────────────────────────
echo
if [[ "$FAIL" -eq 0 ]]; then
  echo "✅ PASS —— 静态核验全部通过"
  echo
  echo "注：本脚本只验字节层面。运行时行为（三条链是否真能解开）"
  echo "    由 apk-protect-action 仓库的真机验证脚本负责。"
  exit 0
fi
echo "❌ FAIL —— 见上方 ❌ 项"
exit 1
