# 开发与测试脚本（dpt-shell 侧）

本仓库只放**验证 dpt 自身**的脚本。真机验证与模块组合识别在下游
`apk-protect-action`（产物是那条流水线出的）。

| 脚本 | 用途 | 频率 |
|---|---|---|
| `verify-apk-static.sh` | 静态核验加壳产物（`.bitcode` 熵 / 符号 / 明文串 / 载荷） | 改完 dpt 就跑 |
| `bench-pack.sh` | 打包耗时基准 | 只做性能优化时 |
| `bench-runtime.sh` | 运行时指标基准 | 只做性能优化时 |

性能基准的详细说明见 [benchmark.md](./benchmark.md)。

---

## 1. verify-apk-static.sh（静态核验）

**不需要真机**，只验产物里的字节是否符合契约。

```bash
scripts/dev/verify-apk-static.sh <加壳后.apk>
```

核验项（来自 [docs/基线-v1.3.2-真机验证.md](../../docs/基线-v1.3.2-真机验证.md) §4）：

| 项 | 期望 |
|---|---|
| 壳 so 数量 | ≥ 1 |
| `xixin_config` 存在 | ✅ |
| `.bitcode` 熵 | > 7.9（密文） |
| `.text` 可解析 | ✅（派生链要读它算 CRC32） |
| 哨兵 `1234567890abcdef` | 不存在（否则说明有明文 key 载体） |
| `DPT_UNKNOWN_DATA` 符号 | 0 |
| `.comment` 段 | 0（否则泄露 clang/LLD 版本） |
| `dpt-sec-v1` / `dpt-kl-v1` / `dpt-cfg-v1` / `dpt-cfg-master` | 明文串 0 |
| `xixin_data` magic / version | `0x4f4f4f35` / 5 |
| 载荷块偏移长度 | 自洽（不越界、rawOffset 升序） |

退出码：0 全通过 / 1 有失败项 / 2 参数或环境错误。

输出示例：

```
── 壳 so 段级核验 ──
  ✅ [arm] .bitcode 28324B 熵=7.993
  ✅ [arm64] .bitcode 37244B 熵=7.996
── 逆向面回归 ──
  ✅ [arm64] DPT_UNKNOWN_DATA 已移除
  ✅ [arm64] .comment 已移除
  ✅ [arm64] 派生常量无明文串
── 载荷结构 ──
  ✅ version=5 dexCount=1 blockCount=72 size=2906808
✅ PASS
```

**它不验什么**：运行时行为（三条链是否真能解开）。那需要真机，
由下游 `apk-protect-action/scripts/verify/verify-on-device.sh` 负责。

---

性能基准脚本（`bench-pack.sh` / `bench-runtime.sh`）的说明见 [benchmark.md](./benchmark.md)。
