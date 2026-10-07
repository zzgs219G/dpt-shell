# Phase 1 终态设计说明（as-built，Task 1.6 输出物）

> 本文描述 Phase 1 全部任务完成后的**实际架构**（以 v1.0.9 / `ee77871` 为准），
> 面向后续维护者，取代逐任务笔记拼图。设计依据与实施记录见
> `phase1-perf-plan.md`（唯一执行依据）与 `进度与交接.md`（§4 = Task 1.4，§8 = Task 1.5）；
> 验收数据见 `phase1-test.md`。凡"未验证"处均如实标注。

## 1. 流水线总览

```
打包期（dpt.jar，纯 Java）
  目标 APK/AAB
    → 抽取各 dex，方法体挖空（filler 回填）
    → insns 以 ChaCha20 加密写入载荷 assets/OoooooOooo（v4 格式）
    → 注入壳 classes.dex + 各 ABI libdpt.so，按配置签名
  运行期（libdpt.so + 壳 dex）
    → 载荷/原始 dex 装载（内存路径 or 文件路径）
    → hook 类加载，命中类逐个开页粒度 RW 窗口 → 解密回填 → 关窗
    → 应用正常执行
```

## 2. 打包侧设计

### 2.1 OoooooOooo v4 载荷

- 头部 `u16 version = 4`（`Const.MULTI_DEX_CODE_VERSION_V4`，与
  `MultiDexCode.h`/`MultiDexCode.java` 的结构注释一致，两侧单测
  `MultiDexCodeV4Test`、`PayloadRecordPairingTest` 对拍）。
- 按 dex 组织记录，方法级记录与 methodIdx 配对；`-K` keep-classes 时
  部分类不抽取、留在包内（`DexUtils` splitDex）。
- 填充字节 filler 为 `return-void` 或随机（`InsnsFillerBytesTest` 覆盖），
  不再是上游的 `writeShort(0)` 固定 nop。

### 2.2 指令加密：ChaCha20（RFC 8439）

- 密钥：`g_shell_config.aes_key`（32B），由配置密钥派生
  （`ConfigKeyDerivationTest`）。
- nonce：`methodIdx` 的 12 字节小端编码（低 4 字节有效），counter = 0。
- **RC4 已彻底移除**：`grep "buildInsnsRc4Key|rc4_crypt_insns" dpt/ shell/`
  零命中（1.6 实测）；计划中"保留 v2 RC4 分支回退"已在 Task 1.3 收尾时删除。
  so 的 `.bitcode` 段仍用 RC4（与 insns 无关，见计划书术语表）。
- 向量与边界：`CryptoUtilsChaCha20Test`、`InsnsCryptoContractTest`。

### 2.3 配置与参数

- `-c` 保护配置（`shellPkgName`、`signature` 等）、`-r` 排除规则
  （**整体替换**内置默认，全类名正则，模板见 `executable/*.rules`）、
  `-e` ABI 排除、`-S` 小体积、`-x` 不签名等——语义已在 README 逐条核实。
- 打包 IO：Task 1.7 批量化（`DexUtils` 写路径），1.6 实测较基线 −24.7%
  （calc.apk，见 `进度与交接.md` §7）。
- 基准工具：`tools/benchmark/bench-pack.sh`、`bench-runtime.sh`（Task 1.10）。

## 3. 运行时设计

### 3.1 载入路径（Task 1.4 + 1.8）

| 路径 | 触发条件 | 机制 |
|---|---|---|
| **内存路径（默认）** | API ≥ 29 且未 `--disable-inmemory-dex` | 运行时经 `ensure_package_loaded`（复用 Task 1.8 的 `load_zip_by_mmap` 缓存）读 `OoooooOooo`/原始 dex 条目，组 in-memory elements 交 InMemoryDexClassLoader；**code_cache 不落盘**（1.6 真机实测为空） |
| 文件路径 | API < 29 或显式禁用 | 解出 `code_cache/i11111i111.zip` 加载（旧行为） |

- 内存路径有 gate 白名单 + **内容指纹兜底**（v1.0.5 VerifyError 的修复，
  见 `启动闪退根因分析.md` §9~§10）。
- dex 内部按**运行时字节直接解析**（Task 1.9，含 descriptor 缓存），
  不再依赖 65536 项 classDataOff 大表（该表已删，仅存注释）。

### 3.2 解密回填：页粒度 RW 窗口（Task 1.5，v1.0.9 语义）

命中类（LoadClass/DefineClass hook）执行：

1. 收集本类需回填方法的 insns 页 → `std::set` 排序去重；
2. 按页取自旋锁（防同页并发死锁）；
3. 分段连续化后 `dpt_mprotect` 开 RW 窗口——**开窗无条件**（v1.0.9），
   任一 mprotect 失败则放弃该类（失败面刻意保留：跳过开窗正是 v1.0.8 崩溃根因）；
4. 逐方法 ChaCha20 解密回填；
5. 关窗仍由 `restoreRead` 决定：**文件 dex 恢复 PROT_READ；内存 dex 不恢复**
   （否则破坏相邻堆分配）。开窗与关窗是两个独立决策——v1.0.9 的核心修复
   （`restoreRead` 用途拆分，`启动闪退根因分析.md` §十）；
6. 恢复权限前 `__builtin___clear_cache` 刷 i-cache。

窗口按页而非整 dex，权限位暴露时间最小化（计划缺陷 B4 的修复形态）。

### 3.3 诊断与日志

- release 构建裁掉 DLOGI/DLOGD；**ELOG 常驻**（仅失败路径：gate 拒绝、
  payload/decrypt 失败、hook 失败）。1.6 实测正常启动 `dpt_native` 标签 0 条。
- 崩溃 handler 走 sigchain 内部 + logcat 单通道（v1.0.8 诊断能力，
  §11.5 已真机验证：handler 调用、ART 转发、字段完整三项 ✅）。

## 4. 与计划书的偏差（as-built 覆盖 as-planned）

| 计划书内容 | 实际终态 | 依据 |
|---|---|---|
| `dexMap` 每 dex 65536 项表 | **已删除**（Task 1.1 索引重构） | 交接 §8.2，`grep dexMap` 零命中 |
| 保留 v2 RC4 分支回退 | **已删除**（Task 1.3 收尾） | 1.6 grep 零命中 |
| `restoreRead` 单一决策 | **拆为开窗/关窗两决策**（v1.0.8 崩溃修复） | `启动闪退根因分析.md` §十 |
| `change_dex_protective` 整 dex RW | **已废弃**（页粒度取代） | 交接 §三注记，符号引用数 0 |

## 5. 已知代价与未验证项

由 1.6 验收（`phase1-test.md` §六）得出，**留给 Phase 2**：

1. ❌ **内存路径内存代价未量化即上线**：21-dex 应用 TOTAL PSS
   209 MB → 504+ MB（目标 <5MB）。native 堆 116MB + 匿名页 90MB 是大头。
2. ❌ 冷启动增量 **+299ms**（目标 <150ms），与内存发现同源。
3. ❌ 打包提速 **−24.7%**，未达计划 −30%（≥20% 线已过）。
4. ⏳ RW 窗口时长（需 systrace）、mmap 次数（需 debug shell）、
   低版本/armeabi-v7a/AAB 矩阵、dex 内存直读（需 root）均未测。

## 6. 版本与验收状态

- 当前 `HEAD = origin/main = v1.0.9 = ee77871`，真机验证 2026-10-07（Android 16）。
- Task 1.6 验收结果总表见 `phase1-test.md` §6.1：✅7 / ❌3 / ⏳4+。
