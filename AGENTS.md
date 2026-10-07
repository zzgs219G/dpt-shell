# AGENTS.md

本文件是 dpt-shell 项目中 AI 助手的**工作约定**。接手本项目前请先读完本文件，再动手改代码。

改代码前先看流程地图（流程、跨端契约、红线、改哪里）：[docs/项目流程.md](docs/项目流程.md)。
详细的构建与排障流程见 [docs/build-and-release.md](docs/build-and-release.md)；
踩坑与故障记录见 [docs/pitfalls.md](docs/pitfalls.md)。

---

## 1. 项目是什么

dpt 是 Android 壳工程：`dpt.jar` 是**命令行打包工具**（纯 Java，无 Android 依赖），
`shell` 是 **Android library**，产出 `libdpt.so` 和 `classes.dex`。

典型用法：

```bash
java -jar executable/dpt.jar -f /path/to/app.apk
```

工具会把目标 APK 的 dex 指令加密，替换 dex，注入壳代码，重新签名输出。

## 2. 模块结构

| 模块 | 职责 | 语言 |
|---|---|---|
| `dpt/` | 命令行打包工具 | Java 11 |
| `shell/` | 运行时壳（native + dex） | C++ / Java 8 |
| `shell/src/main/cpp/external/` | vendored 第三方库（submodule） | C/C++ |

Submodule 共 4 个，**克隆时必须带 `--recursive`**，否则 Native 编译失败：

- `Dobby`（bytedance fork）—— native hook
- `bhook`（bytedance）—— PLT hook
- `mbedtls` —— 密码学（ChaCha20 等）
- `minizip-ng` —— 解压 shell 资源

## 3. 环境要求

| 项 | 版本 | 来源 |
|---|---|---|
| JDK | 17 | AGP 要求 |
| Android SDK | compileSdk 36 / minSdk 21 / targetSdk 36 | `build.gradle` |
| NDK | 27.0.12077973 (r27c) | AGP 硬编码默认版本，目录名必须匹配 |
| CMake | 3.31.1 | `build.gradle:50` |
| ninja | 任意近期版本 | Native 构建 |

`appVersionName`（`build.gradle:43`）决定 `dpt.jar` 内部的 `Implementation-Version`。

## 4. 命令

```bash
# 初始化（必须 recursive）
git clone --recursive https://github.com/zzgs219G/dpt-shell
cd dpt-shell && git submodule update --init --recursive

# 完整构建 —— 产出完整 executable/
./gradlew build

# 只跑 Java 单元测试（不需要 Android SDK / NDK）
./gradlew :dpt:test

# 只打 dpt.jar —— 产出 executable/dpt.jar，不含 shell-files
./gradlew :dpt:jar

# 发布：见 docs/build-and-release.md
```

**关键区别**：`./gradlew assemble` **不足以**产出可用的 `executable/`。
`executable/shell-files/`（含各 ABI 的 `libdpt.so`）由 `:shell` 的
`afterAssembleCopy` 生成，挂在 **build 任务**的 `doLast` 上，需要 `./gradlew build`。
仓库 README（中英文）第 19-27 行已同步为 `./gradlew build`（`088079e` 修正）；
若你的本地副本仍写着 `./gradlew assemble`，那是**过时的**，以本文件为准。

## 5. 产物位置

```
executable/
├── dpt.jar                    ← :dpt:jar，打包工具本体
├── dpt-exclude-classes-template.rules
├── dpt-protect-config-template.json
└── shell-files/               ← :shell 的 build 任务，缺失则 dpt.jar 无法工作
    ├── dex/classes.dex
    ├── libs/<abi>/libdpt.so  ← arm64-v8a / armeabi-v7a / x86 / x86_64
    └── build-key
```

`dpt.jar` 启动时会校验 `shell-files/build-key`，key 不匹配即拒绝运行，
所以 `dpt.jar` 与 `shell-files/` **必须来自同一次构建**，不能混用。

`executable/` 已被 `.gitignore` 排除，不会误提交。

## 6. 验证策略（重要）

### Native 改动：靠 GitHub Actions，不要在本机尝试编译

**本机几乎无法编译 Native**，原因随环境而变：

- aapt2、SDK cmake、NDK clang 若是 x86_64 ELF，在 arm64 设备上直接 `cannot execute`
- Termux 的 cmake 可能缺符号，无法运行

遇到这两类情况时，**不要**尝试自建语法检查脚本来"验证" Native 改动。
实测教训：这类脚本在**未修改的基线文件上也会报错**，产出的是"能跑但结论错误"的
工具，比没有更危险。正确做法：

1. 改动后在本地做**代码审查 + 逻辑推导**，确保与现有代码风格、头文件包含、
   宏用法完全一致
2. `git push` 后由 `build.yml` 跑真实 arm64 编译（CI 用 `-Wall -Wextra -Werror`）
3. **从 CI 日志判断成败**，不要只看 workflow 的绿/红

### Java 改动：用 JUnit

```bash
./gradlew :dpt:test
```

当前测试（`dpt/src/test/java/com/luoye/dpt/`）：

| 文件 | 覆盖 |
|---|---|
| `ByteBufferTest.java` | buffer 读写 |
| `ConfigKeyDerivationTest.java` | 配置密钥派生 |
| `CryptoUtilsChaCha20Test.java` | ChaCha20 向量与边界 |
| `InsnsCryptoContractTest.java` | 指令加密契约 |

**测试向量必须取自权威原文**（如 RFC），不能凭记忆写。
实测教训：凭记忆写的 ChaCha20 测试向量是错的，而 round-trip 测试
只验证对称性，会掩盖这类错误 —— 所以关键向量要有硬编码的期望值。

### 真机验收：需要 adb 设备

无设备时，APK 能否启动、指令是否正确还原、启动耗时等**一律标注"待验证"**，
**绝不伪造数据**。

## 7. 改动纪律

- **不要**在 commit message 里加 `Co-Authored-By: Claude` 之类的 trailer，
  除非用户明确要求。它会改变 GitHub 的贡献者统计。
- **不要**顺手改无关代码或重新格式化。改动聚焦到当前任务。
- 改动前先确认工作区干净（`git status`），不要覆盖别人的未提交改动。
- CI 是唯一的 Native 编译验证手段；**不要**在本地失败后伪造"已验证"的结论。
- **git 命令执行不了时（环境故障、超时、无输出）直接跳过并记录，不要重试死循环**。
  把"没跑成 git / 待提交"如实写进交接文档，留给下一任，比反复重试更有用。

## 8. 两条流水线

| 文件 | 触发 | 作用 |
|---|---|---|
| `.github/workflows/build.yml` | push / PR 到 `main` | 只跑 `./gradlew build`，验编译，不留产物 |
| `.github/workflows/release.yml` | push `v*` tag | 构建 → zip `executable/` → 发 GitHub Release |

`build.yml` **不上传 artifact**，跑完产物即丢。要拿完整产物，走 `release.yml`
（打 tag）或在有 Android 环境的机器上本地构建。

## 9. 当前进度

- **Phase 1 Task 1.3 已完成**：指令加密从 RC4 切换为 ChaCha20
  - key 沿用 `g_shell_config.aes_key`（32B），未改密钥体系
  - nonce = `methodIdx` 的 12 字节 LE 编码（低 4 字节有效）
  - counter 从 0；v2 RC4 分支已随 Task 1.3 收尾**删除**（1.6 验收 grep 零命中）
  - 载荷版本 `MULTI_DEX_CODE_VERSION` 2 → 3（Task 1.1 后最终为 **4**）
- **Task 1.6 集成验收已执行**（2026-10-07）：报告 `docs/phase1-test.md`、
  终态设计 `docs/phase1-design.md`；✅7 / ❌3（打包 −24.7% 未达 −30%、
  冷启动 +299ms、内存 +240MB 级）/ ⏳4+，遗留问题归 Phase 2
  - 同日补测**原作者 v2.21.0 汇报口径**（报告 §四）：打包快 23.0%、
    体积 +0.45%~0.89%（持平）、运行时冷启动慢 26.0%/内存重 17.8%（**两轴劣于上游**）；
    纯 v2.21.0 打 21-dex 即崩（`catch (Exception)` 漏 `AssertionError`），
    对照组用了 1 行补丁（披露见报告 §4.3）
- 后续任务与设计见 `docs/进度与交接.md`（执行进度与交接，含 Task 1.4 实施记录与性能基准）
  与 `docs/phase1-perf-plan.md`（性能优化方案，唯一执行依据）
- v1.0.1~1.0.3 启动闪退的根因与修复见 `docs/启动闪退根因分析.md`
- **内存路径 VerifyError（v1.0.5 触发 / v1.0.6 修复）已真机验证**（2026-10-06，Android 16）：
  根因是 ART 不暴露注册 buffer 地址导致 gate 白名单拒绝，修复见
  `docs/启动闪退根因分析.md` §9 与 `docs/进度与交接.md` §10
- **v1.0.9 已真机验证通过**（2026-10-07，Android 16，默认内存路径）：修复了
  v1.0.8 的启动 SIGSEGV（`restoreRead` 用途混用，由 v1.0.7 引入），
  见 `docs/启动闪退根因分析.md` §十 与 `docs/进度与交接.md` §11.6。
  当前 `HEAD` = `origin/main` = `v1.0.9`
