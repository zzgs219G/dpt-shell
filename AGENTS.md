# AGENTS.md

本文件是 dpt-shell 项目中 AI 助手的**工作约定**。接手本项目前请先读完本文件，再动手改代码。

改代码前先看流程地图（流程、跨端契约、红线、改哪里）：[docs/项目流程.md](docs/项目流程.md)。
详细的构建与排障流程见 [docs/构建与发布.md](docs/构建与发布.md)；
踩坑与故障记录见 [docs/踩坑记录.md](docs/踩坑记录.md)。

---

## 1. 项目是什么

dpt 是 Android 壳工程：`dpt.jar` 是**命令行打包工具**（纯 Java，无 Android 依赖），
`shell` 是 **Android library**，产出 `libxixin.so` 和 `classes.dex`。

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

# 发布：见 docs/构建与发布.md
```

**关键区别**：`./gradlew assemble` **不足以**产出可用的 `executable/`。
`executable/shell-files/`（含各 ABI 的 `libxixin.so`）由 `:shell` 的
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
    ├── libs/<abi>/libxixin.so  ← arm64-v8a / armeabi-v7a / x86 / x86_64
    ├── build-key
    └── keyladder-seed.txt
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

- **工具调用必须并行**：模型后端（NVIDIA 免费 API）响应延迟高，串行逐个调用
  会成倍浪费时间。**没有数据依赖的调用（读多个文件、多处 grep、独立的 adb / git
  查询、编译与互不依赖的检查）必须合并到同一个回复里并行发出**；只有后一步
  需要前一步的输出时才串行。这条优先级很高，是本环境实测得出的效率铁律。
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

## 9. 当前标准版本（2026-10-27 更新）

**v1.3.2 是当前标准基线**，详见 [docs/基线-v1.3.2-真机验证.md](docs/基线-v1.3.2-真机验证.md)。
该文档包含密钥派生链的权威定义、真机验证结论、产物静态核验项与四条教训。
**改动前必读，改动后必须复现其中的核验项。**

v1.1.x ~ v1.2.x 全部存在致命缺陷（启动崩溃或密钥泄漏），
失效链见基线文档 §5.1，**不要回退到那些版本**。

## 10. 历史进度（2026-10-13，以 v1.1.3 为基准）

- **当前发布 = v1.1.3**（tag `v1.1.3` = `1ab54d0`，`dpt.jar -v` 自报一致）：
  - 指令加密 ChaCha20（Phase 1 Task 1.3）；载荷 **v5 分块压缩**（先 deflate 后
    块级加密，`Const.MULTI_DEX_CODE_VERSION`，运行时只认 v5，见 `MultiDexCodeV5Test`）
  - `-S` 收敛为统一 `0x0e` 填料；字符串解密桩 **L1 缓存**（真机实测无回归，
    CPU/PSS 小幅改善）；`dpt.jar -v` 自报修复
  - 默认**磁盘加载**（code_cache 落盘），内存路径 opt-in（`--use-inmemory-dex`）
  - 壳内 `BackgroundDexopt`（exec 路线）**实测无效**：App 域（untrusted_app）被
    SELinux 拦截无权执行 dex2oat。代码仍在（`ProxyApplication` 调用，静默失败
    无害），是否删除待定
- **性能归因结论（真机 + atrace 实证，后续优化的指导基线）**：
  - 全模块加壳冷启动 ~427ms vs 原生 ~195ms（+232ms），≈82% 来自「基础加壳」模块，
    其余模块合计仅 ~40ms
  - 主因 = 启动期对运行时还原 dex 的 **VerifyClass（1,660+ 次）+ 解释执行**；
    baseline profile 失配坐实（装包日志 `speed-profile → verify because there
    is no valid profile`）
  - **隐藏 dex 拿不到 AOT 是架构性的**：装包期 dex2oat 只编译 APK 根；
    InMemoryDexClassLoader 无 odex 落点；落盘路线补 dexopt 被 SELinux 拦——三条路全死
- **威胁模型（用户明确，一切取舍以此为准）**：**防特征检测（安装器报毒），
  不防脱壳**——「脱壳前防御」（加密/抽取/隐藏）与「壳特征」本是同一批东西
- **v1.1.4**（仅新增一个参数，无其他行为变化）：`--plain` 防特征模式（仅 APK）——
  不抽取指令、frida/CRC/anti-debug 全关，业务 dex 完整明文走既有尾巴 zip +
  落盘路径，壳特征（壳 so / 代理 Application / config）保留；真机实测冷启动
  ~330ms（较全防御 -22%；落盘无 AOT，到不了原生 ~195ms）。附带两处修复：
  `init_app` 对无 xixin_data 的包安全跳过（空 optional 守卫）；壳 so `.bitcode`
  段在 plain 下**必须保留加密**（native 无条件自解密，跳过即 SIGILL，真机踩坑）
- 历史根因文档仍有效：`docs/启动闪退根因分析.md`（v1.0.x 系列）、
  `docs/进度与交接.md`；性能/防特征调研沉淀在 apk-protect-action 仓库 docs/
- 当前 `HEAD` = `origin/main` = `v1.1.4`
