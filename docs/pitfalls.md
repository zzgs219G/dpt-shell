# 踩坑与故障记录

本文只记录**实际遇到过**的问题。每条都标注证据来源：
- **[本地]** = 在本机（arm64 Termux）实测
- **[CI]** = GitHub Actions 日志实证
- **[推理]** = 读代码推导，未实测

---

## 构建类

### 1. `Cannot find directory: shell-files!`

**[本地] 实测**

`dpt.jar` 运行时读不到 `shell-files/`。

**原因**：只跑了 `./gradlew :dpt:jar`（或过时的 `./gradlew assemble`），
没跑完整 build。`shell-files/` 由 `shell/build.gradle` 的 `afterAssembleCopy`
挂在 build 任务的 `doLast` 上生成。

**处理**：`./gradlew build`，且 `dpt.jar` 与 `shell-files/` 必须同次构建
（`build-key` 会校验）。

详见 [build-and-release.md](build-and-release.md#build-key-校验)。

---

### 2. `./gradlew assemble` 产不出完整 `executable/`

**[CI] + [推理]**

仓库 `README.md` 第 19-27 行给的命令是过时的。
`assemble*` 任务不触发 `afterAssembleCopy`（它挂在 `build` 任务上）。

**处理**：README 与 AGENTS.md 均已标注以 `./gradlew build` 为准。

---

### 3. `cannot execute binary file` —— x86_64 工具链跑在 arm64 上

**[本地] 实测**

本机是 arm64 Termux，而 aapt2、SDK cmake 3.31.1、NDK clang 全是 **x86_64 ELF**：

```
AAPT2 aapt2-8.10.0-12782657-linux Daemon #0: Daemon startup failed
```

**处理**：不要试图绕过。这是环境限制，走 CI 验证。

---

### 4. Termux 的 cmake 不可用

**[本地] 实测**

Termux `cmake` 4.4.4 缺符号，无法运行。

**处理**：同上，走 CI。

---

### 5. NDK 目录名与 AGP 期望不一致

**[本地] 实测**

AGP 硬编码期望 `27.0.12077973`。若解压 NDK 后目录名是
`android-ndk-r27c`，构建直接失败。

**处理**：重命名目录为 `27.0.12077973`。
（改名的过程中曾把目录搞成套娃并误删，只能从压缩包重新解压恢复 ——
**改名前先备份**。）

---

### 6. submodule 未初始化导致 Native 编译失败

**[本地] + [CI]**

`git clone` 不带 `--recursive` 时，4 个 vendored 库都是空目录。

**处理**：

```bash
git submodule update --init --recursive
```

---

### 7. 本地语法检查脚本不可信（重要教训）

**[本地] 实测**

曾在 Termux 上写脚本模拟编译器语法检查来做 Native 改动的"验证"。
**问题**：该脚本在**完全未修改的基线文件上也会报错**。

**结论**：这类自制工具会产出"能跑但结论错误"的结果，**比没有更危险**。

**正确做法**：Native 改动靠
1. 本地代码审查 + 逻辑推导（对齐现有风格、头文件包含、宏用法）
2. `git push` 后由 CI 跑真实编译
3. **读 CI 日志**判断，而不是只看绿灯

CI 用 `-Wall -Wextra -Werror`，比自制脚本严格得多。

---

## Java / 测试类

### 8. 测试向量凭记忆写错

**[本地] 实测**

ChaCha20 测试最初写成：
- nonce = `000000090000004a00000000`（错）
- Initial Counter = 0（错，应为 1）
- 密文含 `27`（错，应为 `1a`）

**为什么没被发现**：round-trip 测试只验证
"加密后再解密能还原"，任何对称加密都满足，**掩盖了向量本身写错**。

**处理**：从 `https://www.rfc-editor.org/rfc/rfc8439.txt` 抓原文逐字节核对。

**教训**：**标准测试向量必须取自权威原文，不能凭记忆写**，
且 round-trip 测试之外必须有硬编码的期望值。

---

### 9. JUnit 断言用错

**[本地] 实测**

`java.util.Arrays.equals(byte[], String)` 无匹配重载，编译失败。

**处理**：数组比较用 `java.util.Arrays.equals(byte[], byte[])`。

---

### 10. `--offline` 跑测试失败

**[本地] 实测**

```
No cached version listing for junit:junit:4.+
```

`dpt/build.gradle` 的 JUnit 依赖用了动态版本 `4.+`，需要联网解析。

**处理**：不要加 `--offline`。

---

### 11. `./gradlew` Permission denied

**[本地] 实测**

Gradle wrapper 没有执行位。

**处理**：`sh gradlew` 或 `chmod +x gradlew`。

---

## Native 代码类（CI 实证）

### 12. `MultiDexCode.h` 缺类结尾 `;`

**[CI] 实测**

修改该文件时误删了命名空间闭合括号，且当时补 `;` 的操作有误。

**CI 报错**：

```
dpt_hook.cpp:560:2: error: expected '}'
note: to match this '{'  MultiDexCode.h:33 namespace dpt::data {
```

**处理**：文件结尾补回 `};`（类闭合）+ `}`（命名空间闭合）。

---

### 13. 构造函数定义缺少限定符

**[CI] 实测**

```cpp
MultiDexCode::MultiDexCode() { ... }   // 错
```

在 `namespace dpt::data` 外的 `.cpp` 里这样定义会报未声明标识符。

**CI 报错**：

```
dpt_hook.cpp: MultiDexCode.cpp:13:1: error: use of undeclared identifier 'MultiDexCode'
```

**处理**：写成 `dpt::data::MultiDexCode::MultiDexCode()`。

---

### 14. CI 的 warning 噪音

**[CI] 实测**

一次成功的构建有 68 个 warning，**全部来自 vendored Dobby**，
项目自己的改动文件零 warning（CI 用 `-Wall -Wextra -Werror`）。

**识别**：看 warning 来自哪个文件，别被 vendored 库的噪音误导。

---

## CI / 发布类

### 15. tag 不符合 semver 被拒

**[CI] 实测**

用 `v1.0` 打 tag，发布失败：

```
The parameter "automatic_release_tag" was not set and the current tag
"v1.0" does not appear to conform to semantic versioning.
```

**处理**：用 `vX.Y.Z` 三段格式，如 `v1.0.0`。

---

### 16. Release 创建被拒：缺 `contents: write`

**[CI] 实测**

构建和 zip 都成功了，卡在最后一步：

```
Resource not accessible by integration
```

**原因**：`release.yml` 的 job 未声明 `permissions`，
`GITHUB_TOKEN` 沿用仓库默认权限，没有 `contents: write`。

**处理**：在 `release.yml` 的 job 下加：

```yaml
permissions:
  contents: write
```

**注意**：这类问题**不会**在本地复现，只有 CI 才暴露。

---

### 17. 本地遗留 tag 挡住新版本号

**[本地] 实测**

克隆仓库时带下一个从未推送的本地 tag `v1.0.0`（指向 2022 年的游离 commit），
导致 `git tag v1.0.0` 报 `already exists`。

**处理**：`git ls-remote --tags origin` 确认远端是否存在。
本地游离 tag 可直接 `git tag -d`。

---

### 18. 改 commit message 需要重写历史

**[本地] 实测**

误加 `Co-Authored-By` trailer 后想清除：

```bash
FILTER_BRANCH_SQUELCH_WARNING=1 git filter-branch -f \
  --msg-filter "sed '/^[[:space:]]*Co-Authored-By: Claude/d'" \
  <earliest>~1..HEAD
```

**注意**：
- 需要 `git push --force-with-lease`（**不要**用 `--force`，
  前者会校验远端是否被别人更新过）
- 已发布的 tag 和 Release 会与新 commit 脱节，需删掉重发
- 重写前先建备份分支：`git branch backup <old-head>`
- filter-branch 失败时**会自动回滚**，可安全重试
- 本环境**没有 `perl`**，只能用 `sed`

---

### 19. GitHub API 匿名调用被限流

**[本地] 实测**

未认证访问 Actions API 返回 403（rate limit）。

**处理**：从 git credential 里取 token：

```bash
printf 'protocol=https\nhost=github.com\n\n' | git credential fill
```

**注意**：token 属敏感信息，只存临时目录、用完删除，
**不要提交进仓库**。

---

## 方法论

### 20. 不要伪造验证结论

**[本地] + [推理]**

无法验证的项目（无 adb 设备、真机行为）必须明确标注**"待验证"**，
不能给出估算数字冒充实测结果。

**分层原则**：

| 层 | 手段 |
|---|---|
| Java 代码 | JUnit 单测（本地可跑） |
| Native 代码 | GitHub Actions 真实编译 |
| 真机行为 | adb 设备（无设备则标注待验证） |
| 性能数据 | 真实构建产物上测，不能估算 |

---

### 21. README 与实际行为不符时，以实测为准

**[本地] 实测**

`README.md` 说的 `./gradlew assemble` 产不出完整产物，
Release 产物名也与实际（`dpt-shell-vX.Y.Z.zip`）不符。

**原则**：文档与实测冲突时，**改文档**，并在文档里注明旧说法为何错。