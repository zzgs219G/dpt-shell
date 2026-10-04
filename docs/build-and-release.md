# 构建与发布流程

面向**人类维护者**和 **AI 助手**。项目整体约定见 [../AGENTS.md](../AGENTS.md)；
踩坑记录见 [pitfalls.md](pitfalls.md)。

---

## 1. 一句话版本

```bash
git tag v1.0.1 && git push origin v1.0.1
```

GitHub Actions 会自动完成构建 → 打包 `executable/` → 创建 Release。
**发版不需要任何人工构建步骤。**

---

## 2. 环境准备

| 项 | 版本 | 备注 |
|---|---|---|
| JDK | 17 | AGP 要求 |
| Android SDK | compileSdk 36 / minSdk 21 | `build.gradle` |
| NDK | **27.0.12077973** (r27c) | 目录名必须完全匹配，否则 AGP 报找不到 |
| CMake | 3.31.1 | `build.gradle:50` |
| ninja | 近期版本 | `apt install ninja-build` |

### 克隆

```bash
git clone --recursive https://github.com/zzgs219G/dpt-shell
cd dpt-shell
git submodule update --init --recursive   # 已有 clone 时补这一步
```

漏掉 submodule 会导致 Native 编译找不到 `Dobby` / `bhook` / `mbedtls` / `minizip-ng`。

### 确认 NDK 目录名

```bash
ls ~/Android/Sdk/ndk/
```

必须是 `27.0.12077973`。如果你的 NDK 是别的版本，**重命名目录**即可，
AGP 读的是 `source.properties` 和目录名里的版本号。

---

## 3. 本地构建

```bash
./gradlew build
```

约 4-6 分钟（4 个 ABI 各编译一次）。

**只想要 `dpt.jar`**（不需要 Android SDK / NDK，纯 Java）：

```bash
./gradlew :dpt:jar
```

**只跑测试**：

```bash
./gradlew :dpt:test
```

### ⚠️ 不要用 `./gradlew assemble`

README 第 19-27 行写的是 `./gradlew assemble`，**这是过时的**，会产出不完整的
`executable/`：

- `executable/dpt.jar` ✅ 有
- `executable/shell-files/` ❌ **没有**

`shell-files/` 由 `shell/build.gradle` 的 `afterAssembleCopy` 生成，挂在
**build 任务**（`assembleDebug` / `assembleRelease`）的 `doLast` 上。

后果：`dpt.jar` 启动时读不到 `shell-files/build-key`，校验失败直接拒绝运行。

---

## 4. 产物说明

```
executable/
├── dpt.jar                            # 打包工具本体
├── dpt-exclude-classes-template.rules # 排除类配置模板
├── dpt-protect-config-template.json   # 保护配置模板
└── shell-files/                       # 必须与 dpt.jar 同次构建
    ├── dex/classes.dex
    ├── libs/arm64-v8a/libdpt.so
    ├── libs/armeabi-v7a/libdpt.so
    ├── libs/x86/libdpt.so
    ├── libs/x86_64/libdpt.so
    └── build-key
```

### build-key 校验

`dpt.jar` 内嵌了一个 key（`dpt/build.gradle` 的 manifest 写入 `Dpt-Build-Key`），
运行时读取 `shell-files/build-key` 比对。**不一致则拒绝工作**。

所以：`dpt.jar` 和 `shell-files/` 必须来自**同一次** `./gradlew build`。
不要跨构建混用，也不要只从别处拷 `dpt.jar`。

### 使用

```bash
cd executable
java -jar dpt.jar -f /path/to/app.apk
```

---

## 5. 发布

### 5.1 更新版本号

`build.gradle` 的 `appVersionName` 应与 tag 一致：

```groovy
ext {
    appVersionCode = 1
    appVersionName = "1.0.0"
}
```

它决定 `dpt.jar` 内部的 `Implementation-Version`，改完重新构建。

### 5.2 打 tag

```bash
git tag v1.0.1
git push origin v1.0.1
```

`release.yml` 触发，依次执行：
1. `./gradlew build`
2. `zip -r dpt-shell-v1.0.1.zip executable/`
3. 创建 GitHub Release 并上传 zip

下载页：<https://github.com/zzgs219G/dpt-shell/releases>

**下载后要先解压**，得到 `executable/` 子目录。

### 5.3 tag 必须符合 semver

`marvinpinto/action-automatic-releases` 要求 **三段**格式：

| tag | 结果 |
|---|---|
| `v1.0` | ❌ `does not appear to conform to semantic versioning` |
| `v1.0.0` | ✅ |
| `v1.0.1` | ✅ |

---

## 6. 排障

遇到构建或发布失败，查 [pitfalls.md](pitfalls.md)。

快速自查：

```bash
# 确认 CI 状态
gh run list --limit 5

# 看某次运行的详细日志
gh run view <run-id> --log

# 找失败步骤
gh run view <run-id> --log-failed
```

### 常见故障速查

| 现象 | 原因 | 处理 |
|---|---|---|
| `Cannot find directory: shell-files!` | 只跑了 `:dpt:jar` 或 `assemble` | 跑完整 `./gradlew build` |
| `does not conform to semantic versioning` | tag 不是三段 | 用 `v1.0.0` 形式 |
| `Resource not accessible by integration` | workflow 缺 `permissions` | 已修复，见 pitfalls |
| `cannot execute binary file` | x86_64 工具链跑在 arm64 上 | 用 CI，不要本地编译 |
| 找不到 `Dobby` / `bhook` | submodule 未初始化 | `git submodule update --init --recursive` |
| NDK 版本不匹配 | 目录名不是 `27.0.12077973` | 重命名 NDK 目录 |

---

## 7. 两条流水线的区别

| | `build.yml` | `release.yml` |
|---|---|---|
| 触发 | push / PR 到 `main` | push `v*` tag |
| 构建 | ✅ | ✅ |
| 打包 | ❌ | ✅ zip `executable/` |
| 发布 | ❌ | ✅ GitHub Release |
| 留产物 | ❌ 跑完即丢 | ✅ Release 页面 |

`build.yml` **不上传 artifact**，所以它跑完你拿不到任何东西。
要完整产物，只能打 tag 走 `release.yml`，或在本地跑 `./gradlew build`。