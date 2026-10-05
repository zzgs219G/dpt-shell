# Phase 1 执行进度（交接文档）

> **给下一任 AI 或上下文压缩后的接手者。**先读完这一页，再动手。
> 最后更新：本次会话（载荷格式 v4 落地后）

---

## 一句话现状

Phase 1 的 **Task 1.10 / 1.7 / 1.1 / 1.3 已完成并推送**，当前工作区有**未提交的 v4 改动**待验证。
**Native 编译尚未验证，真机行为尚未验证。**

---

## ⚠️ 接手第一件事：先确认状态，别重复劳动

```bash
cd "/data/data/com.termux/files/home/克隆仓库x/dpt-shell"
git status --short          # 看有没有未提交改动
git log --oneline -3
```

如果看到 `dpt/src/main/java/com/luoye/dpt/config/Const.java` 等 **19 个文件被修改**、
且 `Const.MULTI_DEX_CODE_VERSION == 4`，说明 **v4 改动就在工作区里，已经做完了，不要重做**。

---

## 二、已完成的工作

| Task | 内容 | 状态 | 提交 |
|---|---|---|---|
| — | Phase 1 计划书（源码复核修正版） | ✅ | `8b2cf9c` |
| 1.10 | 性能基准工具 `tools/benchmark/` | ✅ | 本次待提交 |
| 1.7 | 打包侧 IO 优化 | ✅ | 本次待提交 |
| 1.1 | OoooooOooo v4 格式 + 类索引 | ✅ 代码完成 | 本次待提交 |
| 1.3 | RC4 insns 路径清理 | ✅ | 本次待提交 |

执行顺序是按**风险从低到高**排的（1.10 → 1.7 → 1.1+1.3），理由见 `docs/phase1-perf-plan.md` §1.4。

---

## 三、本次做了什么（v4 格式，破坏性变更）

### 3.1 格式变化

```
v3（旧）                          v4（新）
version(2) dexCount(2)            magic(4) version(2) dexCount(2)
dexCodeIndex[dexCount] u32        classIndexOffset(4) methodDataOffset(4)
每 dex: methodCount(2) + ...      ClassIndex[] 每项 16B，按 (dexIdx,classDataOff) 排序
每方法: methodIdx(4)              MethodData[] 变长：
        dataSize(4) data[]          methodIdx(4) insnsSize(2) encryptedInsns[]
```

**目的**：运行时用一次二分查找代替「每 dex 65536 指针数组 + 每方法一次堆分配」。
5 万方法时省掉约 512KB/dex 的空槽数组和 5 万个堆对象。

### 3.2 三个最容易踩的坑（都已处理，勿回退）

1. **`insnsSize` 是字节数，不是 code unit 数**
   `Instruction.getInstructionDataSize()` 存的是 `insnsCapacity * 2`。
   C++ 侧 `getMethodData` 按 `6 + insnsSize` 前进。写成 `* 2` 会越界读 2 倍。

2. **`RandomAccessFile.writeShort` 是大端**
   现有 `writeShort(0x0e)` 实际写入 `00 0e`，不是 dex 标准的 `0e 00`。
   Task 1.7 的批量写**手工复刻了大端顺序**，产物逐字节不变。
   见 `InsnsFillerBytesTest`。

3. **方法顺序契约：direct → virtual**
   Java 用 `ClassData.allMethods()`（smali 已验证 = direct 在前），Native 用
   `patchClass` 解析 ClassData（direct 先）。两者必须一致，否则密文写进错误方法体。
   `patchOneClassMethod` 里加了 `methodIdx` 不匹配就报错，作为兜底。

### 3.3 测试抓出的真实 bug（说明测试是有用的）

**ClassIndex 定义了比较器却忘了调用** → 索引未排序 → 运行时二分查找失效。
若没有 `classIndexIsSortedByDexIdxThenClassDataOff`，这个 bug 会潜伏到真机才暴露。
修复时还必须**同步置换 methodData 分块**，否则 `methodDataOff` 全错位。

---

## 四、改动清单

### 4.1 Java（dpt/src/main/java/com/luoye/dpt/）

| 文件 | 改动 |
|---|---|
| `config/Const.java` | `MULTI_DEX_CODE_VERSION` 3→4，新增 `MULTI_DEX_CODE_VERSION_V4`、`MULTI_DEX_CODE_MAGIC`、两个尺寸常量 |
| `model/Instruction.java` | 新增 `classDataOff` 字段（v4 索引键） |
| `model/MultiDexCode.java` | 重写为 v4 模型（classIndexOffset / methodDataOffset / classIndex / methodData） |
| `model/ClassIndexEntry.java` | **新增**，16 字节小端索引项 |
| `util/MultiDexCodeUtils.java` | 重写：分组 + **无符号排序**（同步置换分块）+ 写 v4 布局 |
| `util/DexUtils.java` | 补 `setClassDataOff`；Task 1.7 的 IO 优化（O(n)→O(1)）；`INS_RANDOM` 提为 static |
| `util/CryptoUtils.java` | 删 `buildInsnsRc4Key`（**保留 `rc4Crypt` 和 `RC4Transform`**，so 的 .bitcode 在用） |

### 4.2 Native（shell/src/main/cpp/）

| 文件 | 改动 |
|---|---|
| `dex/MultiDexCode.h/.cpp` | 重写：v4 解析、二分查找、变长游进、inline readUInt* |
| `dpt.cpp` | `readCodeItem` 删 65536 数组与 `dexMap` |
| `dpt_hook.cpp` | `patchMethod` → `patchMethodInsns`；新增 `patchOneClassMethod` |
| `dpt_crypto.h/.cpp` | 删 `rc4_crypt_insns` |
| `dex/CodeItem.h/.cpp` | **已删除**（`data::CodeItem` 无引用），CMakeLists 已同步 |
| `dpt.h`、`dpt_hook.cpp` | 删指向已删头文件的 include |

### 4.3 新增

- `dpt/src/test/java/com/luoye/dpt/util/MultiDexCodeV4Test.java`（13 用例）
- `dpt/src/test/java/com/luoye/dpt/util/ExtractMethodIoCountTest.java`（4 用例）
- `dpt/src/test/java/com/luoye/dpt/util/InsnsFillerBytesTest.java`（3 用例）
- `tools/benchmark/{bench-pack.sh, bench-runtime.sh, README.md}`
- `docs/phase1-benchmark.md`

---

## 五、验证状态（务必看清哪些没验）

### ✅ 本机已验证

```
./gradlew :dpt:test    → 37 用例全绿（failures=0 errors=0）
./gradlew :dpt:jar     → BUILD SUCCESSFUL
g++ -fsyntax-only MultiDexCode.cpp / dpt_crypto.cpp → OK
```

**跨语言对拍**（本次最有价值的验证）：
用真实 `dpt.jar` 生成 126 字节 v4 payload，`od` 核对字节
（`34 4f 4f 4f` = "4OOO"、version=4、ciOff=16、mdOff=64），
再用 C++ 解析逻辑读这份**真实产物** → ALL PASS（查找、记录顺序、越界防护、密文字节全对）。

### ❌ 尚未验证（必须补）

| 项 | 为什么本机不行 | 怎么验 |
|---|---|---|
| **Native 编译** | NDK 是 x86_64 交叉工具链，本机 arm64；`dpt_hook.cpp`/`dpt.cpp` 依赖 Android 头文件 | 推 main，CI `build.yml`（`-Wall -Wextra -Werror`） |
| **指令真被解密** | 需要设备 | 真机装包启动，看是否闪退 |
| 内存 / 冷启动收益 | 需要设备 | `tools/benchmark/bench-runtime.sh` |
| 打包耗时实际收益 | 需要完整 `executable/` | `tools/benchmark/bench-pack.sh` |

**不要**为验证 Native 写本地语法检查脚本——本机跑不了交叉工具链，
这类脚本会在**未修改的基线文件上也会报错**（`AGENTS.md` 已记录此教训）。

---

## 六、踩过的坑（避免重蹈）

1. **`TMPDIR` 失效导致 g++ 报 `unable to make temporary file`**
   会话中间 TMPDIR 指向的目录被清理，g++ 无法创建临时文件。
   症状像环境坏了。解法：`export TMPDIR=/tmp`。

2. **`dpt.jar` 失败时仍 exit 0**
   缺 `shell-files/` 时抛 `FileNotFoundException` 但进程返回 0。
   所以 `bench-pack.sh` 不能靠退出码判断成败，必须校验产物是否存在。
   **否则会输出漂亮但完全错误的性能数字。**

3. **`set -e` + 命令替换会让函数里的报错分支永远执行不到**
   `$(run_once ...)` 中函数 `return 1` 会连带终止脚本，错误信息打不出来。
   需显式 `set +e` 包裹。

4. **rg 匹配 `CodeItem` 会命中 `CodeItemView`、`CodeItem.cpp`**
   查引用要用词边界 `\b`，否则会误判「还有引用」而不敢删。

---

## 七、下一步（按顺序）

### 7.1 立刻做：提交并推送 main

```bash
git add -A dpt shell tools docs/phase1-benchmark.md
git status --short          # 确认不含 docs/项目新方向.md（用户自己的文件）
git commit -m "..."
git push origin main
```

**注意**：`docs/项目新方向.md` 是用户原有文件，**不要提交**。

### 7.2 等 CI 编译结果

CI `build.yml` 会验 Native 编译。**从日志判断成败**，不要只看绿/红。
若编译失败，重点看 `dpt_hook.cpp`（改动最大）。

### 7.3 CI 绿后打 tag

```bash
git tag v1.0.1
git push origin v1.0.1
```

`v1.0.1` 触发 `release.yml`（`tags: v*`），产出 GitHub Release。
用户已确认用 `1.0.1`（`appVersionName` 当前是 `1.0.0`；`v2.x` 是旧线，`v1.0.0` 是最近的）。

### 7.4 后续 Task

| Task | 内容 | 依赖 |
|---|---|---|
| 1.9 | 运行时字节解析 + descriptor 缓存 | 1.1（部分已顺手做了 inline readUInt*） |
| 1.5 | 页粒度 RW + 按页自旋锁 | 1.1；**注意需加 `__builtin___clear_cache`** |
| 1.4 | InMemoryDexClassLoader | **门槛 ≥29**，且需放宽 `patchClass` 的 location 判断 |
| 1.6 | 集成验收（真机） | 全部 |

---

## 八、Task 1.4 的三个坑（尚未实施，但极易踩）

`dpt_hook.cpp` 现有硬门槛 `location.rfind("i11111i111.zip")` 会让
InMemoryDexClassLoader 加载的类**一个都不解密** → APK 100% 崩溃，且 try-catch 兜不住
（静默不解密）。

- **API 阈值必须是 29**，不是 27。AOSP 证实 API 26–28 的 location 是
  `Anonymous-DexFile@%p-%p`（映射地址范围），**不含 dex 下标**，多 dex 会全被当成 dex0；
  API 29+ 才是 `<...>.jar!classesN.dex`，`parse_dex_number` 才能正确解析。
- 需放宽门槛同时接受 `i11111i111.zip` 与 `Anonymous-DexFile`。
- **InMemory 分支下不能调 `cbde`**，否则同一份 dex 会被追加两次 → DuplicateClass。

---

## 九、关键文件位置

| 内容 | 路径 |
|---|---|
| Phase 1 计划书（含全部 Task 细节） | `docs/phase1-perf-plan.md` |
| 性能基线表（未实测项留 `?`） | `docs/phase1-benchmark.md` |
| 基准工具说明 | `tools/benchmark/README.md` |
| 项目约定与历史教训 | `AGENTS.md` |
| 构建与排障 | `docs/build-and-release.md` |
| 踩坑记录 | `docs/pitfalls.md` |
| 流水线 | `.github/workflows/build.yml`（验编译）、`release.yml`（打 tag 发版） |