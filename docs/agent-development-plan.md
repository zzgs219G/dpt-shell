dpt-shell 2.0 Agent 可执行开发计划书

版本：v1.0
日期：2026-10-04
状态：正式版
存放路径：docs/agent-development-plan.md

---

〇、执行总则

〇.1 目标

在保持 APK/AAB 加壳功能可用的前提下，完成三项升级：

1. 性能更强
2. 防御更强（非签名校验类）
3. 不能被一键 dpt-unpack

〇.2 执行策略

· 每个 Task 独立可验证，Task 之间有明确依赖
· 优先做 Phase 1（收益确定、风险低），再 Phase 2，最后 Phase 3
· 每个 Task 完成后必须通过验收标准才能进入下一 Task
· 保留调试开关，任何改动不能破坏 --debug 模式

〇.3 执行环境

· JDK 17
· Android SDK 36 / NDK（CMake 3.31.1）
· Gradle 8.14
· 测试机：Android 11（API 30）arm64-v8a 真机 + 模拟器

〇.4 如何使用本文档

· 本文档是 Agent 的执行依据，每个 Task 独立可交付
· 启动任一 Task 前，Agent 必须完成第五章"Agent 执行模板"里的前置检查
· 每个 Task 完成后，必须勾选第九章"文档产出检查清单"
· Phase 之间不允许并行，Phase 内部允许 Task 并行（按第四章依赖图）
· 任何 Task 失败，必须走"失败回滚"，不允许带病进入下一 Task

---

一、Phase 1：性能重构

Task 1.1：OoooooOooo 格式重构 + 索引表

依赖：无
预计工时：3–5 天
风险：中（格式变更需两端同步）

改动文件：

· dpt/src/main/java/com/luoye/dpt/util/MultiDexCodeUtils.java
· dpt/src/main/java/com/luoye/dpt/model/MultiDexCode.java
· dpt/src/main/java/com/luoye/dpt/model/DexCode.java
· shell/src/main/cpp/dex/MultiDexCode.cpp
· shell/src/main/cpp/dex/MultiDexCode.h
· shell/src/main/cpp/dex/CodeItem.cpp
· shell/src/main/cpp/dex/CodeItem.h

新格式定义（写入 MultiDexCodeUtils 的注释和写入逻辑）：

```
OoooooOooo v3 格式:
┌──────────────────────────────────────────────┐
│ Header (16 字节)                              │
│   uint32 magic         = 0x4F4F4F33 ("OOO3")  │
│   uint16 version       = 3                    │
│   uint16 dexCount                             │
│   uint32 classIndexOffset                     │
│   uint32 methodDataOffset                     │
├──────────────────────────────────────────────┤
│ ClassIndex[] (每项 16 字节)                    │
│   uint8  dexIdx                               │
│   uint8  reserved                             │
│   uint16 methodCount                          │
│   uint32 classDataOff                         │
│   uint32 methodDataOff  (相对 methodData 起点) │
├──────────────────────────────────────────────┤
│ MethodData[] (紧凑二进制)                      │
│   { uint32 methodIdx,                         │
│     uint16 insnsSize,                         │
│     uint8[insnsSize*2] encryptedInsns }       │
└──────────────────────────────────────────────┘
```

Java 侧改动：

1. MultiDexCodeUtils.makeMultiDexCode 改为：
   · 收集所有 Instruction，按 (dexIdx, classDataOff) 排序
   · 构建 ClassIndex[] 和 MethodData[]
   · 计算 offset 并写入
2. MultiDexCodeUtils.writeMultiDexCode 按新格式写
3. 新增 ClassIndexEntry 内部类

Native 侧改动：

1. MultiDexCode::init 解析 header
2. 新增 MultiDexCode::getClassIndex(dexIdx, classDataOff) 用二分查找
3. 新增 MultiDexCode::getMethodData(offset) 返回 POD 视图（不 new）
4. 删除 nextCodeItem 和 CodeItem 对象 new 逻辑
5. 内部 CodeItem 改为栈上 POD：

```cpp
// 注意：这是 dpt-shell 内部使用的视图结构，与 Dex 文件格式里的
// dex::CodeItem（含 registers_size_、insns_ 等字段）是两回事。
struct CodeItemView {
    uint32_t methodIdx;
    uint16_t insnsSize;
    const uint8_t* encryptedInsns;
};
```

验收标准：

☐ 用一个小 APK（<5MB）加壳，能正常启动
☐ 用 --debug 模式验证 readCodeItem 输出的索引条目数与原始方法数一致
☐ 内存 profiler 显示 dexMap 相关内存下降 40%+
☐ 原 OoooooOooo v2 格式仍可解析（向后兼容）

回滚方案：保留 v2 解析分支，通过 header.magic 区分。

---

Task 1.2：去掉 65536 指针数组

依赖：Task 1.1（新格式提供排序索引）
预计工时：1–2 天
风险：低

改动文件：

· shell/src/main/cpp/dpt.cpp（readCodeItem）
· shell/src/main/cpp/dex/MultiDexCode.h

改动内容：

删除：

```cpp
auto codeItemVec = new std::vector<data::CodeItem *>(65536);
```

替换为：

```cpp
// 每个 dex 一份排序索引，按 classDataOff 排序
struct DexIndex {
    std::vector<ClassIndexEntry> classes;  // 排序后
    const uint8_t* methodDataBase;
    uint32_t methodDataSize;
};
std::unordered_map<int, DexIndex> dexIndexMap;
```

patchClass 中查找：

```cpp
auto it = dexIndexMap.find(dexIdx);
if (it != dexIndexMap.end()) {
    auto& idx = it->second;
    auto entry = std::lower_bound(idx.classes.begin(), idx.classes.end(),
        class_def->class_data_off_,
        [](const ClassIndexEntry& a, uint32_t off) { return a.classDataOff < off; });
    // 处理 entry
}
```

验收标准：

☐ 10 万方法 APK 加壳后，启动内存增量 < 5MB
☐ patchClass 查找耗时 < 1μs（用 systrace 验证）

---

Task 1.3：RC4 → ChaCha20

依赖：无（可与 Task 1.1 并行）
预计工时：3–4 天
风险：中（两端需同步）

改动文件：

· dpt/src/main/java/com/luoye/dpt/util/CryptoUtils.java
· shell/src/main/cpp/dpt_crypto.cpp
· shell/src/main/cpp/dpt_crypto.h
· shell/src/main/cpp/dpt_hook.cpp（patchMethod）
· dpt/src/main/java/com/luoye/dpt/util/DexUtils.java（extractMethod）

Java 侧：

```java
// 新增
public static byte[] chacha20Crypt(byte[] key, byte[] nonce, byte[] in) {
    // 使用 BouncyCastle 或自实现 ChaCha20
    // key: 32 字节, nonce: 12 字节
}
```

Native 侧：

· 引入 ChaCha20 实现（自实现或复用 mbedtls 的 mbedtls_chacha20）
· patchMethod 改为：

```cpp
uint8_t nonce[12];
memcpy(nonce, methodIdx 派生, 12);
mbedtls_chacha20_crypt(key, nonce, 0, sz, enc, realInsnsPtr);
```

注意：

· ChaCha20 的 counter 从 0 开始
· 每次解密使用相同 key + nonce，不要跨方法复用

验收标准：

☐ 加壳 APK 正常启动
☐ 单元测试：CryptoUtilsTest.chacha20KnownVector 通过 RFC 8439 test vector
☐ 类加载 CPU 耗时比 RC4 版下降 30%+

兼容性说明：

· 旧版用 RC4 加壳的 APK 用新版运行时会出现解密失败
· 通过 OoooooOooo header 中的 version 字段区分：v3 用 ChaCha20，v2 用 RC4

---

Task 1.4：首次启动 InMemoryDexClassLoader

依赖：无
预计工时：2–3 天
风险：中（API < 26 需回退）

改动文件：

· shell/src/main/java/com/luoyesiqiu/shell/ProxyApplication.java
· shell/src/main/java/com/luoyesiqiu/shell/ProxyComponentFactory.java
· shell/src/main/java/com/luoyesiqiu/shell/Global.java

改动内容：

Global.java 新增：

```java
public static final boolean USE_IN_MEMORY_DEX = Build.VERSION.SDK_INT >= 26;
```

ProxyApplication.attachBaseContext 中：

```java
if (Global.USE_IN_MEMORY_DEX) {
    // 从 APK 中读出 i11111i111.zip 内容到 ByteBuffer
    byte[] dexZip = readDexZipFromApk(applicationInfo.sourceDir);
    ByteBuffer buffer = ByteBuffer.wrap(dexZip);
    ClassLoader inMemoryLoader = new InMemoryDexClassLoader(buffer, base.getClassLoader());
    JniBridge.cbde(inMemoryLoader);
} else {
    // 回退原逻辑
    JniBridge.ia();
    JniBridge.cbde(base.getClassLoader());
}
```

注意：

· InMemoryDexClassLoader 接受的是原始 DEX 数据，不是 zip
· 需要把 zip 里的每个 classes*.dex 解出来，逐个创建 InMemoryDexClassLoader 或合并成一个
· 保留原 code_cache 路径作为回退

验收标准：

☐ Android 11 上启动正常，code_cache/i11111i111.zip 不生成
☐ Android 8.0（API 26）上启动正常
☐ Android 7.0（API 24）上走回退路径，启动正常

---

Task 1.5：页粒度 RW 窗口 + 按页自旋锁

依赖：Task 1.1（CodeItemView 提供精确地址）
预计工时：2–3 天
风险：中（并发场景需充分测试）

改动文件：

· shell/src/main/cpp/dpt_hook.cpp（patchMethod、change_dex_protective）
· shell/src/main/cpp/dpt_util.h（新增页锁）

改动内容：

删除 change_dex_protective 的 dex 粒度逻辑，改为：

```cpp
// 全局页锁表
static std::unordered_map<uintptr_t, std::mutex> g_pageLocks;
static std::mutex g_pageLockTableMutex;

std::mutex& getPageLock(uintptr_t pageAddr) {
    std::lock_guard<std::mutex> lg(g_pageLockTableMutex);
    return g_pageLocks[pageAddr];
}

void patchMethodWithPageLock(uint8_t* begin, ..., uint32_t codeOff, ...) {
    // 注意：这里的 dex::CodeItem 是 Dex 文件格式里的结构，
    // 与 Task 1.1 引入的 CodeItemView 是两回事。
    auto* dexCodeItem = (dex::CodeItem *)(begin + codeOff);
    auto* realInsnsPtr = (uint8_t *)(dexCodeItem->insns_);
    uintptr_t pageStart = DPT_PAGE_START((uintptr_t)realInsnsPtr);
    size_t pageLen = ...; // 跨页处理

    std::lock_guard<std::mutex> lg(getPageLock(pageStart));
    dpt_mprotect((void*)pageStart, (void*)(pageStart + pageLen), PROT_READ | PROT_WRITE);
    // 解密写入
    rc4_or_chacha20_crypt(...);
    dpt_mprotect((void*)pageStart, (void*)(pageStart + pageLen), PROT_READ);
}
```

关键修正：

· 恢复权限用 PROT_READ，不是 PROT_READ | PROT_EXEC
· 跨页时对每页加锁（按页地址排序，避免死锁）

验收标准：

☐ 多线程并发加载同一个 dex 的类，无 SIGSEGV
☐ 单方法 patch 期间，RW 窗口 < 100μs（systrace 验证）
☐ dexMemMap 不再常驻整个 dex 的 RW 映射

---

Task 1.6：Phase 1 集成验收

依赖：Task 1.1–1.5 全部完成
预计工时：2 天

验收流程：

1. 编译 ./gradlew assemble
2. 用测试 APK（10MB，5 万方法）加壳
3. 在 Android 11 真机上安装启动
4. 测量：
   · 冷启动增量（对比原版 APK）
   · 内存增量（dumpsys meminfo）
   · 首次启动落盘（code_cache 是否有 zip）
5. 记录数据到 docs/phase1-benchmark.md

通过标准：

指标 目标
冷启动增量 <200ms
内存增量 <5MB
首次落盘 0（API≥26）
类加载 CPU <10%

---

二、Phase 2：提高离线脱壳成本

Task 2.1：Runtime Key 分层

依赖：Phase 1 完成
预计工时：3–4 天
风险：中

改动文件：

· dpt/src/main/java/com/luoye/dpt/util/CryptoUtils.java
· dpt/src/main/java/com/luoye/dpt/builder/AndroidPackage.java
· dpt/src/main/java/com/luoye/dpt/config/ShellConfig.java
· shell/src/main/cpp/dpt.cpp（read_shell_config）
· shell/src/main/cpp/dpt_crypto.cpp

改动内容：

Java 侧：

```java
// 替代 deriveConfigAesKey
public static byte[] deriveMasterKey(byte[] randomKey, String packageName, String buildKey) {
    return CryptoUtils.hmacSha256(randomKey, packageName + "_" + buildKey);
}

public static byte[] deriveSessionKey(byte[] masterKey, byte[] runtimeNonce) {
    // HKDF-Expand
    return CryptoUtils.hkdfSha256(masterKey, runtimeNonce, "dpt-session", 32);
}

public static byte[] deriveMethodKey(byte[] sessionKey, int dexIdx, int methodIdx) {
    byte[] info = ByteBuffer.allocate(8)
        .putInt(dexIdx).putInt(methodIdx).array();
    return CryptoUtils.hkdfSha256(sessionKey, info, "dpt-method", 32);
}
```

Native 侧：

```cpp
// read_shell_config 中
auto master_key = hmac_sha256(DPT_UNKNOWN_DATA, 16, key_material.data(), key_material.size());

// 生成 runtimeNonce（随机 16 字节）
uint8_t runtime_nonce[16];
getrandom(runtime_nonce, 16, 0);

// 派生 sessionKey
auto session_key = hkdf_sha256(master_key, runtime_nonce, "dpt-session", 32);
memcpy(g_shell_config.session_key, session_key.data(), 32);

// patchMethod 中
auto method_key = hkdf_sha256(g_shell_config.session_key, info, "dpt-method", 32);
```

注意：

· masterKey 仍可从 APK + SO 推导，不能解决离线脱壳
· 目的是把攻击者逼到运行时 Hook
· 文档中必须明确说明这个边界

验收标准：

☐ 加壳 APK 正常启动
☐ sessionKey 每次启动不同（日志验证）
☐ 单元测试：testDeriveSessionKeyDeterministic 通过

---

Task 2.2：数据格式随机化

依赖：Task 2.1
预计工时：4–5 天
风险：高（两端解析需严格同步）

改动文件：

· dpt/src/main/java/com/luoye/dpt/util/MultiDexCodeUtils.java
· shell/src/main/cpp/dex/MultiDexCode.cpp
· dpt/src/main/java/com/luoye/dpt/config/Const.java（新增随机种子配置）

改动内容：

构建时：

1. 生成随机种子 formatSeed（4 字节）
2. 用 formatSeed 派生：
   · 字段顺序（用 formatSeed % N! 决定）
   · 索引编码（uleb128 / 定长 / 变长）
   · dex 顺序
   · Junk Bytes 长度（每方法间插入 0–15 字节随机）
3. formatSeed 用 sessionKey 加密后写在 OoooooOooo 尾部

运行时：

1. 读尾部 formatSeed（用 sessionKey 解密）
2. 按 formatSeed 派生的规则解析

关键实现：

```java
// Java 侧
byte[] seed = new byte[4];
new SecureRandom().nextBytes(seed);
int formatSeed = ByteBuffer.wrap(seed).getInt();

// 打乱顺序
List<ClassIndexEntry> shuffled = shuffleBySeed(entries, formatSeed);
```

```cpp
// Native 侧
uint32_t format_seed = decrypt_seed(...);
auto order = derive_field_order(format_seed);
auto encoding = derive_encoding(format_seed);
```

验收标准：

☐ 连续构建 3 次，OoooooOooo 二进制布局不同
☐ dpt-unpack 对随机化后的 APK 脱壳失败（需人工验证）
☐ --debug 模式下输出格式描述，便于调试

---

Task 2.3：虚假 CodeItem 注入

依赖：Task 2.2
预计工时：2 天
风险：低

改动文件：

· dpt/src/main/java/com/luoye/dpt/util/MultiDexCodeUtils.java
· shell/src/main/cpp/dex/MultiDexCode.cpp
· dpt/src/main/java/com/luoye/dpt/config/Const.java

改动内容：

Const.java 新增：

```java
public static final float FAKE_CODE_ITEM_RATIO = 0.4f;  // 可调整
```

构建时：

1. 统计真实方法数 realCount
2. 生成 fakeCount = (int)(realCount * Const.FAKE_CODE_ITEM_RATIO)
3. 假数据特征：
   · methodIdx 随机（不与真实的冲突）
   · insnsSize 随机（16–256）
   · encryptedInsns 随机字节
4. 用 sessionKey 派生真伪判别：hash(methodIdx, sessionKey) % 2 == 0 为真

运行时：

1. patchClass 查找时，先判别真伪
2. 假的直接跳过

验收标准：

☐ dpt-unpack 遍历输出包含 FAKE_CODE_ITEM_RATIO 比例的假数据
☐ App 启动正常，真实方法全部正确回填
☐ 调整 FAKE_CODE_ITEM_RATIO 后，输出文件大小随之变化

---

Task 2.4：检测逻辑内联 + 结果参与解密

依赖：Task 2.1
预计工时：3–4 天
风险：中

改动文件：

· shell/src/main/cpp/dpt_risk.cpp
· shell/src/main/cpp/dpt_risk.h
· shell/src/main/cpp/dpt_hook.cpp（patchMethod）

改动内容：

1. 删除独立 detectFrida / detectDebugger / verifyLibcTextCrc 调用
2. 改为内联到 patchMethod：

```cpp
uint8_t risk_byte = 0;
risk_byte ^= (check_tracer_pid() == 0) ? 0x00 : 0x01;
risk_byte ^= (check_frida_maps() == 0) ? 0x00 : 0x02;
risk_byte ^= (check_libc_crc() == 0) ? 0x00 : 0x04;

// risk_byte 参与密钥派生
auto method_key = hkdf_sha256(session_key, info, "dpt-method", 32);
method_key[0] ^= risk_byte;  // 检测失败则解密错误
```

3. 保留原独立检测函数供 --debug 模式使用

验收标准：

☐ 正常环境下 App 启动正常
☐ 用 Frida 附加后，App 解密出错（方法行为异常）
☐ Patch 掉 check_tracer_pid 后，App 仍解密失败

---

Task 2.5：Phase 2 集成验收

依赖：Task 2.1–2.4 全部完成
预计工时：2 天

验收流程：

1. 构建 3 次，每次用不同测试 APK
2. 运行 dpt-unpack（开源工具），记录结果
3. 用 Frida 尝试 Hook patchMethod，记录结果

通过标准：

☐ dpt-unpack 无法一键脱壳（需人工逆向格式）
☐ Frida Hook 后 App 异常
☐ 手动脱壳需要 2 天以上

---

三、Phase 3：防运行时 Dump

Task 3.1：ArtMethod 入口点动态偏移推导

依赖：Phase 2 完成
预计工时：4–5 天
风险：高

改动文件：

· shell/src/main/cpp/art/art_method.h（新建）
· shell/src/main/cpp/art/art_method.cpp（新建）
· shell/src/main/cpp/dpt_hook.cpp

改动内容：

1. 通过 DobbySymbolResolver 找到 art::ArtMethod::Invoke 或从 ClassLinker 反推 ArtMethod 布局
2. 动态推导 entry_point_from_quick_compiled_code_ 的偏移：

```cpp
size_t deriveEntryPointOffset() {
    // 方法 1：从 AOSP 源码已知偏移 + 版本适配
    // 方法 2：通过反射创建已知方法，扫描内存找 entry point
    // 方法 3：从 libart.so 的符号表推导
}
```

3. 缓存偏移，避免每次计算

验收标准：

☐ Android 11/12/13/14 上偏移推导正确
☐ 单元测试：对已知方法验证偏移

---

Task 3.2：核心方法入口点接管 + 执行后擦除

依赖：Task 3.1
预计工时：5–7 天
风险：极高

改动文件：

· shell/src/main/cpp/dpt_hook.cpp
· shell/src/main/cpp/art/art_method.cpp
· dpt/src/main/java/com/luoye/dpt/util/DexUtils.java（新增 -core 标记）
· dpt/src/main/java/com/luoye/dpt/config/Const.java

改动内容：

构建时：

1. 新增 -core 选项，标记核心方法
2. 核心方法在 OoooooOooo 中标记（新增 flag 位）

运行时：

1. DefineClass 后，对核心方法：

```cpp
artMethod->access_flags_ |= kAccNative;
artMethod->entry_point_from_quick_compiled_code_ = &core_method_stub;
```

2. core_method_stub 实现：

```cpp
extern "C" void core_method_stub(void* thiz, ...) {
    ArtMethod* method = getCurrentArtMethod();
    // 1. 解密
    decrypt_core_method(method);
    // 2. 原子引用计数
    int refs = atomic_fetch_add(&g_refCount[method], 1);
    // 3. 调用原方法
    invoke_original_method(method, ...);
    // 4. 计数归零时擦除
    refs = atomic_fetch_sub(&g_refCount[method], 1);
    if (refs == 1) {
        memset(insns, 0, size);
    }
}
```

注意：

· 必须处理异常（try/catch 或 C++ 异常）
· 必须处理递归调用
· JIT 可能覆盖 entry point，需要定期检查

验收标准：

☐ Android 11 上核心方法正常执行
☐ 用 frida-dexdump 抓取，核心方法 insns 为 0
☐ 递归调用核心方法不崩溃
☐ 核心方法执行时间 < 未加壳版本的 3 倍
☐ 核心方法执行时间 < 普通方法（Lazy Decrypt）的 3 倍

---

Task 3.3：多点 Hook

依赖：Task 3.1
预计工时：2–3 天
风险：中

改动文件：

· shell/src/main/cpp/dpt_hook.cpp

改动内容：

在现有 DefineClass / LoadClass 基础上，新增：

· LoadMethod hook（兜底）
· LinkCode hook（JIT 编译前拦截）
· VisitMethods hook（可选）

所有 hook 调用同一个幂等的 patchClass。

验收标准：

☐ 绕过 DefineClass 后，LoadMethod 仍能触发 patch
☐ 不重复 patch 同一方法（日志验证）

---

Task 3.4：Phase 3 集成验收

依赖：Task 3.1–3.3 全部完成
预计工时：2 天

验收流程：

1. 用 -core 标记 3 个核心方法（如登录、加密、授权）
2. 加壳
3. 运行 FART、frida-dexdump、Youpk
4. 检查核心方法 insns 是否为 0

通过标准：

☐ FART 抓不到核心方法明文
☐ frida-dexdump 核心方法为 0
☐ 核心方法执行时间 < 3 倍

---

四、任务依赖图

```
Phase 1:
  1.1 ─┬─> 1.2 ─┐
       │        ├─> 1.6
  1.3 ─┘        │
  1.4 ──────────┤
  1.5 ──────────┘

Phase 2:
  2.1 ─┬─> 2.2 ─> 2.3 ─┐
       │                ├─> 2.5
  2.4 ─┘                │
                        │
Phase 3:                │
  3.1 ─┬─> 3.2 ────────┤
       │                ├─> 3.4
  3.3 ─┘                │
                        │
                        v
                   最终验收
```

---

五、每个任务的 Agent 执行模板

每个任务交给 Agent 时，使用以下模板：

```markdown
## Task X.Y: [任务名]

### 前置检查
- [ ] 依赖任务已完成
- [ ] 当前代码可编译通过
- [ ] 测试 APK 已准备

### 执行步骤
1. [具体步骤 1]
2. [具体步骤 2]
...

### 改动文件清单
- [文件路径]：[改动描述]

### 编译验证
./gradlew assemble

### 运行时验证
1. 用测试 APK 加壳
2. 安装到测试机
3. 执行 [验证操作]

### 验收标准
- [ ] [标准 1]
- [ ] [标准 2]

### 失败回滚
git checkout [文件列表]

### 输出物
- [ ] 代码改动（提交到指定分支）
- [ ] 测试报告：docs/task-X.Y.md
- [ ] 文档更新（按第九章要求）：
    - [ ] docs/phase-X-design.md（本 Task 相关章节）
    - [ ] docs/known-issues.md（如发现新问题）
    - [ ] docs/project-workflow.md（如涉及流程变更）
    - [ ] docs/reverse-engineering-manual.md（如涉及防御变更）
    - [ ] tools/verify-defense/（如新增防御措施）
```

---

六、里程碑与验收节点

六.1 里程碑

里程碑 内容 时间 验收
M1 Phase 1 完成 第 3 周末 冷启动 <200ms，内存 <5MB
M2 Phase 2 完成 第 7 周末 dpt-unpack 失效
M3 Phase 3 完成 第 13 周末 核心方法防 dump
M4 全量回归 第 14 周 20 个测试 APK 全部通过

六.2 Phase 过渡检查清单

进入下一 Phase 前，必须完成：

☐ 当前 Phase 所有 Task 验收通过
☐ 当前 Phase 所有文档产出并 review
☐ 完整测试矩阵跑一遍，无阻塞性问题
☐ known-issues.md 已更新，无 P0 问题
☐ 上一个 Phase 的性能基准已记录，作为下一个 Phase 的对比基线
☐ 团队/负责人签字确认

---

七、风险登记与应对

风险 概率 影响 应对
格式变更导致兼容性崩溃 中 高 保留 v2 分支，header.magic 区分
ChaCha20 实现有 bug 低 高 RFC 8439 test vector + 对照 OpenSSL
ChaCha20 迁移期间新旧 APK 不兼容 中 中 保留 RC4 解析分支，通过 header.version 区分
InMemoryDexClassLoader 在部分 ROM 失败 中 中 保留 code_cache 回退
页锁死锁 低 高 按页地址排序加锁，单元测试覆盖
ArtMethod 偏移推导失败 高 高 多版本适配 + fallback 到原方案
核心方法擦除导致崩溃 中 极高 只对 -core 标记方法启用，默认关闭

---

八、测试矩阵

八.1 覆盖维度

测试维度 覆盖
Android 版本 8.0, 10, 11, 12, 13, 14
ABI arm64-v8a, armeabi-v7a
APK 大小 <5MB, 10MB, 30MB, 50MB
方法数 <1万, 5万, 10万, 20万
场景 冷启动, 热启动, 首次安装, 升级安装
功能一致性 加壳 APK 与原 APK 功能完全一致（自动化 UI 测试）
签名与校验 v1 / v2 / v3 签名均通过，--verify-sign 正常

八.2 测试 APK 列表

建议在 tools/test-apks/README.md 里列出具体清单：

· 5 个 <5MB 小 APK（不同 Android 版本）
· 5 个 10MB 中 APK
· 5 个 30MB 大 APK
· 5 个特殊场景 APK（Compose、Flutter、RN、Native 为主、插件化）

每个 Phase 完成后跑一遍完整矩阵。

---

九、文档要求

每个 Phase 完成后必须产出的文档，分为两类：

· A 类：Phase 阶段性文档（每个 Phase 独立产出一份）
· B 类：全局维护文档（每个 Phase 完成后必须同步更新，贯穿全项目）

A 类：Phase 阶段性文档

A1. 设计文档 —— docs/phase-X-design.md

作用：记录本 Phase 的技术设计，回答"这个 Phase 做了什么、为什么这样做"。

必须包含：

· 本 Phase 的目标与非目标
· 每个 Task 的技术方案（数据结构、算法、接口变更）
· 关键设计决策及理由
· 与前一版的差异对比（改了什么、为什么改）
· 未解决的开放问题

验收标准：一个没参与开发的工程师，看完能理解本 Phase 的每一处代码改动。

---

A2. 测试报告 —— docs/phase-X-test.md

作用：记录本 Phase 的测试执行结果，回答"改动是否真的有效"。

必须包含：

· 测试矩阵（Android 版本 × ABI × APK 大小 × 方法数）
· 每个测试用例的输入、步骤、预期、实际
· 通过的用例列表
· 失败的用例列表及原因分析
· 回归测试结果（对比上一 Phase）

验收标准：测试矩阵全部覆盖，失败用例有明确根因。

---

A3. 性能对比 —— docs/phase-X-benchmark.md

作用：量化本 Phase 的性能收益，回答"到底快了多少、省了多少"。

必须包含：

· 基准 APK 信息（大小、方法数、ABI）
· 测试设备信息（型号、Android 版本、CPU）
· 对比指标：
  · 冷启动耗时（原版 / 上一版 / 本版）
  · 热启动耗时
  · 首次启动 I/O（落盘字节数）
  · 类加载 CPU 耗时
  · 常驻内存增量
  · APK 体积增量
· 每项指标的测量方法（用什么工具、采样几次、如何取中位数）
· 结论与瓶颈分析

验收标准：数据可复现，有原始日志或脚本附在 tools/benchmark/。

---

A4. 升级指南 —— docs/upgrade-to-2.x.md

作用：告诉用户如何从旧版本迁移到新版本，回答"我原来的用法还能用吗、要改什么"。

必须包含：

· 最低环境要求（JDK、SDK、NDK、Gradle 版本）
· 命令行参数变化（新增、删除、语义变更）
· 配置文件格式变化（protect-config、rules-file）
· 旧版加壳 APK 的兼容性说明（能否直接升级）
· 常见迁移问题的解决方案
· 快速验证清单（迁移后如何确认一切正常）

验收标准：一个用旧版本的用户，按文档操作能顺利迁移。

---

A5. 已知问题 —— docs/known-issues.md

作用：记录当前版本仍存在的问题，回答"我知道它有什么坑"。

必须包含：

· 问题描述
· 触发条件
· 影响范围（哪些 Android 版本、哪些设备）
· 临时规避方案
· 计划修复的 Phase
· 是否阻断发布

更新规则：每个 Phase 完成后，已修复的问题移到"已修复"，新发现的问题加入。

---

B 类：全局维护文档

B1. 项目流程文档 —— docs/project-workflow.md

定位：项目的端到端全景图，贯穿所有 Phase，每次代码改动后同步更新。

作用：
让 Agent 和维护者在改动任何一处代码前，能快速理解"这个函数在整体流程中的位置、被谁调用、影响谁"。

必须包含：

1. 整体流程图：从 APK 输入 → Processor 处理 → Shell 集成 → 加壳 APK 输出，每个阶段的输入输出、调用链、关键函数
2. Processor 端流程：解压 → Manifest 编辑 → Dex 抽取 → 压缩对齐 → SO 加密 → 配置写入 → 打包签名，每步涉及哪些类、哪些文件
3. Shell 端流程：启动 → ProxyApplication/ProxyComponentFactory → 加载 SO → 读配置 → 读 CodeItem → 合并 dexElements → 类加载时 patch → 调用真实 Application，各阶段时序与依赖
4. 配置与密钥流转：buildKey → masterKey → sessionKey → methodKey 的完整推导链，每层在哪个阶段产生、存在哪里、何时销毁
5. 数据格式流转：原始 Dex → 抽取后的 Dex → OoooooOooo → i11111i111.zip → 最终 APK 的每一步变换
6. 构建与发布流程：./gradlew assemble 如何产出 executable/dpt.jar 和 shell-files/，build-key 与 dpt-build-ids.properties 的作用
7. 调试开关矩阵：--debug、--disable-*、--noisy-log 等选项对各阶段的影响

为什么 Agent 需要它：

· 改一个函数前，能知道它属于哪个阶段、被谁调用
· 跨 Phase 改造时（如 Phase 2 的 Runtime Key 会改动 Processor 和 Shell 两端），能看清密钥流转
· 新 Agent 接手时，先读这份文档再读源码

更新规则：每个 Phase 完成后必须更新，尤其密钥流转图、数据格式流转图、类加载时序图。

验收标准：一个没读过源码的人，看完能画出完整的加壳和解壳时序图。

---

B2. 逆向手册 —— docs/reverse-engineering-manual.md

定位：针对 dpt-shell 加壳 APK 的完整逆向指南，是攻防对称的核心文档。

作用：
让防御方能量化攻击成本——每加一层防护，攻击者多花多少时间、用什么工具、需要什么技能。没有这份文档，防御设计就是盲目的。

这份文档的目的不是教人破解别人的 App，而是让防御方知道自己会被怎么攻击。防得住也要逆得了，否则你不知道如何破解，就不知道如何去做防御。

必须包含：

1. 目标 APK 静态侦察：
   · 如何识别一个 APK 是否被 dpt-shell 加壳（Manifest 里的 ProxyApplication、assets 里的 d_shell_data_001、OoooooOooo、i11111i111.zip）
   · 如何区分 dpt-shell 版本（v1 / v2 / 2.x）
   · 如何判断开启了哪些保护（risk_check_flags、--verify-sign、-core）
2. 离线脱壳路径（针对 Phase 2 前）：
   · 从 APK 提取 build-key 和 SO
   · 推导 masterKey 的完整公式
   · 解析 OoooooOooo 固定格式
   · 用 Python 脚本批量还原所有方法
   · 参考 dpt-unpack 的实现思路
3. 离线脱壳路径（针对 Phase 2 后）：
   · 识别格式随机化后的字段布局
   · 用 Unicorn 模拟白盒函数（如果启用）
   · 处理虚假 CodeItem 注入
   · 估算手动脱壳所需时间
4. 运行时脱壳路径：
   · Frida Hook patchMethod 抓解密后明文
   · FART / Youpk / frida-dexdump 对普通方法的效果
   · 针对 ArtMethod 入口点接管的核心方法，如何绕过
   · 针对执行后擦除，如何抢在擦除前 dump
5. 绕过防御的路径：
   · Hook detectFrida / detectDebugger / verifyLibcTextCrc
   · Patch 检测结果参与解密的逻辑
   · 绕过 SO 自校验
   · 绕过内存扫描检测
6. 攻击成本评估表：
   防御措施 攻击者需要做什么 所需工具 预计耗时 技能门槛
   静态密钥 读源码推导 Python 1 小时 低
   Runtime Key Hook 运行时 Frida + 脚本 1 天 中
   格式随机化 逆向格式描述 IDA + Unicorn 2–3 天 高
   白盒密码学 模拟执行 Unicorn + 逆向 1 周 极高
   执行后擦除 抢时间窗口 dump Frida + 竞态 3–5 天 高
   ArtMethod 接管 逆向 stub + 绕过 IDA + Frida 1 周 极高
7. 每个 Phase 后的攻击成本对比：
   · Phase 1 完成后：攻击成本基本不变（只做了性能优化）
   · Phase 2 完成后：离线脱壳从 1 小时 → 2–3 天
   · Phase 3 完成后：运行时 dump 从 1 小时 → 3–7 天

为什么 Agent 需要它：

· Phase 2/3 每次改动后必须用这份手册验证：按手册走一遍脱壳流程，确认攻击成本确实提高了
· 防止"防御幻觉"：把攻击成本量化，避免自欺欺人
· 攻防对称：防御方必须知道攻击方的完整路径，才能找到真正的薄弱点
· 合规声明：文档开头必须写明"仅用于自有 App 的安全测试和授权研究"

更新规则：

· 每个 Phase 完成后必须更新
· 新增攻击路径必须同步更新成本表
· 每个攻击路径必须在 tools/verify-defense/ 里有对应的自动化验证脚本

验收标准：

· 一个熟悉 Frida 和 IDA 的安全工程师，看完手册能：
  · 在 1 小时内判断一个 APK 是否被 dpt-shell 加壳
  · 在 1 天内完成对 Phase 2 前版本的离线脱壳
  · 在 1 周内完成对 Phase 2 后版本的脱壳
· 手册中每个攻击路径都有对应的验证脚本（tools/verify-defense/），可自动跑一遍确认防御是否生效

---

文档产出检查清单（Agent 执行模板）

每个 Phase 完成后，Agent 必须勾选：

```markdown
### A 类：Phase 阶段性文档
- [ ] docs/phase-X-design.md
- [ ] docs/phase-X-test.md
- [ ] docs/phase-X-benchmark.md
- [ ] docs/upgrade-to-2.x.md（仅 Phase 3 或最终版本更新）
- [ ] docs/known-issues.md（更新）

### B 类：全局维护文档
- [ ] docs/project-workflow.md（更新流程图、密钥流转、数据格式流转）
- [ ] docs/reverse-engineering-manual.md（更新攻击成本表、新增攻击路径）
- [ ] tools/verify-defense/（新增或更新验证脚本）

### 内部检查
- [ ] 所有文档中的函数名、行号、文件路径与实际代码一致
- [ ] 所有攻击成本数据有实际测试支撑，非估算
- [ ] 所有流程图可用（mermaid 或图片）
```

文档与 Phase 的对应关系

文档 Phase 1 Phase 2 Phase 3
phase-X-design.md 产出 产出 产出
phase-X-test.md 产出 产出 产出
phase-X-benchmark.md 产出 产出 产出
upgrade-to-2.x.md — — 最终产出
known-issues.md 更新 更新 更新
project-workflow.md 更新 更新 更新
reverse-engineering-manual.md 更新 更新 更新
tools/verify-defense/ 建立 扩充 扩充

关键约束

1. B 类文档不是一次性产出，而是每个 Phase 完成后必须同步更新，否则视为 Phase 未完成
2. 逆向手册中的每个攻击路径必须有对应的自动化验证脚本，不能只写文字
3. 项目流程文档中的每个关键函数必须与源码注释互相引用（如 @see docs/project-workflow.md#key-derivation）
4. 文档必须与代码同步提交，不允许"先写代码，文档后续补"
5. 逆向手册开头必须有合规声明："本手册仅用于自有 App 的安全测试和授权研究，禁止用于未授权逆向"
6. Phase 未完成判定：A 类文档 + B 类文档更新 + 测试矩阵全通过 + 逆向手册攻击成本验证通过，四者缺一不可

---

十、Agent 执行优先级建议

如果只能按一个顺序执行：

1. Task 1.3（RC4 → ChaCha20）——独立，收益确定
2. Task 1.1 + 1.2（格式重构 + 去 65536）——性能核心
3. Task 1.5（页粒度 mprotect）——并发安全
4. Task 1.4（InMemoryDex）——首次启动优化
5. Task 2.2（格式随机化）——反 dpt-unpack 最有效
6. Task 2.1（Runtime Key）——逼到运行时
7. Task 2.4（检测内联）——抗 patch
8. Task 3.1 + 3.2（ArtMethod 接管）——防运行时 dump
9. Task 2.3（假数据）——低优先级混淆
10. Task 3.3（多点 Hook）——兜底

先做 Phase 1，再做 Phase 2，最后 Phase 3。不要跳阶段。

---

附录：推荐目录结构

```
dpt-shell/
├── docs/
│   ├── agent-development-plan.md      ← 本文档
│   ├── upgrade-plan-2.0.md            ← 最终方案
│   ├── project-workflow.md            ← 项目流程（B1，需实际写）
│   ├── reverse-engineering-manual.md  ← 逆向手册（B2，需实际写）
│   ├── design-decisions.md            ← ADR（可选）
│   ├── HowItWorks.zh-CN.md            ← 已有的
│   ├── known-issues.md                ← 已知问题
│   ├── upgrade-to-2.x.md              ← 升级指南
│   ├── phase1-design.md               ← Phase 1 完成后产出
│   ├── phase1-test.md
│   ├── phase1-benchmark.md
│   └── ...
├── tools/
│   ├── verify-defense/                ← 逆向手册的验证脚本
│   │   ├── test-static-key.sh
│   │   ├── test-runtime-key.sh
│   │   ├── test-format-randomization.sh
│   │   └── test-artmethod-erase.sh
│   ├── benchmark/                     ← 性能基准脚本
│   └── test-apks/                     ← 测试 APK 列表
├── dpt/
├── shell/
└── README.md
```

---

文档结束

这份可以直接复制粘贴到 docs/agent-development-plan.md。

启动 Phase 1 时，建议从 Task 1.3（RC4 → ChaCha20） 开始，因为它独立、收益确定、风险低，最适合作为第一个练手任务。