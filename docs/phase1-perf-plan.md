# dpt-shell Phase 1 性能优化方案（修正版）

本方案基于 `docs/开发工程计划书.md`（初稿）与 `docs/开发工程审核.md`（审核），
逐条对照**真实源码**与 **AOSP 官方源码**复核后重写。

- 初稿保留为历史记录，本文档为**唯一执行依据**
- 审核指出的 5 条阻断性错误全部成立，本文档已全部吸收（见第一章 1.7）
- 复核过程中**新发现 4 条审核未覆盖的阻断性问题**，本文档一并修正（见第一章 1.8）
- 本文档所有行号/符号均已在源码中核对过；标注 `⏳` 的一律为"待验证"

---

## 目录

- [〇、执行总则](#〇执行总则)
- [一、Phase 1 总览](#一phase-1-总览)
- [二、Task 1.1：OoooooOooo v4 格式重构 + 索引](#二task-11ooooo-v4-格式重构--索引)
- [三、Task 1.3：ChaCha20 收尾（清理 RC4 残留）](#三task-13chacha20-收尾清理-rc4-残留)
- [四、Task 1.4：InMemoryDexClassLoader](#四task-14inmemorydexclassloader)
- [五、Task 1.5：页粒度 RW + 按页自旋锁](#五task-15页粒度-rw--按页自旋锁)
- [六、Task 1.6：集成验收](#六task-16集成验收)
- [七、Task 1.7：打包侧加速](#七task-17打包侧加速)
- [八、Task 1.8：运行时 mmap 合并](#八task-18运行时-mmap-合并)
- [九、Task 1.9：运行时字节解析与 descriptor 缓存](#九task-19运行时字节解析与-descriptor-缓存)
- [十、Task 1.10：性能基准脚本](#十task-110性能基准脚本)
- [十一、附录](#十一附录)

---

## 〇、执行总则

### 〇.1 目标

在保持加壳功能可用的前提下压榨性能：

| # | 目标 | 当前 | 目标值 | 测量方式 |
|---|---|---|---|---|
| 1 | 打包耗时（5 万方法） | 基线 | −30% | `tools/benchmark/bench-pack.sh` |
| 2 | 运行时内存增量 | ~15MB | < 5MB | `dumpsys meminfo` ⏳ |
| 3 | 冷启动增量 | +300ms | < 150ms | `am start -W` ⏳ |
| 4 | 首次落盘 `i11111i111.zip` | 必落 | API ≥ 29 不落 ⏳ | `ls code_cache/` |
| 5 | dex 可写窗口 | 整个生命周期 | 单次 patch < 100μs ⏳ | systrace |
| 6 | 每次启动 mmap APK | 2 次 | 1 次 ⏳ | 日志计数 |

**所有目标都是目标，不是实测。** 验收时必须附真实日志，无设备一律标 ⏳。

不做的事：

- 不做防御（Runtime Key / 格式随机化 / 假数据 / ArtMethod 接管）
- 不做字符串加密 / anti-diff / 签名校验 / 环境检测（`apk-protect-action` 已覆盖）
- 不引入 VMP / 解释器 / 白盒密码学

### 〇.2 执行环境

沿用仓库 `AGENTS.md` 第 3 节：JDK 17 / compileSdk 36 / minSdk 21 / NDK 27.0.12077973 / CMake 3.31.1。

**本机限制**：Native 无法本地编译（x86_64 工具链在 arm64 上直接失败），靠 GitHub Actions `build.yml` 验证。
不要写本地语法检查脚本来"验证" Native 改动——历史教训是这类脚本在**未修改的基线文件上也会报错**。

### 〇.3 版本命名规范（强制）

| 名词 | 含义 | 取值 |
|---|---|---|
| OoooooOooo 结构版本 | 载荷文件内部布局 | **v4**（本方案唯一） |
| 加密算法版本 | 指令解密算法 | **ChaCha20**（唯一） |
| dpt-shell 版本 | 包版本号 | `appVersionName`（`build.gradle:43`，当前 `"1.0.0"`） |

禁止再出现"OoooooOooo v2/v3"这种歧义表述。

---

## 一、Phase 1 总览

### 1.1 性能瓶颈清单（源码实证）

| # | 位置 | 问题 | 量级 | 对应 Task |
|---|---|---|---|---|
| B1 | `dpt.cpp:461` | 每 dex `new vector<CodeItem*>(65536)` | 每 dex 512KB | 1.1 |
| B2 | `MultiDexCode.cpp:76` | `nextCodeItem` 每方法 `new CodeItem` | 5 万方法 = 5 万堆对象 | 1.1 |
| B3 | OoooooOooo | 无索引，patch 时靠 methodIdx 散列 | 65536 槽位 88% 空 | 1.1 |
| B4 | `dpt_hook.cpp:111` | `change_dex_protective` 整 dex RW 且不恢复 | 权限位长期暴露 | 1.5 |
| B5 | `dpt_util.cpp:353` | `extractDexesInNeeded` 首次启动落盘几十 MB | I/O 瓶颈 | 1.4 |
| B6 | `DexUtils.java:405-414` | 每 2 字节一次 seek | 300 万次系统调用 | 1.7 |
| B7 | `dpt.cpp:419` + `:478` | APK 被 mmap 两次 | 每次启动白做一份工 | 1.8 |
| B8 | `MultiDexCode.cpp:81-95` | `readUInt*` 跨翻译单元 `memcpy` | 类加载每次多次 | 1.9 |
| B9 | `dpt_hook.cpp:190` | `getClassDescriptor` 每次重解析 | 类加载每次一遍 | 1.9 |
| B10 | 无 | 无性能基准 | 指标全凭承诺 | 1.10 |

### 1.2 Task 一览与依赖

| Task | 名称 | 依赖 | 工时 | 风险 |
|---|---|---|---|---|
| 1.7 | 打包侧加速 | 无 | 2–3 天 | 低 |
| 1.10 | 性能基准脚本 | 无 | 1 天 | 低 |
| 1.1 + 1.3 | v4 格式 + RC4 收尾（**合并**） | 无 | 5–7 天 | 中 |
| 1.9 | 字节解析 + descriptor 缓存 | 1.1 | 1–2 天 | 低 |
| 1.8 | mmap 合并 | 无 | 1–2 天 | 中 |
| 1.4 | InMemoryDexClassLoader | 无 | 3–4 天 | 中 |
| 1.5 | 页粒度 RW | 1.1 | 2–3 天 | 中 |
| 1.6 | 集成验收 | 全部 | 2 天 | 低 |

### 1.3 修正后的执行顺序

**初稿的依赖图是错的**（见 1.7 错误 1）。修正为：

```
1.10（基准脚本，先有尺子）
  └─> 1.7（打包侧，独立可测）
  └─> 1.1 + 1.3（合并：Java 写 v4 + Native 读 v4 同一次提交完成）
        ├─> 1.9（缓存，与 1.1 一起改，都动 MultiDexCode）
        ├─> 1.5（页粒度，依赖 1.1 的 classDataOff）
        └─> 1.6
  1.8（mmap，独立，随时可做）
  1.4（InMemory，独立，但门槛放宽后才安全）
  └─> 1.6
```

**串行硬约束**：

1. **1.3 必须合并进 1.1**。`Const.MULTI_DEX_CODE_VERSION = 3` 是当前唯一写入者，
   `MultiDexCode.cpp:30` 的 `case V3` 是当前唯一解密分发。先删 v3 = 新打包的 v4 payload
   运行时直接进 `default` 分支 → **全部方法解密失败 → 加壳 APK 启动即崩**。
2. **1.5 必须在 1.1 之后**（依赖 `classDataOff` 索引）。
3. **1.6 必须在所有 Task 之后**。

可并行：1.7 / 1.1 / 1.4 / 1.8 互不依赖。

### 1.4 优先级（投入产出比）

| 顺序 | Task | 理由 |
|---|---|---|
| 1 | 1.10 | 没尺子，后面全是空口承诺 |
| 2 | 1.7 | 收益确定、风险低、本机可测，适合热身 |
| 3 | 1.1+1.3 | 收益最大（内存 −60%），但风险中、周期长 |
| 4 | 1.9 | 简单，与 1.1 一起做 |
| 5 | 1.8 | 独立，改动小 |
| 6 | 1.4 | 收益大但**门槛已放宽**（见 1.8 问题 1/2），需真机验证 |
| 7 | 1.5 | 依赖 1.1，靠后 |
| 8 | 1.6 | 全部完成后 |

### 1.5 每 Task 交付物

- ☐ 代码改动（提交到 `main`）
- ☐ 测试报告 `docs/task-X.Y.md`
- ☐ 本文档对应章节勾选
- ☐ 新坑追加 `docs/pitfalls.md`
- ☐ 基准数据追加 `docs/phase1-benchmark.md`

### 1.6 全局验证命令

```bash
./gradlew :dpt:test        # Java 单测，不需要 SDK/NDK
./gradlew build            # 完整构建，产出 executable/
```

---

## 二、Task 1.1：OoooooOooo v4 格式重构 + 索引

### 2.1 背景（源码实证）

`dpt.cpp:443` `readCodeItem`：

```cpp
auto codeItemVec = new std::vector<data::CodeItem *>(65536);   // :461 每 dex 512KB
uint32_t codeItemIndex = dexCodeOffset + 2;
for (int k = 0; k < methodCount; k++) {
    data::CodeItem *codeItem = dexCode->nextCodeItem(&codeItemIndex);
    codeItemVec->at(codeItem->getMethodIdx()) = codeItem;      // 每方法 new
}
dexMap.emplace(i, codeItemVec);
```

`MultiDexCode.cpp:71` `nextCodeItem`：

```cpp
uint32_t methodIdx = readUInt32(*offset);
uint32_t insnsSize = readUInt32(*offset + 4);
auto* insns = (uint8_t*)(m_buffer + *offset + 8);
*offset = (*offset + 8 + insnsSize);
auto* codeItem = new CodeItem(methodIdx, insnsSize, insns);    // ← 每方法一次堆分配
```

5 万方法 = 5 万堆对象 + 每 dex 512KB 空槽数组。改造方向：**每类一份索引 + 紧凑
MethodData，运行时按 `classDataOff` 二分查找，全程不 new**。

### 2.2 新格式定义（v4）

```
┌────────────────────────────────────────────────┐
│ Header (16 字节)                                │
│   uint32 magic            = 0x4F4F4F34 "OOO4"  │
│   uint16 version          = 4                   │
│   uint16 dexCount                               │
│   uint32 classIndexOffset (相对文件起点)         │
│   uint32 methodDataOffset (相对文件起点)         │
├────────────────────────────────────────────────┤
│ ClassIndex[] (每项 16 字节，按 (dexIdx,classDataOff) 升序) │
│   +0  uint8  dexIdx                            │
│   +1  uint8  flags        预留，写 0            │
│   +2  uint16 methodCount                        │
│   +4  uint32 classDataOff                       │
│   +8  uint32 methodDataOff 相对 methodDataOffset │
│   +12 uint32 reserved       写 0，读时忽略       │
├────────────────────────────────────────────────┤
│ MethodData[] (紧凑变长)                          │
│   每条: uint32 methodIdx                        │
│         uint16 insnsSize                        │
│         uint8[insnsSize] encryptedInsns          │
└────────────────────────────────────────────────┘
```

#### ⚠️ `insnsSize` 语义：字节数，不是 code unit 数

这是**初稿和审核都没抓到的坑**，会导致运行时越界读 2 倍。

源码事实：

```java
// DexUtils.java:400
int insnsCapacity = code.getInstructions().length;   // code unit 数
instruction.setInstructionDataSize(insnsCapacity * 2);   // ← 存的是【字节数】
byte[] byteCode = new byte[insnsCapacity * 2];
```

```cpp
// MultiDexCode.cpp:70 现有 v3 解析
uint32_t insnsSize = readUInt32(*offset + 4);        // ← 读到的就是字节数
auto* insns = (uint8_t*)(m_buffer + *offset + 8);
*offset = (*offset + 8 + insnsSize);                // ← 按字节数前进，正确
```

```cpp
// dpt_hook.cpp:173 现有 v3 使用
uint32_t sz = codeItem->getInsnsSize();
dexCode->cryptInsns(g_shell_config.aes_key, methodIndex, enc, sz, realInsnsPtr);
//                                                          ^^ 字节数
```

**结论**：v4 的 `insnsSize` 字段必须存**字节数**（即 `Instruction.getInstructionDataSize()`），
`getMethodData` 里 `p += 6 + insnsSize`（**不是** `6 + insnsSize * 2`）。
初稿 §2.4.2 的 `p += 6 + size * 2` 会导致读到下一个方法的头部。

Java 侧写入时直接复用 `instruction.getInstructionDataSize()`，不要重新计算。

### 2.3 Java 侧改动

#### 2.3.1 `dpt/src/main/java/com/luoye/dpt/config/Const.java`

```java
// 替换 :66-72 整段注释 + 常量
// OoooooOooo payload version.
//   4 = instructions encrypted with ChaCha20, with a per-class index (see
//       docs/phase1-perf-plan.md Task 1.1).
// Must stay in sync with DPT_MULTI_DEX_CODE_VERSION_V4 in
// shell/src/main/cpp/dex/MultiDexCode.h.
public static final short MULTI_DEX_CODE_VERSION_V4 = 4;
public static final short MULTI_DEX_CODE_VERSION = MULTI_DEX_CODE_VERSION_V4;

public static final int MULTI_DEX_CODE_MAGIC = 0x4F4F4F34;
```

**注意**：`InsnsCryptoContractTest.java:33` 断言 `assertEquals(3, Const.MULTI_DEX_CODE_VERSION)`，
必须同步改成 4，否则测试直接红。

#### 2.3.2 `dpt/src/main/java/com/luoye/dpt/model/Instruction.java`

新增字段（v4 索引必需）：

```java
public int getClassDataOff() { return classDataOff; }
public void setClassDataOff(int classDataOff) { this.classDataOff = classDataOff; }

// 该指令所属类的 classDataOff（v4 索引必需）
private int classDataOff;
```

#### 2.3.3 `dpt/src/main/java/com/luoye/dpt/util/DexUtils.java`

`extractMethod`（`:354`）内新增一行：

```java
// 原 :398 起
instruction.setMethodIndex(method.getMethodIndex());
instruction.setClassDataOff(classDef.getClassDataOffset());   // ← 新增
instruction.setInstructionDataSize(insnsCapacity * 2);
```

#### 2.3.4 `dpt/src/main/java/com/luoye/dpt/model/MultiDexCode.java`

```java
private short version;                       // = 4
private short dexCount;
private int classIndexOffset;                // 新增
private int methodDataOffset;                // 新增
private List<ClassIndexEntry> classIndex;    // 新增
private List<byte[]> methodData;             // 新增：每项一条完整 MethodData 字节
// 删除：dexCodesIndex, dexCodes
```

`DexCode.java` 随之删除（其职责被 `ClassIndexEntry` + `methodData` 取代）。

#### 2.3.5 `dpt/src/main/java/com/luoye/dpt/util/MultiDexCodeUtils.java`

`makeMultiDexCode` + `writeMultiDexCode` 完全重写：

```java
public static class ClassIndexEntry {
    public byte dexIdx;
    public byte flags;          // 预留，写 0
    public short methodCount;
    public int classDataOff;
    public int methodDataOff;
    public int reserved;        // 写 0

    public byte[] toBytes() {
        ByteBuffer buf = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
        buf.put(dexIdx);
        buf.put(flags);
        buf.putShort(methodCount);
        buf.putInt(classDataOff);
        buf.putInt(methodDataOff);
        buf.putInt(reserved);
        return buf.array();
    }
}
```

`makeMultiDexCode` 逻辑：

1. 遍历 `multiDexInsns`，把 `(dexIdx, classDataOff, List<Instruction>)` 组装成中间结构
2. **按 `(dexIdx, classDataOff)` 无符号升序排序**（见 2.3.6 的排序陷阱）
3. 按排序后顺序分配 `ClassIndexEntry.methodDataOff` 与 `methodData` 字节块
4. 计算 `classIndexOffset = 16`、`methodDataOffset = 16 + 16 * classIndex.size()`

每条 MethodData 字节：

```java
ByteBuffer md = ByteBuffer.allocate(6 + ins.getInstructionDataSize())
                           .order(ByteOrder.LITTLE_ENDIAN);
md.putInt(ins.getMethodIndex());
md.putShort((short) ins.getInstructionDataSize());   // 字节数，不是 code unit
md.put(ins.getInstructionsData());
```

#### 2.3.6 ⚠️ 排序必须无符号

审核第 2 节中风险 2 提到但没给完整方案。Java 的 `classDataOff` 是 `int`，
dex 偏移可能超过 `Integer.MAX_VALUE`，`Integer.compare` 会排错。

```java
// 错：Integer.compare(a, b)
// 对：
private static final Comparator<ClassIndexEntry> CLASS_INDEX_ORDER =
        Comparator.comparingInt((ClassIndexEntry e) -> e.dexIdx)
                   .thenComparingLong(e -> Integer.toUnsignedLong(e.classDataOff));
```

Native 侧用 `uint32_t`，两侧语义一致。

#### 2.3.7 ⚠️ 方法顺序契约必须钉死

Java 侧 `DexUtils.java:298` 遍历 `classData.allMethods()`，
smali 的 `allMethods()` 返回顺序是 **direct → virtual**，与 Native 侧
`patchClass` 解析 `directMethods` 再 `virtualMethods` 的顺序一致。

**v4 的 `getMethodData(entry, i)` 依赖这个顺序**。若不成立，`patchClass` 会把
A 方法的密文写到 B 方法的指令区——不崩溃，但行为错乱，极难排查。

措施：
- `MultiDexCodeUtils` 写 ClassIndex 前加断言注释说明该契约
- 新增单元测试 `testMethodOrderMatchesClassDataOrder`（见 2.5）
- `patchClass` 加注释锚定同一顺序

### 2.4 Native 侧改动

#### 2.4.1 `shell/src/main/cpp/dex/MultiDexCode.h`

```cpp
// 替换 :15-19 的 V2/V3 宏（删除在本 Task 1.3 内做）
#define DPT_MULTI_DEX_CODE_VERSION_V4 4
#define DPT_MULTI_DEX_CODE_MAGIC       0x4F4F4F34u

namespace dpt::data {

struct ClassIndexEntry {
    uint8_t  dexIdx;
    uint8_t  flags;
    uint16_t methodCount;
    uint32_t classDataOff;
    uint32_t methodDataOff;
    uint32_t reserved;
};

struct CodeItemView {                 // POD，不堆分配
    uint32_t methodIdx;
    uint16_t insnsSize;               // 字节数，见 2.2
    const uint8_t* encryptedInsns;
};

class MultiDexCode {
public:
    static MultiDexCode* getInst();
    void init(uint8_t* buffer, size_t size);

    uint16_t getVersion() const;
    uint16_t getDexCount() const;
    uint32_t getClassIndexOffset() const;
    uint32_t getMethodDataOffset() const;
    const ClassIndexEntry* getClassIndexBegin() const;
    const ClassIndexEntry* getClassIndexEnd() const;

    // 按 (dexIdx, classDataOff) 二分查找
    const ClassIndexEntry* findClassIndex(uint8_t dexIdx, uint32_t classDataOff) const;

    // 按 direct → virtual 顺序取第 index 个方法（契约见 2.3.7）
    CodeItemView getMethodData(const ClassIndexEntry* entry, uint16_t index) const;

    bool cryptInsns(const uint8_t* key, uint32_t methodIdx,
                    const uint8_t* in, size_t inlen, uint8_t* out) const;

private:
    size_t m_size;
    uint8_t* m_buffer;
    uint16_t m_version;
    uint16_t m_dexCount;
    uint32_t m_classIndexOffset;
    uint32_t m_methodDataOffset;
    insns_crypt_fn m_crypt_insns;

    uint8_t  readUInt8(uint32_t offset) const;
    uint16_t readUInt16(uint32_t offset) const;
    uint32_t readUInt32(uint32_t offset) const;
};
}
```

删除：`readDexCodeIndex`、`nextCodeItem`、`CodeItem` 相关引用。

#### 2.4.2 `shell/src/main/cpp/dex/MultiDexCode.cpp`

```cpp
void MultiDexCode::init(uint8_t* buffer, size_t size) {
    m_buffer = buffer;
    m_size = size;
    m_classIndexOffset = 0;
    m_methodDataOffset = 0;
    m_dexCount = 0;
    m_crypt_insns = nullptr;

    if (m_buffer == nullptr || m_size < 16) {
        DLOGE("OoooooOooo too small: %zu", m_size);
        return;
    }

    uint32_t magic = readUInt32(0);
    m_version = readUInt16(4);
    if (magic != DPT_MULTI_DEX_CODE_MAGIC || m_version != DPT_MULTI_DEX_CODE_VERSION_V4) {
        DLOGE("unsupported OoooooOooo: magic=0x%x version=%u", magic, m_version);
        return;
    }

    m_dexCount = readUInt16(6);
    m_classIndexOffset = readUInt32(8);
    m_methodDataOffset = readUInt32(12);

    // 越界防护：索引区必须在文件内
    if (m_classIndexOffset > m_size || m_methodDataOffset > m_size
            || m_methodDataOffset < m_classIndexOffset) {
        DLOGE("corrupt OoooooOooo offsets: ci=%u md=%u size=%zu",
              m_classIndexOffset, m_methodDataOffset, m_size);
        m_classIndexOffset = 0;
        m_methodDataOffset = 0;
        return;
    }

    // 只认 v4 → 只绑 ChaCha20
    m_crypt_insns = chacha20_crypt_insns;
    DLOGI("OoooooOooo v4 loaded: dexCount=%u", m_dexCount);
}

const ClassIndexEntry* MultiDexCode::getClassIndexBegin() const {
    return reinterpret_cast<const ClassIndexEntry*>(m_buffer + m_classIndexOffset);
}

const ClassIndexEntry* MultiDexCode::getClassIndexEnd() const {
    // 项数 = (methodDataOffset - classIndexOffset) / 16
    size_t n = (m_methodDataOffset - m_classIndexOffset) / sizeof(ClassIndexEntry);
    return getClassIndexBegin() + n;
}

const ClassIndexEntry* MultiDexCode::findClassIndex(uint8_t dexIdx,
                                                    uint32_t classDataOff) const {
    if (m_buffer == nullptr || m_classIndexOffset == 0) return nullptr;
    const ClassIndexEntry* begin = getClassIndexBegin();
    const ClassIndexEntry* end = getClassIndexEnd();
    const ClassIndexEntry* it = std::lower_bound(
            begin, end, classDataOff,
            [dexIdx](const ClassIndexEntry& e, uint32_t key) {
                return e.dexIdx != dexIdx ? e.dexIdx < dexIdx : e.classDataOff < key;
            });
    if (it == end || it->dexIdx != dexIdx || it->classDataOff != classDataOff) return nullptr;
    return it;
}

CodeItemView MultiDexCode::getMethodData(const ClassIndexEntry* entry,
                                         uint16_t index) const {
    CodeItemView v{0, 0, nullptr};
    if (entry == nullptr || index >= entry->methodCount) return v;

    const uint8_t* p = m_buffer + m_methodDataOffset + entry->methodDataOff;
    const uint8_t* end = m_buffer + m_size;
    for (uint16_t i = 0; i < index; i++) {
        if (p + 6 > end) return v;                       // 越界防护
        uint16_t sz = readUInt16At(p + 4);
        p += 6 + sz;                                    // sz 是字节数，不乘 2
        if (p > end) return v;
    }
    if (p + 6 > end) return v;

    v.methodIdx = readUInt32At(p);
    v.insnsSize = readUInt16At(p + 4);
    v.encryptedInsns = p + 6;
    return v;
}
```

`readUInt16At` / `readUInt32At` 是 `(m_buffer + offset)` 上的局部小工具，避免虚指成员函数。

#### 2.4.3 `shell/src/main/cpp/dpt.cpp` `readCodeItem`

```cpp
DPT_ENCRYPT void readCodeItem(uint8_t *data, size_t data_len) {
    if (data == nullptr || data_len < 16) {
        DLOGE("OoooooOooo invalid: data=%p len=%zu", data, data_len);
        return;
    }
    auto* dexCode = data::MultiDexCode::getInst();
    dexCode->init(data, data_len);
    // 不再建 dexMap，不 new，不再 65536 数组；patch 时直接查索引
}
```

同时删除 `dpt.cpp:19` 的全局 `dexMap` 与 `dpt_hook.cpp:21` 的 `extern` 声明。

#### 2.4.4 `shell/src/main/cpp/dpt_hook.cpp` `patchClass`

```cpp
DPT_ENCRYPT void patchClass(const char* descriptor,
                            const void* dex_file,
                            const void* dex_class_def) {
    // ... junk class 检查（不变）...

    if (LIKELY(dex_file != nullptr)) {
        std::string location;
        uint8_t* begin = nullptr;
        uint64_t dexSize = 0;
        // ... 按 g_sdkLevel 取 location / begin / dexSize（不变）...

        // ★ Task 1.4 后门槛放宽为：i11111i111.zip 或 Anonymous-DexFile（见第四章）
        if (is_shell_dex_location(location) && dex_class_def != nullptr) {
            int dexIndex = parse_dex_number(location);
            auto* class_def = (dex::ClassDef*)dex_class_def;

            if (LIKELY(class_def->class_data_off_ != 0)) {
                auto* dexCode = data::MultiDexCode::getInst();
                const auto* entry = dexCode->findClassIndex(
                        (uint8_t)dexIndex, class_def->class_data_off_);
                if (entry == nullptr) return;            // 该类未被加壳

                // 解析一次 ClassData，拿 direct → virtual 的 codeOff（顺序契约见 2.3.7）
                auto classMethods = parse_class_data(begin, class_def->class_data_off_);
                if (!classMethods.ok) return;

                uint16_t i = 0;
                for (const auto& m : classMethods.methods) {   // direct 先，virtual 后
                    if (i >= entry->methodCount) break;
                    auto view = dexCode->getMethodData(entry, i);
                    if (view.encryptedInsns == nullptr) { i++; continue; }
                    if (m.methodIdx != view.methodIdx) {
                        DLOGE("method order mismatch: dex=%d code=%u payload=%u",
                              dexIndex, m.methodIdx, view.methodIdx);
                        i++;
                        continue;
                    }
                    if (m.codeOff != 0) {
                        patchMethodInsns(begin, dexSize, view.methodIdx,
                                         m.codeOff, view.encryptedInsns, view.insnsSize);
                    }
                    i++;
                }
            }
        }
    }
}
```

```cpp
// 统一接口：codeOff 由 patchClass 传入（修正初稿 §2.4.4 缺参数的问题）
DPT_ENCRYPT void patchMethodInsns(uint8_t* begin, uint64_t dexSize, uint32_t methodIdx,
                                  uint32_t codeOff, const uint8_t* enc, uint32_t insnsSize) {
    auto* dexCodeItem = (dex::CodeItem*)(begin + codeOff);
    auto* realInsns = (uint8_t*)(dexCodeItem->insns_);

    auto* dexCode = data::MultiDexCode::getInst();
    if (UNLIKELY(!dexCode->cryptInsns(g_shell_config.aes_key, methodIdx, enc, insnsSize, realInsns))) {
        DLOGE("decrypt insns failed: methodIdx=%u size=%u", methodIdx, insnsSize);
    }
}
```

删除原 `patchMethod`（`dpt_hook.cpp:133`）。

**关键简化**：`dex_file.cpp:52` `readMethods` 已经把 `method_idx_delta_` **累加成绝对 methodIdx**：

```cpp
methodIndexDelta += methodIndex;
method[i].method_idx_delta_ = methodIndexDelta;   // ← 绝对值，不是 delta
```

所以初稿 §2.4.5 那个 `findCodeOffByMethodIdx(...)` 二分查找是**多余的**——按顺序一一对应即可，
`m.methodIdx == view.methodIdx` 还能顺带做契约自检。

#### 2.4.5 `dex::CodeItem` 删除范围

```bash
grep -rn "data::CodeItem\|dex/CodeItem.h" shell/src/main/cpp/
```

删除 `shell/src/main/cpp/dex/CodeItem.h` 与 `CodeItem.cpp`，并清理 `MultiDexCode.h` 的 include。
注意 `shell/src/main/cpp/dex/dex_file.h:93` 的 `dex::CodeItem` 是**另一个结构**，
是 dex 里的 code_item 结构体，**必须保留**。

### 2.5 单元测试

新增 `dpt/src/test/java/com/luoye/dpt/MultiDexCodeV4Test.java`：

| 用例 | 断言 |
|---|---|
| `headerMagicAndVersion` | magic == 0x4F4F4F34，version == 4，header 16 字节 |
| `classIndexEntryIs16Bytes` | 每项恰好 16 字节 |
| `classIndexSortedUnsigned` | 含负 int 的 classDataOff 按无符号升序 |
| `roundTrip` | 3 dex × 2 类 × 3 方法，写入后按 header/ClassIndex/MethodData 逐字节读回一致 |
| `insnsSizeIsByteCount` | MethodData 的 size 字段 == `getInstructionDataSize()`（字节数），且能正确定位下一条 |
| `methodOrderMatchesClassDataOrder` | direct → virtual 顺序写入，读回顺序一致 |
| `versionIsFour` | `Const.MULTI_DEX_CODE_VERSION == 4`（同步改 `InsnsCryptoContractTest:33`） |

### 2.6 验收标准

| 项 | 本机 | 真机 |
|---|---|---|
| `./gradlew build` 通过 | ✅ | — |
| `./gradlew :dpt:test` 全绿 | ✅ | — |
| v4 字节级对拍 `MultiDexCodeV4Test` | ✅ | — |
| CI `build.yml` 绿 | ✅ | — |
| 加壳 APK 正常启动 | — | ⏳ |
| 内存（dexMap 相关）−40%+ | — | ⏳ `dumpsys meminfo` |
| `grep -rn "new std::vector<data::CodeItem" shell/` 无命中 | ✅ | — |
| `grep -rn "dexMap" shell/` 无命中 | ✅ | — |

### 2.7 回滚方案

不保留 v3 分支。回滚 = `git revert` 本 Task 全部 commit，
**注意回滚后新生成的 APK 回到 v3 格式，不能与 v4 之后的产物混用**。

### 2.8 输出物

- ☐ 代码改动（Java 5 个文件 + Native 5 个文件）
- ☐ `docs/task-1.1.md`
- ☐ `docs/phase1-benchmark.md` 内存基线

---
## 三、Task 1.3：ChaCha20 收尾（清理 RC4 残留）

> ⚠️ **本 Task 必须与 Task 1.1 合并为一次提交。**
> 理由见 1.3 节错误 1：先删 `case V3` 而不改写入版本号，会让全部加壳 APK 解密失败。

### 3.1 背景

ChaCha20 切换已完成（`AGENTS.md` 第 9 节记录）。本 Task 只做清理。

### 3.2 删除清单（逐文件）

#### 3.2.1 `dpt/src/main/java/com/luoye/dpt/util/CryptoUtils.java`

删除：

```java
// :34
public static byte[] buildInsnsRc4Key(byte[] aesKey, int methodIndex) { ... }
```

**必须保留**（审核第 2 节错误 2，源码实证）：

```java
// :16-27
public static final String RC4Transform = "RC4";
public static byte[] rc4Crypt(byte[] key, byte[] in) { ... }
```

原因：`AndroidPackage.java:603` 的 `encryptSoFile` 用它加密 so 文件的 `.bitcode` section：

```java
byte[] enc = CryptoUtils.rc4Crypt(rc4Key, bitcode);
```

这是 **so 加密**，与 insns 加密完全无关，删了会打不开 so 的 bitcode。

#### 3.2.2 `shell/src/main/cpp/dpt_crypto.h` / `.cpp`

删除 `rc4_crypt_insns` 的声明（`dpt_crypto.h:66`）与实现（`dpt_crypto.cpp:130`）。
**保留** `chacha20_crypt_insns`（`:108`）。

`rc4/rc4.c`、`rc4/rc4.h` **保留**（`CMakeLists.txt:12` 仍编译，`dpt.h` 的
`decrypt_section` 用于解 so 的 `.bitcode`）。

#### 3.2.3 `shell/src/main/cpp/dex/MultiDexCode.h`

```cpp
// 删除 :18-19
#define DPT_MULTI_DEX_CODE_VERSION_V2 2
#define DPT_MULTI_DEX_CODE_VERSION_V3 3
```

（V4 宏在 Task 1.1 新增。）

#### 3.2.4 `shell/src/main/cpp/dex/MultiDexCode.cpp`

`init` 的 switch 已在 Task 1.1 改为"只认 v4 + 只绑 chacha20_crypt_insns"，本 Task 无额外改动。
删除旧版 `nextCodeItem` / `readDexCodeIndex`（Task 1.1 已删）。

#### 3.2.5 测试文件

删除：

| 文件 | 删除内容 |
|---|---|
| `InsnsCryptoContractTest.java` | `legacyRc4KeyLayoutUnchanged`（:40-52）——它断言的 `buildInsnsRc4Key` 被删 |
| `ConfigKeyDerivationTest.java` | `testInsnsRc4KeyAppendsLittleEndianMethodId`（:69-89） |
| `ConfigKeyDerivationTest.java` | `testBuildInsnsRc4KeyRejectsEmptyAesKey`（:91-95） |

**保留** `InsnsCryptoContractTest` 的 `methodScopedChaCha20RoundTrip` 与
`ciphertextLengthPreservedForRealisticInsnsSizes`——这两个是 ChaCha20 契约核心。

`ConfigKeyDerivationTest` 里 `rc4Crypt` 本身若还有调用需保留 import。

### 3.3 验收标准

```bash
./gradlew :dpt:test                                        # 全绿
./gradlew build                                            # exit 0
grep -rn "buildInsnsRc4Key" dpt/ shell/                    # 无命中
grep -rn "rc4_crypt_insns" shell/                          # 无命中
grep -rn "DPT_MULTI_DEX_CODE_VERSION_V2\|DPT_MULTI_DEX_CODE_VERSION_V3" shell/   # 无命中
grep -rn "rc4Crypt" dpt/                                   # 仅命中 CryptoUtils 定义 + AndroidPackage:603
grep -rn "RC4Transform" dpt/                               # 仅命中 CryptoUtils:16,21,22
```

### 3.4 回滚方案

`git revert`。因与 Task 1.1 合并提交，回滚会同时撤销 v4 格式。

### 3.5 输出物

- ☐ 代码改动（Java 3 个文件 + Native 2 个文件 + 测试 2 个文件）
- ☐ `docs/task-1.3.md`

---

## 四、Task 1.4：InMemoryDexClassLoader

### 4.1 背景

`dpt_util.cpp:353` `extractDexesInNeeded`：

```cpp
if (access(codeCachePathChs, F_OK) == 0) {
    if (access(compressedDexesPathChs, F_OK) != 0) {
        writeDexAchieve(compressedDexesPathChs, package_addr, package_size);  // 几十 MB
        chmod(compressedDexesPathChs, 0444);
    }
}
```

`dpt.cpp:99` `combineDexElements` 再把 `i11111i111.zip` 追加进 ClassLoader 的 dexPathList。
首次启动必落盘几十 MB。

### 4.2 ⚠️⚠️ 三条审核未覆盖的阻断性问题

#### 问题 1（最致命）：location 门槛会导致 100% 不解密

`dpt_hook.cpp:274` 现有硬门槛：

```cpp
if (location.rfind(DEXES_ZIP_NAME) != std::string::npos && dex_class_def) {
```

`DEXES_ZIP_NAME` 定义在 `common/dpt_macro.h:27`，值为 `"i11111i111.zip"`。

而 `InMemoryDexClassLoader` 加载的 dex，其 ART `DexFile::location_` 是：

| API | location 实际值 | 含 `i11111i111.zip`？ | 含 dex 下标？ |
|---|---|---|---|
| 26–28 | `Anonymous-DexFile@0x70b2a3c000-0x70b2a4f000` | ❌ | ❌ |
| 29+ | `<data_dir>/Anonymous-DexFile@<checksum>.jar` | ❌ | 第 2 个起为 `!classesN.dex` |

来源：AOSP `android-8.0.0_r1` `runtime/native/dalvik_system_DexFile.cc` `CreateDexFile`：

```cpp
std::string location = StringPrintf("Anonymous-DexFile@%p-%p",
                                     dex_mem_map->Begin(), dex_mem_map->End());
```

AOSP `android-10.0.0_r1` `runtime/oat_file_manager.cc`：

```cpp
DexFileLoader::GetMultiDexLocation(i, dex_location.c_str())
// 第 0 个 = dex_location，第 i 个 = dex_location + "!classes" + (i+1) + ".dex"
```

**后果**：走 InMemoryDex 后 `location.rfind("i11111i111.zip") == npos`，
`patchClass` 直接跳过 → **所有方法体保持 nop → 加壳 APK 启动即崩**。
`try-catch` 兜不住——它根本不报错，只是静默不解密。

#### 问题 2：API 26–28 无法正确解析 dexIndex

`parse_dex_number`（`dpt_util.cpp:170`）对无 `!` 的 location 返回 0。
API 26–28 的 location 不带 `!classesN.dex`，**多 dex 应用的 classes2.dex+ 会被全部当成 dex0**，
按错误的索引表解密 → 指令错乱 → 崩溃。

所以**阈值必须是 API 29，不是审核建议的 27**（审核只查了构造器有无，
没查 location 是否带下标，这是它漏掉的第二个根因）。

补充事实：本地 SDK `platforms/android-36/data/api-versions.xml:81279` 确认
`dalvik/system/InMemoryDexClassLoader` `since=26`；但 AOSP libcore `android-8.0.0_r1`
的该类只有 `ByteBuffer[]` 与 `ByteBuffer` 两参构造器（数组版带 `@hide`），
三参 `(ByteBuffer[], String, ClassLoader)` 与 `openInMemoryDexFilesNative`
要到 `android-10.0.0_r1` 才加入。

#### 问题 3：`cbde` 与 InMemoryDexClassLoader 重复追加同一份 dex

初稿 §4.3.2 的伪代码写 `JniBridge.cbde(inMem)`，
而 `dpt.cpp:99` `combineDexElements` 会把 `i11111i111.zip` 追加进 `inMem` 的 dexPathList。
InMemoryDexClassLoader 已经持有全部 dex，再追加一份 → `DuplicateClassError`，
或类加载顺序错乱。

**修正**：InMemoryDex 分支下**不得调用 `cbde`**。

### 4.3 修正方案

#### 4.3.1 门槛放宽（`dpt_hook.cpp`）

在 `common/dpt_macro.h` 增加前缀常量：

```cpp
#define DEXES_ZIP_NAME       "i11111i111.zip"
#define ANONYMOUS_DEX_PREFIX "Anonymous-DexFile"
```

`dpt_hook.cpp` 增加判定函数：

```cpp
// 壳 dex 的两种来源：落盘 zip（默认路径）与 InMemoryDexClassLoader（Task 1.4）
static bool is_shell_dex_location(const std::string& location) {
    return location.rfind(DEXES_ZIP_NAME) != std::string::npos
        || location.rfind(ANONYMOUS_DEX_PREFIX) != std::string::npos;
}
```

替换 `dpt_hook.cpp:274` 的条件。

**兼容性**：API ≥ 29 的 location 形如
`/data/app/~~xxx/base.apk!/i11111i111.zip`（默认路径）或
`/data/data/<pkg>/Anonymous-DexFile@<cksum>.jar!classes2.dex`（InMemory 路径），
两者都能被 `parse_dex_number` 正确解析。

**遗留风险**：`Anonymous-DexFile` 是 ART 通用前缀，若被壳加载的类里有
来自其它 `InMemoryDexClassLoader` 的 dex（少见但可能，例如某些 SDK 动态下发代码），
会误判为壳 dex。此时 `findClassIndex` 找不到条目会 `return`，行为等同现状（不解密），
**不会崩溃**，可接受。

#### 4.3.2 阈值与开关（`Global.java`）

```java
// 只有 API 29+ 的 InMemoryDex location 才带 "!classesN.dex" 下标，
// parse_dex_number 才能算出正确 dexIndex。API 26–28 的 location 是
// "Anonymous-DexFile@<begin>-<end>"（映射地址范围），多 dex 会全被当成 dex0。
// 见 docs/phase1-perf-plan.md 第四章 4.2 问题 2。
public static final boolean USE_IN_MEMORY_DEX =
        Build.VERSION.SDK_INT >= 29 && Global.sInMemoryDexEnabled;
```

`sInMemoryDexEnabled` 由 `JniBridge` 传入（见 4.3.5），默认 true，可被
`--disable-inmemory-dex` 关闭。

#### 4.3.3 `ProxyApplication.java`

```java
@Override
protected void attachBaseContext(Context base) {
    super.attachBaseContext(base);
    if (!Global.sIsReplacedClassLoader) {
        ApplicationInfo applicationInfo = base.getApplicationInfo();
        if (applicationInfo == null) throw new NullPointerException("application info is null");
        FileUtils.unzipLibs(applicationInfo.sourceDir, applicationInfo.dataDir);
        JniBridge.loadShellLibs(applicationInfo.dataDir);
        JniBridge.ia();

        ClassLoader inMem = null;
        if (Global.USE_IN_MEMORY_DEX) {
            try {
                inMem = createInMemoryDexClassLoader(base);
            } catch (Throwable t) {
                Log.w(TAG, "InMemoryDex unavailable, fallback to zip", t);
                inMem = null;
            }
        }

        if (inMem != null) {
            // ★ 绝不调用 cbde：它会把同一份 zip 再追加一遍（见 4.2 问题 3）
            JniBridge.setInMemoryDex(true);
            JniBridge.cbde(inMem);
            Global.sIsReplacedClassLoader = true;
            realApplicationName = JniBridge.rapn();
            return;
        }

        JniBridge.setInMemoryDex(false);
        JniBridge.cbde(base.getClassLoader());
        Global.sIsReplacedClassLoader = true;
    }
    realApplicationName = JniBridge.rapn();
}
```

#### 4.3.4 native 侧：`extractDexesInNeeded` 跳过

新增全局开关（`dpt.h`）：

```cpp
extern bool g_use_in_memory_dex;   // 由 Java 经 JNI 传入
```

`dpt_util.cpp:353`：

```cpp
DPT_ENCRYPT void extractDexesInNeeded(JNIEnv *env, void *package_addr, size_t package_size) {
    if (g_use_in_memory_dex) {
        DLOGI("in-memory dex mode, skip writing %s", DEXES_ZIP_NAME);
        return;                       // ★ 审核错误 4 的修正：只改 Java 层达不到目标
    }
    // ... 原逻辑不变 ...
}
```

注意 `init_app`（`dpt.cpp:413`）在 `JniBridge.ia()` 时调用
`extractDexesInNeeded`，而 Java 侧必须**先** `setInMemoryDex(true)` 再调 `ia()`。
因此 4.3.3 的顺序需调整：`JniBridge.setInMemoryDex(...)` 必须在 `JniBridge.ia()` 之前。
但此时 InMemoryDexClassLoader 还没建（需要 `ia()` 之后 native 才可用）——
所以 `createInMemoryDexClassLoader` 必须在 `ia()` 之后，此时 zip 已被写出。
**这意味着 `extractDexesInNeeded` 的跳过开关需要在 `cbde` 阶段重新评估**：

**简化后的正确做法**：让 `extractDexesInNeeded` 不再无条件写盘，改为由
`combineDexElements` 决定：

```cpp
// dpt.cpp:98
DPT_ENCRYPT void combineDexElements(JNIEnv* env, jclass klass, jobject targetClassLoader) {
    if (g_use_in_memory_dex) {
        // InMemoryDexClassLoader 已持有全部 dex，只需做 junk class 校验
        DLOGI("in-memory dex mode, skip combining zip elements");
#ifndef DEBUG
        junkCodeDexProtect(env);
#endif
        return;
    }
    char compressedDexesPathChs[256] = {0};
    getCompressedDexesPath(env, compressedDexesPathChs, ARRAY_LENGTH(compressedDexesPathChs));
    combineDexElement(env, klass, targetClassLoader, compressedDexesPathChs);
#ifndef DEBUG
    junkCodeDexProtect(env);
#endif
}
```

但 `init_app`（`ia()`）里的 `extractDexesInNeeded` 在 `cbde` **之前**执行，
此时 `g_use_in_memory_dex` 还没被设置。

**最终方案**：新增独立 JNI 方法 `setInMemoryDex(boolean)`，Java 在 `ia()` **之前**调用：

```java
JniBridge.setInMemoryDex(Global.USE_IN_MEMORY_DEX && !Global.sInMemoryDexDisabled);
JniBridge.ia();
if (Global.USE_IN_MEMORY_DEX) {
    ClassLoader inMem = createInMemoryDexClassLoader(base);
    if (inMem != null) { JniBridge.cbde(inMem); ... }
}
```

这样 `init_app` → `extractDexesInNeeded` 读到 `g_use_in_memory_dex == true` 就直接 return，
不落盘。随后 `cbde` 也跳过 zip 追加。**顺序必须在计划里写死，否则会白写盘再白用内存 loader。**

#### 4.3.5 新增 JNI

`dpt.h` / `dpt.cpp`：

```cpp
DPT_ENCRYPT void setInMemoryDex(JNIEnv *env, jclass __unused, jboolean enable) {
    g_use_in_memory_dex = (enable == JNI_TRUE);
    DLOGI("in-memory dex mode = %s", g_use_in_memory_dex ? "on" : "off");
}

DPT_ENCRYPT jbyteArray readDexZipFromApkTail(JNIEnv* env, jclass __unused) {
    void* package_addr = nullptr;
    size_t package_size = 0;
    load_package(env, &package_addr, &package_size);

    auto entry = read_zip_file_entry(package_addr, package_size,
                                     AY_OBFUSCATE(COMBINE_DEX_FILES_NAME_IN_ZIP));
    if (!entry.has_value()) { unload_package(package_addr, package_size); return nullptr; }

    auto [entry_data, entry_size] = entry.value();
    uint32_t zipDataLen = readZipLength((uint8_t*)entry_data, entry_size);
    if (zipDataLen == 0 || entry_size <= zipDataLen + 4) {
        delete[] entry_data;
        unload_package(package_addr, package_size);
        return nullptr;
    }
    uint8_t* zipStart = (uint8_t*)entry_data + (entry_size - zipDataLen - 4);
    jbyteArray arr = env->NewByteArray(zipDataLen);
    env->SetByteArrayRegion(arr, 0, zipDataLen, (jbyte*)zipStart);
    delete[] entry_data;
    unload_package(package_addr, package_size);
    return arr;
}
```

**⚠️ 初稿又漏了一个编译错误**：`readZipLength` 定义在 `dpt_util.cpp:307`，是 `static`，
`dpt_util.h` 里没有声明，**跨文件不可见**。必须把它移到 `dpt_util.h` 声明
（或在 `dpt.cpp` 里重新实现一份）。推荐前者。

`gMethods` 注册（`dpt.cpp:27`）：

```cpp
{"setInMemoryDex", "(Z)V", (void *) setInMemoryDex},
{"readDexZipFromApkTail", "()[B", (void *) readDexZipFromApkTail},
```

`JniBridge.java`：

```java
public static native void setInMemoryDex(boolean enable);
public static native byte[] readDexZipFromApkTail();
```

#### 4.3.6 InMemoryDexClassLoader 构造

```java
private ClassLoader createInMemoryDexClassLoader(Context base) throws Exception {
    byte[] zipData = JniBridge.readDexZipFromApkTail();
    if (zipData == null || zipData.length == 0) return null;

    // ★ API 26–28 的 heap buffer 路径无 arrayOffset 修正、无 read-only 兜底，
    //   用 direct ByteBuffer 规避（见 AOSP libcore android-8.0.0_r1 DexFile.java）
    List<ByteBuffer> buffers = new ArrayList<>();
    try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(zipData))) {
        ZipEntry entry;
        byte[] buf = new byte[16384];
        while ((entry = zis.getNextEntry()) != null) {
            if (!entry.getName().matches("classes\\d*\\.dex")) continue;
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            int n;
            while ((n = zis.read(buf)) != -1) baos.write(buf, 0, n);
            ByteBuffer direct = ByteBuffer.allocateDirect(baos.size());
            direct.put(baos.toByteArray());
            direct.rewind();
            buffers.add(direct);
        }
    }
    if (buffers.isEmpty()) return null;

    ByteBuffer[] array = buffers.toArray(new ByteBuffer[0]);
    // 保持 zip 内原有顺序（classes.dex 必须在最前），ART 依此生成 !classesN.dex 下标
    return new InMemoryDexClassLoader(array, base.getClassLoader());
}
```

**顺序要求**：必须按 zip 内 entry 顺序（classes.dex → classes2.dex → …）传入。
ART 的 `GetMultiDexLocation(i)` 按数组下标生成 `!classes{i+1}.dex`，
顺序错乱会让 dexIndex 与 payload 索引对不上。

#### 4.3.7 `ProxyComponentFactory.java`

`instantiateClassLoader`（Android 10+ 入口）同样要改，且**不能调用 `cbde`**：

```java
@Override
public ClassLoader instantiateClassLoader(@NonNull ClassLoader cl, @NonNull ApplicationInfo aInfo) {
    FileUtils.unzipLibs(aInfo.sourceDir, aInfo.dataDir);
    JniBridge.loadShellLibs(aInfo.dataDir);

    boolean useInMem = Build.VERSION.SDK_INT >= 29;
    JniBridge.setInMemoryDex(useInMem);
    JniBridge.ia();

    if (useInMem) {
        try {
            ClassLoader inMem = createInMemoryDexClassLoader(aInfo);
            if (inMem != null) {
                Global.sIsReplacedClassLoader = true;
                Global.sNeedCalledApplication = false;
                return inMem;
            }
        } catch (Throwable ignored) { }
    }
    JniBridge.setInMemoryDex(false);
    JniBridge.cbde(cl);
    Global.sIsReplacedClassLoader = true;
    ...
}
```

**注意**：`ProxyComponentFactory.instantiateApplication`（`:63`）里也有一处
`JniBridge.ia()`，需要同样先 `setInMemoryDex`。这是初稿和审核都漏掉的第三处调用点。

#### 4.3.8 CLI 开关（打包侧）

`Const.java`：

```java
public static final String OPTION_DISABLE_INMEMORY_DEX_LONG = "disable-inmemory-dex";
```

`Dpt.java:104` 的 Options 里加：

```java
options.addOption(new Option(null, Const.OPTION_DISABLE_INMEMORY_DEX_LONG, false,
        "Disable InMemoryDexClassLoader (fallback to code_cache zip)."));
```

值写进 `ShellConfig`，`init_app` 读配置决定默认是否开启
（`g_use_in_memory_dex` 的初值），Java 的 `setInMemoryDex` 可再覆盖。

### 4.4 兜底矩阵

| 场景 | 行为 |
|---|---|
| API ≥ 29 + 未禁用 | InMemoryDex，不落盘 |
| API 26–28 | 落盘（阈值以下，location 无下标） |
| 用户传 `--disable-inmemory-dex` | 落盘 |
| InMemoryDex 构造抛异常 | try-catch → 回退落盘 |
| `readDexZipFromApkTail` 返回 null | 回退落盘 |

**注意**：回退路径要求 zip 已被写出。若 `g_use_in_memory_dex` 为 true 时
`extractDexesInNeeded` 跳过了写盘，回退就会缺文件。
→ **修正：`extractDexesInNeeded` 在 InMemory 模式下仍需写盘，或改为延迟到
`createInMemoryDexClassLoader` 失败时才写**。推荐后者：

```cpp
// init_app 里
if (!g_use_in_memory_dex) {
    pthread_mutex_lock(&g_write_dexes_mutex);
    extractDexesInNeeded(env, package_addr, package_size);
    pthread_mutex_unlock(&g_write_dexes_mutex);
}
```

并在 `createInMemoryDexClassLoader` 失败时调 `JniBridge.rde(null)` 触发
native 侧补写——**这需要新增一个 JNI 方法 `ensureDexesOnDisk()`**。
Task 实施时必须补上，否则回退路径会因缺 zip 而启动失败。

### 4.5 验收标准

| 项 | 本机 | 真机 |
|---|---|---|
| `./gradlew build` 通过 | ✅ | — |
| CI `build.yml` 绿 | ✅ | — |
| Android 10 / 11 / 12 / 13 启动正常 | — | ⏳ |
| Android 9 (API 28) 走落盘路径且启动正常 | — | ⏳ |
| Android 8.0 走落盘路径且启动正常 | — | ⏳ |
| `code_cache/i11111i111.zip` 不生成（API ≥ 29） | — | ⏳ |
| 多 dex APK（≥ 3 个 dex）启动正常 | — | ⏳ |
| `--disable-inmemory-dex` 回退正常 | — | ⏳ |
| **InMemory 路径下指令确实被解密**（非静默 nop） | — | ⏳ 关键 |

### 4.6 风险

| 风险 | 概率 | 应对 |
|---|---|---|
| 部分 ROM InMemoryDex 有 bug | 中 | try-catch 回退 |
| ART 版本差异导致 location 格式变化 | 中 | 门槛用前缀匹配而非全等 |
| dex 顺序错乱 | 低 | 单测 + 注释钉死 |
| 回退路径缺 zip | 中 | 见 4.4 的 `ensureDexesOnDisk` |
| API 26–28 仍落盘 | 确定 | 已知限制，文档标注 |

### 4.7 回滚方案

保留原落盘路径不删除，只是"优先尝试 InMemoryDex，失败回退"。
回滚 = 删掉 InMemoryDex 分支 + 去掉 `setInMemoryDex` 调用。

---

## 五、Task 1.5：页粒度 RW + 按页自旋锁

### 5.1 背景

`dpt_hook.cpp:111` `change_dex_protective`：

```cpp
void change_dex_protective(uint8_t * begin, int dexSize, int dexIndex) {
    for (int i = 0; i < 10;) {
        int ret = dpt_mprotect(begin, begin + dexSize, PROT_READ | PROT_WRITE);
        if (ret != 0) { i++; }
        else {
            dexMemMap.insert(std::pair<int, uint8_t *>(dexIndex, begin));  // 永不恢复
            break;
        }
    }
}
```

一次把整个 dex 设 RW，写进 `dexMemMap` 后**永不恢复**。

### 5.2 修订方案（延迟恢复）

```
patchClass(一个类) {
    1. 收集本类所有方法 insns 涉及的页 → touchedPages
    2. 排序 + 按页取锁（防死锁）
    3. 一次性 mprotect RW
    4. 逐方法解密写回
    5. 一次性 mprotect READ 恢复
    6. 逆序解锁（unique_lock 析构自动完成）
}
```

为什么"延迟恢复"而非"每方法恢复"：

- 每方法 2 次 mprotect 约 2μs，一个类平均 5–10 方法 → 20–40μs
- 每类一次：开销可接受，窗口仍 < 100μs

### 5.3 ⚠️ 初稿的两个错误（审核只提了其一）

#### 错误 A：mprotect 覆盖无关页

初稿 §5.4 用 `dpt_mprotect(firstPage, lastPage)`，会把两个目标页之间的
所有无关页也设为 RW，扩大了可写范围。

**修正**：逐页 mprotect，或确保范围在同一 dex 映射内。
推荐**分段连续化**：把排序后的页列表合并成若干连续区间，逐区间 mprotect。

```cpp
// 把 pages（已排序去重）合并成连续区间，减少系统调用同时不越界
size_t i = 0;
while (i < pages.size()) {
    size_t j = i;
    while (j + 1 < pages.size() && pages[j + 1] == pages[j] + pageSize) j++;
    uintptr_t segStart = pages[i];
    uintptr_t segEnd = pages[j] + pageSize;
    dpt_mprotect((void*)segStart, (void*)segEnd, PROT_READ | PROT_WRITE);
    // 记录区间供恢复
    segs.push_back({segStart, segEnd});
    i = j + 1;
}
```

#### 错误 B（审核中风险 4 提到）：页锁表只增不减

`g_pageLocks` 用 `unordered_map<uintptr_t, unique_ptr<mutex>>`，进程生命周期只增不减。
页数有限（每 dex 页数），量级不大，但必须**在文档标注**，不要假装不存在。

#### 错误 C（审核与初稿都漏）：`dpt_mprotect` 自己已经做了页对齐

`dpt_util.cpp:109-116`：

```cpp
uintptr_t start_addr = DPT_PAGE_START(start);
uintptr_t end_addr = DPT_PAGE_START(end - 1) + get_cache_page_size();
mprotect((void*)start_addr, end_addr - start_addr, prot);
```

`common/dpt_macro.h:35-37` 已有 `DPT_PAGE_MASK` / `DPT_PAGE_START` 宏。
所以上层**不必**再手工取页对齐，传原始区间即可，宏会处理。
但要注意：既然 `dpt_mprotect` 已对齐，传 `firstPage` 与传 `realInsns` 结果相同——
初稿手写的 `pageEnd` 计算是冗余的，且 `pageEnd` 在 `len == 0` 时会下溢。
**修正**：直接用 `DPT_PAGE_START` 计算页集合，`mprotect` 交给 `dpt_mprotect`。

### 5.4 页锁表

`dpt_util.h`：

```cpp
#include <mutex>
#include <memory>
#include <unordered_map>

namespace dpt {
    // 注意：本表进程生命周期只增不减，不回收（页数有限，量级可接受）。
    extern std::unordered_map<uintptr_t, std::unique_ptr<std::mutex>> g_pageLocks;
    extern std::mutex g_pageLockTableMutex;
    std::mutex& getPageLock(uintptr_t pageAddr);
}
```

`dpt_hook.cpp`：

```cpp
std::unordered_map<uintptr_t, std::unique_ptr<std::mutex>> dpt::g_pageLocks;
std::mutex dpt::g_pageLockTableMutex;

std::mutex& dpt::getPageLock(uintptr_t pageAddr) {
    std::lock_guard<std::mutex> lg(g_pageLockTableMutex);
    auto& slot = g_pageLocks[pageAddr];
    if (!slot) slot = std::make_unique<std::mutex>();
    return *slot;
}
```

### 5.5 patchClass 改造

```cpp
struct PendingPatch {
    uint32_t methodIdx;
    uint32_t codeOff;
    const uint8_t* enc;
    uint32_t insnsSize;      // 字节数
};

DPT_ENCRYPT void patchClass(...) {
    // ... 前置逻辑同 Task 1.1 ...

    const auto* entry = dexCode->findClassIndex((uint8_t)dexIndex, class_def->class_data_off_);
    if (entry == nullptr) return;
    auto classMethods = parse_class_data(begin, class_def->class_data_off_);
    if (!classMethods.ok) return;

    std::vector<PendingPatch> patches;
    std::set<uintptr_t> touchedPages;   // std::set 自带去重 + 排序
    const size_t pageSize = (size_t)get_cache_page_size();

    uint16_t i = 0;
    for (const auto& m : classMethods.methods) {
        if (i >= entry->methodCount) break;
        auto view = dexCode->getMethodData(entry, i++);
        if (view.encryptedInsns == nullptr || m.codeOff == 0) continue;
        if (m.methodIdx != view.methodIdx) continue;

        patches.push_back({view.methodIdx, m.codeOff, view.encryptedInsns, view.insnsSize});

        auto* item = (dex::CodeItem*)(begin + m.codeOff);
        uint8_t* realInsns = (uint8_t*)(item->insns_);
        size_t len = view.insnsSize;
        if (len == 0) continue;
        for (uintptr_t p = DPT_PAGE_START((uintptr_t)realInsns);
             p < DPT_PAGE_START((uintptr_t)(realInsns + len - 1)) + pageSize;
             p += pageSize) {
            touchedPages.insert(p);
        }
    }
    if (patches.empty()) return;

    // 排序后取锁（防死锁）
    std::vector<std::unique_lock<std::mutex>> locks;
    locks.reserve(touchedPages.size());
    for (uintptr_t p : touchedPages) locks.emplace_back(dpt::getPageLock(p));

    // 分段连续化后 mprotect（避免覆盖无关页）
    std::vector<std::pair<uintptr_t, uintptr_t>> segs;
    for (auto it = touchedPages.begin(); it != touchedPages.end(); ) {
        uintptr_t segStart = *it;
        auto jt = std::next(it);
        while (jt != touchedPages.end() && *jt == *std::prev(jt) + pageSize) jt = std::next(jt);
        uintptr_t segEnd = *std::prev(jt) + pageSize;
        dpt_mprotect((void*)segStart, (void*)segEnd, PROT_READ | PROT_WRITE);
        segs.emplace_back(segStart, segEnd);
        it = jt;
    }

    for (const auto& pt : patches) {
        auto* item = (dex::CodeItem*)(begin + pt.codeOff);
        auto* realInsns = (uint8_t*)(item->insns_);
        if (UNLIKELY(!dexCode->cryptInsns(g_shell_config.aes_key, pt.methodIdx,
                                          pt.enc, pt.insnsSize, realInsns))) {
            DLOGE("decrypt insns failed: methodIdx=%u size=%u", pt.methodIdx, pt.insnsSize);
        }
    }

    for (const auto& s : segs) {
        dpt_mprotect((void*)s.first, (void*)s.second, PROT_READ);
    }
    // locks 析构自动逆序解锁
}
```

### 5.6 删除清单

| 文件 | 删除 |
|---|---|
| `dpt_hook.cpp` | `change_dex_protective` 函数（:111） |
| `dpt_hook.cpp` | `std::map<int, uint8_t*> dexMemMap;` 全局（:22） |
| `dpt.cpp:19` | `dexMap`（Task 1.1 已删） |

### 5.7 ⚠️ 关键约束：mprotect 后必须 `__builtin___clear_cache`

**审核与初稿都没提这一点。** 解密写回的是**正在被 ART 解释/编译的 dex 指令字节**。

现有实现在 `change_dex_protective` 里整 dex 设 RW 后就返回，
后续 `patchMethod` 写回——同样没有 clear_cache，说明当前靠
"整 dex 长期 RW + 后续 ART 自己会重新校验"的巧合工作。

改为**短暂 RW 后立刻恢复 READ** 后，i-cache 里可能仍是被打乱的方法体。
ARM64 上必须 `__builtin___clear_cache(begin, end)`，否则解密后的指令不生效
或行为诡异。

**修正**：恢复权限前加：

```cpp
// 解密写回的是热指令，必须刷 i-cache，否则 ARM64 上仍执行密文
__builtin___clear_cache((const char*)segStart, (const char*)segEnd);
```

### 5.8 验收标准

| 项 | 本机 | 真机 |
|---|---|---|
| 编译通过 | ✅ | — |
| CI `build.yml` 绿 | ✅ | — |
| `grep -rn "dexMemMap" shell/` 无命中 | ✅ | — |
| 多线程并发加载同一 dex 不崩 | — | ⏳ |
| RW 窗口 < 100μs | — | ⏳ systrace |
| **解密后指令确实生效**（方法可正常执行） | — | ⏳ 关键 |

### 5.9 回滚方案

`git revert`。删除新分支，恢复 `change_dex_protective`。

### 5.10 输出物

- ☐ `dpt_hook.cpp`、`dpt_util.h`、`dpt.cpp` 改动
- ☐ `docs/task-1.5.md`

---

## 六、Task 1.6：集成验收

### 6.1 第一层：本机可做（必须全过）

| 项 | 命令 | 通过标准 |
|---|---|---|
| 编译通过 | `./gradlew build` | exit 0 |
| Java 单测 | `./gradlew :dpt:test` | 全绿 |
| v4 读写对拍 | `MultiDexCodeV4Test` | 全绿 |
| CI 编译 | GitHub Actions `build.yml` | 绿 |
| 无 RC4 insns 残留 | `grep -rn "buildInsnsRc4Key\|rc4_crypt_insns" dpt/ shell/` | 无命中 |
| 无 dexMemMap | `grep -rn "dexMemMap" shell/` | 无命中 |
| 无 65536 数组 | `grep -rn "65536" shell/src/main/cpp/` | 无命中 |
| 打包耗时对比 | `tools/benchmark/bench-pack.sh` | −30%+ |

### 6.2 第二层：需设备（无设备一律标 ⏳）

| 项 | 方法 | 通过标准 |
|---|---|---|
| 加壳 APK 启动正常 | 真机 | 无闪退 |
| **指令确实被解密** | 真机 + 关键类调用 | 不是 nop |
| 冷启动增量 | `am start -W` | < 150ms |
| 内存增量 | `dumpsys meminfo` | < 5MB |
| code_cache 不落盘（API ≥ 29） | `ls code_cache/` | 无 zip |
| RW 窗口 | systrace | < 100μs |
| mmap 次数 | 日志计数 | 1 |

### 6.3 测试矩阵

| 维度 | 覆盖 |
|---|---|
| Android 版本 | 8.0 / 9 / 10 / 11 / 12 / 13 |
| ABI | arm64-v8a / armeabi-v7a |
| APK 大小 | < 5MB / 10MB / 30MB |
| **dex 数量** | **1 / 2 / 5（多 dex 是 InMemory 路径的高危区）** |
| 方法数 | < 1 万 / 5 万 / 10 万 |
| 格式 | **APK + AAB**（`Aab extends AndroidPackage`，共用 `extractDexCode`） |
| 场景 | 冷启动 / 热启动 / 首次安装 / 升级安装 |

**补充**：初稿与审核都没覆盖 **AAB**。
`Aab.java:16` `class Aab extends AndroidPackage`，`extractDexCode` 是继承来的，
所以 v4 改动对 AAB 同样生效，测试矩阵必须含 AAB。

### 6.4 输出物

- ☐ `docs/phase1-test.md`
- ☐ `docs/phase1-benchmark.md`
- ☐ `docs/phase1-design.md`

---

## 七、Task 1.7：打包侧加速

### 7.1 背景（源码实证）

`DexUtils.java:405-414`：

```java
for (int i = 0; i < insnsCapacity; i++) {
    outRandomAccessFile.seek(insnsOffset + (i * 2));
    byteCode[i * 2] = outRandomAccessFile.readByte();
    byteCode[i * 2 + 1] = outRandomAccessFile.readByte();
    outRandomAccessFile.seek(insnsOffset + (i * 2));
    if (obfuscateIns) {
        outRandomAccessFile.writeShort(insRandom.nextInt());
    } else {
        outRandomAccessFile.writeShort(0x0e);
    }
}
```

每 2 字节一次 seek。5 万方法 × 30 code unit = 300 万次系统调用。

### 7.2 ⚠️ 修正初稿 §7.2.1 的严重错误

初稿的改法：

```java
outRandomAccessFile.seek(insnsOffset);
byte[] byteCode = new byte[insnsCapacity * 2];
outRandomAccessFile.readFully(byteCode);
Arrays.fill(byteCode, (byte)0x00);        // ← 错误
outRandomAccessFile.seek(insnsOffset);
outRandomAccessFile.write(byteCode);
```

**两处错**：

1. `Arrays.fill(byteCode, 0)` 把要**加密**的原指令清成全 0 → 加密的是垃圾
2. `writeShort(0x0e)` 小端写的是 `0e 00`（nop），不是 `00 00`

这是审核第 2 节**错误 3** 指出的点，此处给出完整正确实现：

```java
// 1. 一次性读出原指令
outRandomAccessFile.seek(insnsOffset);
byte[] original = new byte[insnsCapacity * 2];
outRandomAccessFile.readFully(original);          // ← 原指令，后面要加密它

// 2. 构造写回 dex 的填充字节（与原 writeShort 语义完全一致）
byte[] filler = new byte[original.length];
if (obfuscateIns) {
    for (int i = 0; i < insnsCapacity; i++) {
        short v = (short) insRandom.nextInt();     // 每 code unit 一次 nextInt，与原逻辑一致
        filler[i * 2]     = (byte) (v & 0xff);
        filler[i * 2 + 1] = (byte) ((v >> 8) & 0xff);   // RandomAccessFile.writeShort 是大端！
    }
} else {
    for (int i = 0; i < insnsCapacity; i++) {
        filler[i * 2]     = 0x0e;                 // return-void
        filler[i * 2 + 1] = 0x00;
    }
}

// 3. 写回 dex
outRandomAccessFile.seek(insnsOffset);
outRandomAccessFile.write(filler);                // 抽空方法体

// 4. 加密原指令（此处才开始用 original）
byte[] aesKey = ShellConfig.getInstance().getInsnsCryptKey();
byte[] nonce = CryptoUtils.buildChaCha20Nonce(method.getMethodIndex());
byte[] encrypted = CryptoUtils.chacha20Crypt(aesKey, nonce, original);
if (encrypted == null || encrypted.length != original.length) {
    throw new IllegalStateException("chacha20 encrypt insns failed");
}
instruction.setInstructionsData(encrypted);
instruction.setInstructionDataSize(original.length);   // v4 需要，字节数
```

**⚠️ 关于 `writeShort` 的字节序**：`RandomAccessFile.writeShort(int)` 是**大端**。
原来 `writeShort(0x0e)` 实际写 `00 0e`，不是 `0e 00`。
dex insns 是小端，`return-void` 的正确字节应为 `0e 00`。

初稿把大端误认为小端了。**保留原行为的写法**（不改变既有产物）：

```java
// 若要严格保持与 writeShort(0x0e) 相同的产物字节：
filler[i * 2]     = 0x00;
filler[i * 2 + 1] = 0x0e;
```

**决策**：本 Task 不改写回字节（保持产物兼容），只把"每 2 字节 seek"改成
"一次性 readFully + 一次性 write"，写回内容用与 `writeShort` 完全等价的显式字节。
实施时以 `writeShort` 的大端语义为准，加注释说明。

`insRandom` 也要提到循环外（当前在方法内 `new SecureRandom()`，
每个方法新建一次 → 5 万次）。改为类级单例。

### 7.3 `MultiDexCodeUtils.writeMultiDexCode` 改 BufferedOutputStream

现状（`:68`）用 `RandomAccessFile` 逐字段写 + `Endian.makeLittleEndian` 每次 `new byte[]`。
v4 重写时直接用 `BufferedOutputStream` 顺序写（Task 1.1 已含此设计）。

### 7.4 `ReflectionClinitInjector.inject` 单次遍历

初稿列为"可选，收益不明显可跳过"。**本方案同样建议跳过**——
它的正确性风险高于收益，且与 v4 格式无关。

若后续要做，必须有独立测试，不与 1.1 混做。

### 7.5 验收标准

| 项 | 命令 | 通过标准 |
|---|---|---|
| `:dpt:jar` 通过 | `./gradlew :dpt:jar` | exit 0 |
| 单测 | `./gradlew :dpt:test` | 全绿 |
| **写回字节与改动前逐字节一致** | 见 7.6 | 一致 |
| 加壳产物功能不变 | 真机 | 启动正常 |
| 打包耗时下降 | `bench-pack.sh` | ≥ 20% |

### 7.6 ⚠️ 字节一致性验证方法（初稿缺）

改动写回逻辑有风险，必须证明产物一致：

```bash
# 1. 用改动前的 dpt.jar 打一个基准包
git stash
./gradlew :dpt:jar && cp executable/dpt.jar /tmp/dpt-before.jar
java -jar /tmp/dpt-before.jar -f app.apk -o /tmp/before
git stash pop

# 2. 用改动后打
./gradlew :dpt:jar
java -jar executable/dpt.jar -f app.apk -o /tmp/after

# 3. 对比 classes.dex 的 insns 区
unzip -p /tmp/before/out.apk classes.dex | xxd > /tmp/before.hex
unzip -p /tmp/after/out.apk classes.dex | xxd > /tmp/after.hex
diff /tmp/before.hex /tmp/after.hex && echo "字节一致"
```

注意：OoooooOooo 的密文会因 nonce/key 相同而一致（ChaCha20 是确定性的，
nonce 由 methodIdx 推导，key 每次构建由 build-key 派生 → 同一次构建内一致）。
若两次构建的 build-key 不同，密文会不同，此时只对比 **dex 里的 filler 区**。

### 7.7 风险

低（不改格式，只改 I/O 方式）。唯一真实风险是写回字节搞错，由 7.6 兜住。

---

## 八、Task 1.8：运行时 mmap 合并

### 8.1 背景

`dpt.cpp:475` `read_shell_config` 与 `dpt.cpp:413` `init_app` 各自
`load_package` + `unload_package`（`dpt_util.cpp:423`/`:429`），同一 APK mmap 两次。

### 8.2 ⚠️ 初稿的 `std::call_once` 有坑（审核中风险 5 指出）

```cpp
std::call_once(g_mmap_once, [&](){ load_package(...); });
```

若第一次 `load_package` 失败，后续直接复用 null → 崩。

**修正**：双重检查 + 失败重置。

```cpp
// dpt.cpp
static std::mutex g_pkg_mutex;
static void* g_cached_package_addr = nullptr;
static size_t g_cached_package_size = 0;

void ensure_package_loaded(JNIEnv* env, void** out_addr, size_t* out_size) {
    {
        std::lock_guard<std::mutex> lg(g_pkg_mutex);
        if (g_cached_package_addr != nullptr) {          // 成功过才复用
            *out_addr = g_cached_package_addr;
            *out_size = g_cached_package_size;
            return;
        }
    }
    void* addr = nullptr;
    size_t size = 0;
    load_package(env, &addr, &size);
    std::lock_guard<std::mutex> lg(g_pkg_mutex);
    if (addr != nullptr && size > 0) {
        g_cached_package_addr = addr;
        g_cached_package_size = size;
    }
    *out_addr = addr;
    *out_size = size;
}
```

失败时 `g_cached_package_addr` 保持 null，下次调用会**重试**，符合审核要求。

### 8.3 进程退出清理

```cpp
__attribute__((destructor)) void cleanup_package() {
    if (g_cached_package_addr != nullptr) {
        unload_package(g_cached_package_addr, g_cached_package_size);
        g_cached_package_addr = nullptr;
    }
}
```

**⚠️ 初稿与审核都没考虑的一个致命点**：

`init_app`（`dpt.cpp:433`）把 `assets/OoooooOooo` 的内容拷到
`g_codeItemFileData`（`std::optional<std::tuple<uint8_t*, size_t>>`，
是**堆拷贝**，不是 mmap 指针）——所以卸载 mmap 不影响它。

但 **`read_shell_config` 读的 `SHELL_CONFIG_IN_ZIP` 若也存了指针**
（而非拷贝），卸载就会 use-after-free。实施时必须逐个确认：

- `g_codeItemFileData`：`read_zip_file_entry` 返回 `new uint8_t[]` → 堆拷贝，**安全**
- `g_shell_config`：`read_shell_config` 里若是 `std::string` 拷贝 → **安全**

**这是 Task 1.8 的前置检查项**，未确认前不得合并 mmap。

### 8.4 `find_so_path` 缓存

初稿 §8.2.4 的缓存有**重复加锁**问题：它把查找也放在 `lock_guard` 内，
并发时全部串行。

**修正**：双重检查 + 锁内只做查表：

```cpp
static std::unordered_map<std::string, std::string> g_soPathCache;
static std::mutex g_soPathCacheMutex;

std::string find_so_path(const char* so_name) {
    {
        std::lock_guard<std::mutex> lg(g_soPathCacheMutex);
        auto it = g_soPathCache.find(so_name);
        if (it != g_soPathCache.end()) return it->second;   // 返回拷贝，避免悬垂引用
    }
    // 原查找逻辑（不加锁，允许重复计算）
    std::string result = /* ... */;
    std::lock_guard<std::mutex> lg(g_soPathCacheMutex);
    g_soPathCache[so_name] = result;
    return result;
}
```

注意现有 `dpt_hook.cpp:46` `resolveLibPathCached` 已经有一套
`static std::string` + `bool resolved` 缓存，二者职责重叠，
实施时应合并而非叠加。

### 8.5 验收标准

| 项 | 本机 | 真机 |
|---|---|---|
| 编译通过 | ✅ | — |
| CI 绿 | ✅ | — |
| 加壳 APK 启动正常 | — | ⏳ |
| mmap 计数 = 1 | — | ⏳ |
| **无 use-after-free**（多线程 + 退出时清理） | — | ⏳ |

### 8.6 风险

| 风险 | 概率 | 应对 |
|---|---|---|
| 进程退出 munmap 崩溃 | 低 | `__attribute__((destructor))` |
| 缓存地址在卸载后被访问 | 中 | **必须先做 8.3 的指针审计** |
| 内存常驻（不卸载） | 低 | 进程退出即释放 |

保留 `--disable-mmap-cache` 编译期宏便于回退。

---

## 九、Task 1.9：运行时字节解析与 descriptor 缓存

### 9.1 背景

`MultiDexCode.cpp:81-95` 的 `readUInt8/16/32` 是非 inline 的成员函数，
跨翻译单元调用。`getClassDescriptor`（`dpt_hook.cpp:190`）每次 `patchClass`
重新解析 descriptor。

### 9.2 `readUInt*` 改 inline

Task 1.1 已把它们改为 `MultiDexCode.h` 里的私有 inline 成员，
本 Task 无额外改动。若保留在 `.cpp`，改为：

```cpp
// MultiDexCode.h
inline uint8_t MultiDexCode::readUInt8(uint32_t offset) const {
    return m_buffer[offset];
}
inline uint16_t MultiDexCode::readUInt16(uint32_t offset) const {
    uint16_t t;
    __builtin_memcpy(&t, m_buffer + offset, sizeof(t));   // 严格对齐要求，不能直接 deref
    return t;
}
inline uint32_t MultiDexCode::readUInt32(uint32_t offset) const {
    uint32_t t;
    __builtin_memcpy(&t, m_buffer + offset, sizeof(t));
    return t;
}
```

**⚠️ 不能直接 `*(uint32_t*)(m_buffer + offset)`**：
`m_buffer` 是 `mmap` 出来的页对齐内存，但 `offset` 是任意字节偏移，
非对齐访问在 arm64 上虽然多数能跑，但会触发对齐检查陷阱，
且 `-fsanitize` / 严格对齐架构上直接崩。必须用 `memcpy`。

### 9.3 `getClassDescriptor` 缓存

```cpp
static std::unordered_map<std::pair<const void*, const void*>, std::string>
        g_descriptorCache;
static std::mutex g_descriptorCacheMutex;
```

**key 用 `std::pair`（审核中风险 6 正确）**：
初稿的 `((uint64_t)dex_file) ^ ((uint64_t)dex_class_def)` 异或会碰撞。

```cpp
static const char* getClassDescriptor(const void* dex_file, const void* dex_class_def) {
    if (dex_file == nullptr || dex_class_def == nullptr) return nullptr;

    auto key = std::make_pair(dex_file, dex_class_def);
    {
        std::lock_guard<std::mutex> lg(g_descriptorCacheMutex);
        auto it = g_descriptorCache.find(key);
        if (it != g_descriptorCache.end()) return it->second.c_str();
    }

    // ... 原解析逻辑，结果写入 std::string result ...

    {
        std::lock_guard<std::mutex> lg(g_descriptorCacheMutex);
        auto& slot = g_descriptorCache[key];
        if (slot.empty()) slot = result;         // 并发时先到者赢
        return slot.c_str();
    }
}
```

**返回 `c_str()` 的安全性**：`std::unordered_map` 的 value 在 rehash 时会移动，
`c_str()` 可能失效。

**⚠️ 初稿与审核都没提这一点。** 修正：改用 `std::deque<std::string>`
（地址稳定）或返回 `const std::string&`，并约定调用方在锁外立即拷贝：

```cpp
static std::deque<std::string> g_descriptorCache;   // deque 元素地址稳定
static std::unordered_map<std::pair<const void*,const void*>, size_t> g_descIndex;
```

或更简单：**缓存 `std::string` 到 deque，用 `unordered_map<key, size_t>` 索引**。

**但更根本的问题**：descriptor 字符串指向的是 **dex 内存**
（`begin + string_ids[idx].string_data_off_`），不是缓存里的副本。
一旦 dex 卸载，缓存里的指针也悬垂。所以缓存必须存**拷贝**，
每次返回缓存里的 `c_str()`（地址稳定），而不是 dex 里的原始指针。

### 9.4 junkClassName 长度预计算

```cpp
static size_t g_junkClassNameLen = 0;   // init_app 时算好
```

`patchClass` 里的 `dpt_strstr(descriptor, junkClassName)` 无法用长度优化
（strstr 本身就要读），但可以避免**每次重新计算 junkClassName 指针**
（`g_shell_config.junk_class_name.c_str()` 每次调用都解引用）。

**收益很小，本 Task 可选。**

### 9.5 验收标准

| 项 | 本机 | 真机 |
|---|---|---|
| 编译通过 | ✅ | — |
| CI 绿 | ✅ | — |
| 加壳 APK 启动正常 | — | ⏳ |
| 类加载 CPU 下降 | — | ⏳ systrace |

### 9.6 风险

低。descriptor 缓存有悬垂风险，需按 9.3 的方案用稳定地址容器。

---

## 十、Task 1.10：性能基准脚本

### 10.1 `tools/benchmark/bench-pack.sh`

初稿用 `bc`（审核中风险 7 指出很多环境没装）。

```bash
#!/usr/bin/env bash
# 打包同一 APK 多次取中位数。用 date +%s%N 算毫秒，不依赖 bc。
set -euo pipefail

APK="${1:?usage: bench-pack.sh <apk> [runs] [jar]}"
RUNS="${2:-3}"
JAR="${3:-executable/dpt.jar}"

if [[ ! -f "$JAR" ]]; then
    echo "skip: $JAR not found (run ./gradlew build first)" >&2
    exit 0
fi

OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT

TIMES=()
for ((i = 0; i < RUNS; i++)); do
    START=$(date +%s%N)
    java -jar "$JAR" -f "$APK" -o "$OUT" >/dev/null 2>&1 || {
        echo "run $i failed" >&2; exit 1; }
    END=$(date +%s%N)
    TIMES+=( $(( (END - START) / 1000000 )) )   # 毫秒
done

printf '%s\n' "${TIMES[@]}" | sort -n | awk '
    { a[NR] = $1 }
    END {
        mid = (NR % 2) ? a[(NR+1)/2] : (a[NR/2] + a[NR/2+1]) / 2
        printf "runs=%d  min=%dms  median=%.0fms  max=%dms\n", NR, a[1], mid, a[NR]
    }'
```

### 10.2 `tools/benchmark/bench-runtime.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail
PKG="${1:?usage: bench-runtime.sh <package.name> [activity]}"

if ! command -v adb >/dev/null 2>&1; then
    echo "skip: adb not available"; exit 0
fi
if ! adb get-state >/dev/null 2>&1; then
    echo "skip: no device connected"; exit 0
fi

echo "== cold start =="
adb shell am force-stop "$PKG"
adb shell am start -W "${2:-"$PKG/.MainActivity"}" | grep -E "TotalTime|WaitTime"

echo "== memory =="
adb shell dumpsys meminfo "$PKG" | grep -E "TOTAL|Native Heap|Dalvik Heap"

echo "== code_cache =="
adb shell run-as "$PKG" ls -l code_cache/ 2>/dev/null || echo "(code_cache 不可读或不存在)"
```

无设备时打印 skip 并 `exit 0`（初稿的验收标准要求"无设备时打印 skip"，已保留）。

### 10.3 `docs/phase1-benchmark.md` 基线表

| 指标 | 基线 | 1.7 后 | 1.1 后 | 1.8 后 | 1.4 后 | 1.5 后 |
|---|---|---|---|---|---|---|
| 打包时间（5 万方法） | ? | ? | — | — | — | — |
| 内存增量 | ? | — | ? | ? | ? | ? |
| 冷启动增量 | ? | — | ? | ? | ? | ? |
| RW 窗口 | ? | — | — | — | — | ? |
| mmap 次数 | ? | — | — | ? | — | — |

**未填的格子保持 `?`，禁止预填估算值。**

### 10.4 验收标准

- `bench-pack.sh` 本机可跑出数字
- `bench-runtime.sh` 无设备时打印 skip
- `docs/phase1-benchmark.md` 有**真实**基线（来自 1.7 之前的未改动构建）

---

## 十一、附录

### 11.1 术语表

| 术语 | 含义 |
|---|---|
| OoooooOooo | dpt 载荷文件（`assets/OoooooOooo`），内含加密后的 insns |
| insns | dex 方法体的指令序列 |
| classDataOff | dex 里 class_data_item 的偏移 |
| codeOff | dex 里 code_item 的偏移 |
| filler | 写回 dex 抽空方法体的填充字节（`return-void` 或随机） |
| ChaCha20 | 指令加密算法（RFC 8439） |
| RC4 | 旧 insns 加密算法（已删）；**so 的 `.bitcode` 仍用** |
| `.bitcode` | so 文件里的自定义 section，用 RC4 加密 |

### 11.2 ⚠️ 术语纠错：`insnsSize` 是字节数

全文统一：**`insnsSize` = 字节数 = `Instruction.getInstructionDataSize()`**。

不是 code unit 数。这是最容易写错的一处（初稿和审核都没抓）。

### 11.3 改动文件汇总

| Task | Java | Native | 测试 | 文档 |
|---|---|---|---|---|
| 1.1 | `Const`, `Instruction`, `DexUtils`, `MultiDexCode`, `MultiDexCodeUtils` | `MultiDexCode.h/cpp`, `CodeItem.h/cpp`(删), `dpt.cpp`, `dpt_hook.cpp`, `dpt_util.h` | `MultiDexCodeV4Test`, `InsnsCryptoContractTest` | `task-1.1.md` |
| 1.3 | `CryptoUtils` | `dpt_crypto.h/cpp`, `MultiDexCode.h` | 删 2 个 RC4 测试 | `task-1.3.md` |
| 1.4 | `Global`, `ProxyApplication`, `ProxyComponentFactory`, `JniBridge`, `Dpt`, `Const` | `dpt.cpp`, `dpt_util.h/cpp`, `dpt_hook.cpp`, `dpt_macro.h` | — | `task-1.4.md` |
| 1.5 | — | `dpt_hook.cpp`, `dpt_util.h` | — | `task-1.5.md` |
| 1.6 | — | — | — | `phase1-test.md` 等 3 个 |
| 1.7 | `DexUtils`, `MultiDexCodeUtils` | — | — | `task-1.7.md` |
| 1.8 | — | `dpt.cpp`, `dpt_util.h/cpp` | — | `task-1.8.md` |
| 1.9 | — | `MultiDexCode.h`, `dpt_hook.cpp` | — | `task-1.9.md` |
| 1.10 | — | — | — | `phase1-benchmark.md` |

### 11.4 未验证项（诚实标注）

以下本机无法验证，需 CI 或真机：

- **Native 编译**：本机 arm64 跑不了 NDK，靠 `build.yml`
- **真机启动 / 内存 / 冷启动 / RW 窗口**：需 adb 设备
- **指令是否正确解密**：**最关键的一项，必须真机验证**
- **性能对比数据**：需真实 APK + 多次采样

绝不伪造数字。文档里凡是"目标"就写"目标"，凡是"实测"就附日志。

### 11.5 与 apk-protect-action 的接口

| Task | 对 apk-protect-action 的影响 |
|---|---|
| 1.1 / 1.3 / 1.4 / 1.5 / 1.7 / 1.8 / 1.9 | 无影响（CLI 契约不变） |

仅需替换 `tools/dpt-shell.zip`，`packer.sh` 零改动。

**但**：`--disable-inmemory-dex` 是新增 CLI 选项，属向后兼容（新增可选参数）。

### 11.6 版本命名规范（强制）

| 名词 | 取值 |
|---|---|
| OoooooOooo 结构版本 | **v4** |
| 加密算法版本 | **ChaCha20**（唯一） |
| dpt-shell 版本 | `appVersionName` |

`appVersionName`（`build.gradle:43`）当前是 `"1.0.0"`。
v4 与 v3 不兼容（审核小问题 3），**必须升 major**，建议 `"2.0.0"`。
这是 dpt-shell 的对外产物版本，`apk-protect-action` 升级 zip 即可。

### 11.7 本次复核新增的问题清单（审核未覆盖）

| # | 问题 | 严重度 | 所在 Task |
|---|---|---|---|
| N1 | `insnsSize` 应是字节数，初稿按 code unit 算，运行时越界读 2 倍 | **阻断** | 1.1 §2.2 |
| N2 | InMemoryDex 的 location 不含 `i11111i111.zip`，`patchClass` 静默不解密 → 100% 崩溃 | **阻断** | 1.4 §4.2 |
| N3 | API 26–28 location 无 dex 下标，阈值必须是 29 而非审核说的 27 | **阻断** | 1.4 §4.2 |
| N4 | `cbde` 与 InMemoryDexClassLoader 重复追加同一份 dex → DuplicateClass | **阻断** | 1.4 §4.2 |
| N5 | `readZipLength` 是 `static`，跨文件不可见，初稿伪代码编译不过 | 高 | 1.4 §4.3.5 |
| N6 | `ProxyComponentFactory.instantiateApplication` 还有第三处 `ia()` 调用点未处理 | 高 | 1.4 §4.3.7 |
| N7 | 恢复 mprotect READ 前缺 `__builtin___clear_cache`，解密后指令不生效 | 高 | 1.5 §5.7 |
| N8 | `RandomAccessFile.writeShort` 是**大端**，初稿误按小端 | 中 | 1.7 §7.2 |
| N9 | `extractDexesInNeeded` 跳过写盘后，回退路径会缺 zip，需补 `ensureDexesOnDisk` | 中 | 1.4 §4.4 |
| N10 | `g_shell_config` 若存 mmap 指针，卸载会 UAF，合并 mmap 前必须审计 | 中 | 1.8 §8.3 |
| N11 | `unordered_map` value 的 `c_str()` 会因 rehash 失效 | 中 | 1.9 §9.3 |
| N12 | `writeShort` 后多余的 `seek(insnsOffset)` 是死代码 | 低 | 1.7 §7.2 |
| N13 | 测试矩阵缺 AAB（`Aab extends AndroidPackage`） | 低 | 1.6 §6.3 |
| N14 | `insRandom` 每方法 `new SecureRandom()`，5 万次创建 | 低 | 1.7 §7.2 |
| N15 | `findClassIndex` / `getMethodData` 缺越界防护，坏 payload 会越界读 | 中 | 1.1 §2.4.2 |

### 11.8 一句话总结

Phase 1 = 10 个 Task，覆盖**打包速度 / 运行时内存 / 运行时启动 / 运行时权限 / 性能可量化**。
执行顺序：**1.10 → 1.7 → (1.1+1.3) → 1.9 → 1.8 → 1.4 → 1.5 → 1.6**。

---

## 文档结束

**执行前请注意**：本文档已在源码层面逐条核对，但 **Native 改动必须靠
GitHub Actions `build.yml` 验证编译**，且 **指令是否真正解密必须真机验证**。
这两项无法在本机完成，不得伪造结论。

启动 Phase 1 时，从 Task 1.10（基准脚本）开始，然后 1.7（打包侧加速）——
它独立、收益确定、本机可测、风险低。
