dpt-shell 2.0 完整升级方案（基于源码验证）

一、先说清楚我看到的源码事实

在给方案之前，我把关键代码再核对一遍，避免再说错。

性能瓶颈，源码坐实：

dpt.cpp 的 readCodeItem()：

```cpp
auto codeItemVec = new std::vector<data::CodeItem *>(65536);  // 每 dex 512KB
for (int k = 0; k < methodCount; k++) {
    data::CodeItem *codeItem = dexCode->nextCodeItem(&codeItemIndex);
    codeItemVec->at(methodIdx) = codeItem;  // 每方法 new 一个对象
}
```

MultiDexCode::nextCodeItem 每次 new CodeItem。

patchMethod 每次都要 rc4_init（256 次 KSA）：

```cpp
struct rc4_state state;
rc4_init(&state, rc4_key, sizeof(rc4_key));
rc4_crypt(&state, enc, realInsnsPtr, sz);
```

防御弱点，源码坐实：

AndroidPackage.deriveConfigAesKey：

```java
String keyMaterial = packageName + "_" + buildKey;
return CryptoUtils.hmacSha256(randomKey, keyMaterial);
```

CryptoUtils.buildInsnsRc4Key：

```java
buf.put(aesKey);          // 32 字节固定
buf.putInt(methodIndex);  // 每方法不同，但 aesKey 是全局
```

Native patchMethod 解密后直接写 realInsnsPtr，之后永不重新加密。

change_dex_protective 已经是按 dex 粒度一次 mprotect 并缓存到 dexMemMap——我之前说"批量 mprotect"是错的，它是按 dex 一次，不是按方法。

dpt-unpack 能一键脱壳的根本原因：

· masterKey 从 APK + SO 完全可推导
· OoooooOooo 格式固定
· 解密后明文常驻
· 这些前提在源码里全部成立

---

二、方案设计原则

原则 1：分层威胁模型（这是所有设计的基础）

威胁 目标 对应改造
离线脱壳（dpt-unpack） 让 APK+SO 不足以推导密钥 Runtime Key + 格式随机化
运行时 dump（FART/frida-dexdump） 内存不出现完整明文 执行后擦除（核心方法）
静态分析（JADX） 看不到业务逻辑 当前抽取壳已做到
Hook 绕过 单点失效 多点 Hook + 内联检测

原则 2：明确承认边界

离线脱壳在纯软件、无硬件绑定前提下，不可能完全防止。目标是破坏自动化工具 + 提高手动成本，不是"不可逆"。

原则 3：不做 VMP

不引入 DEX 解释器、自定义 IR、匿名可执行内存。原因：

· 工程量对个人项目过大
· 性能下降 5–10 倍，只适合极少量方法
· 兼容性风险极高
· 用户明确说"先不搞方案四"

原则 4：不做伪优化

· 不用 XOR 当加密方案
· 不做"批量 mprotect"（当前已是按 dex 粒度，真正该做的是页粒度 + 缩小 RW 窗口）
· 不把安全性建立在设备指纹上

---

三、Phase 1：性能重构

3.1 CodeItem 惰性解析 + 紧凑索引

当前问题：readCodeItem 一次性解析所有方法，每个 dex 创建 65536 指针数组，每个方法 new CodeItem。

新格式（OoooooOooo 重构）：

```
┌──────────────────────────────────────────┐
│ Header                                    │
│   magic, version, dexCount, flags         │
│   classIndexOffset, methodDataOffset      │
├──────────────────────────────────────────┤
│ ClassIndex[] (按 dexIdx + classDataOff 排序)│
│   { uint8 dexIdx,                         │
│     uint32 classDataOff,                  │
│     uint32 methodCount,                   │
│     uint32 dataOffset }                   │
├──────────────────────────────────────────┤
│ MethodData[] (紧凑二进制)                  │
│   { uint32 methodIdx,                     │
│     uint16 insnsSize,                     │
│     uint8[insnsSize*2] encryptedInsns }   │
└──────────────────────────────────────────┘
```

运行时改动：

readCodeItem 只建索引，不建对象：

```cpp
void readCodeItem(uint8_t *data, size_t data_len) {
    // 1. 读 header
    // 2. 建 classIndex 排序数组（每个 dex 一份）
    // 3. 不解析 method data，不 new 任何对象
}
```

patchClass 二分查找 + 按需读取：

```cpp
void patchClass(const char* descriptor, const void* dex_file, const void* dex_class_def) {
    auto* class_def = (dex::ClassDef*)dex_class_def;
    auto entry = binarySearchClassIndex(dexIdx, class_def->class_data_off_);
    for (auto& m : entry.methods) {
        patchMethod(begin, ..., m.methodIdx, m.codeOff);
    }
}
```

效果：

· 内存：大型 App 降 40–50%
· 启动：init_app 只读 header + 索引，快 30%+

3.2 去掉 65536 指针数组

改造：

```cpp
struct DexMethodEntry { uint32_t methodIdx; uint32_t dataOff; uint32_t size; };
std::vector<DexMethodEntry> dexMethods[dexCount];  // 按 methodIdx 排序
```

效果：5 dex / 10 万方法从 2.5MB 降到 1.2MB。

3.3 RC4 优化

现状：每个方法都要 rc4_init 做 256 次 KSA。

改造：预计算 RC4 状态快照。

因为同一 dex 内所有方法的 RC4 key 只有最后 4 字节（methodIdx）不同，前 32 字节相同。所以：

· 为每个 dex 预计算 RC4 状态前缀快照，只在 methodIdx 部分做一次 seek
· 或者换成 ChaCha20，天然支持 seek

推荐 ChaCha20（无 KSA、支持随机访问、ARM 上无需硬件加速，且不是 RC4 那种已被证明有偏置的算法）。

效果：类加载阶段 CPU 降 30–50%。

3.4 首次启动优化

现状：extractDexesInNeeded 首次启动把几十 MB dex zip 写到 code_cache。

改造：

· API ≥ 26：用 InMemoryDexClassLoader(ByteBuffer, parent) 直接从内存加载，不落盘
· API < 26：回退到 code_cache 文件方案

注意：InMemoryDexClassLoader 不需要 PROT_EXEC 内存，ART 的 Dex 内存是数据映射，保持 PROT_READ 即可。

效果：首次启动减少落盘 I/O，同时减少持久化痕迹。

3.5 页粒度 RW 窗口

现状：change_dex_protective 按 dex 粒度一次 mprotect，缓存到 dexMemMap。

这里我要修正上一版的表述：mprotect 只改权限，不会让明文消失。真正被缩短的是 RW 暴露窗口，不是明文生命周期。

改造：

· 按页粒度 mprotect，只对包含目标 CodeItem 的页做 RW
· patch 完成后立即恢复 PROT_READ（不是 PROT_EXEC！）
· 必须配合按页自旋锁，防止多线程并发 patch 同一页时 SIGSEGV

效果：RW 窗口从"整个 dex 生命周期"缩短到"单次 patch 调用"。

3.6 Phase 1 验收标准

指标 当前 目标
大型 App 冷启动增量 300–800ms <200ms
内存增量 10–20MB <5MB
首次启动落盘 I/O 1–3s 接近 0（API≥26）
类加载 CPU 增量 10–30% <10%

---

四、Phase 2：提高离线脱壳成本

4.1 定位修正

核心事实：只要密文在 APK 里、解密逻辑在 SO 里、两者都暴露给攻击者，离线脱壳不可能完全防止。目标是破坏 dpt-unpack 的自动化流程 + 提高手动逆向成本。

4.2 Runtime Key（明确边界）

先说清楚：这不能解决离线脱壳。构建时密文已生成，runtimeNonce 那时不存在，所以只能用 masterKey 加密。masterKey 可离线推导。

那 Runtime Key 有什么用？

它把攻击者从"离线"逼到"运行时"：

· 攻击者必须在正确设备上运行 App
· 必须Hook 运行时拿到 sessionKey
· 必须在会话内 dump 明文

而不能"拿到 APK + SO，离线推导 masterKey，直接解密 OoooooOooo"。

这增加了攻击成本，但没有消除攻击可能。

4.3 数据格式随机化（最有效的反 dpt-unpack 手段）

· 每次构建随机打乱 OoooooOooo 字段顺序
· 索引编码在 uleb128 / 定长 / 变长之间随机选择
· dex 顺序随机
· 格式描述加密后写在尾部，只有运行时用 sessionKey 解密才能拿到
· 或在方法数据之间插入随机长度的 Junk Bytes

效果：dpt-unpack 的硬编码解析器失效，必须重新逆向格式。

注意：SO 里必然存在解析器，所以这不是"不可逆"，只是"提高成本"。

4.4 虚假 CodeItem 注入（低优先级混淆）

· 构建时注入 30–50% 假 CodeItem：methodIdx 随机、数据随机
· 运行时用 sessionKey 派生"真伪判别"函数
· dpt-unpack 遍历会拿到大量假数据

定位：针对静态傻瓜型 unpacker 有效，对运行时动态脱壳价值有限。低优先级，但不删。

4.5 检测逻辑内联 + 结果参与解密

现状：detectFrida / detectDebugger / verifyLibcTextCrc 是独立函数，patch 掉即绕过。

改造：

· 不写 if (detected) crash()
· 把检测结果（如 tracerPid == 0 ? 1 : 0）作为解密密钥派生的一个输入
· 检测失败 → 密钥错误 → 解密出错误字节码 → 方法行为异常 → 自然崩溃
· 检测逻辑内联到 patchMethod，不独立成函数

效果：patch 掉检测函数，反而导致解密失败。

4.6 白盒密码学（进阶，可选）

如果 Phase 2 的格式随机化 + 假数据不足以对抗 dpt-unpack，再考虑白盒。

· 用查表法重写 ChaCha20，密钥打散融合在代码表中
· dpt-unpack 必须引入 Unicorn 模拟执行才能还原
· 代价：代码表大小数百 KB，需自定义实现，维护成本高

定位：Phase 2 的进阶选项，不作为第一优先级。

4.7 Phase 2 验收标准

· dpt-unpack 无法一键脱壳（需重新逆向格式）
· 攻击者必须运行时 Hook 才能拿到 sessionKey
· 手动离线脱壳需要 2–3 天以上

不承诺：完全防止专业分析者的手动脱壳。

---

五、Phase 3：防运行时 Dump

5.1 分层策略

方法类型 保护方式 性能代价
普通方法 Lazy Decrypt 无额外
重要方法（-core 标记） 执行后擦除 ×2–3
极核心方法 （留给未来 VMP） —

5.2 核心方法执行后擦除

这里必须修正一个关键错误：

上一版我说 Hook ExecuteMterpImpl，这是过时知识。从 Android 10 开始，ART 引入 Nterp，ExecuteMterpImpl 已被移除。而且 instrumentation 激活时 Nterp 会被禁用，回退到 Switch 解释器。解释器路径不是单一的。

正确方案：接管 ArtMethod 入口点，而不是 Hook 底层解释器。

```cpp
// 1. 动态推导 ArtMethod entry point 偏移（不能硬编码）
//    ART 是 Mainline 模块，布局可能因设备而异

// 2. 对核心方法：
//    - access_flags_ |= kAccNative
//    - entry_point_from_quick_compiled_code_ = &my_stub

// 3. my_stub 中：
//    - 解密该方法的 DEX 指令块
//    - 通过 art::Invoke 调用原始方法
//    - 等待返回（原子引用计数）
//    - 计数归零时，用 0 覆写指令内存

// 4. 多线程并发处理：
std::atomic<int> ref_count;
```

关键约束：

· 不硬编码 entry point 偏移，必须动态推导
· 需要处理 JIT 可能覆盖 entry point 的情况
· 需要处理异常、递归、嵌套调用
· 这是整个 Phase 3 最大的工程难题

白名单机制：

· 构建时用 -core 选项标记核心方法
· 运行时只对这些方法执行擦除
· 非核心方法保持 Lazy Decrypt

5.3 多点 Hook

现状：只 Hook DefineClass / LoadClass。

改造：

· 同时 Hook DefineClass、LoadClass、LoadMethod、LinkCode、VisitMethods
· 任一触发都做 patch，逻辑幂等
· 记录已 patch 的方法，避免重复

5.4 SO 自校验

· 启动时计算 SO .text 的 CRC，与构建时嵌入值比对
· 关键函数用 OLLVM 控制流平坦化
· 关键常量分片存在多 section，运行时拼接

5.5 内存扫描检测

· Hook process_vm_readv / ptrace / madvise
· 检测 /proc/self/maps 异常访问
· 检测可疑线程扫描自己内存

5.6 Phase 3 验收标准

· FART / frida-dexdump 对核心方法无效（dump 到加密状态）
· 普通方法仍可被 dump（这是设计上的权衡）
· 核心方法执行时间增加不超过 3 倍

---

六、实施路线图

Phase 1：性能重构（2–3 周，收益最确定）

☐ OoooooOooo 格式重构 + 索引表
☐ readCodeItem 惰性化，去掉 65536 数组
☐ RC4 → ChaCha20
☐ 首次启动 InMemoryDexClassLoader（API≥26）
☐ 页粒度 RW 窗口 + 按页自旋锁

验收：大型 App 冷启动降 30%，内存降 40%。

Phase 2：提高离线脱壳成本（3–4 周）

☐ Runtime Key（含明确边界文档）
☐ 数据格式随机化
☐ 虚假 CodeItem 注入
☐ 检测内联 + 参与解密
☐ 白盒密码学（可选进阶）

验收：dpt-unpack 一键脱壳失效。

Phase 3：防运行时 Dump（4–6 周，工程复杂度最高）

☐ 核心方法 ArtMethod 入口点接管
☐ 原子引用计数 + 执行后擦除
☐ 多点 Hook
☐ SO 自校验
☐ 内存扫描检测

验收：FART / frida-dexdump 对核心方法无效。

明确不做的事

· ❌ VMP（工程量太大，性能代价太高）
· ❌ 承诺完全防止离线脱壳（做不到）
· ❌ 依赖设备指纹作为密钥（不可靠）
· ❌ XOR 作为加密方案
· ❌ Hook 底层解释器（ExecuteMterpImpl 已死）

---

七、关键代码改动清单

文件 改动
MultiDexCode.cpp 删 nextCodeItem，加 getCodeItemByClass
dpt.cpp init_app 惰性化；read_shell_config 加 sessionKey
dpt_hook.cpp patchMethod 用 sessionKey；页粒度 mprotect；多点 Hook
dpt_risk.cpp 检测返回值参与密钥派生
CryptoUtils.java deriveConfigAesKey → deriveMasterKey + deriveSessionKey
DexUtils.java extractMethod 用 sessionKey；ChaCha20
MultiDexCodeUtils.java 写 OoooooOooo 时格式随机化、注入假数据
AndroidPackage.java 首次启动 InMemoryDexClassLoader；页粒度 mprotect

---

八、风险与权衡

改造 风险 兼容性
惰性解析 索引格式设计复杂 需充分测试
ChaCha20 替换 RC4 需同步改两端 低风险
Runtime Key 不解决离线脱壳，只是提高成本 需文档说明
格式随机化 每次构建不同，调试困难 需保留调试模式
执行后擦除 ART 路径复杂，异常处理难 高风险，需多版本适配
多点 Hook 某些 ROM 兼容性差 需多版本适配

---

九、最终架构图

```
dpt-shell 2.x（不含 VMP）
     │
     ├── Phase 1：性能重构
     │   ├── CodeItem 惰性解析 + 紧凑索引
     │   ├── ChaCha20（替代 RC4）
     │   ├── InMemoryDexClassLoader（API≥26）
     │   └── 页粒度 mprotect + 按页自旋锁
     │
     ├── Phase 2：对抗 dpt-unpack
     │   ├── Runtime Key（把攻击逼到运行时）
     │   ├── 格式随机化 + Junk Bytes
     │   ├── 虚假 CodeItem（低优先级）
     │   └── 检测内联 + 参与解密
     │
     └── Phase 3：防运行时 Dump
         ├── ArtMethod 入口点接管（非解释器 Hook）
         ├── 原子引用计数 + 执行后擦除
         ├── 多点 Hook
         └── SO 自校验 + 内存扫描检测
```

---

十、最小可行改造（投入产出比最高）

如果时间有限，按以下顺序做：

1. CodeItem 惰性解析 + 紧凑索引（性能，收益确定）
2. RC4 → ChaCha20（性能 + 密码学正确）
3. 页粒度 RW 窗口 + 按页自旋锁（明确区分 RW 与明文生命周期）
4. Runtime Key + 格式随机化（提高离线脱壳成本）
5. 检测内联 + 结果参与解密（抗 patch）
6. 核心方法执行后擦除（防运行时 dump）

做完这 6 项，dpt-unpack 一键脱壳失效，性能提升 30%+，内存降 40%+，核心方法防运行时 dump。

VMP 不做，留作未来可选方向。

---

总结

这份方案基于实际源码逐项核对，修正了上一版的几处错误：

1. Runtime Key 的时间悖论：不承诺解决离线脱壳，只把攻击逼到运行时
2. mprotect 不改变明文生命周期：只缩短 RW 窗口，擦除才能缩短明文窗口
3. ExecuteMterpImpl 已死：改用 ArtMethod 入口点接管
4. 不硬编码 entry point 偏移：ART 是 Mainline 模块，布局可能因设备而异

你明确说"先不搞方案四"，所以本方案不含 VMP。

如果你要实际动手，建议从 Phase 1 的 3.1 + 3.2 + 3.3 开始，这三项收益最确定、风险最低。做完之后再上 Phase 2。你想先从哪一项细化？