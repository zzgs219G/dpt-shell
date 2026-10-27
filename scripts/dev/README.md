# 开发与测试脚本

本目录放**所有非生产用途的脚本**：真机验证、性能基准。
生产流水线的脚本不在这里（在 `apk-protect-action` 仓库）。

| 脚本 | 用途 | 需要什么 | 详见 |
|---|---|---|---|
| `verify-on-device.sh` | **功能冒烟**：装机→启动→按判据输出 PASS/FAIL，指出崩在哪层 | adb + 一台设备 | [§1](#1-verify-on-devicesh功能冒烟) |
| `bench-pack.sh` | **打包耗时**基准 | 一个 APK + 完整 `executable/` | [§2](#2-bench-packsh打包耗时) |
| `bench-runtime.sh` | **启动耗时 / 内存 / 是否落盘**基准 | adb + 一台设备 | [§3](#3-bench-runtime-sh运行时指标) |

三个脚本都不依赖额外工具链（不需要 bc / hyperfine / perf）。

---

## 1. verify-on-device.sh（功能冒烟）

一条命令替代"装机 → 截图 → 逐条翻 logcat"。

```bash
adb connect 192.168.1.5:39963
scripts/dev/verify-on-device.sh /path/to/app_signed.apk --device 192.168.1.5:39963
```

输出：

```
▶ 设备: 2602BRT18C / Android 16 / arm64-v8a
── 判据 ──
  ✅ 派生链：[kl] ... cert_len=666 crc_rc=0 text_crc=0x5ee57564 derive_rc=0
  ✅ 配置链：无错误
  ✅ 载荷链：无 inflate 失败
  ✅ JNI 注册：正常
  ✅ 进程存活：pid=31706
✅ PASS
```

### 参数

| 参数 | 说明 |
|---|---|
| `<apk>` | 必填，已签名 APK |
| `--device <host:port>` | Wi-Fi ADB 地址；不传则用当前唯一设备 |
| `--pkg <包名>` | 默认 `com.xixin.box` |
| `--activity <.MainActivity>` | 默认 `.MainActivity` |
| `--wait <秒>` | 等进程出现的上限，默认 12 |
| `--expect-dpt-only` | 额外校验壳 dex 无 stringenc 痕迹 |

### 退出码

| 码 | 含义 |
|---|---|
| 0 | PASS |
| 1 | FAIL（崩溃 / 某条链失败） |
| 2 | 参数或环境错误 |

### 判据来源

来自 [docs/基线-v1.3.2-真机验证.md](../../docs/基线-v1.3.2-真机验证.md) §3：

| 判据 | 对应历史事故 |
|---|---|
| `[kl] ... derive_rc=0` | v1.2.3~v1.2.6 全崩在这条 |
| 无 `config:` 错误 | v1.2.8 `java_class == null` |
| 无 `materializeBlock` 失败 | v1.3.1 inflate failed |
| 无 `java_class == null` | v1.2.8 |
| 进程存活 | 最终判据 |

**为什么用"进程存活"而不只看 FATAL**：有些崩溃（`abort()` 前的
`JNI DETECTED ERROR`）不打 `FATAL EXCEPTION`，只看 FATAL 会漏判。

### 该测哪个模块组合

**两个都要测**，任一失败都算失败：

| 组合 | 目的 |
|---|---|
| **只勾 packer（dpt）** | 验证 dpt 自身三条链。**定位最快**——挂了就是 dpt 的问题，与联动无关 |
| **全模块**（sigcheck+dex2c+stringenc+dex2c_stub+envcheck+packer） | 验证联合链路：桩进壳 dex、`gseed`、dex2c 产物与壳协同 |

历史经验：v1.2.6 ~ v1.3.1 的所有缺陷**只勾 dpt 就能复现**。

### 关于 CI 自动化

**不要用公网隧道暴露 ADB**（cloudflared/ngrok）：ADB 无认证机制，
暴露 = 交出真机完全控制权。

若将来要做，正确方式是**自托管 runner**：家里一台常开机器注册为
GitHub Actions self-hosted runner，手机与它同局域网直连，零公网暴露。
（前提：需要一台常开的电脑。）

**Tailscale** 是可接受的替代（WireGuard 私有 mesh，非公网入口），
但需配套 ACL 只放行 CI 节点到设备 5555 端口，且用 ephemeral authkey。

---

## 2. bench-pack.sh（打包耗时）

```bash
scripts/dev/bench-pack.sh <apk> [runs] [dpt.jar]
```

例：

```bash
scripts/dev/bench-pack.sh app.apk
scripts/dev/bench-pack.sh app.apk 7
scripts/dev/bench-pack.sh app.apk 5 executable/dpt.jar
```

`dpt.jar` 默认取 `executable/dpt.jar`，需**完整** `executable/`
（含 `shell-files/`，用 `./gradlew build` 生成）。

输出中位数 + 波动。首次运行含 JVM 解释执行 + JIT，明显偏慢，
默认丢弃第 1 次（`BENCH_WARMUP=0` 可关闭）。

**波动警告**：`max - min > 中位数 × 15%` 时打印警告。此时数字不可信，
先排除环境干扰（充电、后台应用、其他构建任务）。

---

## 3. bench-runtime.sh（运行时指标）

```bash
scripts/dev/bench-runtime.sh <package.name> [activity]
```

例：

```bash
scripts/dev/bench-runtime.sh com.example.app
scripts/dev/bench-runtime.sh com.example.app com.example.app/.MainActivity
```

采集四项：

1. **code_cache** —— 首次安装后是否有 `xixin_dexes.zip`（判断落盘还是内存加载）
2. **冷启动** —— 每次 `am force-stop` 后再启动，取 `TotalTime` 中位数
3. **热启动** —— 不 force-stop
4. **内存** —— `dumpsys meminfo` 的 TOTAL PSS

无 adb 或无设备时打印 `skip` 并以 **0 退出**，不阻塞流水线。
`BENCH_RUNS=20` 可增加冷启动采样次数（默认 10）。

### 为什么冷热启动必须分开

**解密只在类加载时发生。** 热启动 App 已驻留内存，根本不走解密路径——
测热启动等于什么都没测。冷启动才是解密成本的体现。

---

## 4. 测量纪律（比脚本本身更重要）

1. **基线要先拿到。** 一旦开始改代码，基线就永久失去了。
   第一件事是测当前 `main` 并填进 [docs/性能基准.md](../../docs/性能基准.md)。

2. **锁定变量。** 同一台设备、同一份 APK（记 hash）、同一 ROM。
   **系统升级后测得的数字不可与之前比较。**

3. **跨机器数字没有意义。** 只能同机前后对比。

4. **未实测的格子留 `?`，禁止填估算值。**（AGENTS.md §6）

---

## 5. 常见问题

**Q：打包耗时每次差很多怎么办？**
先看脚本的"波动"行。波动大说明环境不稳，不是 dpt 的问题。
关掉后台应用、插电、隔几秒再跑。

**Q：`归一化` 那一行怎么算的？**
`中位数毫秒 ÷ 方法数 × 1000`，即每千方法的毫秒数。

**Q：能不能只测一个方法运行得更快？**
本套工具**不测单个方法的执行速度**。指令解密只发生在类加载时，
不是每次方法调用都解密。
