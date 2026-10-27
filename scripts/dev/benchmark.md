# 性能基准工具

> **低频工具**：只在做性能优化时才需要。日常改代码/验证用
> [README.md](./README.md) 里的真机冒烟脚本。

两个脚本，对应两类指标。**都不依赖额外工具链**（不需要 bc / hyperfine / perf）。

| 脚本 | 测什么 | 需要什么 |
|---|---|---|
| `bench-pack.sh` | 打包耗时 | 一个加壳后的 APK + 完整 `executable/` |
| `bench-runtime.sh` | 启动耗时 / 内存 / 是否落盘 | 一台安卓设备 + adb |

历史实测数据见 [docs/性能基准.md](../../docs/性能基准.md)
（Phase 1，v1.0.0~v1.1.0，**不代表当前版本**）。

---

## bench-pack.sh

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

输出中位数 + 波动。首次运行含 JVM 解释执行 + JIT 编译，明显偏慢，
默认丢弃第 1 次（`BENCH_WARMUP=0` 可关闭）。

### 波动警告

脚本在 `max - min > 中位数 × 15%` 时打印警告。此时数字不可信，
应先排除环境干扰（充电、后台应用、其他构建任务）。

---

## bench-runtime.sh

```bash
scripts/dev/bench-runtime.sh <package.name> [activity]
```

例：

```bash
scripts/dev/bench-runtime.sh com.example.app
scripts/dev/bench-runtime.sh com.example.app com.example.app/.MainActivity
```

采集四项：

1. **code_cache** —— 首次安装后是否有 `xixin_dexes.zip`（判断走落盘还是内存加载）
2. **冷启动** —— 每次 `am force-stop` 后再启动，取 `TotalTime` 中位数
3. **热启动** —— 不 force-stop
4. **内存** —— `dumpsys meminfo` 的 TOTAL PSS

无 adb 或无设备时打印 `skip` 并以 **0 退出**，不阻塞流水线。

`BENCH_RUNS=20` 可增加冷启动采样次数（默认 10）。

### 为什么冷热启动必须分开

**解密只在类加载时发生。** 热启动 App 已驻留内存，根本不走解密路径——
测热启动等于什么都没测。冷启动才是解密成本的体现。

---

## 测量纪律

这四条比脚本本身更重要：

1. **基线要先拿到。** 一旦开始改代码，基线就永久失去了。
   第一件事是测当前 `main` 并填进 [docs/性能基准.md](../../docs/性能基准.md)。

2. **锁定变量。** 同一台设备、同一份 APK（记 hash）、同一 ROM。
   **系统升级后测得的数字不可与之前比较。**

3. **跨机器数字没有意义。** 只能同机前后对比。

4. **未实测的格子留 `?`，禁止填估算值。**（AGENTS.md §6）

---

## 常见问题

**Q：打包耗时每次差很多怎么办？**
先看脚本的"波动"行。波动大说明环境不稳，不是 dpt 的问题。
关掉后台应用、插电、隔几秒再跑。

**Q：`归一化` 那一行怎么算的？**
`中位数毫秒 ÷ 方法数 × 1000`，即每千方法的毫秒数。

**Q：能不能只测一个方法运行得更快？**
本套工具**不测单个方法的执行速度**。指令解密只发生在类加载时，
不是每次方法调用都解密。
