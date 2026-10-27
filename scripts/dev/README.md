# 真机冒烟验证

一条命令替代"装机 → 截图 → 逐条翻 logcat"，并**直接告诉你崩在哪一层**。

本目录三个脚本：

| 脚本 | 用途 | 频率 |
|---|---|---|
| `identify-combo.sh` | 判断产物来自哪个模块组合 | 拿到 APK 就先用 |
| `verify-on-device.sh` | 真机功能冒烟，指出崩在哪层 | 每次改完都跑 |
| `bench-*.sh` | 性能基准 | 只做优化时用（见 [benchmark.md](./benchmark.md)） |

---

## 0. identify-combo.sh（先判断组合）

```bash
scripts/dev/identify-combo.sh <apk>
```

**为什么第一步要做这个**：两个模块组合的故障定位路径完全不同——
只勾 packer 崩了第一嫌疑是 dpt 自身三条链；全模块崩了要怀疑联动
（桩进壳 dex、`gseed`、dex2c）。但两者在 dpt 侧的症状**都是
`SIGABRT` + 一句 dpt 日志**，分不清就会查错方向。

输出示例（全模块）：

```
✅ dpt 已加壳：assets/xixin/*/libxixin.so × 2
libnc.so   : 存在 × 2（含 sigcheck/dex2c/envcheck）
stringenc  : 有解密桩
→ 判定：全模块（含 stringenc↔dex2c 联动）
```

判据：

| 判据 | 只勾 packer | 全模块 |
|---|---|---|
| `lib/*/libnc.so` | ❌ | ✅ |
| 壳 dex 含 `GAMMA`/`keyByte`/`mix64` | ❌ | ✅ |

⚠️ **不能靠类名**：桩类名每包随机，实测全模块产物 `grep -c strdec` = 0。
必须用桩骨架的结构不变量（那三个名字不参与随机化）。

---

## 1. verify-on-device.sh（功能冒烟）

## 用法

```bash
adb connect 192.168.1.5:39963
scripts/dev/verify-on-device.sh /path/to/app_signed.apk --device 192.168.1.5:39963
```

输出：

```
▶ 设备: 2602BRT18C / Android 16 / arm64-v8a
▶ 安装 简盒_signed_17_41_58_sign.apk
▶ 启动 com.xixin.box/.MainActivity

── 判据 ──
  ✅ 派生链：[kl] ... cert_len=666 crc_rc=0 text_crc=0x5ee57564 derive_rc=0
  ✅ 配置链：无错误
  ✅ 载荷链：无 inflate 失败
  ✅ JNI 注册：正常
  ✅ 进程存活：pid=31706

✅ PASS —— 三条链全部正常，进程存活
```

失败时：

```
  ❌ 载荷链失败：materializeBlock() block 12 inflate failed: comp=56269 raw=94408
  ❌ 进程已退出（崩溃）
❌ FAIL —— 详见上方判据
```

## 参数

| 参数 | 说明 |
|---|---|
| `<apk>` | 必填，已签名 APK |
| `--device <host:port>` | Wi-Fi ADB 地址；不传则用当前唯一 adb 设备 |
| `--pkg <包名>` | 默认 `com.xixin.box` |
| `--activity <.MainActivity>` | 默认 `.MainActivity` |
| `--wait <秒>` | 等进程出现的上限，默认 12 |
| `--expect-dpt-only` | 额外校验壳 dex 里没有 stringenc 痕迹 |

## 退出码

| 码 | 含义 |
|---|---|
| 0 | PASS |
| 1 | FAIL（崩溃 / 某条链失败） |
| 2 | 参数或环境错误（adb 缺失、设备未连、APK 不存在） |

## 判据来源

来自 [docs/基线-v1.3.2-真机验证.md](../../docs/基线-v1.3.2-真机验证.md) §3：

| 判据 | 含义 | 对应历史事故 |
|---|---|---|
| `[kl] ... derive_rc=0` | 派生链成功 | v1.2.3~v1.2.6 全崩在这条 |
| 无 `config:` 错误 | 配置链成功 | v1.2.8 `java_class == null` |
| 无 `materializeBlock` 失败 | 载荷链成功 | v1.3.1 inflate failed |
| 无 `java_class == null` | JNI 注册成功 | v1.2.8 |
| 进程存活 | 最终判据 | 全部 |

**为什么用"进程是否存活"而不只看 FATAL**：有些崩溃（`abort()` 之前的
`JNI DETECTED ERROR`）不打 `FATAL EXCEPTION`，只看 FATAL 会漏判。

## 该测哪个模块组合

**两个都要测**，任一失败都算失败：

| 组合 | 目的 |
|---|---|
| **只勾 packer（dpt）** | 验证 dpt 自身三条链。**定位最快**——挂了就是 dpt 自己的问题，与联动无关 |
| **全模块**（sigcheck + dex2c + stringenc + dex2c_stub + envcheck + packer） | 验证联合链路：桩进壳 dex、`gseed`、dex2c 产物与壳协同 |

历史经验：v1.2.6 ~ v1.3.1 的所有缺陷**只勾 dpt 就能复现**。
"单模块也崩"这句话一次就排除了全部联动嫌疑。

## 关于 CI 自动化（暂未做）

要让 GitHub Actions 自动跑，**不要用公网隧道暴露 ADB**
（cloudflared / ngrok）：ADB 根本没有认证机制——不是密码弱，是没有。
暴露到公网 = 交出真机完全控制权。

三条路，按推荐度：

| 方案 | 前提 | 说明 |
|---|---|---|
| **手动跑本脚本** | 无 | 已是投入产出比最高的形态。打包本来就手动，省掉装机+看日志已足够 |
| **自托管 runner** | 一台常开电脑 | 同局域网直连，零公网暴露，免费。**没有电脑则不可行** |
| **Tailscale** | 账号 | WireGuard 私有 mesh（`100.x.x.x`），不是公网入口。需 ACL 只放行 CI→设备 5555，且用 ephemeral authkey |

**不推荐**：Firebase Test Lab / AWS Device Farm —— 需上传私有加壳包到第三方，
且 Robo test 抓不到 `[kl] derive_rc` 这类自定义日志。
