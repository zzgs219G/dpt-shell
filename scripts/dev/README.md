# 真机冒烟验证

一条命令替代"装机 → 截图 → 逐条翻 logcat"。

## 为什么需要它

本项目 v1.2.3 ~ v1.3.2 共 9 个版本里，**有 5 个是我自己引入或漏改的缺陷**，
且每个都要经过"改代码 → CI → 打 tag → 人工打包 → 人工装机 → 人工截图"
才能发现，一轮 20~40 分钟。

这个脚本把最后三步自动化，并**直接告诉你崩在哪一层**。

## 用法

```bash
# 1. 设备先连上（Wi-Fi ADB 或 USB）
adb connect 192.168.1.5:39963
adb devices          # 确认状态是 device

# 2. 跑验证
scripts/dev/verify-on-device.sh /path/to/app_signed.apk \
    --device 192.168.1.5:39963 \
    --pkg com.xixin.box
```

输出示例（通过）：

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

失败时（示例）：

```
  ❌ 载荷链失败：materializeBlock() block 12 inflate failed: comp=56269 raw=94408
  ❌ 进程已退出（崩溃）
❌ FAIL —— 详见上方判据
```

## 参数

| 参数 | 说明 |
|---|---|
| `<apk>` | 必填，待验证的 APK（已签名版） |
| `--device <host:port>` | Wi-Fi ADB 地址；不传则用当前唯一的 adb 设备 |
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

可直接用于 CI：`verify-on-device.sh ... || exit 1`

## 判据来源

来自 [docs/基线-v1.3.2-真机验证.md](../../docs/基线-v1.3.2-真机验证.md) §3：

| 判据 | 含义 | 对应历史事故 |
|---|---|---|
| `[kl] ... derive_rc=0` | 派生链成功 | v1.2.3~v1.2.6 全崩在这条 |
| 无 `config:` 错误 | 配置链成功 | v1.2.8 `java_class == null` |
| 无 `materializeBlock` 失败 | 载荷链成功 | v1.3.1 inflate failed |
| 无 `java_class == null` | JNI 注册成功 | v1.2.8 |
| 进程存活 | 最终判据 | 全部 |

**为什么用"进程是否存活"而不只看 FATAL**：有些崩溃（如 `abort()` 前的
`JNI DETECTED ERROR`）不打 `FATAL EXCEPTION`，只看 FATAL 会漏判。

## 该测哪个模块组合

**两个都要测**，任一失败都算失败：

| 组合 | 目的 |
|---|---|
| **只勾 packer（dpt）** | 验证 dpt 自身三条链。**定位最快**——挂了就是 dpt 自己的问题，与联动无关 |
| **全模块**（sigcheck + dex2c + stringenc + dex2c_stub + envcheck + packer） | 验证联合链路：桩进壳 dex、`gseed`、dex2c 产物与壳协同 |

历史经验：v1.2.6 ~ v1.3.1 的所有缺陷**只勾 dpt 就能复现**，
"单模块也崩"这句话一次就排除了全部联动嫌疑。

## 关于"自动化到 CI"（暂未做）

要让 GitHub Actions 自动跑，**不要用公网隧道暴露 ADB**（等于把真机
完全控制权交出去）。正确做法是**自托管 runner**：

1. 家里一台机器常开，注册为 GitHub Actions self-hosted runner
2. 手机与它同局域网，`adb connect 192.168.x.x:5555`
3. workflow 里 `runs-on: [self-hosted]`，直接跑本脚本

这样无需任何公网暴露，且免费。

判断是否值得做：如果本项目还要迭代 10 个版本以上，值得；
否则手动跑这一条命令已足够。
