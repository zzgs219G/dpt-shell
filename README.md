# dpt-shell

[![](https://img.shields.io/github/license/luoyesiqiu/dpt-shell)](https://github.com/luoyesiqiu/dpt-shell/blob/main/LICENSE) [![](https://img.shields.io/github/downloads/luoyesiqiu/dpt-shell/total?color=blue)](https://github.com/luoyesiqiu/dpt-shell/releases/latest) [![](https://img.shields.io/github/issues-raw/luoyesiqiu/dpt-shell?color=red)](https://github.com/luoyesiqiu/dpt-shell/issues) ![](https://img.shields.io/badge/Android-5.0%2B-brightgreen)

dpt-shell 是一种将 dex 文件中的函数代码抽空，然后在程序运行时将函数代码填回的那么一种壳。

## 用法

### 快速使用

转到 [Releases](https://github.com/luoyesiqiu/dpt-shell/releases/latest) 页面下载 `dpt-shell-<version>.zip`，解压，执行以下命令：

```shell
java -jar dpt.jar -f /path/to/android-package-file
```

### 手动编译

```shell
git clone --recursive https://github.com/luoyesiqiu/dpt-shell
cd dpt-shell
./gradlew build
cd executable
java -jar dpt.jar -f /path/to/android-package-file
```

### 命令行参数

必填参数只有 `-f`，其余均为可选。各参数含义如下（英文原始输出见本节末尾）：

**基本参数**

| 参数 | 说明 |
| --- | --- |
| `-f, --package-file <文件>` | **必填**。要加壳的安装包路径，支持 `.apk`、`.aab` |
| `-o, --output <路径>` | 输出位置。给目录则输出到该目录（默认为当前目录）；若以 `.apk`/`.aab` 结尾则视为输出文件路径，如 `-o dist/app.apk` |
| `-x, --no-sign` | 不对输出包签名（默认会用内置 keystore 签名） |
| `-v, --version` | 显示版本号 |

**保护配置**

| 参数 | 说明 |
| --- | --- |
| `-c, --protect-config <文件>` | 指定保护配置 JSON，可自定义壳类包名（`shellPkgName`）、签名 keystore（`signature`）等，模板见 `executable/dpt-protect-config-template.json` |
| `-r, --rules-file <文件>` | 不参与保护的类名规则文件：每行一条正则，匹配完整类名（形如 `Lcom/example/Foo;`）。注意：会**整体替换**内置默认规则，模板见 `executable/dpt-exclude-classes-template.rules` |
| `-K, --keep-classes` | 把部分类保留在包内不抽取代码，可一定程度提升启动速度，但并非所有应用都适用 |
| `-S, --smaller` | 用部分运行时性能换取更小的包体积 |
| `-e, --exclude-abi <ABI 列表>` | 打包时排除指定 ABI 的 so，逗号分隔。可选值：`arm`、`arm64`、`x86`、`x86_64`（分别对应 armeabi-v7a、arm64-v8a、x86、x86_64），如 `-e x86,x86_64` |

**运行时行为**（写入壳配置，在被保护应用运行时生效）

| 参数 | 说明 |
| --- | --- |
| `-vs, --verify-sign` | 启用运行时签名校验：打包时自动从签名 keystore 计算证书 SHA-256，应用启动时校验自身签名，防止二次打包 |
| `--disable-anti-debug` | 关闭运行时反调试检测 |
| `--disable-crc-detect` | 关闭运行时 libc .text CRC 完整性检测 |
| `--disable-frida-detect` | 关闭运行时 Frida 注入检测 |
| `--disable-inmemory-dex` | 不使用 `InMemoryDexClassLoader` 内存加载，改为把加密 dex 写入 `code_cache` 后从文件加载（兼容性回退开关） |

**调试与诊断**

| 参数 | 说明 |
| --- | --- |
| `--debug` | 给输出包设置 `android:debuggable=true` |
| `--disable-acf` | 不替换应用的 AppComponentFactory（仅调试用） |
| `--dump-code` | 把 DEX 的 code item 导出为 `.json` 文件，便于分析 |
| `--noisy-log` | 打开打包工具的详细日志 |

#### 原始 usage 输出

以下为 `java -jar dpt.jar` 的原始英文输出：

```text
usage: java -jar dpt.jar [option] -f <package_file>
 -c,--protect-config <arg>   Protect config file.
                             
    --debug                  Make package debuggable.
    --disable-acf            Disable app component factory(just use for
                             debug).
    --disable-anti-debug     Disable runtime anti-debug.
                             
    --disable-crc-detect     Disable runtime libc .text CRC detection.
                             
    --disable-frida-detect   Disable runtime Frida detection.
                             
    --disable-inmemory-dex   Load the protected dex from code_cache
                             instead of InMemoryDexClassLoader.
    --dump-code              Dump the code item of DEX and save it to
                             .json files.
 -e,--exclude-abi <arg>      Exclude specific ABIs (comma separated, e.g.
                             x86,x86_64).
                             Supported ABIs:
                             - arm       (armeabi-v7a)
                             - arm64     (arm64-v8a)
                             - x86
                             - x86_64
 -f,--package-file <arg>     Need to protect android package(*.apk, *.aab)
                             file.
 -K,--keep-classes           Keeping some classes in the package can
                             improve the app's startup speed to a certain
                             extent, but it is not supported by some
                             application packages.
    --noisy-log              Open noisy log.
 -o,--output <arg>           Output directory for protected package.
 -r,--rules-file <arg>       Rules file for class names that will not be
                             protected.
 -S,--smaller                Trade some of the app's performance for a
                             smaller app size.
 -v,--version                Show program's version number.
 -vs,--verify-sign           Enable runtime app signature verification.
                             The certificate SHA-256 is computed
                             automatically from the signing keystore.
 -x,--no-sign                Do not sign package.
```

## 原理解析

[How it works](doc/HowItWorks.zh-CN.md)

## 声明

本项目未经大量测试，仅用于学习交流，不要线上使用，否则自行承担后果。

## 使用或依赖以下项目

- [dx](https://android.googlesource.com/platform/dalvik/+/refs/heads/master/dx/)
- [Dobby](https://github.com/jmpews/Dobby)
- ~~[libzip-android](https://github.com/julienr/libzip-android)~~
- [ManifestEditor](https://github.com/WindySha/ManifestEditor)
- ~~[Xpatch](https://github.com/WindySha/Xpatch)~~
- [bhook](https://github.com/bytedance/bhook)
- [zipalign-java](https://github.com/Iyxan23/zipalign-java)
- [minizip-ng](https://github.com/zlib-ng/minizip-ng)
- [JSON-java](https://github.com/stleary/JSON-java)
- [zip4j](https://github.com/srikanth-lingala/zip4j)
- [commons-cli](https://github.com/apache/commons-cli)
- [dexmaker](https://android.googlesource.com/platform/external/dexmaker)
- [Obfuscate](https://github.com/adamyaxley/Obfuscate)