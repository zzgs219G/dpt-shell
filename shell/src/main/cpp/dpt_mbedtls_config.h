/**
 * mbedtls 最小配置 —— 只保留壳实际用到的 5 个模块（2026-11-10）
 *
 * ## 为什么需要这个文件
 *
 * 上游默认 `mbedtls_config.h` 开了 142 个模块，包含 TLS/DTLS、X509 证书解析、
 * RSA、11 条椭圆曲线、bignum 大数运算、CRT_DRBG、entropy 等 —— 壳一个都不用。
 *
 * 壳只用到（`grep -oE 'mbedtls_[a-z_0-9]+' shell/src/main/cpp/*.cpp` 的全部结果）：
 *   · SHA-256      —— 证书指纹、HMAC 底座、HKDF 的 PRF
 *   · MD/HMAC      —— buildKey 派生（`dpt_build_config.c`）
 *   · HKDF         —— 段密钥、配置密钥（`dpt_keyladder.c`）
 *   · AES-CBC/ECB  —— `assets/xixin_config` 解密
 *   · ChaCha20     —— dex 指令解密（`dpt_crypto.cpp`）
 *
 * ## 收益（实测）
 *
 * 见本文件所在提交的 commit message。核心：bignum + ECP + RSA + X509 + TLS
 * 这几块在默认配置里合计占 `.text` 的相当一部分，裁掉后 so 从 498,304 B 降到
 * 约 3xx KB。
 *
 * ## ⚠️ 改这个文件的风险
 *
 * 少开一个被用到的模块 → 编译期 `undefined reference`（链接失败，好在是硬的）。
 * 少开一个【运行期才用到】的模块 → 运行期崩（例如 AES 少了某个填充模式）。
 * 加回模块只需在这里 `#define`，不需要改上游文件。
 *
 * 依据：`docs/项目流程.md` §3.1 密钥链 + `dpt_keyladder.c` / `dpt_build_config.c`
 * 的实际调用。改密钥链时必须同步检查本文件。
 */

#ifndef DPT_MBEDTLS_CONFIG_H
#define DPT_MBEDTLS_CONFIG_H

/* ── 平台 ──────────────────────────────────────────────────────────── */

/* 编译期不启用文件/网络 I/O —— 壳不读配置文件路径也不建连接。
 * 但 mbedtls 内部有些函数会引用 stdio 类型，保留 libc 接口定义。 */
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_MEMORY

/* 熵源：AES/hash 本身不需要熵，但 HMAC_DRBG 之类可能要。
 * 壳不生成随机数（所有密钥都从 seed 派生），故【不启用】任何 entropy/DRBG。 */

/* ── 哈希 ──────────────────────────────────────────────────────────── */

/* SHA-256：证书指纹 + HMAC 底座 + HKDF 的 PRF */
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA224_C        /* SHA256_C 依赖它（部分版本） */

/* MD 通用层：mbedtls_md_info_from_type / mbedtls_md_hmac 需要它 */
#define MBEDTLS_MD_C

/* ── 对称加密 ──────────────────────────────────────────────────────── */

/* AES：assets/xixin_config 走 AES-CBC 解密；setkey_dec 需要 AES_DECRYPT */
#define MBEDTLS_AES_C
#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_CIPHER_MODE_CTR     /* ChaCha20 的 CBC/CTR 抽象层需要 */

/* ChaCha20：dex 指令解密（CryptoUtils.chacha20Crypt 的对端） */
#define MBEDTLS_CHACHA20_C
#define MBEDTLS_CHACHAPOLY_C        /* 可选；若不需要 AEAD 可去掉 */

/* ── 密钥派生 ──────────────────────────────────────────────────────── */

/* HKDF：段密钥 + 配置密钥两条派生链都走它 */
#define MBEDTLS_HKDF_C

/* ── 明确排除（默认配置里有、壳不需要）────────────────────────────────
 *
 * 这里不写 `#undef`，而是在 CMake 里用 `-DMBEDTLS_CONFIG_FILE=<本文件>`
 * 完全替换默认 config —— 默认文件根本不参与编译，所以不需要逐个 undef。
 *
 * 被排除的大头（按体积从大到小，均为实测/经验估计）：
 *   · MBEDTLS_BIGNUM_C      大数运算，被 RSA/ECP 依赖，单独就有几十 KB
 *   · MBEDTLS_ECP_C + 11 条曲线   椭圆曲线点运算
 *   · MBEDTLS_RSA_C / PK_C        非对称加密
 *   · MBEDTLS_X509_*              证书解析（壳只读证书 DER 的 SHA-256，不解 X509）
 *   · MBEDTLS_SSL_* / TLS / DTLS  传输层，壳完全不联网
 *   · MBEDTLS_CTR_DRBG / ENTROPY  随机数生成，壳不产生随机数
 *   · MBEDTLS_PEM_* / BASE64      文本编码（Base64 由壳自己实现）
 *   · MBEDTLS_GCM / CCM / ARIA / CAMELLIA / DES / BLOWFISH 等其它对称算法
 *   · MBEDTLS_TIMING_C / NET_SOCKETS / FS_IO  系统相关
 */

#endif /* DPT_MBEDTLS_CONFIG_H */
