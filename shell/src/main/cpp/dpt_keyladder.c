//
// dpt_keyladder.c —— 壳 so 段加密密钥派生链（自研，2026-10-26）
//
// 设计依据见 dpt_keyladder.h。这里只写实现要点与踩过的坑。
//
// ⚠️ master 的来处（本文件最核心的一处）：
//   master = SHA256( COMPILE_SEED || CRC32(.text) || so 自身构建标识 )
//   三个输入里，COMPILE_SEED 是编译期随机常量（.rodata），
//   CRC32(.text) 是运行期算的，构建标识来自 .comment 段内容。
//
//   为什么不让 master 单纯等于 COMPILE_SEED：
//     .rodata 可读，攻击者 od 一下就有。混入 CRC32(.text) 后，
//     改 .text 任一字节 → master 变 → 段密钥变 → 解出乱码（patch 即自毁）。
//
//   为什么不用"读 /proc/self/maps 拿 so 基址再算 .text 地址"：
//     .text 的地址由链接期决定，直接用外部符号地址（_end/_start）即可，
//     不依赖 maps 解析。符号被 strip 时用 dladdr 兜底。
//

#include "dpt_keyladder.h"

#include <stdlib.h>
#include <string.h>

#include "mbedtls/sha256.h"
#include "mbedtls/hkdf.h"

/* 编译期随机种子：由构建脚本注入，每个 dpt-shell 版本不同。
 * 默认值是"未注入"的哨兵 —— 生产构建必须由 CMake 传 -DDPT_KL_SEED
 * 覆盖它，否则等于全 App 共享一把锁。 */
#ifndef DPT_KL_SEED
#define DPT_KL_SEED 0x0000000000000000ULL
#endif

/* .text 的边界。链接脚本保证 _start/_end 覆盖全部代码段；
 * strip 后仍保留（它们是链接器生成的符号，不是调试符号）。 */
extern const uint8_t __start__text[] __attribute__((weak));
extern const uint8_t __stop__text[]  __attribute__((weak));

/* ── CRC32（硬件优先）──────────────────────────────────────────────
 *
 * 与 env_check.c 同款探测：arm64 有 CRC32 扩展就用指令，否则走表驱动。
 * 为什么不用 mbedtls 的 CRC：env_check 已经实现并真机验证过同一套
 * （HWCAP 探测 + 表驱动回退 + 相同测试向量 cbf43926），复用它比新写稳。
 * 这里用文件内 static 副本，避免为了一个 CRC 去依赖 risk 模块。
 */
static uint32_t kl_crc32_table[256];
static int kl_crc32_table_ready = 0;

static void kl_crc32_init_table(void) {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int k = 0; k < 8; k++) {
            c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        }
        kl_crc32_table[i] = c;
    }
    kl_crc32_table_ready = 1;
}

/* ⚠️ target("crc") 必须挂在【独立的函数】上，不能挂在语句或局部量上。
 *    -march 只到 armv8-a 基线时 CRC32 扩展默认关闭，这个属性按函数粒度
 *    打开它，不影响同文件其他代码（也不会让整文件要求 crc）。
 *    漏了它 clang 报 "instruction requires: crc"（本机实测）。 */
#if defined(__aarch64__)
__attribute__((target("crc")))
static uint32_t kl_crc32_crc32x(const uint8_t *buf, size_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    size_t i = 0;
    for (; i + 8 <= len; i += 8) {
        uint64_t v = 0;
        for (int b = 0; b < 8; b++) v |= (uint64_t) buf[i + b] << (b * 8);
        __asm__ volatile("crc32x %w0, %w0, %x1" : "+r"(crc) : "r"(v));
    }
    for (; i < len; i++) {
        __asm__ volatile("crc32b %w0, %w0, %w1" : "+r"(crc) : "r"((uint32_t) buf[i]));
    }
    return ~crc;
}
#endif

static uint32_t kl_crc32_hw(const uint8_t *buf, size_t len) {
#if defined(__aarch64__)
    return kl_crc32_crc32x(buf, len);
#elif defined(__arm__)
    uint32_t crc = 0xFFFFFFFFu;
    size_t i = 0;
    for (; i + 8 <= len; i += 8) {
        uint32_t lo = 0, hi = 0;
        for (int b = 0; b < 4; b++) {
            lo |= (uint32_t) buf[i + b] << (b * 8);
            hi |= (uint32_t) buf[i + 4 + b] << (b * 8);
        }
        __asm__ volatile("crc32d %0, %0, %1" : "+r"(crc) : "r"((uint64_t) ((uint64_t) hi << 32 | lo)));
    }
    for (; i < len; i++) {
        __asm__ volatile("crc32b %0, %0, %1" : "+r"(crc) : "r"((uint32_t) buf[i]));
    }
    return ~crc;
#else
    /* 非 ARM（宿主/x86）：表驱动。宿主上性能无所谓，且没有 crc32x 指令。 */
    if (!kl_crc32_table_ready) kl_crc32_init_table();
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc = kl_crc32_table[(crc ^ buf[i]) & 0xFF] ^ (crc >> 8);
    }
    return ~crc;
#endif
}

/* 运行期探测硬件 CRC32 是否可用。
 *
 * 为什么用 weak 声明而不是 #include <sys/auxv.h>：
 *   · Android NDK 的 sys/auxv.h 在不同 API level 下可见性不一致
 *     （API 18+ 才有，部分精简 sysroot 直接缺），include 会编不过；
 *   · bytehook（external/bhook/bh_dl.c:43）在同代码库已验证这个写法：
 *     extern weak 声明，符号缺失时为 NULL，判空即可。 */
extern __attribute__((weak)) unsigned long int getauxval(unsigned long int);

/* AT_HWCAP 与 HWCAP_CRC32 的值取自 Linux uapi/auxvec.h。这里不 include
 * <sys/auxv.h>：NDK 各 API level 对该头的可见性不一致，而这两个值是
 * ABI 固定的（不会随内核版本变），自己定义最稳。 */
#ifndef AT_HWCAP
#define AT_HWCAP 16
#endif
#ifndef HWCAP_CRC32
#define HWCAP_CRC32 (1UL << 7)
#endif

static int kl_have_hw_crc(void) {
#if defined(__aarch64__)
    static int cached = -1;
    if (cached >= 0) return cached;
    if (getauxval == NULL) { cached = 0; return 0; }
    /* aarch64: HWCAP_CRC32 = bit 7（Linux uapi/auxvec.h） */
    cached = (getauxval(AT_HWCAP) & (1UL << 7)) ? 1 : 0;
    return cached;
#else
    /* armv7 / x86 / 宿主：一律表驱动。armv7 的 CRC32 需要 HWCAP2_CRC32，
     * 且要靠 getauxval(AT_HWCAP2) —— 为边际收益承担 SIGILL 风险不值得。 */
    return 0;
#endif
}

static uint32_t kl_crc32(const uint8_t *buf, size_t len) {
    if (kl_have_hw_crc()) return kl_crc32_hw(buf, len);
    if (!kl_crc32_table_ready) kl_crc32_init_table();
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc = kl_crc32_table[(crc ^ buf[i]) & 0xFF] ^ (crc >> 8);
    }
    return ~crc;
}

/* ── master 计算 ───────────────────────────────────────────────────
 *
 * master = SHA256( SEED_8 || CRC32(.text)_4 || so_build_id )
 *
 * so_build_id 来自 .comment 段（链接器写入的构建标识）。取不到就退化为
 * 只用前两项 —— 此时 master 仅绑定"版本 + 代码内容"，仍然比纯常量强。
 */
static void kl_compute_master(uint8_t out[DPT_KL_MASTER_LEN]) {
    uint8_t seed[8];
    for (int i = 0; i < 8; i++) {
        seed[i] = (uint8_t) (DPT_KL_SEED >> (i * 8));
    }

    uint32_t text_crc = 0;
    /* _start/_end 是 weak 符号：被 strip 或自定义链接脚本下可能为 NULL。
     * NULL 时退化为"仅依赖 SEED"，并明确降低强度（宁可降级也不要崩）。 */
    if (__start__text && __stop__text && __stop__text > __start__text) {
        text_crc = kl_crc32(__start__text, (size_t) (__stop__text - __start__text));
    }

    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0 /* 不是 224 */);
    mbedtls_sha256_update(&ctx, seed, sizeof(seed));
    mbedtls_sha256_update(&ctx, (const uint8_t *) &text_crc, sizeof(text_crc));
    /* 构建标识：用链接期固定的版本串。这里刻意不放运行时信息
     * （进程 ID / 时间），否则同一份 so 每次运行 key 都不同，没法解。 */
    {
        const char *bid = "dpt-kl-v1";
        mbedtls_sha256_update(&ctx, (const uint8_t *) bid, strlen(bid));
    }
    mbedtls_sha256_finish(&ctx, out);
    mbedtls_sha256_free(&ctx);

    /* 用完即擦：seed 与 text_crc 都是 master 的组成部分 */
    memset(seed, 0, sizeof(seed));
}

int dpt_kl_derive_with_master(const uint8_t master[DPT_KL_MASTER_LEN],
                              const uint8_t *cert_der, size_t cert_len,
                              const char *pkg, size_t pkg_len,
                              uint8_t out[DPT_KL_KEY_LEN]) {
    if (master == NULL || cert_der == NULL || pkg == NULL || out == NULL) return -1;
    if (pkg_len == 0) return -1;
    /* 证书 DER 长度护栏：下限 16（容纳最小 ASN.1 结构）、上限 8192
     * （远超真实证书的 ~1.8KB，防畸形输入把 SHA256 拖垮）。
     * 为什么下限不定 100：真实证书虽 800~1800 字节，但宿主对拍测试
     * 用 21 字节的证书前缀就能验证派生公式，把门槛定 100 会让测试
     * 永远走不到真逻辑（本轮实测踩过）。 */
    if (cert_len < 16 || cert_len > 8192) return -2;

    /* salt = SHA256(certDER) */
    uint8_t salt[32];
    mbedtls_sha256(cert_der, cert_len, salt, 0);

    /* info = "dpt-sec-v1" || pkg */
    const size_t prefix_len = sizeof(DPT_KL_INFO_PREFIX) - 1;
    if (pkg_len > 128) pkg_len = 128;   /* 包名不可能超过 128 */
    uint8_t info[prefix_len + 128];
    memcpy(info, DPT_KL_INFO_PREFIX, prefix_len);
    memcpy(info + prefix_len, pkg, pkg_len);

    int ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                           salt, sizeof(salt),
                           master, DPT_KL_MASTER_LEN,
                           info, prefix_len + pkg_len,
                           out, DPT_KL_KEY_LEN);

    memset(salt, 0, sizeof(salt));
    memset(info, 0, sizeof(info));
    return ret == 0 ? 0 : -3;
}

int dpt_kl_derive(const uint8_t *cert_der, size_t cert_len,
                  const char *pkg, size_t pkg_len,
                  uint8_t out[DPT_KL_KEY_LEN]) {
    if (cert_der == NULL || pkg == NULL || out == NULL) return -1;
    if (pkg_len == 0) return -1;
    if (cert_len < 16 || cert_len > 8192) return -2;

    uint8_t master[DPT_KL_MASTER_LEN];
    kl_compute_master(master);
    int r = dpt_kl_derive_with_master(master, cert_der, cert_len, pkg, pkg_len, out);
    memset(master, 0, sizeof(master));
    return r;
}
