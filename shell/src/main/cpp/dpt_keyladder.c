//
// dpt_keyladder.c —— 壳 so 段加密密钥派生链（自研，2026-10-26）
//
// 设计依据见 dpt_keyladder.h。这里只写实现要点与踩过的坑。
//
// ⚠️ master 的来处（本文件最核心的一处）：
//   master = SHA256( COMPILE_SEED || CRC32(.text) || "dpt-kl-v1" )
//   · COMPILE_SEED：编译期由 Gradle/CMake 注入，一次构建一把；
//   · CRC32(.text)：运行期解析自身 so 的 ELF 段表，读文件里的 .text 字节；
//   · "dpt-kl-v1"：版本串。
//
//   为什么不让 master 单纯等于 COMPILE_SEED：
//     .rodata 可读，攻击者 od 一下就有。混入 CRC32(.text) 后，
//     改 .text 任一字节 → master 变 → 段密钥变 → 解出乱码（patch 即自毁）。
//
//   为什么不读 /proc/self/maps 后按内存页算 CRC：
//     打包侧加密的是文件里的 .text 字节，两侧必须以【同一份文件字节】算，
//     否则 mprotect/重定位后的内存页可能与文件字节不一致。
//

#include "dpt_keyladder.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "mbedtls/sha256.h"
#include "mbedtls/hkdf.h"
#include "dpt_cert.h"

/* 编译期随机种子：由构建脚本注入，每个 dpt-shell 版本不同。
 * 默认值是"未注入"的哨兵 —— 生产构建必须由 CMake 传 -DDPT_KL_SEED
 * 覆盖它，否则等于全 App 共享一把锁。 */
#ifndef DPT_KL_SEED
#define DPT_KL_SEED 0x0000000000000000ULL
#endif

/* .text 的 CRC32 输入。
 *
 * ⚠️ 不要用 __start__text / __stop__text：实测本仓库产物里这两个 weak 符号
 * 不存在（本地 executable 的 arm64 so readelf 无符号），会让 CRC 退化为 0，
 * 而打包侧 Java 读的是真正 .text 段 → 两侧 key 不同 → init_array abort。
 * 所以这里与打包侧同源：直接解析运行期 so 文件的 ELF 段表，读 .text 字节。
 */

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

/* 硬件/表驱动的统一 CRC32。
 *
 * armv7 分支刻意只走表：CI 实测 kl_crc32_hw 的 armv7 内联汇编没挂
 * target("crc") 会直接 "instruction requires: crc" 编译失败；而且运行期
 * kl_have_hw_crc() 在 armv7 恒为 0，这段汇编本来就不会被执行。 */
static uint32_t kl_crc32_hw(const uint8_t *buf, size_t len) {
#if defined(__aarch64__)
    return kl_crc32_crc32x(buf, len);
#else
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

/* ── 从运行期 so 文件解析 .text 段（与打包侧 SoSectionLocker 完全同源）────
 *
 * 为什么不能dladdr后直接取地址：
 *   打包侧加密的是文件里的 .text 字节；运行期要解同一把 key，必须对
 *   【同一份文件字节】算 CRC，而不是对进程映射后的内存页算（mprotect /
 *   重定位后字节可能不同）。
 * 为什么不用 __start__text / __stop__text：
 *   实测产物里这两个 weak 符号不存在（readelf 无符号），C 侧会退化成 crc=0，
 *   与 Java 侧真实 .text CRC 不一致。
 */
typedef struct {
    uint64_t shoff;    /* ELF 头 e_shoff */
    uint16_t shentsize;
    uint16_t shnum;
    uint16_t shstrndx;
} kl_elf_sh_info;

static uint16_t kl_rd16(const uint8_t *p) {
    return (uint16_t) ((uint16_t) p[0] | ((uint16_t) p[1] << 8));
}
static uint32_t kl_rd32(const uint8_t *p) {
    return (uint32_t) ((uint32_t) p[0] | ((uint32_t) p[1] << 8)
                       | ((uint32_t) p[2] << 16) | ((uint32_t) p[3] << 24));
}
static uint64_t kl_rd64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | p[i];
    return v;
}

static int kl_read_elf_header(int fd, kl_elf_sh_info *out) {
    uint8_t eh[64];
    ssize_t n = pread(fd, eh, sizeof(eh), 0);
    if (n != (ssize_t) sizeof(eh)) return -1;
    if (eh[0] != 0x7f || eh[1] != 'E' || eh[2] != 'L' || eh[3] != 'F') return -1;

    /* 只处理本仓库产物：ELFDATA2LSB（小端），ELFCLASS32/64。 */
    if (eh[5] != 1) return -1;
    if (eh[4] != 1 && eh[4] != 2) return -1;
    int is64 = (eh[4] == 2);

    if (is64) {
        if (sizeof(eh) < 0x40) return -1;
        out->shoff = kl_rd64(eh + 0x28);
        out->shentsize = kl_rd16(eh + 0x3A);
        out->shnum = kl_rd16(eh + 0x3C);
        out->shstrndx = kl_rd16(eh + 0x3E);
    } else {
        if (sizeof(eh) < 0x34) return -1;
        out->shoff = kl_rd32(eh + 0x20);
        out->shentsize = kl_rd16(eh + 0x2E);
        out->shnum = kl_rd16(eh + 0x30);
        out->shstrndx = kl_rd16(eh + 0x32);
    }

    if (out->shoff == 0 || out->shnum == 0 || out->shentsize < 40 ||
        out->shstrndx >= out->shnum) {
        return -1;
    }
    return 0;
}

/* 从 ELF 里找 .text 的 [offset, size)。失败返回负，成功返回 0。 */
static int kl_find_text_section(int fd, uint64_t *offset_out, uint64_t *size_out) {
    kl_elf_sh_info sh;
    if (kl_read_elf_header(fd, &sh) != 0) return -1;

    /* .shstrtab 自身也是段表项。取它的文件 offset（不是 sh_addr，可能为 0）。 */
    uint8_t strtab_hdr[64];
    if (sh.shentsize > sizeof(strtab_hdr)) return -1;
    off_t strtab_hdr_off = (off_t) (sh.shoff + (uint64_t) sh.shstrndx * sh.shentsize);
    if (pread(fd, strtab_hdr, sh.shentsize, strtab_hdr_off) != (ssize_t) sh.shentsize) return -1;

    int is64 = 1; /* header 里再来一次，避免把 eh 传得到处都是 */
    {
        uint8_t eh[64];
        if (pread(fd, eh, sizeof(eh), 0) != (ssize_t) sizeof(eh)) return -1;
        is64 = (eh[4] == 2);
    }

    uint64_t strtab_off;
    uint64_t strtab_size;
    if (is64) {
        strtab_off = kl_rd64(strtab_hdr + 0x18);
        strtab_size = kl_rd64(strtab_hdr + 0x20);
    } else {
        strtab_off = kl_rd32(strtab_hdr + 0x10);
        strtab_size = kl_rd32(strtab_hdr + 0x14);
    }
    if (strtab_off == 0 || strtab_size == 0 || strtab_size > (1u << 20)) return -1;

    char *names = (char *) malloc(strtab_size + 1);
    if (names == NULL) return -1;
    names[strtab_size] = 0;

    uint8_t shdr[64];
    if (sh.shentsize > sizeof(shdr)) {
        free(names);
        return -1;
    }

    /* 段名表必须先完整读进来，否则 for 第一次 strcmp 读的是空 names。 */
    if (pread(fd, names, strtab_size, (off_t) strtab_off) != (ssize_t) strtab_size) {
        free(names);
        return -1;
    }

    for (uint16_t i = 0; i < sh.shnum; i++) {
        off_t hdr_off = (off_t) (sh.shoff + (uint64_t) i * sh.shentsize);
        if (pread(fd, shdr, sh.shentsize, hdr_off) != (ssize_t) sh.shentsize) {
            free(names);
            return -1;
        }

        uint32_t name_off = kl_rd32(shdr);
        if (name_off >= strtab_size) continue;
        if (strcmp(names + name_off, ".text") == 0) {
            uint64_t off, size;
            if (is64) {
                off = kl_rd64(shdr + 0x18);
                size = kl_rd64(shdr + 0x20);
            } else {
                off = kl_rd32(shdr + 0x10);
                size = kl_rd32(shdr + 0x14);
            }
            free(names);
            if (size == 0) return -1;
            *offset_out = off;
            *size_out = size;
            return 0;
        }
    }

    free(names);
    return -1;
}

/* 从 so 文件读 .text 算 CRC32。失败返回负。 */
static int kl_text_crc_from_so(const char *so_path, uint32_t *crc_out) {
    if (so_path == NULL || so_path[0] == 0 || crc_out == NULL) return -1;

    int fd = open(so_path, O_RDONLY);
    if (fd < 0) return -1;

    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size <= 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        return -1;
    }

    uint64_t off = 0, size = 0;
    if (kl_find_text_section(fd, &off, &size) != 0) {
        close(fd);
        return -1;
    }
    if (size > (uint64_t) st.st_size || off > (uint64_t) st.st_size ||
        off + size > (uint64_t) st.st_size) {
        close(fd);
        return -1;
    }

    /* .text 通常几百 KB；一次性读入再算，简单且能继续复用硬件 CRC 分支。 */
    uint8_t *text = (uint8_t *) malloc((size_t) size);
    if (text == NULL) {
        close(fd);
        return -1;
    }
    ssize_t n = pread(fd, text, (size_t) size, (off_t) off);
    if (n < 0 || (uint64_t) n != size) {
        free(text);
        close(fd);
        return -1;
    }

    *crc_out = kl_crc32(text, (size_t) size);
    free(text);
    close(fd);
    return 0;
}

/* ── master 计算 ───────────────────────────────────────────────────
 *
 * master = SHA256( SEED_8 || CRC32(.text)_4 || "dpt-kl-v1" )
 *
 * CRC32(.text) 的来源必须与打包侧 Java 一致：解析运行期 so 文件的 ELF 段表，
 * 读 .text 的【文件字节】。不能用链接期符号（实测不存在），也不能用进程
 * 内存页（mprotect/重定位后可能与文件字节不一致）。
 *
 * 返回 0 成功，-1 表示读不到 .text（此时绝不能按 crc=0 继续，否则会
 * 解出乱码，而日志还显示“derive 成功”）。
 */
static int kl_compute_master(const char *so_path, uint8_t out[DPT_KL_MASTER_LEN]) {
    uint8_t seed[8];
    for (int i = 0; i < 8; i++) {
        seed[i] = (uint8_t) (DPT_KL_SEED >> (i * 8));
    }

    uint32_t text_crc = 0;
    if (kl_text_crc_from_so(so_path, &text_crc) != 0) {
        return -1;
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
    return 0;
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
                  const char *so_path,
                  uint8_t out[DPT_KL_KEY_LEN]) {
    if (cert_der == NULL || pkg == NULL || out == NULL) return -1;
    if (pkg_len == 0) return -1;
    if (cert_len < 16 || cert_len > 8192) return -2;

    uint8_t master[DPT_KL_MASTER_LEN];
    if (kl_compute_master(so_path, master) != 0) {
        memset(master, 0, sizeof(master));
        return -4;
    }
    int r = dpt_kl_derive_with_master(master, cert_der, cert_len, pkg, pkg_len, out);
    memset(master, 0, sizeof(master));
    return r;
}
/* ── 便捷入口：给段解密用的一键派生 ─────────────────────────────────
 *
 * 调用方（dpt.cpp 的 decrypt_section）在 init_array 里跑，早于
 * JNI_OnLoad —— 那时没有 JNIEnv，也还没读 shell config。所以这个函数
 * 必须自包含：自己找 APK、算 .text CRC、提证书、读包名。
 *
 * so_path 有两个用途：① 算 CRC32(.text)；② 反推 APK 路径兜底。
 * 主 APK 来源仍是 /proc/self/maps 里含 base.apk 的行。
 */

/* 从 /proc/self/cmdline 读包名，截到首个 ':' 前。
 * 为什么截：子进程的进程名带 :remote/:push 后缀，不截则主进程通过而
 * 子进程全部 fail-closed（apk-protect-action 同款教训）。 */
static int kl_read_package(char *out, size_t cap) {
    int fd = open("/proc/self/cmdline", O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, out, (int) cap - 1);
    close(fd);
    if (n <= 0) return -1;
    out[n] = 0;
    /* cmdline 是 NUL 分隔的 argv，第一段就是进程名/包名 */
    size_t len = 0;
    while (len < (size_t) n && out[len] != 0) len++;
    out[len] = 0;
    /* 截到首个 ':' */
    for (size_t i = 0; i < len; i++) {
        if (out[i] == ':') { out[i] = 0; len = i; break; }
    }
    return (len > 0) ? 0 : -1;
}

/* 定位自身 APK 路径。两条来源（与 apk-protect-action 的 sig_check.c 同思路）：
 *   ① /proc/self/maps 里含 "base.apk" 的行（ART 会映射 APK）
 *   ② so 路径反推：.../lib/<abi>/xxx.so → .../base.apk
 * 注意：libxixin.so 运行期在 dataDir/dpt-libs/<abi>/，不走 ②，所以 ① 是主路径。 */
static int kl_find_apk(const char *so_path, char *out, size_t cap) {
    /* ① maps */
    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd >= 0) {
        char buf[4096];
        ssize_t n;
        char line[600];
        size_t ll = 0;
        while ((n = read(fd, buf, sizeof(buf))) > 0) {
            for (ssize_t i = 0; i < n; i++) {
                char c = buf[i];
                if (c == '\n') {
                    line[ll] = 0;
                    ll = 0;
                    const char *p = strstr(line, "base.apk");
                    if (p) {
                        const char *s = strchr(line, '/');
                        if (s && s <= p) {
                            size_t l = (size_t) (p - s) + 8;   /* 含 "base.apk" */
                            if (l < cap) {
                                memcpy(out, s, l);
                                out[l] = 0;
                                close(fd);
                                return 0;
                            }
                        }
                    }
                } else if (ll + 1 < sizeof(line)) {
                    line[ll++] = c;
                }
            }
        }
        close(fd);
    }

    /* ② so 路径反推 */
    if (so_path) {
        const char *lib = strstr(so_path, "/lib/");
        if (lib) {
            size_t dirlen = (size_t) (lib - so_path);
            const char *base = "/base.apk";
            size_t bl = strlen(base);
            if (dirlen + bl < cap) {
                memcpy(out, so_path, dirlen);
                memcpy(out + dirlen, base, bl + 1);
                return 0;
            }
        }
    }
    return -1;
}

int dpt_kl_derive_section_key(const char *so_path, uint8_t out[DPT_KL_KEY_LEN]) {
    if (out == NULL) return -1;

    char apk[512] = {0};
    char pkg[256] = {0};
    if (kl_find_apk(so_path, apk, sizeof(apk)) != 0) return -1;
    if (kl_read_package(pkg, sizeof(pkg)) != 0) return -1;

    dpt_cert_t cert;
    int rc = dpt_cert_first_signer(apk, &cert);
    if (rc != 0) return -1;

    rc = dpt_kl_derive(cert.der, cert.der_len, pkg, strlen(pkg), so_path, out);
    dpt_cert_free(&cert);
    return rc;
}

/* 测试专用：给定 seed 与 CRC32 算 master（绕过 __start__text 等链接期符号，
 * 宿主测试链接不到那些符号）。与 Java 侧 KeyLadder.computeMaster 对应。 */
void kl_compute_master_for_test(uint8_t out[DPT_KL_MASTER_LEN],
                                long long seed, unsigned crc) {
    uint8_t seedb[8];
    for (int i = 0; i < 8; i++) seedb[i] = (uint8_t) (seed >> (i * 8));
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, seedb, sizeof(seedb));
    mbedtls_sha256_update(&ctx, (const uint8_t *) &crc, sizeof(crc));
    const char *bid = "dpt-kl-v1";
    mbedtls_sha256_update(&ctx, (const uint8_t *) bid, strlen(bid));
    mbedtls_sha256_finish(&ctx, out);
    mbedtls_sha256_free(&ctx);
    memset(seedb, 0, sizeof(seedb));
}
