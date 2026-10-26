//
// test_keyladder_ossl.c —— 派生链宿主对拍（OpenSSL 版，自研件第 1 步）
//
// 【为什么有 OpenSSL 变体】
//   dpt_keyladder.c 调 mbedtls，而仓库里 mbedtls 是未编译的 submodule。
//   为了本机（Termux）就能验证派生公式本身，用 OpenSSL 提供同名符号。
//
//   ⚠️ 只用于宿主验证，不进产物。真机路径仍走 mbedtls。
//   ⚠️ 本文件【直接 #include dpt_keyladder.c】（而不是链入 .o），
//      这样同名静态函数能共享，也不用维护 impl 头。
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

/* ── mbedtls 同名薄封装 ──────────────────────────────────────────── */
/* mbedtls 的 include 由编译期 -I 指向一个只含空文件的 fakembedtls/ 目录
 * 顶替（见 Makefile/CI 的 -I 参数），这里只提供同名符号。 */

typedef struct { unsigned char buf[4096]; size_t len; } mbedtls_sha256_context;
static void mbedtls_sha256_init(mbedtls_sha256_context *c) { c->len = 0; }
static void mbedtls_sha256_free(mbedtls_sha256_context *c) { (void) c; }
static void mbedtls_sha256_starts(mbedtls_sha256_context *c, int is224) {
    (void) is224; c->len = 0;
}
static void mbedtls_sha256_update(mbedtls_sha256_context *c,
                                  const unsigned char *p, size_t n) {
    if (n < sizeof(c->buf) - c->len) { memcpy(c->buf + c->len, p, n); c->len += n; }
}
static void mbedtls_sha256_finish(mbedtls_sha256_context *c, unsigned char out[32]) {
    SHA256(c->buf, c->len, out);
    c->len = 0;
}
static void mbedtls_sha256(const unsigned char *in, size_t n, unsigned char out[32], int is224) {
    (void) is224;
    SHA256(in, n, out);
}
static const void *mbedtls_md_info_from_type(int t) { (void) t; return (const void *) 1; }
#define MBEDTLS_MD_SHA256 0
/* OpenSSL 1.1 无 <openssl/hkdf.h>，按 RFC 5869 §2 用 HMAC 拼 */
static int mbedtls_hkdf(const void *md, const unsigned char *salt, size_t sl,
                        const unsigned char *ikm, size_t il,
                        const unsigned char *info, size_t infol,
                        unsigned char *okm, size_t okml) {
    (void) md;
    unsigned char prk[32]; unsigned int prk_len = 0;
    static const unsigned char zero_salt[32] = { 0 };
    if (sl == 0) { salt = zero_salt; sl = sizeof(zero_salt); }
    if (!HMAC(EVP_sha256(), salt, (int) sl, ikm, il, prk, &prk_len)) return -1;
    unsigned char t[32]; size_t t_len = 0, done = 0; unsigned char ctr = 1;
    while (done < okml) {
        HMAC_CTX *ctx = HMAC_CTX_new();
        if (!ctx) return -1;
        HMAC_Init_ex(ctx, prk, sizeof(prk), EVP_sha256(), NULL);
        if (t_len) HMAC_Update(ctx, t, t_len);
        if (infol) HMAC_Update(ctx, info, infol);
        HMAC_Update(ctx, &ctr, 1);
        unsigned int ol = 0;
        HMAC_Final(ctx, t, &ol);
        HMAC_CTX_free(ctx);
        t_len = ol;
        size_t take = (okml - done < t_len) ? (okml - done) : t_len;
        memcpy(okm + done, t, take);
        done += take;
        ctr++;
    }
    return 0;
}

/* 直接吃被测 .c：静态函数可见，不用维护 impl 头。
 * mbedtls 的 include 在上面已被同名符号顶替，这里屏蔽掉。 */
#define mbedtls_sha256_h
#define mbedtls_hkdf_h
#include "dpt_keyladder.c"

int main(void) {
    /* 真实格式的 X.509 证书 DER 前缀（派生只看字节流，不需要完整证书） */
    static uint8_t cert[] = {
        0x30, 0x82, 0x03, 0x6d, 0x30, 0x82, 0x02, 0x55, 0xa0, 0x03, 0x02,
        0x01, 0x02, 0x02, 0x14, 0x2b, 0x7f, 0x1c, 0x9a, 0x33, 0x77, 0x5c };
    const char *pkg = "com.xixin.box";
    /* master 由 computeMaster(SEED, CRC) 算出，与 Java 侧 KeyLadder
     * .computeMaster 走同一条路 —— 这样才是真正的两侧对拍。
     * 之前直接传 ASCII 字符串当 master，与 Java 的 computeMaster 输入不同，
     * 输出必然不同（测试设计缺陷，不是实现 bug）。 */
    uint8_t master[DPT_KL_MASTER_LEN];
    kl_compute_master_for_test(master, 0x0123456789abcdefLL, 0);
    uint8_t a[DPT_KL_KEY_LEN], b[DPT_KL_KEY_LEN], c2[DPT_KL_KEY_LEN];
    int fails = 0;

    printf("══ 派生链宿主对拍（OpenSSL 版）══\n\n");

    if (dpt_kl_derive_with_master(master, cert, sizeof(cert), pkg, strlen(pkg), a) != 0) {
        printf("❌ 派生失败\n"); return 1;
    }
    dpt_kl_derive_with_master(master, cert, sizeof(cert), pkg, strlen(pkg), b);
    if (memcmp(a, b, DPT_KL_KEY_LEN) == 0) printf("✅ 确定性\n");
    else { printf("❌ 不确定\n"); fails++; }

    printf("   derive = ");
    for (int i = 0; i < DPT_KL_KEY_LEN; i++) printf("%02x", a[i]);
    printf("\n\n");

    cert[sizeof(cert) - 1] ^= 1;
    dpt_kl_derive_with_master(master, cert, sizeof(cert), pkg, strlen(pkg), c2);
    if (memcmp(a, c2, DPT_KL_KEY_LEN) != 0) printf("✅ 证书绑定（改 1 bit 换 key）\n");
    else { printf("❌ 证书未绑定\n"); fails++; }

    dpt_kl_derive_with_master(master, cert, sizeof(cert), "com.other.app", 13, c2);
    if (memcmp(a, c2, DPT_KL_KEY_LEN) != 0) printf("✅ 包名绑定\n");
    else { printf("❌ 包名未绑定\n"); fails++; }

    if (dpt_kl_derive_with_master(NULL, cert, sizeof(cert), pkg, strlen(pkg), c2) < 0
        && dpt_kl_derive_with_master(master, cert, 8, pkg, strlen(pkg), c2) < 0)
        printf("✅ 入参校验\n");
    else { printf("❌ 入参校验漏了\n"); fails++; }

    /* 运行期 C 与打包侧 Java 的 CRC32 输入必须是同一段 .text 文件字节。
     * 这里不验证具体 CRC 值（随测试二进制变化），只验证 .text 段能解析出来，
     * 防止以后又退回 __start__text 之类“产物里其实不存在”的输入。 */
    uint32_t self_text_crc = 0;
    if (kl_text_crc_from_so("/proc/self/exe", &self_text_crc) == 0 && self_text_crc != 0)
        printf("✅ 运行期 .text 段解析（/proc/self/exe）\n");
    else { printf("❌ 运行期 .text 段解析失败\n"); fails++; }

    printf("\n%s\n", fails == 0 ? "✅ 全绿" : "❌ 有失败");
    return fails;
}
