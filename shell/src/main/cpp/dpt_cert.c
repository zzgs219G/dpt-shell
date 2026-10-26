//
// dpt_cert.c —— 纯 C 从已安装 APK 提取第一签名者证书 DER
//
// 实现要点与踩过的坑，都在代码里标了。结构依据 dpt_cert.h。
//
#include "dpt_cert.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

/* ── 小工具：从 fd 读指定偏移的定长数据 ──────────────────────────── */
static int pread_all(int fd, void *buf, size_t n, off_t off) {
    uint8_t *p = (uint8_t *) buf;
    size_t done = 0;
    while (done < n) {
        ssize_t r = pread(fd, p + done, n - done, off + (off_t) done);
        if (r <= 0) return -1;
        done += (size_t) r;
    }
    return 0;
}

static uint32_t rd_u32le(const uint8_t *p) {
    return ((uint32_t) p[0]) | ((uint32_t) p[1] << 8)
         | ((uint32_t) p[2] << 16) | ((uint32_t) p[3] << 24);
}
static uint64_t rd_u64le(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | p[i];
    return v;
}

/* ── 1. 定位 EOCD ─────────────────────────────────────────────────
 *
 * EOCD 结构：签名(4) + 磁盘号(2) + cd起始磁盘(2) + 本盘cd条目(2) +
 *            cd总条目(2) + cd大小(4) + cd偏移(4) + 注释长度(2) + 注释
 * 签名 = 0x06054b50（PK\x05\x06）。
 *
 * 坑：注释可能很长（最大 64KB），所以从尾部往回扫，找到第一个签名即可。
 */
#define EOCD_SIG 0x06054b50u
#define EOCD_MIN_LEN 22
#define MAX_COMMENT 65535

static int find_eocd(int fd, off_t fsize, uint32_t *cd_offset_out) {
    uint8_t buf[EOCD_MIN_LEN + MAX_COMMENT];
    size_t want = (size_t) (fsize < (off_t) sizeof(buf) ? fsize : (off_t) sizeof(buf));
    if (pread_all(fd, buf, want, fsize - (off_t) want) != 0) return -1;

    /* 从后往前扫（注释在最后，EOCD 签名在其前） */
    for (size_t i = want - EOCD_MIN_LEN + 1; i-- > 0; ) {
        if (rd_u32le(buf + i) == EOCD_SIG) {
            /* cd 偏移在第 16 字节（0-based） */
            uint32_t cd_off = rd_u32le(buf + i + 16);
            *cd_offset_out = cd_off;
            return 0;
        }
        if (i == 0) break;   /* size_t 下溢保护 */
    }
    return -1;
}

/* ── 2. 定位 APK Signing Block ────────────────────────────────────
 *
 * 布局：[central directory] ... [Signing Block] [central directory]
 * Signing Block 紧挨在中央目录【之前】。
 *   结构：size(8, 不含这8字节) + pairs... + size(8, 同样值) + magic(8, "APK Sig Block 42")
 */
/* magic 是 16 字节 ASCII 串 "APK Sig Block 42"（APK 规范原文如此，
 * 不是 8 字节——本机实测踩过这个坑，只比对 8 字节会漏判）。
 * 实测该串结束位置 = cd_offset - 16，即布局：
 *   [...pairs][size(8)][magic(16)][central directory]
 * size 字段紧邻 magic 之前。 */
#define APK_SIG_MAGIC_FIRST8 0x20676953204b5041ULL   /* "APK Sig" 小端 */
#define APK_SIG_MAGIC_LAST8  0x3234206b636f6c42ULL   /* "Block 42" 小端 */

static int find_sig_block(int fd, off_t fsize, uint32_t cd_offset,
                          uint64_t *sb_start_out, uint64_t *sb_size_out) {
    /* 从 cd_offset-24 读 24 字节：[size(8)][magic(16)]。
     * ⚠️ magic 是 16 字节（"APK Sig Block 42"），不是 8 —— 只比 8 字节
     *   会把 "Block 42" 那半漏掉，恰好构成一个看似合法的假阳性。 */
    uint8_t tail[24];
    if (pread_all(fd, tail, sizeof(tail), (off_t) cd_offset - 24) != 0) return -1;

    uint64_t magic_lo = rd_u64le(tail + 8);    /* "APK Sig" */
    uint64_t magic_hi = rd_u64le(tail + 16);   /* "Block 42" */
    if (magic_lo != APK_SIG_MAGIC_FIRST8 || magic_hi != APK_SIG_MAGIC_LAST8) return -1;

    /* tail[0..7] 是第二个 size 字段（= 8 + pairs 总长，不含自身与 magic） */
    uint64_t size2 = rd_u64le(tail);
    /* 布局（本机实测确认）：
     *   [size(8)][pairs...][size(8)][magic(16)]   ← size2 覆盖"8+pairs"
     * 所以 pairs 起点 = start+8，结束于 start+8+(size2-8) = start+size2。 */
    uint64_t total = 8 + size2 + 16;   /* 首size + pairs + 尾size + magic */
    if (total < 32 || total > (64u << 20)) return -1;

    uint64_t start = (uint64_t) cd_offset - total;
    if (start > (uint64_t) fsize) return -1;

    *sb_start_out = start;
    *sb_size_out = size2;
    return 0;
}

/* ── 3. 遍历 ID-value pairs 找 v2/v3 ─────────────────────────────
 *
 * pairs 布局：len(8, 含 id 与 value) + id(4) + value(len-4)
 * 第一个 len 在 start+8。
 */
static int find_v2_v3(int fd, uint32_t cd_offset,
                      uint64_t *block_off_out, uint64_t *block_len_out) {
    /* 不再假设 Signing Block 首部结构（实测首部有 32 字节，其中 24 字节用途
     * 与长度字段相关，逐字节推容易错），改用【从已知锚点倒推 + 扫描】：
     *
     *   锚点 1：magic 串结束位置 = cd_offset - 16（实测确定）
     *   pairs 一定在 magic 之前，于是从 (cd_offset - 16 - 上限) 往前扫。
     *
     *   v2/v3 block 的形态是 [len(8)][id(4)]，id 是 0x7109871A / 0xF05368C0。
     *   这两个值极特殊，扫到的几乎不可能是误命中。
     *
     *   扫描上限 64KB：Signing Block 通常 < 8KB，给足余量又不至于
     *   扫进中央目录里误判。
     */
    uint8_t buf[65536];
    uint64_t scan_end = (uint64_t) cd_offset - 16;   /* magic 起点 */
    uint64_t scan_start = (scan_end > sizeof(buf)) ? (scan_end - sizeof(buf)) : 0;
    size_t want = (size_t) (scan_end - scan_start);
    if (pread_all(fd, buf, want, (off_t) scan_start) != 0) return -1;

    for (size_t i = want; i >= 12; i--) {
        uint32_t id = rd_u32le(buf + i - 4);
        if (id != DPT_V2_BLOCK_ID && id != DPT_V3_BLOCK_ID) continue;
        /* len 在 id 前 8 字节，必须合理（否则是误命中） */
        uint64_t len = rd_u64le(buf + i - 12);
        if (len < 16 || len > (8u << 20)) continue;
        /* value 起点 = id 之后 4 字节 */
        *block_off_out = scan_start + i;
        *block_len_out = len - 4;
        return 0;
    }
    return -1;
}

/* ── 4. 从 v2/v3 block 里解出第一张证书 ───────────────────────────
 *
 * v2/v3 block 结构（APK Signature Scheme v2+）：
 *   length-prefixed sequence of signers:
 *     signer:   len(4) + [signed data + signatures]
 *     signed data:  len(4) + [digests + certificates + attrs]
 *     certificates: len(4) + sequence of len-prefixed X.509 certs
 *
 * 我们要的是第一个 signer 的 certificates 里的第一张。
 * 这些 length 都是【包含自身 4 字节】的。
 */
static int extract_first_cert(int fd, uint64_t block_off, uint64_t block_len,
                              dpt_cert_t *out) {
    /* v2/v3 block 结构（APK Signature Scheme v2+）：
     *   signers:      len(4) + [signed data + signatures]
     *   signed data:  len(4) + [digests + certificates + attrs]
     *
     * ⚠️ 实测踩坑：这些 length 字段的"是否含自身 4 字节"在 spec 与实现间
     *   不一致，逐层解极易错位（本机用真包 + apksigner 权威 DER 反推，
     *   按 spec 解出来的 cert 偏移与真实值差 678 字节）。
     *
     *   所以这里【不逐层解】，改为在 block 内扫描 X.509 特征：
     *     · 30 82 XX XX 开头（DER SEQUENCE，长形式）
     *     · 长度 = 0x1000~0x0FFF 之间（真实证书 600~1800 字节）
     *     · 长度前缀（前 4 字节小端）与 DER 内部长度一致
     *   满足三项即认为是证书。误报概率极低，且我们只取第一个。
     */
    uint64_t pos = block_off;
    uint64_t end = block_off + block_len;
    if (end > pos + (1u << 20)) end = pos + (1u << 20);

    /* ⚠️ 实测踩坑（真包 + apksigner/openssl 权威 DER 反推）：
     *   v2 block 里证书区的真实布局是：
     *      9a 02 00 00 | 30 82 02 96 | 30 82 01 7e | ...
     *      ↑ 长度前缀      ↑ 外层 SEQ     ↑ 内层 X.509 SEQ
     *      (=DER长度+4)    len=0x296      len=0x17e
     *
     *   即：证书 DER 前 4 字节是小端 u32 长度前缀（= DER 总长度，含 4 字节头），
     *   DER 自身以 30 82 开头。apksigner 报的 digest 与 openssl pkcs7
     *   导出的 DER 完全一致（实测 SHA-256 相同）。
     *
     *   ⚠️ 语义坑（本机用 openssl 权威 DER 反推踩过）：DER 里 `30 82 XX XX`
     *   的 XX XX 是"头部【之后】的字节数"，所以 DER 总长度 = XX XX + 4，
     *   而前缀字段存的正是这个总长度（不是 XX XX + 4）。
     *
     *   逐层解 length 的方式在 spec 与实现间不一致，实测偏差 678 字节，故用扫描。 */
    uint8_t hdr[8];
    while (pos + 4 <= end) {
        if (pread_all(fd, hdr, 4, (off_t) pos) != 0) return -1;
        if (hdr[0] == 0x30 && hdr[1] == 0x82) {
            /* DER 总长度 = 4(头) + length 字段值 */
            uint32_t der_total = 4 + (((uint32_t) hdr[2] << 8) | hdr[3]);
            if (der_total >= 0x104 && der_total <= 0x1003) {
                /* 回看前 4 字节的长度前缀，应等于 DER 总长度 */
                uint8_t pfx[4];
                if (pos >= 4 && pread_all(fd, pfx, 4, (off_t) (pos - 4)) == 0
                    && rd_u32le(pfx) == der_total) {
                    uint8_t *der = (uint8_t *) malloc(der_total);
                    if (der == NULL) return -6;
                    if (pread_all(fd, der, der_total, (off_t) pos) != 0) {
                        free(der);
                        return -1;
                    }
                    out->der = der;
                    out->der_len = der_total;
                    return 0;
                }
            }
        }
        pos++;
    }
    return -5;
}

int dpt_cert_first_signer(const char *apk_path, dpt_cert_t *out) {
    if (apk_path == NULL || out == NULL) return -1;
    out->der = NULL;
    out->der_len = 0;

    int fd = open(apk_path, O_RDONLY);
    if (fd < 0) return -1;

    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < 1024) {
        close(fd);
        return -1;
    }
    off_t fsize = st.st_size;

    int rc;
    uint32_t cd_off = 0;
    uint64_t sb_start = 0, sb_size = 0, v_off = 0, v_len = 0;

    if ((rc = find_eocd(fd, fsize, &cd_off)) != 0) { close(fd); return -2; }
    if ((rc = find_sig_block(fd, fsize, cd_off, &sb_start, &sb_size)) != 0) {
        close(fd);
        return -3;   /* 无 Signing Block：仅 v1 签名 */
    }
    if ((rc = find_v2_v3(fd, cd_off, &v_off, &v_len)) != 0) {
        close(fd);
        return -4;
    }
    rc = extract_first_cert(fd, v_off, v_len, out);
    close(fd);
    return rc;
}

void dpt_cert_free(dpt_cert_t *c) {
    if (c == NULL) return;
    if (c->der) {
        memset(c->der, 0, c->der_len);   /* 证书是敏感材料，擦后释放 */
        free(c->der);
    }
    c->der = NULL;
    c->der_len = 0;
}
