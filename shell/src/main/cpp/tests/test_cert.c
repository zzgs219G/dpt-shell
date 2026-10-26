//
// test_cert.c —— 用真实 APK 验证证书提取（宿主测试）
//
// 【为什么必须真包验证】
//   APK Signing Block 的嵌套 length-prefixed 结构极易写错偏移，
//   而错 1 字节就解出垃圾。合成样本覆盖不了真实签名的各种形态
//   （v2/v3、多 signer、变长证书），必须用真包。
//
// 【怎么跑】
//   cc -o t test_cert.c dpt_cert.c && ./t <apk路径>
//   期望输出：证书 DER 长度 + SHA-256 前 16 字节
//   把 SHA-256 与 keytool/apksigner 的输出对比即知对错。
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dpt_cert.h"

/* 本地 SHA-256（避免为测试链 mbedtls）。用 openssl。 */
#include <openssl/sha.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "用法: %s <apk路径>\n", argv[0]);
        return 2;
    }

    dpt_cert_t c;
    int rc = dpt_cert_first_signer(argv[1], &c);
    printf("APK: %s\n", argv[1]);
    printf("rc  = %d (%s)\n", rc, rc == 0 ? "OK" : "FAIL");

    if (rc != 0) {
        const char *why[] = {
            "入参非法/打不开", "不是zip", "无Signing Block",
            "无v2/v3", "证书长度异常", "内存失败"
        };
        int i = -rc;
        if (i >= 1 && i <= 6) printf("原因: %s\n", why[i - 1]);
        return 1;
    }

    printf("证书 DER 长度: %zu 字节\n", c.der_len);

    unsigned char h[32];
    SHA256(c.der, c.der_len, h);
    printf("证书 SHA-256 : ");
    for (int i = 0; i < 32; i++) printf("%02x", h[i]);
    printf("\n");

    /* 前 4 字节应该是 ASN.1 SEQUENCE（0x30 0x82 ...）—— 快速 sanity check */
    printf("DER 头 4 字节: %02x %02x %02x %02x  %s\n",
           c.der[0], c.der[1], c.der[2], c.der[3],
           (c.der[0] == 0x30 && c.der[1] == 0x82) ? "✅ 像 X.509" : "⚠️ 不像");

    dpt_cert_free(&c);
    return 0;
}
