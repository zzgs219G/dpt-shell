//
// dpt_cert.h/.c —— 纯 C 从已安装 APK 提取第一签名者证书 DER
//
// 【为什么不用 Java 的 PackageManager（dpt_risk.cpp 的做法）】
//   段解密发生在 init_array 的 constructor 里，早于 JNI_OnLoad ——
//   那时还没有 JNIEnv，拿不到 PackageManager。必须纯 C。
//
// 【为什么不用 androguard / 外部库】
//   这是 so 里唯一需要"自己打开自己 APK"的地方，用纯 stdlib 写
//   约 150 行，比引入一个 APK 解析库（几百 KB）划算得多。
//
// 【APK 签名结构（只需要这几步）】
//   1. 读文件尾部找 EOCD（End Of Central Directory），定位中央目录偏移
//   2. 中央目录之前是 APK Signing Block，magic = "APK Sig Block 42"
//   3. Signing Block 里是一串 ID-value pair，遍历找 v2(0x7109871A) 或 v3(0xF05368C0)
//   4. v2/v3 block 内部：length-prefixed signer 列表 → 第一个 signer 的
//      signed data 里含 certificates → 第一张证书的 DER
//
//   这个结构与 apk-protect-action 的 extract-cert-fp.py（纯 Python 实现）
//   一致，两侧必须解出同一个 DER —— 由对拍测试锁定。
//
// 【性能】
//   只读 APK 尾部 ~100KB（EOCD + Signing Block），不整文件读。
//   实测约 300~500μs，每进程一次。
//
#ifndef DPT_CERT_H
#define DPT_CERT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* APK Signing Block 里的 block ID（APK Signature Scheme v2/v3）。 */
#define DPT_V2_BLOCK_ID 0x7109871Au
#define DPT_V3_BLOCK_ID 0xF05368C0u

/* 提取结果。失败时所有字段为 0，调用方据此判定。 */
typedef struct {
    uint8_t *der;      /* 证书 DER（malloc 出来，调用方必须 free） */
    size_t   der_len;
} dpt_cert_t;

/* 从 APK 提取第一签名者证书 DER。
 *
 * apk_path: APK 文件路径（已安装位置，如 /data/app/.../base.apk）
 * out:      输出。成功时 out->der 非 NULL（调用方 free）。
 *
 * 返回 0 成功，负数为失败：
 *   -1  入参非法 / 打不开文件
 *   -2  不是 zip（无 EOCD）
 *   -3  无 APK Signing Block（仅 v1 签名）
 *   -4  Signing Block 里无 v2/v3 数据
 *   -5  证书长度异常（0 或 > 8192）
 *   -6  内存分配失败
 */
int dpt_cert_first_signer(const char *apk_path, dpt_cert_t *out);

/* 释放 dpt_cert_t 里的 der。 */
void dpt_cert_free(dpt_cert_t *c);

#ifdef __cplusplus
}
#endif

#endif // DPT_CERT_H
