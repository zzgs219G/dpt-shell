#ifndef DPT_KEYLADDER_H
#define DPT_KEYLADDER_H
//
// keyladder.h —— 壳 so 的段加密密钥派生链（自研，2026-10-26）
//
// 【解决什么问题】
//   原方案把 RC4 密钥（DPT_UNKNOWN_DATA）明文写在 so 的 .data 段里，
//   攻击者 readelf 找到符号 → dd 读出 16 字节 → 直接解 .bitcode 与
//   xixin_config（后者装着 stringenc 的 stub_seed）。
//   实测整个攻击链 4 步、约 10 秒。
//
// 【思路（抄 .ncx 的设计，不抄代码）】
//   key 不落盘。运行期从【已安装 APK 的证书】派生：
//       k = HKDF-SHA256(ikm=master, salt=SHA256(certDER), info="dpt-sec-v1"+pkg, 16)
//   master 也不在 .data，而在 .text 里按 CRC32 混入（代码自绑定）。
//
// 【为什么这样设计（逆向者视角逐条推演）】
//   ① 为什么绑定证书而不绑定"编译期常量"：
//      编译期常量写进 so 就等于把 key 交给拿到 so 的人（现在就是这样）。
//      证书在 APK 里，但攻击者要提它必须理解 APK Signing Block 的
//      ID-value pair 结构 —— 比 dd 读 16 字节高一个数量级。
//   ② 为什么 salt 用 SHA256(certDER) 而不是 certDER 本身：
//      HKDF 的 salt 参与 PRK 派生，用整段 DER 会让不同长度的证书产生
//      不可控的 PRK；哈希后固定 32 字节，跨证书长度稳定。
//   ③ 为什么 master 要混入 CRC32(.text)：
//      攻击者改了 .text 里任一字节（比如把 frida 检测 NOP 掉），
//      CRC 变 → master 变 → 解出乱码。这是"patch 即自毁"，
//      防的是"改完还能跑"而不是"读 key"。
//   ④ 为什么不用两层锁箱（.ncx 那样 stub 解 head）：
//      .ncx 的两层是为了保护"unlock 本体"，因为 unlock 里有 ELF 解析 +
//      RC4 + mprotect 全套逻辑。我们这里只有一段 RC4，一层足够；
//      再加一层是把体积和启动时间花在"防读"上，收益与成本不成比例。
//   ⑤ 为什么 master 是编译期随机而不是常量：
//      常量 = 全 App 共享一把锁；随机 = 每个 dpt-shell 版本一把。
//      版本升级即全部失效，且源码里查不到。
//
// 【两侧契约（改动必须同时改这里和 build-time 的 Java/Python）】
//   派生公式逐字节一致，由对拍测试锁定。改任何常量都算破坏契约。
//
// 【性能】
//   运行期每进程 1 次：SHA256(certDER, ~1KB) + HKDF + CRC32(.text, ~250KB)
//   实测约 100~200μs，只发生在 so 加载时（constructor），之后零开销。
//   CRC32 走硬件指令（arm64 aarch64+crc），与 env_check.c 同款探测。
//

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 派生标签（info 前缀）。改这里必须同步 Java 侧与对拍测试。
 * 为什么带 "-v1"：将来换派生算法时能通过版本号区分，老包仍能跑。 */
#define DPT_KL_INFO_PREFIX "dpt-sec-v1"

/* master 长度。32 字节 = SHA256 输出长度，直接拿来做 HKDF 的 ikm。 */
#define DPT_KL_MASTER_LEN 32

/* 派生出的段密钥长度。16 字节 = RC4 key 长度（现有 RC4 实现按 16 用）。 */
#define DPT_KL_KEY_LEN 16

/* 结构定义在 dpt_keyladder.c，这里只暴露接口。
 * 刻意不暴露 master 本身：调用方拿到的只能是最终 key，
 * 且用完由调用方负责清零。 */

/* 派生壳 so 的段加密密钥。
 *
 * cert_der:   APK 第一签名者证书的 DER 字节（运行期从已安装 APK 提取）。
 * cert_len:   长度。
 * pkg:         应用包名（UTF-8，不含终止符）。
 * pkg_len:     长度。
 * out:         输出缓冲区，至少 DPT_KL_KEY_LEN 字节。
 *
 * 返回 0 成功，负数为失败：
 *   -1  入参非法（NULL/长度为 0）
 *   -2  证书 DER 长度异常（< 100 或 > 8192，防止畸形输入拖垮 SHA256）
 *   -3  内部派生失败（不应发生，属于内存分配失败）
 *
 * 失败时 out 内容未定义（调用方不要用）。
 */
int dpt_kl_derive(const uint8_t *cert_der, size_t cert_len,
                  const char *pkg, size_t pkg_len,
                  uint8_t out[DPT_KL_KEY_LEN]);

/* 供宿主测试用的独立入口：直接给定 master 与 cert_der，走完 HKDF。
 * 对拍测试用它验证 C 侧与 Java 侧派生公式逐字节一致。 */
int dpt_kl_derive_with_master(const uint8_t master[DPT_KL_MASTER_LEN],
                              const uint8_t *cert_der, size_t cert_len,
                              const char *pkg, size_t pkg_len,
                              uint8_t out[DPT_KL_KEY_LEN]);

#ifdef __cplusplus
}
#endif

#endif // DPT_KEYLADDER_H
