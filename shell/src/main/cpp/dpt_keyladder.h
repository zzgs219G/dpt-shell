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
 * 为什么带 "-v1"：将来换派生算法时能通过版本号区分，老包仍能跑。
 *
 * ⚠️ 这些常量不能以完整字面量出现在产物里（2026-10-27 逆向实测）：
 *   `strings libxixin.so | grep dpt-` 一条命令就能看到 "dpt-sec-v1"、
 *   "dpt-kl-v1"，等于把派生公式的结构告诉逆向者。
 *
 *   曾经试过"拆成相邻两段字面量由编译器拼接"——【无效】：
 *   C 标准规定相邻字符串字面量在编译期拼接，产物里仍是完整的一份
 *   （v1.3.0 实测：四个常量串全部原样存在）。
 *
 *   最终方案：以【位置相关掩码】存密文，运行期用 volatile 指针取值异或还原。
 *   volatile 是必需的 —— 否则优化器做常量传播，会把明文算回 .rodata
 *   （实测：不加 volatile 仍泄漏 "dpt-sec-"）。
 *
 *   能力边界（如实）：这挡的是静态 strings/二进制扫描；
 *   动态调试下断点看 kl_info_prefix() 的返回值仍能拿到明文。
 *   真正要藏住必须让 key 不依赖固定常量，那是另一层设计。 */

/* 密文 + 掩码：运行时还原成 "dpt-sec-v1"。 */
#define DPT_KL_INFO_LEN 10
#define DPT_KL_CONFIG_INFO_LEN 10
#define DPT_KL_MASTER_BID_LEN 9
#define DPT_KL_CONFIG_MASTER_BID_LEN 14

/* 配置解密材料（aes_key/iv）的派生 info 前缀。
 *
 * 为什么配置也要走派生链（2026-10-27 逆向实证）：
 *   旧方案把 encKey 明文写进导出符号 DPT_UNKNOWN_DATA，逆向者
 *   `readelf -sW --dyn-syms | grep DPT_UNKNOWN_DATA` 定位后 dd 出 16 字节，
 *   再 HMAC 出配置 key、AES-CBC 解开 assets/xixin_config，直接拿到
 *   stub_seed（字符串加密的全部密钥流种子）。整条链 5 步、零 root。
 *   改走派生链后 so 里不再有任何配置密钥材料，该符号可以彻底删除。
 *
 * 与段密钥用不同前缀（域分离）：同一 master/cert 下两条链的 key 不可互推。 */
/* 运行期还原 info 前缀 / master 版本串。
 * 为什么不用 #define 字符串：见上方说明（编译期拼接无效）。
 * out 需至少 len+1 字节；返回 out。 */
const char *dpt_kl_info_prefix(char *out, size_t cap);
const char *dpt_kl_config_info_prefix(char *out, size_t cap);
const char *dpt_kl_master_bid(char *out, size_t cap);
const char *dpt_kl_config_master_bid(char *out, size_t cap);

/* 配置材料长度：aes_key 32 字节 + iv 16 字节 = 48。 */
#define DPT_KL_CONFIG_MATERIAL_LEN 48

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
 *   -2  证书 DER 长度异常（< 16 或 > 8192，防止畸形输入拖垮 SHA256）
 *   -3  内部派生失败（不应发生，属于内存分配失败）
 *   -4  读不到运行期 so 的 .text 段（无法与打包侧算同一 CRC32）
 *
 * 失败时 out 内容未定义（调用方不要用）。
 */
/* 便捷入口：给段解密用的一键派生（自包含找 APK/证书/包名）。
 *
 * 设计给 init_array 阶段的调用方（那时没有 JNIEnv、也没读 shell config），
 * 所以本函数自己完成：
 *   1. 定位自身 APK（/proc/self/maps 找 base.apk，失败则用 so_path 反推）
 *   2. 提取第一签名者证书 DER（纯 C，不经 Java）
 *   3. 读包名（/proc/self/cmdline，截到首个 ':' 前）
 *   4. 解析自身 so 文件的 .text 段算 CRC32（与打包侧 Java 同一口径）
 *   5. 走 dpt_kl_derive 派生
 *
 * so_path 不能省：CRC32(.text) 与 APK 反推兜底都用它。
 * 返回 0 成功，负数为失败（调用方应 fail-closed，不要解密）。
 */
/* 测试专用：给定 seed 与 CRC32(.text) 算 master，绕过链接期符号依赖。
 * 与 Java 侧 KeyLadder.computeMaster(seed, crc) 一一对应，供两侧对拍。 */
void kl_compute_master_for_test(uint8_t out[DPT_KL_MASTER_LEN],
                                long long seed, unsigned crc);

int dpt_kl_derive_section_key(const char *so_path,
                              uint8_t out[DPT_KL_KEY_LEN]);

// so_path: running shell so path; used for CRC32(.text) and APK fallback
// resolution. cert/pkg come from the installed APK at runtime.
/* 派生任意长度、任意 info 前缀的密钥材料（HKDF 的通用形态）。
 *
 * 给配置链用：dpt_kl_derive_config_material() 需要 48 字节，
 * 而 dpt_kl_derive() 固定输出 16 字节（段密钥）。
 *
 * info = info_prefix || pkg，其它输入与段密钥完全一致（同一 master、同一 salt）。
 * 返回 0 成功，负数含义同 dpt_kl_derive。 */
int dpt_kl_derive_material(const uint8_t *cert_der, size_t cert_len,
                           const char *pkg, size_t pkg_len,
                           const char *so_path,
                           const char *info_prefix,
                           uint8_t *out, size_t out_len);

/* 派生配置解密材料：out = [aes_key(32) || iv(16)]。
 * 纯函数，不落盘、不读符号。 */
/* 定位已安装 APK 路径（供配置链在 JNI_OnLoad 里复用同一套探测逻辑：
 * 先读 Java 写的 DPT_APK_PATH 环境变量，再 apk-path 文件，最后 maps/反推）。
 * 返回 0 成功。 */
int dpt_kl_locate_apk(const char *so_path, char *out, size_t cap);

int dpt_kl_derive_config_material(const uint8_t *cert_der, size_t cert_len,
                                  const char *pkg, size_t pkg_len,
                                  const char *so_path,
                                  uint8_t out[DPT_KL_CONFIG_MATERIAL_LEN]);

int dpt_kl_derive(const uint8_t *cert_der, size_t cert_len,
                  const char *pkg, size_t pkg_len,
                  const char *so_path,
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
