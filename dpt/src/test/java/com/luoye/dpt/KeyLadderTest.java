package com.luoye.dpt;

import com.luoye.dpt.util.HexUtils;
import com.luoye.dpt.util.KeyLadder;

import org.junit.Test;

import java.io.File;
import java.nio.charset.StandardCharsets;

import static org.junit.Assert.*;

/**
 * KeyLadderTest —— Java 侧派生链对拍（与 C 侧 dpt_keyladder.c 逐字节一致）
 *
 * 【为什么必须有这个测试】
 *   两侧各写一份派生公式。历史上"以为一致其实不一致"的事故反复
 *   （apk-protect-action 报错十八）。结论：可执行对拍是唯一可靠的锁。
 *
 * 【对拍基线从哪来】
 *   C 侧的期望值由 tests/test_keyladder_ossl.c 打印（宿主 OpenSSL 版），
 *   固化为下面的常量。改任何一侧的派生公式，这个测试必须同步更新，
 *   且要在 docs/变更历史.md 记录为什么改。
 */
public class KeyLadderTest {

    /* 固定测试向量（与 C 侧 test_keyladder_ossl.c 完全相同的输入） */
    private static final long TEST_SEED = 0x0123456789abcdefL;
    private static final long TEST_CRC = 0L;   /* 对拍时 CRC 置 0，隔离变量 */
    private static final String TEST_PKG = "com.xixin.box";

    /* 真实格式的 X.509 证书 DER 前缀（21 字节，派生只看字节流）。
     * 与 C 侧 test_keyladder_ossl.c 的 cert 数组逐字节相同。 */
    private static final byte[] TEST_CERT = new byte[]{
            0x30, (byte) 0x82, 0x03, 0x6d, 0x30, (byte) 0x82, 0x02, 0x55,
            (byte) 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x2b, 0x7f,
            0x1c, (byte) 0x9a, 0x33, 0x77, 0x5c
    };

    /** C 侧 test_keyladder_ossl.c 对同一输入的输出（2026-10-26 固化）。
     *  两侧都走 computeMaster(0x0123456789abcdef, 0) → HKDF 的同一条路。 */
    private static final String C_SIDE_EXPECTED = "9b76af40d3ec2fb0c840166e66dd7a23";

    @Test
    public void deriveKey_matchesCSide() {
        byte[] key = KeyLadder.deriveKey(TEST_SEED, TEST_CRC, TEST_CERT, TEST_PKG);
        assertEquals("派生 key 长度必须 16 字节", 16, key.length);
        assertEquals("Java 侧派生结果必须与 C 侧逐字节一致（改公式要同步两侧）",
                C_SIDE_EXPECTED, HexUtils.toHexString(key));
    }

    @Test
    public void deriveKey_isDeterministic() {
        byte[] a = KeyLadder.deriveKey(TEST_SEED, TEST_CRC, TEST_CERT, TEST_PKG);
        byte[] b = KeyLadder.deriveKey(TEST_SEED, TEST_CRC, TEST_CERT, TEST_PKG);
        assertArrayEquals("同输入必须同输出", a, b);
    }

    @Test
    public void deriveKey_bindsCertificate() {
        byte[] a = KeyLadder.deriveKey(TEST_SEED, TEST_CRC, TEST_CERT, TEST_PKG);
        byte[] cert2 = TEST_CERT.clone();
        cert2[cert2.length - 1] ^= 0x01;      /* 翻 1 bit */
        byte[] b = KeyLadder.deriveKey(TEST_SEED, TEST_CRC, cert2, TEST_PKG);
        assertFalse("证书改 1 bit 必须换 key（否则证书没真绑进去）",
                java.util.Arrays.equals(a, b));
    }

    @Test
    public void deriveKey_bindsPackage() {
        byte[] a = KeyLadder.deriveKey(TEST_SEED, TEST_CRC, TEST_CERT, "com.a.app");
        byte[] b = KeyLadder.deriveKey(TEST_SEED, TEST_CRC, TEST_CERT, "com.b.app");
        assertFalse("包名不同必须换 key", java.util.Arrays.equals(a, b));
    }

    @Test
    public void deriveKey_bindsSeed() {
        byte[] a = KeyLadder.deriveKey(TEST_SEED, TEST_CRC, TEST_CERT, TEST_PKG);
        byte[] b = KeyLadder.deriveKey(TEST_SEED + 1, TEST_CRC, TEST_CERT, TEST_PKG);
        assertFalse("编译期 seed 不同必须换 key", java.util.Arrays.equals(a, b));
    }

    /** HKDF 必须与 RFC 5869 Test Case 1 一致（证明 HKDF 实现本身对）。 */
    @Test
    public void hkdf_matchesRfc5869Case1() {
        byte[] ikm = new byte[22];
        for (int i = 0; i < 22; i++) ikm[i] = 0x0b;
        byte[] salt = new byte[]{0,1,2,3,4,5,6,7,8,9,10,11,12};
        byte[] info = new byte[]{(byte)0xf0,(byte)0xf1,(byte)0xf2,(byte)0xf3,
                                 (byte)0xf4,(byte)0xf5,(byte)0xf6,(byte)0xf7,
                                 (byte)0xf8,(byte)0xf9};
        // RFC 5869 A.1 Test Case 1（SHA-256）。注意：末尾是 d5b887185865，
        // 不是 73f03e7e382b11 —— 后者是 A.4（SHA-1）的尾巴，抄错过的教训。
        String expected = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                        + "34007208d5b887185865";   /* 42 字节 */
        byte[] okm = KeyLadder.hkdfSha256(salt, ikm, info, 42);
        assertEquals(expected, HexUtils.toHexString(okm));
    }

    /** master 必须包含 seed：改 seed 必变（证明 seed 真进了 master）。 */
    @Test
    public void master_bindsSeed() {
        byte[] a = KeyLadder.computeMaster(TEST_SEED, TEST_CRC);
        byte[] b = KeyLadder.computeMaster(TEST_SEED + 1, TEST_CRC);
        assertFalse("master 必须随 seed 变", java.util.Arrays.equals(a, b));
    }

    /** master 必须包含 CRC32(.text)：改 CRC 必变（证明代码自绑定成立）。 */
    @Test
    public void master_bindsTextCrc() {
        byte[] a = KeyLadder.computeMaster(TEST_SEED, 0L);
        byte[] b = KeyLadder.computeMaster(TEST_SEED, 0x12345678L);
        assertFalse("master 必须随 .text CRC 变（patch 即自毁）",
                java.util.Arrays.equals(a, b));
    }

    /**
     * 证书提取：用一个真实 APK 验证（若能找到）。
     * 找不到则 skip 而非 fail —— 测试环境不该依赖外部文件存在。
     */
    @Test
    public void extractCertDer_realApk_ifPresent() throws Exception {
        String[] candidates = {
                System.getenv("TEST_APK"),
                "/storage/emulated/0/常用/工作台😡/简盒-正式版-v2.1.2_212-20261025-0704-a8403a9 (1)_sign.apk",
        };
        File apk = null;
        for (String c : candidates) {
            if (c != null && new File(c).isFile()) { apk = new File(c); break; }
        }
        if (apk == null) {
            System.out.println("⏭ 跳过：未找到测试 APK（设 TEST_APK 环境变量可启用）");
            return;
        }
        byte[] der = KeyLadder.extractFirstCertDer(apk);
        assertNotNull("必须能提出证书 DER", der);
        // ⚠️ byte 是有符号的：0x82 作为 byte 是 -126，直接 == 0x82 永远 false。
        //    必须 & 0xFF。这个坑在 KeyLadder.findDer 里也踩过（2026-10-26）。
        assertTrue("DER 必须是 30 82 开头的 X.509",
                (der[0] & 0xFF) == 0x30 && (der[1] & 0xFF) == 0x82);
        // 与 C 侧/openssl 对拍的权威值（2026-10-26 实测）
        String expectedSha256 = "d82e48dae7ce6268ebcefd61feb8128fdf1a55f574cbbbc788db7be4491b689e";
        String actual = KeyLadder.sha256Hex(der);
        assertEquals("证书 DER 的 SHA-256 必须与 apksigner/openssl 一致",
                expectedSha256, actual);
    }
}
