package com.luoye.dpt.util;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.util.jar.JarFile;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * KeyLadder.java —— 段加密密钥派生链（Java 侧，与 C 侧 dpt_keyladder.c 逐字节一致）
 *
 * 【为什么必须两侧各写一份】
 *   C 侧在 so 里跑，Java 侧在打包时跑，两者无法共享代码。历史上
 *   "两侧以为一致其实不一致"的事故反复发生（apk-protect-action 报错十八：
 *   两包内容一致却一崩一不崩）。结论：**必须有可执行的对拍，不能只看注释。**
 *
 * 【派生公式（改这里必须同步 C 侧 dpt_keyladder.c 与对拍测试）】
 *   master = SHA256( SEED_8 || CRC32(.text)_4 || "dpt-kl-v1" )
 *   salt   = SHA256(certDER)
 *   key    = HKDF-SHA256(ikm=master, salt=salt, info="dpt-sec-v1"+pkg, len=16)
 *
 * ⚠️ Java 侧拿不到 CRC32(.text)：
 *   .text 是编译产物，Java 侧读不到"运行期将要被 hash 的那段"的精确内容
 *   （因为 strip/重定位后字节会变）。所以 Java 侧用 master_seed 单独派生，
 *   而 C 侧用 seed+CRC32 派生 —— 这两者【必然不同】。
 *
 *   → 所以实际接入方式不是"Java 加密、C 解密同一段"，而是：
 *     · .bitcode 段（壳自身防御代码）由 C 侧自产自销：
 *       打包时用 Java 派生 key 加密，运行时 C 用同一 key 解密 —— 这条路
 *       要求两侧 key 一致，即 Java 也要能算出 CRC32(.text)。
 *     · 现实约束下，本期采用【C 侧派生 + Java 侧灌入】：
 *       Java 侧派生 key → 加密段 → 把 key 的派生材料（seed）写进 so 的
 *       预留位置 → C 侧运行期读材料 + 算自己的 CRC32 → 派生同一 key。
 *
 *   本期只交付 Java 侧的派生实现（供对拍与后续接入），不改变加密流程。
 */
public final class KeyLadder {

    private KeyLadder() {}

    /** 与 C 侧 DPT_KL_INFO_PREFIX 一致。 */
    private static final String INFO_PREFIX = "dpt-sec-v1";

    /** 与 C 侧 master 里的版本串一致。 */
    private static final String MASTER_BID = "dpt-kl-v1";

    /** 派生 key 长度，与 C 侧 DPT_KL_KEY_LEN 一致。 */
    public static final int KEY_LEN = 16;

    /* ── SHA-256 ─────────────────────────────────────────────────── */

    /** SHA-256 的 hex 形态（对拍测试用）。 */
    public static String sha256Hex(byte[] data) {
        return HexUtils.toHexString(sha256(data));
    }

    public static byte[] sha256(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(data);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /* ── HKDF-SHA256（RFC 5869 §2，自实现）──────────────────────────
     *
     * 为什么不用 javax.crypto 的 HKDF：JDK 17 没有标准 HKDF API
     * （javax.crypto.KDF 要到 JDK 才有），且 Tink 之类的外部依赖不该
     * 为一个 40 行的东西进打包器。用 Mac(HmacSHA256) 拼最稳。 */

    public static byte[] hkdfSha256(byte[] salt, byte[] ikm, byte[] info, int len) {
        try {
            // PRK = HMAC-SHA256(salt, IKM)。salt 为空时用 32 个 0（RFC 5869 §2.2）
            byte[] realSalt = (salt == null || salt.length == 0) ? new byte[32] : salt;
            Mac prkMac = Mac.getInstance("HmacSHA256");
            prkMac.init(new SecretKeySpec(realSalt, "HmacSHA256"));
            byte[] prk = prkMac.doFinal(ikm);

            // T(i) = HMAC(PRK, T(i-1) || info || i)
            Mac tMac = Mac.getInstance("HmacSHA256");
            tMac.init(new SecretKeySpec(prk, "HmacSHA256"));
            ByteArrayOutputStream okm = new ByteArrayOutputStream();
            byte[] t = new byte[0];
            byte counter = 1;
            while (okm.size() < len) {
                tMac.reset();
                if (t.length > 0) tMac.update(t);
                if (info != null && info.length > 0) tMac.update(info);
                tMac.update(counter);
                t = tMac.doFinal();
                int take = Math.min(len - okm.size(), t.length);
                okm.write(t, 0, take);
                counter++;
            }
            return okm.toByteArray();
        } catch (Exception e) {
            throw new IllegalStateException("HKDF-SHA256 failed", e);
        }
    }

    /* ── master ──────────────────────────────────────────────────── */

    /** 8 字节 seed 转字节数组（与 C 侧的小端拆分一致）。 */
    public static byte[] seedToBytes(long seed) {
        byte[] b = new byte[8];
        for (int i = 0; i < 8; i++) {
            b[i] = (byte) (seed >> (i * 8));
        }
        return b;
    }

    /**
     * master = SHA256(seed_8 || crc32_4 || "dpt-kl-v1")
     *
     * crc32 由调用方给：C 侧运行期算 CRC32(.text)，Java 侧若要模拟可传 0
     * （仅用于对拍"除 CRC32 外的部分"）。
     */
    public static byte[] computeMaster(long seed, long crc32Text) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(seedToBytes(seed));
            md.update(ByteBuffer.allocate(4).putInt((int) crc32Text).array());
            md.update(MASTER_BID.getBytes(StandardCharsets.US_ASCII));
            return md.digest();
        } catch (Exception e) {
            throw new IllegalStateException("master computation failed", e);
        }
    }

    /* ── 派生 key ────────────────────────────────────────────────── */

    /**
     * key = HKDF-SHA256(ikm=master, salt=SHA256(certDER), info="dpt-sec-v1"+pkg, 16)
     *
     * certDer: APK 第一签名者证书 DER
     * pkg:     应用包名
     */
    public static byte[] deriveKey(long seed, long crc32Text, byte[] certDer, String pkg) {
        byte[] master = computeMaster(seed, crc32Text);
        byte[] salt = sha256(certDer);
        byte[] info = (INFO_PREFIX + pkg).getBytes(StandardCharsets.UTF_8);
        return hkdfSha256(salt, master, info, KEY_LEN);
    }

    /* ── 证书 DER 提取（v1/v2/v3）────────────────────────────────────
     *
     * 为什么不用 PackageManager：打包时没有设备上下文，且我们要的是"打进
     * APK 的那张证书"而不是"设备上安装的那张"（重签后会变）。
     *
     * 优先 v3(0xF05368C0) → v2(0x7109871A) → v1(META-INF/*.RSA)。
     * 与 apk-protect-action 的 extract-cert-fp.py 同优先级。 */

    private static final int V2_BLOCK_ID = 0x7109871A;
    private static final int V3_BLOCK_ID = 0xF05368C0;

    public static byte[] extractFirstCertDer(File apk) throws IOException {
        // v2/v3 优先
        byte[] der = extractFromSigningBlock(apk);
        if (der != null) return der;
        // v1 兜底：META-INF/*.RSA 是 PKCS#7，证书在里面
        return extractFromV1(apk);
    }

    /**
     * 从 APK Signing Block 里扫 v2/v3 block 并提取证书。
     *
     * ⚠️ 实现策略与 C 侧 dpt_cert.c 完全一致（双包实测通过）：
     *    【不解析嵌套结构】，改为从 cd_offset 往前扫 v2/v3 的 block ID。
     *    原因：v2/v3 block 内部的 length 字段"是否含自身 4 字节"在 spec
     *    与实现间不一致，逐层解会偏差 678 字节（本机用 apksigner 权威 DER
     *    反推实测）。block ID 是 0x7109871A/0xF05368C0 这种极特殊的值，
     *    扫到的几乎不可能是误命中。
     *
     *    扫到 ID 后，在其后的 value 范围里找 DER 特征：
     *      30 82 XX XX，且【前 4 字节】小端 u32 == 4 + XX XX（DER 总长度）。
     *    "前 4 字节"这个位置是关键 —— 长度前缀在 DER 之前，不在 DER 头里
     *    （同样是实测踩出来的）。
     */
    private static byte[] extractFromSigningBlock(File apk) throws IOException {
        byte[] data = readAll(apk);

        /* 1. EOCD → cd_offset */
        int eocd = lastIndexOf(data, new byte[]{'P', 'K', 0x05, 0x06});
        if (eocd < 0 || eocd + 20 > data.length) return null;
        int cdOff = le32(data, eocd + 16);
        if (cdOff <= 0 || cdOff > data.length) return null;

        /* 2. 从 cdOff-16（magic 起点）往前扫 64KB 找 v2/v3 block ID */
        int scanStart = Math.max(0, cdOff - 16 - 65536);
        for (int i = cdOff - 16; i >= scanStart + 12; i--) {
            int id = le32(data, i);
            if (id != V2_BLOCK_ID && id != V3_BLOCK_ID) continue;
            long pairLen = le64(data, i - 8);
            if (pairLen < 16 || pairLen > (8 << 20)) continue;

            int vStart = i + 4;
            int vEnd = (int) Math.min(vStart + pairLen, data.length);
            byte[] der = findDer(data, vStart, vEnd);
            if (der != null) return der;
        }
        return null;
    }

    private static byte[] extractFromV1(File apk) throws IOException {
        try (ZipFile zf = new ZipFile(apk)) {
            ZipEntry best = null;
            java.util.Enumeration<? extends ZipEntry> en = zf.entries();
            while (en.hasMoreElements()) {
                ZipEntry e = en.nextElement();
                String n = e.getName();
                if (n.startsWith("META-INF/") && (n.endsWith(".RSA") || n.endsWith(".DSA") || n.endsWith(".EC"))) {
                    if (best == null || n.length() < best.getName().length()) best = e;
                }
            }
            if (best == null) return null;
            byte[] p7 = readAll(zf.getInputStream(best));
            return findDer(p7, 0, p7.length);
        }
    }

    /* 扫描 DER：30 82 XX XX，且前 4 字节小端 u32 == 总长度(4+XXXX)。 */
    private static byte[] findDer(byte[] data, int start, int end) {
        for (int i = Math.max(start, 4); i + 4 <= end; i++) {
            if ((data[i] & 0xFF) == 0x30 && (data[i + 1] & 0xFF) == 0x82) {
                int bodyLen = ((data[i + 2] & 0xFF) << 8) | (data[i + 3] & 0xFF);
                int total = bodyLen + 4;
                int pfx = le32(data, i - 4);
                if (total < 0x104 || total > 0x1003) continue;
                if (le32(data, i - 4) != total) continue;
                if (i + total > data.length) continue;
                byte[] out = new byte[total];
                System.arraycopy(data, i, out, 0, total);
                return out;
            }
        }
        return null;
    }

    /* ── 小工具 ──────────────────────────────────────────────────── */

    private static byte[] readAll(File f) throws IOException {
        try (FileInputStream in = new FileInputStream(f);
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
            return out.toByteArray();
        }
    }

    private static byte[] readAll(java.io.InputStream in) throws IOException {
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
            return out.toByteArray();
        }
    }

    private static int lastIndexOf(byte[] data, byte[] needle) {
        return lastIndexOf(data, needle, data.length);
    }

    private static int lastIndexOf(byte[] data, byte[] needle, int limit) {
        int end = Math.min(limit, data.length - needle.length);
        for (int i = end; i >= 0; i--) {
            boolean ok = true;
            for (int j = 0; j < needle.length; j++) {
                if (data[i + j] != needle[j]) { ok = false; break; }
            }
            if (ok) return i;
        }
        return -1;
    }

    private static int le32(byte[] d, int off) {
        return (d[off] & 0xFF) | ((d[off + 1] & 0xFF) << 8)
                | ((d[off + 2] & 0xFF) << 16) | ((d[off + 3] & 0xFF) << 24);
    }

    private static long le64(byte[] d, int off) {
        long v = 0;
        for (int i = 7; i >= 0; i--) v = (v << 8) | (d[off + i] & 0xFF);
        return v;
    }
}
