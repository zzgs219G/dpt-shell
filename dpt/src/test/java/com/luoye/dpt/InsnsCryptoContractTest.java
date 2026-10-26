package com.luoye.dpt;

import com.luoye.dpt.config.Const;
import com.luoye.dpt.util.CryptoUtils;

import org.junit.Assert;
import org.junit.Test;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Locks the build-side contract that the native runtime depends on.
 *
 * The native side cannot be exercised from a JVM test, so these assertions pin
 * the exact byte semantics the C++ must reproduce:
 *
 *   build side : MultiDexCodeUtils.compressBlock
 *                -> CryptoUtils.deflateRaw(plaintext records)
 *                -> CryptoUtils.chacha20Crypt(aesKey, buildChaCha20Nonce(blockIdx), block)
 *   native side: MultiDexCode::materializeBlock
 *                -> chacha20_crypt_insns(aes_key, blockIdx, block)
 *                -> zlib inflateInit2(-15)
 *
 * build_chacha20_nonce() in shell/src/main/cpp/dpt_crypto.cpp must equal
 * buildChaCha20Nonce() below (the argument is now the BLOCK index, not a method
 * index), and MultiDexCode::init must accept only Const.MULTI_DEX_CODE_VERSION.
 */
public class InsnsCryptoContractTest {

    /**
     * Header version written into xixin_data must be 5, because only v5 is
     * accepted by MultiDexCode::init. If this ever drifts, every packed APK
     * silently decrypts to garbage.
     */
    @Test
    public void payloadVersionIsFive() {
        Assert.assertEquals(5, Const.MULTI_DEX_CODE_VERSION);
    }

    @Test
    public void magicIsOoo5() {
        Assert.assertEquals(0x4F4F4F35, Const.MULTI_DEX_CODE_MAGIC);
        byte[] le = ByteBuffer.allocate(4)
                .order(java.nio.ByteOrder.LITTLE_ENDIAN)
                .putInt(Const.MULTI_DEX_CODE_MAGIC)
                .array();
        Assert.assertArrayEquals(new byte[]{'5', 'O', 'O', 'O'}, le);
    }

    /**
     * End-to-end shape of the v5 block path: same key + same block nonce must
     * decrypt what encryption produced, and a neighbouring block must not.
     */
    @Test
    public void blockScopedChaCha20RoundTrip() {
        byte[] aesKey = new byte[32];
        for (int i = 0; i < aesKey.length; i++) {
            aesKey[i] = (byte) (0x40 + i);
        }
        byte[] block = "deflated method records of one 64KB block".getBytes(
                StandardCharsets.US_ASCII);

        int blockIdx = 0x2A3B;
        byte[] encrypted = CryptoUtils.chacha20Crypt(
                aesKey, CryptoUtils.buildChaCha20Nonce(blockIdx), block);
        Assert.assertNotNull(encrypted);
        Assert.assertEquals(block.length, encrypted.length);

        byte[] decrypted = CryptoUtils.chacha20Crypt(
                aesKey, CryptoUtils.buildChaCha20Nonce(blockIdx), encrypted);
        Assert.assertArrayEquals(block, decrypted);

        // Wrong block index must not recover the plaintext.
        byte[] wrongBlock = CryptoUtils.chacha20Crypt(
                aesKey, CryptoUtils.buildChaCha20Nonce(blockIdx + 1), encrypted);
        Assert.assertFalse(Arrays.equals(block, wrongBlock));
    }

    /**
     * Ciphertext length must equal plaintext length: the runtime decrypts into
     * an exact-size heap buffer and asserts the inflated length against the
     * block table, so a length change would break materialization.
     */
    @Test
    public void blockCiphertextLengthPreservedForRealisticSizes() {
        byte[] aesKey = new byte[32];
        byte[] nonce = CryptoUtils.buildChaCha20Nonce(7);
        // blocks are ~64KB; cover small, odd and even lengths around that
        for (int len : new int[]{2, 6, 14, 128, 510, 4094, 65536}) {
            byte[] data = new byte[len];
            for (int i = 0; i < len; i++) {
                data[i] = (byte) (i * 31 + 7);
            }
            byte[] encrypted = CryptoUtils.chacha20Crypt(aesKey, nonce, data);
            Assert.assertEquals("length must be preserved for " + len + " bytes",
                    len, encrypted.length);
            Assert.assertArrayEquals(data,
                    CryptoUtils.chacha20Crypt(aesKey, nonce, encrypted));
        }
    }

    /**
     * The compression pairing with the runtime: native inflates with
     * zlib windowBits = -15 (raw deflate). inflateRaw below uses
     * {@code new Inflater(true)} — the Java-side equivalent — so a round-trip
     * here pins the stream format the C++ must read.
     */
    @Test
    public void rawDeflateRoundTrip() {
        for (int len : new int[]{1, 2, 64, 1024, 65536, 70000}) {
            byte[] data = new byte[len];
            for (int i = 0; i < len; i++) {
                data[i] = (byte) (i * 7 + (i % 3));
            }
            byte[] deflated = CryptoUtils.deflateRaw(data);
            Assert.assertNotNull("deflate must succeed for " + len + " bytes", deflated);
            byte[] inflated = CryptoUtils.inflateRaw(deflated, len);
            Assert.assertNotNull("inflate must succeed for " + len + " bytes", inflated);
            Assert.assertArrayEquals(data, inflated);
        }
    }

    /**
     * v5 exists because instruction bytes compress well. Pin that assumption:
     * if dex bytecode ever stops compressing ~50%, the whole format change is
     * moot and should be revisited.
     */
    @Test
    public void instructionLikeDataCompressesMeaningfully() {
        byte[] data = new byte[65536];
        for (int i = 0; i < data.length; i++) {
            // dex-ish: small register numbers, repeating opcode patterns
            data[i] = (byte) ((i % 16) * 13 + (i % 5));
        }
        byte[] deflated = CryptoUtils.deflateRaw(data);
        Assert.assertTrue("期望 64KB 指令样数据压到一半以下，实际 " + deflated.length,
                deflated.length < data.length / 2);
    }

    /**
     * 回归：超大单块 + 高重复内容必须能压完。
     *
     * <p>CI 实测（apk-protect-action run 40326879912）旧实现在真实包上抛
     * {@code IllegalStateException: deflater made no progress} —— 它把
     * {@code deflate()} 返回 0 一律当成死锁，而 Deflater 允许返回 0（应查
     * {@code needsInput()}）。v5 的单块上限是 {@code MULTI_DEX_CODE_BLOCK_MAX_RAW_SIZE}
     * （16MB），经过 dex2c/stringenc 的包完全可能产出远超 64KB 目标的块，
     * 所以这里用大于 {@code MULTI_DEX_CODE_BLOCK_TARGET_SIZE} 的高重复数据钉住。
     *
     * <p>同时校验 raw deflate 的 round-trip：格式必须仍能被
     * {@code Inflater(true)} 解回（native 侧是 zlib windowBits=-15）。
     */
    @Test
    public void deflateRaw_handlesOversizedHighlyCompressibleBlock() {
        int len = 4 * 1024 * 1024;   // 4MB，远大于 64KB 目标块
        byte[] data = new byte[len];
        for (int i = 0; i < len; i++) {
            data[i] = (byte) (i & 0xFF);   // 高重复：每个周期完全一致
        }
        byte[] deflated = CryptoUtils.deflateRaw(data);
        Assert.assertNotNull(deflated);
        Assert.assertTrue("高重复数据必须显著压缩，实际 " + deflated.length,
                deflated.length < len / 100);
        byte[] inflated = CryptoUtils.inflateRaw(deflated, len);
        Assert.assertNotNull("raw deflate 必须能被 Inflater(true) 解回", inflated);
        Assert.assertArrayEquals(data, inflated);
    }

    /** 回归：块边界附近（64KB±1）输入也要逐字节 round-trip。 */
    @Test
    public void deflateRaw_roundTripsAroundChunkBoundary() {
        for (int len : new int[]{65535, 65536, 65537, 131072, 131073}) {
            byte[] data = new byte[len];
            for (int i = 0; i < len; i++) {
                data[i] = (byte) ((i * 31) ^ (i >>> 5));
            }
            byte[] deflated = CryptoUtils.deflateRaw(data);
            byte[] inflated = CryptoUtils.inflateRaw(deflated, len);
            Assert.assertNotNull("len=" + len + " 必须能解回", inflated);
            Assert.assertArrayEquals("len=" + len + " 必须逐字节一致", data, inflated);
        }
    }
}
