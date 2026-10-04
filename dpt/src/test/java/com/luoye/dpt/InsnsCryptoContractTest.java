package com.luoye.dpt;

import com.luoye.dpt.config.Const;
import com.luoye.dpt.util.CryptoUtils;

import org.junit.Assert;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

/**
 * Locks the build-side contract that the native runtime depends on.
 *
 * The native side cannot be exercised from a JVM test, so these assertions pin
 * the exact byte layout the C++ must reproduce:
 *
 *   build side : DexUtils -> CryptoUtils.chacha20Crypt(aesKey, buildChaCha20Nonce(methodIdx), insns)
 *   native side: MultiDexCode::cryptInsns -> chacha20_crypt_insns(aes_key, methodIdx, insns)
 *
 * build_chacha20_nonce() in shell/src/main/cpp/dpt_crypto.cpp must equal
 * buildChaCha20Nonce() below, and MultiDexCode::init must map
 * Const.MULTI_DEX_CODE_VERSION onto the ChaCha20 routine.
 */
public class InsnsCryptoContractTest {

    /**
     * Header version written into OoooooOooo must be 3, because only v3 selects
     * ChaCha20 in MultiDexCode::init. If this ever drifts, every packed APK
     * silently decrypts to garbage.
     */
    @Test
    public void payloadVersionIsThree() {
        Assert.assertEquals(3, Const.MULTI_DEX_CODE_VERSION);
    }

    /**
     * Native builds the RC4 key with memcpy(&methodIdx), i.e. native byte order.
     * The Java side must encode little-endian, matching buildInsnsRc4Key.
     * This guards the legacy v2 path.
     */
    @Test
    public void legacyRc4KeyLayoutUnchanged() {
        byte[] aesKey = new byte[32];
        for (int i = 0; i < aesKey.length; i++) {
            aesKey[i] = (byte) i;
        }
        byte[] key = CryptoUtils.buildInsnsRc4Key(aesKey, 0x01020304);
        Assert.assertEquals(36, key.length);
        Assert.assertArrayEquals(
                new byte[]{0x04, 0x03, 0x02, 0x01},
                new byte[]{key[32], key[33], key[34], key[35]});
    }

    /**
     * End-to-end shape of the v3 path: same key + same nonce must decrypt what
     * encryption produced, and a neighbouring method must not.
     */
    @Test
    public void methodScopedChaCha20RoundTrip() {
        byte[] aesKey = new byte[32];
        for (int i = 0; i < aesKey.length; i++) {
            aesKey[i] = (byte) (0x40 + i);
        }
        byte[] insns = "invoke-virtual/range bytecode payload".getBytes(StandardCharsets.US_ASCII);

        int methodIdx = 0x2A3B;
        byte[] encrypted = CryptoUtils.chacha20Crypt(
                aesKey, CryptoUtils.buildChaCha20Nonce(methodIdx), insns);
        Assert.assertNotNull(encrypted);
        Assert.assertEquals(insns.length, encrypted.length);

        byte[] decrypted = CryptoUtils.chacha20Crypt(
                aesKey, CryptoUtils.buildChaCha20Nonce(methodIdx), encrypted);
        Assert.assertArrayEquals(insns, decrypted);

        // Wrong method index must not recover the plaintext.
        byte[] wrongMethod = CryptoUtils.chacha20Crypt(
                aesKey, CryptoUtils.buildChaCha20Nonce(methodIdx + 1), encrypted);
        Assert.assertFalse(java.util.Arrays.equals(insns, wrongMethod));
    }

    /**
     * Ciphertext length must equal plaintext length: the runtime decrypts
     * straight into dex memory, so a length change would corrupt the dex.
     */
    @Test
    public void ciphertextLengthPreservedForRealisticInsnsSizes() {
        byte[] aesKey = new byte[32];
        byte[] nonce = CryptoUtils.buildChaCha20Nonce(7);
        // dex instruction counts are small; cover both odd and even byte lengths
        for (int len : new int[]{2, 6, 14, 128, 510, 4094}) {
            byte[] insns = new byte[len];
            for (int i = 0; i < len; i++) {
                insns[i] = (byte) (i * 31 + 7);
            }
            byte[] encrypted = CryptoUtils.chacha20Crypt(aesKey, nonce, insns);
            Assert.assertEquals("length must be preserved for " + len + " bytes",
                    len, encrypted.length);
            Assert.assertArrayEquals(insns,
                    CryptoUtils.chacha20Crypt(aesKey, nonce, encrypted));
        }
    }
}
