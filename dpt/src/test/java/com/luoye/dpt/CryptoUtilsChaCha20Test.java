package com.luoye.dpt;

import com.luoye.dpt.util.CryptoUtils;

import org.junit.Assert;
import org.junit.Test;

/**
 * ChaCha20 tests for OoooooOooo v3 payloads.
 *
 * The native runtime decrypts with mbedtls_chacha20_crypt, so the vectors below
 * come from RFC 8439 section 2.4.2. If this test passes, the Java build side and
 * the mbedtls runtime agree on the keystream.
 */
public class CryptoUtilsChaCha20Test {

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    /**
     * RFC 8439 section 2.4.2 test vector.
     *
     * Values are transcribed verbatim from the RFC:
     *   Key   = 00:01:02:...:1f
     *   Nonce = 00:00:00:00:00:00:00:4a:00:00:00:00
     *   Initial Counter = 1
     */
    @Test
    public void chacha20KnownVector() {
        byte[] key = hexToBytes(
                "000102030405060708090a0b0c0d0e0f"
                        + "101112131415161718191a1b1c1d1e1f");
        byte[] nonce = hexToBytes("000000000000004a00000000");
        byte[] plaintext = ("Ladies and Gentlemen of the class of '99: If I could offer you "
                + "only one tip for the future, sunscreen would be it.")
                .getBytes(java.nio.charset.StandardCharsets.US_ASCII);

        byte[] ciphertext = hexToBytes(
                "6e2e359a2568f98041ba0728dd0d69"
                        + "81e97e7aec1d4360c20a27afccfd9f"
                        + "ae0bf91b65c5524733ab8f593dabc"
                        + "d62b3571639d624e65152ab8f530c"
                        + "359f0861d807ca0dbf500d6a6156a3"
                        + "8e088a22b65e52bc514d16ccf8068"
                        + "18ce91ab77937365af90bbf74a35b"
                        + "e6b40b8eedf2785e42874d");

        byte[] actual = CryptoUtils.chacha20Crypt(key, nonce, plaintext, 1);

        Assert.assertArrayEquals(ciphertext, actual);
    }

    /**
     * RFC 8439 section 2.3.2 publishes the raw keystream of block 1, which pins
     * the block function independently of any ciphertext.
     */
    @Test
    public void chacha20KeystreamVector() {
        byte[] key = new byte[32];
        for (int i = 0; i < key.length; i++) {
            key[i] = (byte) i;
        }
        byte[] nonce = hexToBytes("000000000000004a00000000");
        byte[] keystream = hexToBytes(
                "224f51f3401bd9e12fde276fb8631ded"
                        + "8c131f823d2c06e27e4fcaec9ef3cf7"
                        + "88a3b0aa372600a92b57974cded2b93"
                        + "34794cba40c63e34cdea212c4cf07d4"
                        + "1b7");

        // Encrypting 64 zero bytes at counter 1 must yield exactly the keystream.
        byte[] zeros = new byte[64];
        byte[] actual = CryptoUtils.chacha20Crypt(key, nonce, zeros, 1);

        Assert.assertArrayEquals(keystream, actual);
    }

    /**
     * The cipher is symmetric, so decryption must restore the plaintext.
     */
    @Test
    public void chacha20RoundTrip() {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        for (int i = 0; i < key.length; i++) {
            key[i] = (byte) (i * 7 + 1);
        }
        for (int i = 0; i < nonce.length; i++) {
            nonce[i] = (byte) (i * 3 + 5);
        }

        byte[] plaintext = new byte[257];
        for (int i = 0; i < plaintext.length; i++) {
            plaintext[i] = (byte) (i ^ 0x5A);
        }

        byte[] encrypted = CryptoUtils.chacha20Crypt(key, nonce, plaintext);
        Assert.assertNotEquals("ciphertext must differ from plaintext",
                java.util.Arrays.toString(plaintext), java.util.Arrays.toString(encrypted));
        Assert.assertArrayEquals(plaintext, CryptoUtils.chacha20Crypt(key, nonce, encrypted));
    }

    /**
     * Different nonces must produce different keystreams for the same key.
     */
    @Test
    public void chacha20NonceSeparation() {
        byte[] key = new byte[32];
        byte[] plaintext = "the quick brown fox".getBytes(java.nio.charset.StandardCharsets.US_ASCII);

        byte[] enc0 = CryptoUtils.chacha20Crypt(key, CryptoUtils.buildChaCha20Nonce(0), plaintext);
        byte[] enc1 = CryptoUtils.chacha20Crypt(key, CryptoUtils.buildChaCha20Nonce(1), plaintext);

        Assert.assertNotEquals(java.util.Arrays.toString(enc0), java.util.Arrays.toString(enc1));
    }

    /**
     * nonce layout: little-endian methodIdx in the low 4 bytes, zero above.
     *
     * Must match build_chacha20_nonce() in shell/src/main/cpp/dpt_crypto.cpp.
     */
    @Test
    public void buildNonceLayout() {
        byte[] nonce = CryptoUtils.buildChaCha20Nonce(0x04030201);
        Assert.assertEquals(12, nonce.length);
        Assert.assertArrayEquals(
                hexToBytes("010203040000000000000000"), nonce);

        byte[] zero = CryptoUtils.buildChaCha20Nonce(0);
        Assert.assertArrayEquals(new byte[12], zero);
    }

    /**
     * Distinct method indices must never share a nonce.
     */
    @Test
    public void buildNonceUniquePerMethod() {
        Assert.assertFalse(java.util.Arrays.equals(
                CryptoUtils.buildChaCha20Nonce(1), CryptoUtils.buildChaCha20Nonce(2)));
        Assert.assertFalse(java.util.Arrays.equals(
                CryptoUtils.buildChaCha20Nonce(0), CryptoUtils.buildChaCha20Nonce(65536)));
        // high bit of methodIdx must land in the last low-order byte
        Assert.assertEquals((byte) 0x80,
                CryptoUtils.buildChaCha20Nonce(0x80000000)[3]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void chacha20RejectsShortKey() {
        CryptoUtils.chacha20Crypt(new byte[16], new byte[12], new byte[4]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void chacha20RejectsShortNonce() {
        CryptoUtils.chacha20Crypt(new byte[32], new byte[8], new byte[4]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void chacha20RejectsEmptyInput() {
        CryptoUtils.chacha20Crypt(new byte[32], new byte[12], new byte[0]);
    }
}
