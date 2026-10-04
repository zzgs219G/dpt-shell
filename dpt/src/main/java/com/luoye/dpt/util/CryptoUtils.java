package com.luoye.dpt.util;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class CryptoUtils {
    public static final String RC4Transform = "RC4";
    private static final String HMAC_SHA256 = "HmacSHA256";

    public static byte[] rc4Crypt(byte[] key, byte[] in) {
        try {
            Cipher cipher = Cipher.getInstance(RC4Transform);
            SecretKeySpec spec = new SecretKeySpec(key, RC4Transform);
            cipher.init(Cipher.ENCRYPT_MODE,spec);
            return cipher.doFinal(in);
        } catch (Exception e) {
        }

        return null;
    }

    /**
     * RC4 key for a code item: AES-256 config key followed by little-endian methodIdx.
     */
    public static byte[] buildInsnsRc4Key(byte[] aesKey, int methodIndex) {
        if (aesKey == null || aesKey.length == 0) {
            throw new IllegalArgumentException("aes key is empty");
        }
        ByteBuffer buf = ByteBuffer.allocate(aesKey.length + 4).order(ByteOrder.LITTLE_ENDIAN);
        buf.put(aesKey);
        buf.putInt(methodIndex);
        return buf.array();
    }

    /**
     * Derive AES-256 key by HMAC-SHA256(randomKey, UTF-8(keyMaterial)).
     */
    public static byte[] hmacSha256(byte[] key, String keyMaterial) {
        if (key == null || key.length == 0) {
            throw new IllegalArgumentException("hmac key is empty");
        }
        if (keyMaterial == null || keyMaterial.isEmpty()) {
            throw new IllegalArgumentException("key material is empty");
        }
        try {
            Mac mac = Mac.getInstance(HMAC_SHA256);
            mac.init(new SecretKeySpec(key, HMAC_SHA256));
            byte[] result = mac.doFinal(keyMaterial.getBytes(StandardCharsets.UTF_8));
            if (result == null || result.length != 32) {
                throw new IllegalStateException("unexpected hmac length");
            }
            return result;
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException("hmac-sha256 failed", e);
        }
    }

    public static byte[] aesEncrypt(byte[] key, byte[] iv, byte[] in) {
        try {
            Key secretKeySpec = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

            cipher.init(Cipher.ENCRYPT_MODE,secretKeySpec,ivParameterSpec);
            return cipher.doFinal(in);
        }
        catch (Exception e){
        }
        return null;
    }

    // ---------------------------------------------------------------------
    // ChaCha20 (RFC 8439), used for OoooooOooo v3 payloads.
    //
    // Implemented here rather than pulled from BouncyCastle because dpt.jar
    // ships without that dependency. The native side decrypts with mbedtls
    // (shell/src/main/cpp/dpt_crypto.cpp), so both implementations must follow
    // RFC 8439 exactly - verified by chacha20KnownVector in CryptoUtilsTest.
    // ---------------------------------------------------------------------

    public static final int CHACHA20_KEY_SIZE = 32;
    public static final int CHACHA20_NONCE_SIZE = 12;

    private static final int CHACHA20_STATE_CONSTANTS = 4;
    private static final int CHACHA20_ROUNDS = 20;

    private static final byte[] CHACHA20_CONSTANTS = "expand 32-byte k".getBytes(StandardCharsets.US_ASCII);

    private static int rotl32(int value, int count) {
        return (value << count) | (value >>> (32 - count));
    }

    private static void quarterRound(int[] state, int a, int b, int c, int d) {
        state[a] += state[b];
        state[d] = rotl32(state[d] ^ state[a], 16);
        state[c] += state[d];
        state[b] = rotl32(state[b] ^ state[c], 12);
        state[a] += state[b];
        state[d] = rotl32(state[d] ^ state[a], 8);
        state[c] += state[d];
        state[b] = rotl32(state[b] ^ state[c], 7);
    }

    /**
     * Produce one 64-byte ChaCha20 keystream block for the given state.
     */
    private static byte[] chacha20Block(int[] state) {
        int[] working = state.clone();
        for (int i = 0; i < CHACHA20_ROUNDS; i += 2) {
            // column rounds
            quarterRound(working, 0, 4, 8, 12);
            quarterRound(working, 1, 5, 9, 13);
            quarterRound(working, 2, 6, 10, 14);
            quarterRound(working, 3, 7, 11, 15);
            // diagonal rounds
            quarterRound(working, 0, 5, 10, 15);
            quarterRound(working, 1, 6, 11, 12);
            quarterRound(working, 2, 7, 8, 13);
            quarterRound(working, 3, 4, 9, 14);
        }

        byte[] block = new byte[64];
        for (int i = 0; i < 16; i++) {
            int value = working[i] + state[i];
            block[i * 4] = (byte) value;
            block[i * 4 + 1] = (byte) (value >>> 8);
            block[i * 4 + 2] = (byte) (value >>> 16);
            block[i * 4 + 3] = (byte) (value >>> 24);
        }
        return block;
    }

    private static int readUint32Le(byte[] src, int offset) {
        return (src[offset] & 0xFF)
                | ((src[offset + 1] & 0xFF) << 8)
                | ((src[offset + 2] & 0xFF) << 16)
                | ((src[offset + 3] & 0xFF) << 24);
    }

    private static void writeUint32Le(byte[] dst, int offset, int value) {
        dst[offset] = (byte) value;
        dst[offset + 1] = (byte) (value >>> 8);
        dst[offset + 2] = (byte) (value >>> 16);
        dst[offset + 3] = (byte) (value >>> 24);
    }

    /**
     * 12-byte nonce for a method: little-endian methodIdx in the low 4 bytes,
     * the remaining 8 bytes zero.
     *
     * Must stay byte-identical to build_chacha20_nonce() on the native side.
     */
    public static byte[] buildChaCha20Nonce(int methodIdx) {
        byte[] nonce = new byte[CHACHA20_NONCE_SIZE];
        writeUint32Le(nonce, 0, methodIdx);
        return nonce;
    }

    /**
     * ChaCha20 encryption/decryption of {@code in}. The cipher is symmetric, so
     * one method covers both directions and output may alias input.
     *
     * @param key   32-byte key
     * @param nonce 12-byte nonce
     * @param in    input bytes, must not be empty
     * @return the transformed bytes, or null when the arguments are invalid
     */
    public static byte[] chacha20Crypt(byte[] key, byte[] nonce, byte[] in) {
        return chacha20Crypt(key, nonce, in, 0);
    }

    /**
     * ChaCha20 starting at an explicit block counter.
     *
     * dpt itself always uses counter 0 (see chacha20Crypt(key, nonce, in)).
     * The counter is exposed so the RFC 8439 test vector, which specifies
     * counter = 1, can be reproduced exactly.
     *
     * @param initialCounter first block index
     */
    public static byte[] chacha20Crypt(byte[] key, byte[] nonce, byte[] in, int initialCounter) {
        if (key == null || key.length != CHACHA20_KEY_SIZE) {
            throw new IllegalArgumentException("chacha20 key must be " + CHACHA20_KEY_SIZE + " bytes");
        }
        if (nonce == null || nonce.length != CHACHA20_NONCE_SIZE) {
            throw new IllegalArgumentException("chacha20 nonce must be " + CHACHA20_NONCE_SIZE + " bytes");
        }
        if (in == null || in.length == 0) {
            throw new IllegalArgumentException("chacha20 input is empty");
        }
        if (initialCounter < 0) {
            throw new IllegalArgumentException("chacha20 initial counter must not be negative");
        }

        int[] state = new int[16];
        for (int i = 0; i < CHACHA20_STATE_CONSTANTS; i++) {
            state[i] = readUint32Le(CHACHA20_CONSTANTS, i * 4);
        }
        for (int i = 0; i < 8; i++) {
            state[CHACHA20_STATE_CONSTANTS + i] = readUint32Le(key, i * 4);
        }
        state[12] = initialCounter;
        for (int i = 0; i < 3; i++) {
            state[13 + i] = readUint32Le(nonce, i * 4);
        }

        byte[] out = new byte[in.length];
        int offset = 0;
        while (offset < in.length) {
            byte[] keystream = chacha20Block(state);
            int chunk = Math.min(64, in.length - offset);
            for (int i = 0; i < chunk; i++) {
                out[offset + i] = (byte) (in[offset + i] ^ keystream[i]);
            }
            offset += chunk;
            state[12]++;
        }
        return out;
    }
}
