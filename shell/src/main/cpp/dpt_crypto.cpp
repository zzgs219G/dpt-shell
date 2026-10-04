//
// Created by luoyesiqiu on 2025/11/26.
//

#include "dpt_crypto.h"
#include <cstring>
#include <climits>
#include "rc4/rc4.h"

std::vector<uint8_t> hmac_sha256(const uint8_t *key,
                                 size_t key_len,
                                 const uint8_t *input,
                                 size_t input_len) {
    if (key == nullptr || key_len == 0 || input == nullptr || input_len == 0) {
        DLOGE("invalid hmac input");
        return {};
    }

    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md_info == nullptr) {
        DLOGE("mbedtls sha256 unavailable");
        return {};
    }

    std::vector<uint8_t> out(32);
    int ret = mbedtls_md_hmac(md_info, key, key_len, input, input_len, out.data());
    if (ret != 0) {
        DLOGE("hmac-sha256 failed: %d", ret);
        return {};
    }
    return out;
}

std::vector<uint8_t> aes_cbc_decrypt(const uint8_t *key,
                                     size_t key_bits,
                                     const uint8_t *iv,
                                     const uint8_t *in,
                                     size_t inlen) {
    if (key == nullptr || iv == nullptr || in == nullptr || inlen == 0 || (inlen % 16) != 0) {
        DLOGE("invalid aes cbc input");
        return {};
    }
    if (key_bits != 128 && key_bits != 192 && key_bits != 256) {
        DLOGE("unsupported aes key bits: %zu", key_bits);
        return {};
    }

    std::vector<uint8_t> out_vec(inlen);

    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);

    int setkey_ret = mbedtls_aes_setkey_dec(&ctx, key, static_cast<unsigned int>(key_bits));

    if(setkey_ret == 0) {
        DLOGD("set key success");
    }
    else {
        DLOGE("set key fail");
        mbedtls_aes_free(&ctx);
        return {};
    }

    uint8_t new_iv[16] = {0};
    memcpy(new_iv, iv, 16);

    int ret = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, inlen, new_iv, in, out_vec.data());

    if(ret == 0) {
        DLOGD("decrypt ret: %d", ret);
    }
    else {
        DLOGE("decrypt fail");
        mbedtls_aes_free(&ctx);
        return {};
    }

    if (!out_vec.empty()) {
        uint8_t pad = out_vec.back();
        DLOGD("padding: %d", pad);
        if (pad > 0 && pad <= 16 && pad <= out_vec.size()) {
            out_vec.resize(out_vec.size() - pad);
        } else {
            DLOGE("invalid padding");
            mbedtls_aes_free(&ctx);
            return {};
        }
    }

    mbedtls_aes_free(&ctx);

    return out_vec;
}

void build_chacha20_nonce(uint32_t methodIdx, uint8_t *nonce) {
    if (nonce == nullptr) {
        return;
    }
    memset(nonce, 0, DPT_CHACHA20_NONCE_SIZE);
    // Little-endian methodIdx into the low 4 bytes, mirroring
    // CryptoUtils.buildChaCha20Nonce() on the build side.
    nonce[0] = static_cast<uint8_t>(methodIdx & 0xFF);
    nonce[1] = static_cast<uint8_t>((methodIdx >> 8) & 0xFF);
    nonce[2] = static_cast<uint8_t>((methodIdx >> 16) & 0xFF);
    nonce[3] = static_cast<uint8_t>((methodIdx >> 24) & 0xFF);
}

bool chacha20_crypt_insns(const uint8_t *key,
                          uint32_t methodIdx,
                          const uint8_t *in,
                          size_t inlen,
                          uint8_t *out) {
    if (key == nullptr || in == nullptr || out == nullptr || inlen == 0) {
        return false;
    }

    uint8_t nonce[DPT_CHACHA20_NONCE_SIZE];
    build_chacha20_nonce(methodIdx, nonce);

    // ChaCha20 is a stream cipher: counter starts at 0 and the same call both
    // encrypts and decrypts, so output may alias input.
    int ret = mbedtls_chacha20_crypt(key, nonce, 0, inlen, in, out);
    if (ret != 0) {
        DLOGE("chacha20 crypt failed: %d", ret);
        return false;
    }
    return true;
}

bool rc4_crypt_insns(const uint8_t *key,
                     uint32_t methodIdx,
                     const uint8_t *in,
                     size_t inlen,
                     uint8_t *out) {
    if (key == nullptr || in == nullptr || out == nullptr || inlen == 0) {
        return false;
    }
    if (inlen > static_cast<size_t>(INT_MAX)) {
        return false;
    }

    // Legacy v2 layout: 32-byte aes_key followed by little-endian methodIdx.
    uint8_t rc4_key[DPT_CHACHA20_KEY_SIZE + sizeof(uint32_t)];
    memcpy(rc4_key, key, DPT_CHACHA20_KEY_SIZE);
    memcpy(rc4_key + DPT_CHACHA20_KEY_SIZE, &methodIdx, sizeof(methodIdx));

    struct rc4_state state;
    rc4_init(&state, rc4_key, static_cast<int>(sizeof(rc4_key)));
    rc4_crypt(&state, in, out, static_cast<int>(inlen));
    return true;
}
