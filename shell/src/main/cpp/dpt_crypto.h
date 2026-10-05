//
// Created by luoyesiqiu on 2025/11/26.
//

#ifndef DPT_DPT_CRYPTO_H
#define DPT_DPT_CRYPTO_H

#include <vector>
#include <stdint.h>
#include <stddef.h>
#include <mbedtls/aes.h>
#include <mbedtls/md.h>
#include <mbedtls/chacha20.h>
#include "common/dpt_log.h"

// ChaCha20 parameters. mbedtls_chacha20_crypt takes a 32-byte key, a 12-byte
// nonce and a 32-bit block counter (RFC 8439 layout).
#define DPT_CHACHA20_KEY_SIZE   32
#define DPT_CHACHA20_NONCE_SIZE 12

std::vector<uint8_t> hmac_sha256(const uint8_t *key,
                                 size_t key_len,
                                 const uint8_t *input,
                                 size_t input_len);

std::vector<uint8_t> aes_cbc_decrypt(const uint8_t *key,
                                     size_t key_bits,
                                     const uint8_t *iv,
                                     const uint8_t *in,
                                     size_t inlen);

/**
 * Build the 12-byte ChaCha20 nonce for a method.
 *
 * methodIdx is encoded little-endian into the low 4 bytes and the remaining
 * 8 bytes stay zero. Distinct method indices therefore always produce distinct
 * nonces (no collision below 2^32 methods), while the same method always uses
 * the same key+nonce pair - required for symmetric encryption.
 *
 * NOTE: the layout must stay identical to CryptoUtils.buildChaCha20Nonce() on
 * the build side, otherwise decryption yields garbage.
 */
void build_chacha20_nonce(uint32_t methodIdx, uint8_t *nonce);

/**
 * Decrypt a code item's instructions in place (ChaCha20 is a stream cipher,
 * so the same call both encrypts and decrypts).
 *
 * @param key       32-byte insns crypt key (ShellConfig::aes_key)
 * @param methodIdx method index used to derive the nonce
 * @param in        encrypted instructions
 * @param inlen     number of bytes
 * @param out       output buffer, may alias in
 * @return true on success
 */
bool chacha20_crypt_insns(const uint8_t *key,
                          uint32_t methodIdx,
                          const uint8_t *in,
                          size_t inlen,
                          uint8_t *out);

#endif //DPT_DPT_CRYPTO_H
