//
// Created by luoyesiqiu
//

#ifndef DPT_MULTIDEXCODE_H
#define DPT_MULTIDEXCODE_H

#include <cstdint>
#include <cstring>
#include <cstddef>
#include <type_traits>
#include "CodeItem.h"
#include "common/dpt_log.h"

// OoooooOooo payload versions. v2 stores instructions encrypted with RC4,
// v3 stores them encrypted with ChaCha20. The runtime picks the decryption
// routine once, while parsing the header, so patchMethod stays branch-free.
#define DPT_MULTI_DEX_CODE_VERSION_V2 2
#define DPT_MULTI_DEX_CODE_VERSION_V3 3

/**
 * Decrypt one code item's instructions in place.
 *
 * Both implementations are symmetric, so the same signature also covers the
 * build-time encryption direction on the Java side.
 */
typedef bool (*insns_crypt_fn)(const uint8_t *key,
                               uint32_t methodIdx,
                               const uint8_t *in,
                               size_t inlen,
                               uint8_t *out);

namespace dpt::data {
        class MultiDexCode {
        private:
            size_t m_size;
            uint8_t *m_buffer;
            uint16_t m_version;
            // Selected once from m_version so the patch hot path has no branch.
            insns_crypt_fn m_crypt_insns;
        public:
            static MultiDexCode *getInst();

            MultiDexCode();

            void init(uint8_t *buffer, size_t size);

            uint8_t readUInt8(uint32_t offset);

            uint16_t readUInt16(uint32_t offset);

            uint32_t readUInt32(uint32_t offset);

            uint16_t readVersion();

            uint16_t readDexCount();

            uint32_t *readDexCodeIndex(int *count);

            dpt::data::CodeItem *nextCodeItem(uint32_t *offset);

            /**
             * Decrypt instructions with the routine bound to this payload's
             * version. Falls back to RC4 for unknown versions so a v2 payload
             * keeps working; logs a warning.
             */
            bool cryptInsns(const uint8_t *key,
                            uint32_t methodIdx,
                            const uint8_t *in,
                            size_t inlen,
                            uint8_t *out) const;
    };



#endif //DPT_MULTIDEXCODE_H
