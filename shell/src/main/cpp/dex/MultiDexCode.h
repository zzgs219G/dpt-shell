//
// Created by luoyesiqiu
//

#ifndef DPT_MULTIDEXCODE_H
#define DPT_MULTIDEXCODE_H

#include <cstdint>
#include <cstring>
#include <cstddef>
#include <type_traits>
#include "common/dpt_log.h"

/**
 * OoooooOooo payload, v4 layout.
 *
 * The runtime reads this straight out of mapped memory, so every field is
 * little-endian and every accessor must stay within [0, size).
 *
 *   Header (16 bytes)
 *     u32 magic = 0x4F4F4F34
 *     u16 version = 4
 *     u16 dexCount
 *     u32 classIndexOffset
 *     u32 methodDataOffset
 *
 *   ClassIndex[] (16 bytes per entry, sorted by (dexIdx, classDataOff))
 *     +0  u8  dexIdx
 *     +1  u8  flags        reserved
 *     +2  u16 methodCount
 *     +4  u32 classDataOff
 *     +8  u32 methodDataOff  relative to methodDataOffset
 *     +12 u32 reserved
 *
 *   MethodData[] (variable length)
 *     u32 methodIdx
 *     u16 insnsSize          BYTE count, not code-unit count
 *     u8[insnsSize] encryptedInsns
 */
#define DPT_MULTI_DEX_CODE_VERSION_V4    4
#define DPT_MULTI_DEX_CODE_MAGIC          0x4F4F4F34u
#define DPT_MULTI_DEX_CODE_HEADER_SIZE    16
#define DPT_MULTI_DEX_CODE_INDEX_ENTRY_SIZE 16

/** Decrypt one code item's instructions in place. */
typedef bool (*insns_crypt_fn)(const uint8_t *key,
                               uint32_t methodIdx,
                               const uint8_t *in,
                               size_t inlen,
                               uint8_t *out);

namespace dpt::data {

    /** One ClassIndex entry. Layout is fixed so the array can be walked with a fixed stride. */
    struct ClassIndexEntry {
        uint8_t dexIdx;
        uint8_t flags;
        uint16_t methodCount;
        uint32_t classDataOff;
        uint32_t methodDataOff;
        uint32_t reserved;

        /**
         * member accessor for readability at call sites; the field is public so the
         * array can also be indexed directly.
         */
        inline uint32_t class_data_off() const { return classDataOff; }
    };

    static_assert(sizeof(ClassIndexEntry) == 16, "ClassIndexEntry must be exactly 16 bytes");

    /**
     * A view onto one method's ciphertext. Points into the mapped payload; nothing
     * is allocated, so the class-loading hot path stays free of heap traffic.
     */
    struct CodeItemView {
        uint32_t methodIdx;
        uint16_t insnsSize;               // byte count
        const uint8_t *encryptedInsns;
    };

    class MultiDexCode {
    private:
        size_t m_size;
        uint8_t *m_buffer;
        uint16_t m_version;
        uint16_t m_dexCount;
        uint32_t m_classIndexOffset;
        uint32_t m_methodDataOffset;
        // Bound once from the version so patching never branches on it.
        insns_crypt_fn m_crypt_insns;

        // Private byte readers: inlined in the header so class loading does not
        // pay a cross-translation-unit call per field.
        inline uint8_t readUInt8(uint32_t offset) const {
            return m_buffer[offset];
        }

        inline uint16_t readUInt16(uint32_t offset) const {
            uint16_t t;
            __builtin_memcpy(&t, m_buffer + offset, sizeof(t));
            return t;
        }

        inline uint32_t readUInt32(uint32_t offset) const {
            uint32_t t;
            __builtin_memcpy(&t, m_buffer + offset, sizeof(t));
            return t;
        }

        // Same readers, but taking an explicit base pointer so getMethodData can
        // walk without re-anchoring on m_buffer.
        static inline uint16_t readUInt16At(const uint8_t *base, size_t offset) {
            uint16_t t;
            __builtin_memcpy(&t, base + offset, sizeof(t));
            return t;
        }

        static inline uint32_t readUInt32At(const uint8_t *base, size_t offset) {
            uint32_t t;
            __builtin_memcpy(&t, base + offset, sizeof(t));
            return t;
        }

    public:
        static MultiDexCode *getInst();

        MultiDexCode();

        void init(uint8_t *buffer, size_t size);

        uint16_t getVersion() const;

        uint16_t getDexCount() const;

        uint32_t getClassIndexOffset() const;

        uint32_t getMethodDataOffset() const;

        const ClassIndexEntry *getClassIndexBegin() const;

        const ClassIndexEntry *getClassIndexEnd() const;

        /** Number of entries in ClassIndex[], derived from the two offsets. */
        uint32_t getClassCount() const;

        /**
         * Locate a class by (dexIdx, classDataOff) using a binary search over the
         * sorted index. Returns nullptr when the class was not protected.
         */
        const ClassIndexEntry *findClassIndex(uint8_t dexIdx, uint32_t classDataOff) const;

        /**
         * Return the {@code index}-th method of a class.
         *
         * <p>Callers rely on this matching patchClass's own ClassData walk order,
         * which is direct methods first, then virtual methods -- the same order
         * ClassData.allMethods() produced the payload with.
         */
        CodeItemView getMethodData(const ClassIndexEntry *entry, uint16_t index) const;

        /**
         * Decrypt instructions with the routine bound to this payload's version.
         */
        bool cryptInsns(const uint8_t *key,
                        uint32_t methodIdx,
                        const uint8_t *in,
                        size_t inlen,
                        uint8_t *out) const;

        /** True when init accepted the payload. */
        bool isValid() const;
    };
}

#endif //DPT_MULTIDEXCODE_H