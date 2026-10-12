//
// Created by luoyesiqiu
//

#ifndef DPT_MULTIDEXCODE_H
#define DPT_MULTIDEXCODE_H

#include <atomic>
#include <cstdint>
#include <cstring>
#include <cstddef>
#include <memory>
#include <type_traits>
#include "common/dpt_log.h"

/**
 * xixin_data payload, v5 layout.
 *
 * The runtime reads this straight out of mapped memory, so every field is
 * little-endian and every accessor must stay within [0, size).
 *
 *   Header (24 bytes)
 *     u32 magic = 0x4F4F4F35
 *     u16 version = 5
 *     u16 dexCount
 *     u32 classIndexOffset
 *     u32 blockTableOffset
 *     u32 blockCount
 *     u32 reserved
 *
 *   ClassIndex[] (16 bytes per entry, sorted by (dexIdx, classDataOff))
 *     — identical to v4:
 *     +0  u8  dexIdx
 *     +1  u8  flags        reserved
 *     +2  u16 methodCount
 *     +4  u32 classDataOff
 *     +8  u32 methodDataOff  relative offset in the *virtual raw* method-data
 *                            space (v4 semantic kept: the layout the flat
 *                            record stream would have had)
 *     +12 u32 reserved
 *
 *   BlockTable[] (16 bytes per entry, rawOffset strictly ascending,
 *   class-aligned — a class's records never straddle two blocks):
 *     +0  u32 rawOffset    virtual raw offset, same space as methodDataOff
 *     +4  u32 rawSize      uncompressed size
 *     +8  u32 compOffset   absolute offset from the payload start
 *     +12 u32 compSize     ciphertext size
 *
 *   Blocks[]: chacha20(aes_key, nonce = block index, raw-deflate(records))
 *
 *     Method records (plaintext once the block is materialized; format
 *     unchanged from v4):
 *       u32 methodIdx
 *       u16 insnsSize          BYTE count, not code-unit count
 *       u8[insnsSize] insns    PLAINTEXT — encryption is per-block in v5
 *
 * v4 payloads (flat per-method encrypted records) are no longer accepted:
 * the payload version always travels with its own shell so, so old packed
 * APKs keep running with their own embedded library.
 */
#define DPT_MULTI_DEX_CODE_VERSION_V5    5
#define DPT_MULTI_DEX_CODE_MAGIC          0x4F4F4F35u
#define DPT_MULTI_DEX_CODE_HEADER_SIZE    24
#define DPT_MULTI_DEX_CODE_INDEX_ENTRY_SIZE 16
#define DPT_MULTI_DEX_CODE_BLOCK_ENTRY_SIZE 16

/**
 * Sanity bound for one block's rawSize. The packer targets ~64KB blocks (a
 * single oversized class may exceed that), but the table is attacker-influenced
 * data, so materialization refuses anything above this before allocating.
 */
#define DPT_MULTI_DEX_CODE_BLOCK_MAX_RAW (16u * 1024u * 1024u)

/**
 * Materialize one method's insns into {@code out} (the dex's code item).
 *
 * The routine is bound once per payload in init so the patch path never
 * branches on the payload version. v5 blocks are decrypted when materialized,
 * so the bound routine for v5 is a plain copy; the signature is kept shared
 * with the old per-method ChaCha20 restorer.
 */
typedef bool (*insns_restore_fn)(const uint8_t *key,
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

    /** One BlockTable entry. Fixed 16-byte stride, same reasoning as above. */
    struct BlockTableEntry {
        uint32_t rawOffset;
        uint32_t rawSize;
        uint32_t compOffset;
        uint32_t compSize;
    };

    static_assert(sizeof(BlockTableEntry) == 16, "BlockTableEntry must be exactly 16 bytes");

    /**
     * A view onto one method's insns. For a materialized v5 block this points
     * into the decrypted cache; nothing persists beyond the walk, so the
     * class-loading hot path stays free of heap traffic (aside from the one
     * block materialization on cache miss).
     */
    struct CodeItemView {
        uint32_t methodIdx;
        uint16_t insnsSize;               // byte count
        const uint8_t *insns;             // plaintext insns
    };

    class MultiDexCode {
    private:
        size_t m_size;
        uint8_t *m_buffer;
        uint16_t m_version;
        uint16_t m_dexCount;
        uint32_t m_classIndexOffset;
        uint32_t m_blockTableOffset;
        uint32_t m_blockCount;
        uint32_t m_blocksOffset;          // derived: blockTableOffset + blockCount * 16
        // Bound once from the version so patching never branches on it.
        insns_restore_fn m_restore_insns;

        // Grow-only block cache, indexed by blockIdx. Class loading is
        // concurrent and a patch walk holds raw pointers into one block's
        // buffer, so blocks are materialized at most once and NEVER freed
        // (freeing a replaced block would be a use-after-free). A lost race
        // just materializes the same block twice and drops the loser; slots
        // are published with release stores. Total memory is bounded by the
        // payload's raw size and only grows with the classes actually loaded —
        // v4 held the whole uncompressed payload for the process lifetime, so
        // this is never worse.
        mutable std::unique_ptr<std::atomic<uint8_t *>[]> m_cachePtrs;
        mutable std::unique_ptr<std::atomic<uint32_t>[]> m_cacheSizes;

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

        /** Last block whose rawOffset <= rawOffset, or nullptr. */
        const BlockTableEntry *findBlock(uint32_t rawOffset) const;

        /** Decrypt + inflate one block into the cache. Returns false on any inconsistency. */
        bool materializeBlock(uint32_t blockIdx, const uint8_t *aesKey) const;

    public:
        static MultiDexCode *getInst();

        MultiDexCode();

        void init(uint8_t *buffer, size_t size);

        uint16_t getVersion() const;

        uint16_t getDexCount() const;

        uint32_t getClassIndexOffset() const;

        uint32_t getBlockTableOffset() const;

        uint32_t getBlockCount() const;

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
         *
         * <p>{@code aesKey} is used on a block-cache miss to decrypt the block
         * holding this class (g_shell_config.aes_key at the call site).
         */
        CodeItemView getMethodData(const ClassIndexEntry *entry,
                                   uint16_t index,
                                   const uint8_t *aesKey) const;

        /**
         * Materialize a method's insns into {@code out}. For v5 payloads the
         * bound routine is a plain copy: the block cache already holds
         * decrypted records.
         */
        bool restoreInsns(const uint8_t *key,
                          uint32_t methodIdx,
                          const uint8_t *in,
                          size_t inlen,
                          uint8_t *out) const;

        /** True when init accepted the payload. */
        bool isValid() const;
    };
}

#endif //DPT_MULTIDEXCODE_H
