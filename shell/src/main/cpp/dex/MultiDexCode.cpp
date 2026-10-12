//
// Created by luoyesiqiu
//

#include "MultiDexCode.h"
#include "dpt_crypto.h"

#include <algorithm>
#include <utility>
#include <zlib.h>

namespace dpt::data {

/**
 * Raw DEFLATE inflate (zlib windowBits = -15), matching the build side's
 * CryptoUtils.deflateRaw (nowrap). The inflated length must equal dstLen
 * exactly — anything else means the block or the table is corrupt.
 */
static bool inflate_raw(const uint8_t *src, size_t srcLen, uint8_t *dst, size_t dstLen) {
    if (srcLen == 0 || dstLen == 0 || dstLen > DPT_MULTI_DEX_CODE_BLOCK_MAX_RAW) {
        return false;
    }
    z_stream zs{};
    if (inflateInit2(&zs, -15) != Z_OK) {
        return false;
    }
    zs.next_in = const_cast<Bytef *>(reinterpret_cast<const Bytef *>(src));
    zs.avail_in = static_cast<uInt>(srcLen);
    zs.next_out = reinterpret_cast<Bytef *>(dst);
    zs.avail_out = static_cast<uInt>(dstLen);
    int rc = inflate(&zs, Z_FINISH);
    inflateEnd(&zs);
    return rc == Z_STREAM_END && zs.avail_out == 0;
}

/** v5 restore routine: blocks are already decrypted, records are plaintext. */
static bool restore_insns_memcpy(const uint8_t * /*key*/,
                                 uint32_t /*methodIdx*/,
                                 const uint8_t *in,
                                 size_t inlen,
                                 uint8_t *out) {
    if (in == nullptr || out == nullptr || inlen == 0) {
        return false;
    }
    memcpy(out, in, inlen);
    return true;
}

dpt::data::MultiDexCode* dpt::data::MultiDexCode::getInst(){
    static auto *m_inst = new MultiDexCode();
    return m_inst;
}

dpt::data::MultiDexCode::MultiDexCode()
        : m_size(0), m_buffer(nullptr), m_version(0), m_dexCount(0),
          m_classIndexOffset(0), m_blockTableOffset(0), m_blockCount(0),
          m_blocksOffset(0), m_restore_insns(nullptr) {
}

void dpt::data::MultiDexCode::init(uint8_t* buffer, size_t size){
    m_buffer = buffer;
    m_size = size;
    m_classIndexOffset = 0;
    m_blockTableOffset = 0;
    m_blockCount = 0;
    m_blocksOffset = 0;
    m_restore_insns = nullptr;
    m_cachePtrs.reset();
    m_cacheSizes.reset();

    if (m_buffer == nullptr || m_size < DPT_MULTI_DEX_CODE_HEADER_SIZE) {
        ELOG("xixin_data too small: %zu", size);
        return;
    }

    uint32_t magic = readUInt32(0);
    m_version = readUInt16(4);

    // v5 only. A v2/v3/v4 payload has a different layout, so accepting it here
    // would make every offset below point at the wrong bytes. (v4 APKs keep
    // running with their own embedded so, which accepts v4.)
    if (magic != DPT_MULTI_DEX_CODE_MAGIC || m_version != DPT_MULTI_DEX_CODE_VERSION_V5) {
        ELOG("unsupported xixin_data: magic=0x%x version=%u", magic, m_version);
        m_version = 0;
        return;
    }

    m_dexCount = readUInt16(6);
    m_classIndexOffset = readUInt32(8);
    m_blockTableOffset = readUInt32(12);
    m_blockCount = readUInt32(16);
    // +20 reserved, ignored

    // The offsets are attacker-influenced data; validate before anything walks
    // them. The block count is bounded first so the blocksOffset multiplication
    // below cannot wrap.
    bool offsetsOk = m_classIndexOffset >= DPT_MULTI_DEX_CODE_HEADER_SIZE
            && m_blockTableOffset >= m_classIndexOffset + DPT_MULTI_DEX_CODE_INDEX_ENTRY_SIZE
            && m_blockCount > 0
            && m_blockCount <= m_size / DPT_MULTI_DEX_CODE_BLOCK_ENTRY_SIZE;
    if (offsetsOk) {
        m_blocksOffset = m_blockTableOffset
                + m_blockCount * DPT_MULTI_DEX_CODE_BLOCK_ENTRY_SIZE;
        offsetsOk = m_blocksOffset <= m_size;
    }
    if (!offsetsOk) {
        ELOG("corrupt xixin_data offsets: ci=%u bt=%u blocks=%u size=%zu",
              m_classIndexOffset, m_blockTableOffset, m_blockCount, m_size);
        m_classIndexOffset = 0;
        m_blockTableOffset = 0;
        m_blockCount = 0;
        m_blocksOffset = 0;
        return;
    }

    // Eagerly validate the whole block table: raw spans must ascend strictly
    // (blocks partition the virtual raw space) and ciphertext must stay inside
    // the payload.
    const BlockTableEntry *table =
            reinterpret_cast<const BlockTableEntry *>(m_buffer + m_blockTableOffset);
    for (uint32_t i = 0; i < m_blockCount; i++) {
        const BlockTableEntry &e = table[i];
        bool bad = e.rawSize == 0
                || e.compSize == 0
                || e.compOffset < m_blocksOffset
                || e.compSize > m_size - e.compOffset
                || e.rawSize > DPT_MULTI_DEX_CODE_BLOCK_MAX_RAW
                || (i > 0 && e.rawOffset <= table[i - 1].rawOffset);
        if (bad) {
            ELOG("corrupt block table entry %u: raw=%u@%u comp=%u@%u",
                  i, e.rawSize, e.rawOffset, e.compSize, e.compOffset);
            m_classIndexOffset = 0;
            m_blockTableOffset = 0;
            m_blockCount = 0;
            m_blocksOffset = 0;
            return;
        }
    }

    // Bind the routine once so the patch path stays branch-free. v5 records are
    // plaintext inside materialized blocks, so the restore is a plain copy.
    m_restore_insns = restore_insns_memcpy;

    // Allocate the grow-only block cache now that the (validated) block count
    // is known. Slots start empty and are published once, never freed.
    m_cachePtrs.reset(new std::atomic<uint8_t *>[m_blockCount]);
    m_cacheSizes.reset(new std::atomic<uint32_t>[m_blockCount]);
    for (uint32_t i = 0; i < m_blockCount; i++) {
        m_cachePtrs[i].store(nullptr, std::memory_order_relaxed);
        m_cacheSizes[i].store(0, std::memory_order_relaxed);
    }

    DLOGI("xixin_data v5 loaded: dexCount=%u classes=%u blocks=%u",
          m_dexCount, getClassCount(), m_blockCount);
}

bool dpt::data::MultiDexCode::isValid() const {
    return m_restore_insns != nullptr && m_classIndexOffset != 0;
}

uint16_t dpt::data::MultiDexCode::getVersion() const {
    return m_version;
}

uint16_t dpt::data::MultiDexCode::getDexCount() const {
    return m_dexCount;
}

uint32_t dpt::data::MultiDexCode::getClassIndexOffset() const {
    return m_classIndexOffset;
}

uint32_t dpt::data::MultiDexCode::getBlockTableOffset() const {
    return m_blockTableOffset;
}

uint32_t dpt::data::MultiDexCode::getBlockCount() const {
    return m_blockCount;
}

uint32_t dpt::data::MultiDexCode::getClassCount() const {
    if (m_buffer == nullptr || m_classIndexOffset == 0
            || m_blockTableOffset < m_classIndexOffset) {
        return 0;
    }
    return (m_blockTableOffset - m_classIndexOffset) / sizeof(ClassIndexEntry);
}

const ClassIndexEntry* dpt::data::MultiDexCode::getClassIndexBegin() const {
    if (m_buffer == nullptr || m_classIndexOffset == 0) return nullptr;
    return reinterpret_cast<const ClassIndexEntry*>(m_buffer + m_classIndexOffset);
}

const ClassIndexEntry* dpt::data::MultiDexCode::getClassIndexEnd() const {
    const ClassIndexEntry* begin = getClassIndexBegin();
    if (begin == nullptr) return nullptr;
    return begin + getClassCount();
}

const ClassIndexEntry* dpt::data::MultiDexCode::findClassIndex(uint8_t dexIdx,
                                                                uint32_t classDataOff) const {
    const ClassIndexEntry* begin = getClassIndexBegin();
    const ClassIndexEntry* end = getClassIndexEnd();
    if (begin == nullptr || end == nullptr) return nullptr;

    // Entries are sorted by (dexIdx, classDataOff) ascending, unsigned.
    const ClassIndexEntry* it = std::lower_bound(
            begin, end, classDataOff,
            [dexIdx](const ClassIndexEntry& e, uint32_t key) {
                return e.dexIdx != dexIdx ? e.dexIdx < dexIdx : e.classDataOff < key;
            });

    if (it == end || it->dexIdx != dexIdx || it->class_data_off() != classDataOff) {
        return nullptr;
    }
    return it;
}

const BlockTableEntry* dpt::data::MultiDexCode::findBlock(uint32_t rawOffset) const {
    if (m_buffer == nullptr || m_blockTableOffset == 0 || m_blockCount == 0) {
        return nullptr;
    }
    const BlockTableEntry *begin =
            reinterpret_cast<const BlockTableEntry *>(m_buffer + m_blockTableOffset);
    const BlockTableEntry *end = begin + m_blockCount;

    // Last entry with rawOffset <= rawOffset: blocks partition the virtual raw
    // space in strictly ascending order.
    const BlockTableEntry *it = std::upper_bound(
            begin, end, rawOffset,
            [](uint32_t key, const BlockTableEntry &e) { return key < e.rawOffset; });
    if (it == begin) return nullptr;
    return it - 1;
}

bool dpt::data::MultiDexCode::materializeBlock(uint32_t blockIdx,
                                               const uint8_t *aesKey) const {
    if (m_buffer == nullptr || m_blockTableOffset == 0
            || blockIdx >= m_blockCount || aesKey == nullptr) {
        return false;
    }
    // Fast path: already materialized by this or another thread. release on
    // the publish store pairs with this acquire, so the rawSize read in
    // getMethodData is guaranteed visible.
    uint8_t *existing = m_cachePtrs[blockIdx].load(std::memory_order_acquire);
    if (existing != nullptr) {
        return true;
    }

    const BlockTableEntry *e =
            reinterpret_cast<const BlockTableEntry *>(m_buffer + m_blockTableOffset)
                    + blockIdx;

    std::unique_ptr<uint8_t[]> comp(new uint8_t[e->compSize]);
    memcpy(comp.get(), m_buffer + e->compOffset, e->compSize);

    // Decrypt in place. ChaCha20 is symmetric; the nonce is derived from the
    // block index (build_chacha20_nonce), matching MultiDexCodeUtils.
    if (!chacha20_crypt_insns(aesKey, blockIdx, comp.get(), e->compSize, comp.get())) {
        ELOG("block %u decrypt failed", blockIdx);
        return false;
    }

    std::unique_ptr<uint8_t[]> raw(new uint8_t[e->rawSize]);
    if (!inflate_raw(comp.get(), e->compSize, raw.get(), e->rawSize)) {
        ELOG("block %u inflate failed: comp=%u raw=%u", blockIdx, e->compSize, e->rawSize);
        return false;
    }

    // Publish. Each slot is written at most once with the same value, so a
    // lost race is harmless: the loser's unique_ptr frees its own redundant
    // copy and the winner's buffer serves everyone. Buffers are never freed
    // afterwards — patch walks hold raw pointers into them.
    m_cacheSizes[blockIdx].store(e->rawSize, std::memory_order_relaxed);
    m_cachePtrs[blockIdx].store(raw.get(), std::memory_order_release);
    (void) raw.release();
    return true;
}

dpt::data::CodeItemView dpt::data::MultiDexCode::getMethodData(const ClassIndexEntry* entry,
                                                               uint16_t index,
                                                               const uint8_t *aesKey) const {
    CodeItemView view{0, 0, nullptr};
    if (entry == nullptr || m_buffer == nullptr || m_classIndexOffset == 0) return view;
    if (index >= entry->methodCount) return view;

    // Locate the block holding this class's records. The packer never lets a
    // class straddle blocks, so one materialization covers the whole walk.
    const BlockTableEntry *block = findBlock(entry->methodDataOff);
    if (block == nullptr
            || entry->methodDataOff < block->rawOffset
            || entry->methodDataOff >= block->rawOffset + block->rawSize) {
        ELOG("class data off %u not inside any block", entry->methodDataOff);
        return view;
    }

    const BlockTableEntry *tableBase =
            reinterpret_cast<const BlockTableEntry *>(m_buffer + m_blockTableOffset);
    uint32_t blockIdx = static_cast<uint32_t>(block - tableBase);
    if (!materializeBlock(blockIdx, aesKey)) {
        return view;
    }
    const uint8_t *raw = m_cachePtrs[blockIdx].load(std::memory_order_acquire);
    if (raw == nullptr) {
        // Unreachable in practice: materializeBlock returning true means the
        // slot was already published or was published by us just now. Treat a
        // violation as corruption rather than dereferencing anything.
        return view;
    }
    const size_t avail = m_cacheSizes[blockIdx].load(std::memory_order_relaxed);
    if (avail == 0 || avail != block->rawSize) {
        return view;
    }

    // Walk forward past the preceding records. Records are variable length, so
    // this cannot be indexed directly; the loop is bounded by methodCount, which
    // is small (tens) for a real class.
    //
    // methodDataOff is a *virtual raw* offset: relative to the start of the
    // method-data region, exactly where the inflated block's own origin sits at
    // block->rawOffset. Every bound below is measured against the block's raw
    // size, never against the payload size.
    const uint8_t* base = raw;
    size_t off = static_cast<size_t>(entry->methodDataOff) - block->rawOffset;
    for (uint16_t i = 0; i < index; i++) {
        if (off + 6 > avail) return view;
        uint16_t sz = readUInt16At(base, off + 4);
        // insnsSize is a BYTE count: advancing by 6 + sz, not 6 + sz * 2.
        off += 6u + sz;
        if (off > avail) return view;
    }

    if (off + 6 > avail) return view;
    // A record must fit entirely inside the materialized block.
    uint16_t insnsSize = readUInt16At(base, off + 4);
    if (off + 6u + insnsSize > avail) return view;

    view.methodIdx = readUInt32At(base, off);
    view.insnsSize = insnsSize;
    view.insns = base + off + 6;
    return view;
}

bool dpt::data::MultiDexCode::restoreInsns(const uint8_t *key,
                                           uint32_t methodIdx,
                                           const uint8_t *in,
                                           size_t inlen,
                                           uint8_t *out) const {
    if (m_restore_insns == nullptr) {
        ELOG("insns restore routine is not initialized");
        return false;
    }
    return m_restore_insns(key, methodIdx, in, inlen, out);
}

} // namespace dpt::data
