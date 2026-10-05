//
// Created by luoyesiqiu
//

#include "MultiDexCode.h"
#include "dpt_crypto.h"

#include <algorithm>
#include <utility>

namespace dpt::data {

dpt::data::MultiDexCode* dpt::data::MultiDexCode::getInst(){
    static auto *m_inst = new MultiDexCode();
    return m_inst;
}

dpt::data::MultiDexCode::MultiDexCode()
        : m_size(0), m_buffer(nullptr), m_version(0), m_dexCount(0),
          m_classIndexOffset(0), m_methodDataOffset(0), m_crypt_insns(nullptr) {
}

void dpt::data::MultiDexCode::init(uint8_t* buffer, size_t size){
    m_buffer = buffer;
    m_size = size;
    m_classIndexOffset = 0;
    m_methodDataOffset = 0;
    m_dexCount = 0;
    m_crypt_insns = nullptr;

    if (m_buffer == nullptr || m_size < DPT_MULTI_DEX_CODE_HEADER_SIZE) {
        DLOGE("OoooooOooo too small: %zu", size);
        return;
    }

    uint32_t magic = readUInt32(0);
    m_version = readUInt16(4);

    // v4 only. A v2/v3 payload has a different layout, so accepting it here
    // would make every offset below point at the wrong bytes.
    if (magic != DPT_MULTI_DEX_CODE_MAGIC || m_version != DPT_MULTI_DEX_CODE_VERSION_V4) {
        DLOGE("unsupported OoooooOooo: magic=0x%x version=%u", magic, m_version);
        m_version = 0;
        return;
    }

    m_dexCount = readUInt16(6);
    m_classIndexOffset = readUInt32(8);
    m_methodDataOffset = readUInt32(12);

    // The offsets are attacker-influenced data; validate before anything walks them.
    if (m_classIndexOffset < DPT_MULTI_DEX_CODE_HEADER_SIZE
            || m_methodDataOffset < m_classIndexOffset
            || m_methodDataOffset > m_size) {
        DLOGE("corrupt OoooooOooo offsets: ci=%u md=%u size=%zu",
              m_classIndexOffset, m_methodDataOffset, m_size);
        m_classIndexOffset = 0;
        m_methodDataOffset = 0;
        return;
    }

    // Bind the routine once so the patch path stays branch-free.
    m_crypt_insns = chacha20_crypt_insns;
    DLOGI("OoooooOooo v4 loaded: dexCount=%u classes=%u", m_dexCount, getClassCount());
}

bool dpt::data::MultiDexCode::isValid() const {
    return m_crypt_insns != nullptr && m_classIndexOffset != 0;
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

uint32_t dpt::data::MultiDexCode::getMethodDataOffset() const {
    return m_methodDataOffset;
}

uint32_t dpt::data::MultiDexCode::getClassCount() const {
    if (m_buffer == nullptr || m_classIndexOffset == 0 || m_methodDataOffset < m_classIndexOffset) {
        return 0;
    }
    return (m_methodDataOffset - m_classIndexOffset) / sizeof(ClassIndexEntry);
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

dpt::data::CodeItemView dpt::data::MultiDexCode::getMethodData(const ClassIndexEntry* entry,
                                                               uint16_t index) const {
    CodeItemView view{0, 0, nullptr};
    if (entry == nullptr || m_buffer == nullptr || m_classIndexOffset == 0) return view;
    if (index >= entry->methodCount) return view;

    // Walk forward past the preceding records. Records are variable length, so
    // this cannot be indexed directly; the loop is bounded by methodCount, which
    // is small (tens) for a real class.
    const uint8_t* base = m_buffer + m_methodDataOffset;
    size_t off = entry->methodDataOff;
    for (uint16_t i = 0; i < index; i++) {
        if (off + 6 > m_size) return view;
        uint16_t sz = readUInt16At(base, off + 4);
        // insnsSize is a BYTE count: advancing by 6 + sz, not 6 + sz * 2.
        off += 6u + sz;
        if (off > m_size) return view;
    }

    if (off + 6 > m_size) return view;
    // A record must fit entirely inside the payload.
    uint16_t insnsSize = readUInt16At(base, off + 4);
    if (off + 6u + insnsSize > m_size) return view;

    view.methodIdx = readUInt32At(base, off);
    view.insnsSize = insnsSize;
    view.encryptedInsns = base + off + 6;
    return view;
}

bool dpt::data::MultiDexCode::cryptInsns(const uint8_t *key,
                                         uint32_t methodIdx,
                                         const uint8_t *in,
                                         size_t inlen,
                                         uint8_t *out) const {
    if (m_crypt_insns == nullptr) {
        DLOGE("insns crypt routine is not initialized");
        return false;
    }
    return m_crypt_insns(key, methodIdx, in, inlen, out);
}
}
