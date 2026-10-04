//
// Created by luoyesiqiu
//

#include "MultiDexCode.h"
#include "dpt_crypto.h"

dpt::data::MultiDexCode* dpt::data::MultiDexCode::getInst(){
    static auto *m_inst = new MultiDexCode();
    return m_inst;
}

MultiDexCode::MultiDexCode() : m_size(0), m_buffer(nullptr), m_version(0),
                               m_crypt_insns(rc4_crypt_insns) {
}

void dpt::data::MultiDexCode::init(uint8_t* buffer, size_t size){
    this->m_buffer = buffer;
    this->m_size = size;

    // Bind the decryption routine once, from the payload version. patchMethod
    // is on the class-loading hot path, so it must not branch per method.
    if (m_buffer != nullptr && m_size >= 2) {
        this->m_version = readUInt16(0);
    } else {
        this->m_version = 0;
    }

    switch (m_version) {
        case DPT_MULTI_DEX_CODE_VERSION_V3:
            m_crypt_insns = chacha20_crypt_insns;
            break;
        case DPT_MULTI_DEX_CODE_VERSION_V2:
            m_crypt_insns = rc4_crypt_insns;
            break;
        default:
            DLOGW("unknown multi dex code version %d, fallback to rc4", m_version);
            m_crypt_insns = rc4_crypt_insns;
            break;
    }
    DLOGI("multi dex code version %d, insns crypt = %s", m_version,
          m_crypt_insns == chacha20_crypt_insns ? "chacha20" : "rc4");
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

uint16_t dpt::data::MultiDexCode::readVersion(){
    return readUInt16(0);
}

uint16_t dpt::data::MultiDexCode::readDexCount(){
    return readUInt16(2);
}

uint32_t* dpt::data::MultiDexCode::readDexCodeIndex(int* count){
    uint16_t dexCount = readDexCount();
    *count = dexCount;
    return (uint32_t*)(m_buffer + 4);
}

dpt::data::CodeItem* dpt::data::MultiDexCode::nextCodeItem(uint32_t* offset) {
    uint32_t methodIdx = readUInt32(*offset);
    uint32_t insnsSize = readUInt32(*offset + 4);
    auto* insns = (uint8_t*)(m_buffer + *offset + 8);
    *offset = (*offset + 8 + insnsSize);
    auto* codeItem = new CodeItem(methodIdx, insnsSize, insns);

    return codeItem;
}

uint8_t dpt::data::MultiDexCode::readUInt8(uint32_t offset){
    uint8_t t = 0;
    memcpy(&t, m_buffer + offset, sizeof(uint8_t));
    return t;
}

uint16_t dpt::data::MultiDexCode::readUInt16(uint32_t offset){
    uint16_t t = 0;
    memcpy(&t, m_buffer + offset, sizeof(uint16_t));
    return t;
}

uint32_t dpt::data::MultiDexCode::readUInt32(uint32_t offset){
    uint32_t t = 0;
    memcpy(&t, m_buffer + offset, sizeof(uint32_t));
    return t;
}