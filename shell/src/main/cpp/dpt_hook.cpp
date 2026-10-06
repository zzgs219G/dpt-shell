//
// Created by luoyesiqiu
//

#include <set>
#include <string>
#include <cstring>
#include <sys/system_properties.h>
#include <unistd.h>
#include "common/dpt_string.h"
#include "dpt_hook.h"
#include "dpt_risk.h"
#include "dpt_util.h"
#include "bytehook.h"

using namespace dpt;

// Dex mappings already made writable by change_dex_protective, keyed by the
// mapping address. Kept as a memo so the mprotect happens once per dex rather
// than once per method -- patchClass runs under the class-loader lock. Keyed
// by address (not dex index) because the location gate below admits two
// different dexes that both parse to index 0 (e.g. a file dex and an
// in-memory dex), and a shared key would leave one of them read-only.
static std::set<uint8_t *> dexMemMap;

int g_sdkLevel = 0;
extern ShellConfig g_shell_config;

// True for dexes the shell wants patched: either loaded from the extracted
// zip on disk, or (Task 1.4) an in-memory buffer this shell registered in
// combineInMemoryDexElements. ART gives ALL in-memory dexes the same
// "Anonymous-DexFile" location prefix, so the range check keeps a foreign
// InMemoryDexClassLoader from being mistaken for shell-protected dexes.
static bool is_shell_dex_location(const std::string &location, const uint8_t *begin) {
    if (location.rfind(DEXES_ZIP_NAME) != std::string::npos) {
        return true;
    }
    return location.rfind(ANONYMOUS_DEX_PREFIX) != std::string::npos
            && isShellInMemoryDex(begin);
}

const char *GetArtLibPath();
const char *GetClassLinkerDefineClassLibPath();

void dpt_hook() {
    bytehook_init(BYTEHOOK_MODE_AUTOMATIC,false);
    g_sdkLevel = android_get_device_api_level();
    DLOGI("sdkLevel=%d, artPath=%s", g_sdkLevel, GetArtLibPath());

    hook_execve();
    hook_mmap();
    hook_write();
    bool hookSuccess = hook_DefineClass();
    if(!hookSuccess) {
        hook_LoadClass();
    }
}

// Resolve the actually-loaded SO path. maps is preferred so Dobby's
// strstr(module.path, image_name) hits the same ELF we parse, not another
// same-named file that merely exists on disk (e.g. art vs art.compatible).
static const char *resolveLibPathCached(const char *so_name,
                                        const char *const *candidates,
                                        size_t candidate_count,
                                        std::string &cached,
                                        bool &resolved) {
    if (resolved) {
        return cached.c_str();
    }

    std::string from_maps = find_so_path(so_name);
    if (!from_maps.empty()) {
        cached = std::move(from_maps);
        resolved = true;
        DLOGI("resolve %s from maps: %s", so_name, cached.c_str());
        return cached.c_str();
    }

    for (size_t i = 0; i < candidate_count; i++) {
        const char *candidate = candidates[i];
        if (candidate == nullptr) {
            continue;
        }
        if (access(candidate, R_OK) == 0) {
            cached.assign(candidate);
            resolved = true;
            DLOGI("resolve %s: %s", so_name, cached.c_str());
            return cached.c_str();
        }
    }

    if (candidate_count > 0 && candidates[0] != nullptr) {
        cached.assign(candidates[0]);
    } else if (so_name != nullptr) {
        cached.assign(so_name);
    } else {
        cached.clear();
    }
    resolved = true;
    DLOGW("resolve %s fallback: %s", so_name, cached.c_str());
    return cached.c_str();
}

const char *GetArtLibPath() {
    // HyperOS/MIUI may ship libart under com.android.art.compatible.
    // Prefer the in-process mapping; cache after first resolve.
    static std::string art_path;
    static bool art_resolved = false;
    if (art_resolved) {
        return art_path.c_str();
    }

    const char *candidates[] = {
            "/apex/com.android.art.compatible/" LIB_DIR "/libart.so",
            "/apex/com.android.art/" LIB_DIR "/libart.so",
            "/apex/com.android.runtime/" LIB_DIR "/libart.so",
            "/system/" LIB_DIR "/libart.so",
    };
    return resolveLibPathCached("libart.so", candidates, ARRAY_LENGTH(candidates),
                                art_path, art_resolved);
}

const char *GetClassLinkerDefineClassLibPath(){
    return GetArtLibPath();
}

/**
 * Make the dex mapping writable, once per dex.
 *
 * <p>Restoring instructions means writing plaintext back into the dex that ART
 * mapped read-only. This has to be done explicitly: ART relies on the mapping
 * staying read-only so that a partially-verified dex can never be observed
 * half-patched by another thread.
 *
 * <p>This used to be called from patchMethod on every method (guarded by a
 * dexMemMap memo), and was deleted in 0af9fbf as "dead code" once the v4 rewrite
 * moved the write into patchMethodInsns. That deletion also removed the only
 * thing guaranteeing the pages were writable, leaving patchMethodInsns to depend
 * entirely on hook_mmap having added PROT_WRITE to whatever mmap ART happened to
 * use. That is not guaranteed -- newer ART releases do not always go through the
 * hooked libc mmap -- so on those devices the restore faults writing to a
 * read-only page, inside ClassLinker::DefineClass.
 *
 * <p>Called once per dex: the memo keeps the mprotect off the per-method path,
 * which matters because this runs while ART holds the class-loader lock.
 */
static void change_dex_protective(uint8_t *begin, uint64_t dexSize,
                                  int dexIndex __attribute__((unused))) {
    if (begin == nullptr || dexSize == 0) {
        DLOGW("skip mprotect dex[%d], begin=%p, dexSize=%llu",
              dexIndex, begin, (unsigned long long)dexSize);
        return;
    }

    for (int i = 0; i < 10;) {
        int ret = dpt_mprotect(begin, begin + dexSize, PROT_READ | PROT_WRITE);
        if (ret != 0) {
            DLOGE("mprotect fail, dex[%d] address: %p, reason: %d!", dexIndex, begin, ret);
            i++;
        } else {
            DLOGD("mprotect success, dex[%d] address: %p.", dexIndex, begin);
            break;
        }
    }
}

DPT_ENCRYPT
ALWAYS_INLINE
void patchMethodInsns(uint8_t *begin,
                      uint32_t methodIdx,
                      uint32_t codeOff,
                      const uint8_t *enc,
                      uint32_t insnsSize) {

    if (enc == nullptr || insnsSize == 0) {
        return;
    }
    if (codeOff == 0) {
        // abstract / native method: nothing to restore
        NLOG("methodIndex = %d no need patch!", methodIdx);
        return;
    }

    auto *dexCodeItem = (dex::CodeItem *)(begin + codeOff);
    auto *realInsnsPtr = (uint8_t *)(dexCodeItem->insns_);

    NLOG("codeItem patch, methodIndex = %d, insnsSize = %d >>> %p(0x%x)",
         methodIdx, insnsSize, realInsnsPtr,
         (unsigned int)(realInsnsPtr - begin));

    // The decryption routine is bound once per payload in MultiDexCode::init,
    // so this hot path does not branch on the payload version.
    auto *dexCode = data::MultiDexCode::getInst();
    if (UNLIKELY(!dexCode->cryptInsns(g_shell_config.aes_key, methodIdx,
                                      enc, insnsSize, realInsnsPtr))) {
        DLOGE("decrypt insns failed, methodIndex = %d, size = %d",
              methodIdx, insnsSize);
    }
}

// Resolve the class descriptor string from a DexFile + ClassDef, since
// ClassLinker::LoadClass does not pass the descriptor as a parameter.
static const char* getClassDescriptor(const void* dex_file, const void* dex_class_def) {
    if(dex_file == nullptr || dex_class_def == nullptr) {
        return nullptr;
    }

    const uint8_t *begin = nullptr;
    const dex::TypeId *type_ids = nullptr;
    const dex::StringId *string_ids = nullptr;

    if(g_sdkLevel >= 35) {
        auto *dexFileV35 = (V35::DexFile *) dex_file;
        begin = dexFileV35->begin_;
        type_ids = dexFileV35->type_ids_;
        string_ids = dexFileV35->string_ids_;
    }
    else if(g_sdkLevel >= __ANDROID_API_P__) {
        auto *dexFileV28 = (V28::DexFile *) dex_file;
        begin = dexFileV28->begin_;
        type_ids = dexFileV28->type_ids_;
        string_ids = dexFileV28->string_ids_;
    }
    else {
        auto *dexFileV21 = (V21::DexFile *) dex_file;
        begin = dexFileV21->begin_;
        type_ids = dexFileV21->type_ids_;
        string_ids = dexFileV21->string_ids_;
    }

    if(begin == nullptr || type_ids == nullptr || string_ids == nullptr) {
        return nullptr;
    }

    auto *class_def = (dex::ClassDef *) dex_class_def;
    uint32_t descriptor_idx = type_ids[class_def->class_idx_].descriptor_idx_;
    const uint8_t *str_data = begin + string_ids[descriptor_idx].string_data_off_;

    // string_data_item is prefixed with a uleb128 utf16 length; skip it.
    uint64_t utf16_length = 0;
    str_data += DexFileUtils::readUleb128(str_data, &utf16_length);
    return (const char *) str_data;
}

/**
 * Decrypt one method's instructions back into the dex.
 */
DPT_ENCRYPT
ALWAYS_INLINE
void patchMethodInsns(uint8_t *begin,
                      uint32_t methodIdx,
                      uint32_t codeOff,
                      const uint8_t *enc,
                      uint32_t insnsSize);

/**
 * Restore one method of a class from the v4 payload.
 *
 * <p>{@code cursor} advances once per method walked in patchClass, i.e. in the
 * same direct-then-virtual order that ClassData.allMethods() used when the
 * payload was built. Keeping the two orders identical is what makes the payload's
 * i-th record line up with the dex's i-th method; if they drift, one method's
 * ciphertext lands in another method's body and the app breaks in ways that are
 * very hard to trace back here.
 *
 * <p>The packing side guarantees the pairing by emitting exactly one record per
 * method walked, including a zero-length placeholder for methods it does not
 * protect (abstract/native, shared code_item). That is why an absent record here
 * can only mean a corrupt payload.
 *
 * <p>The methodIdx check is the last line of defence: it is what keeps a corrupted
 * or desynchronised payload from writing one method's ciphertext into another
 * method's body. It cannot repair the desynchronisation -- when it trips, every
 * later method of this class is off by one too and stays unrestored -- but it does
 * confine the damage to "these methods keep their filler bytes" rather than
 * "this class is silently rewritten with someone else's instructions".
 */
DPT_ENCRYPT
ALWAYS_INLINE
void patchOneClassMethod(uint8_t *begin,
                         const data::ClassIndexEntry *entry,
                         uint16_t *cursor,
                         const dex::ClassDataMethod &method) {
    if (entry == nullptr || *cursor >= entry->methodCount) {
        return;
    }

    auto *dexCode = data::MultiDexCode::getInst();
    auto view = dexCode->getMethodData(entry, *cursor);
    (*cursor)++;

    if (view.encryptedInsns == nullptr) {
        // Zero-length placeholder: the packing side deliberately left this method
        // unprotected. Nothing to restore.
        return;
    }
    if (view.methodIdx != method.method_idx_delta_) {
        // Desynchronised. Do NOT patch: writing here would corrupt this method
        // with a different method's ciphertext, and ART verifies the dex while
        // defining the class, so that surfaces as a VerifyError or SIGSEGV inside
        // ClassLinker::DefineClass rather than as anything traceable to this file.
        // No dex index here: entry->dexIdx already identifies the dex, and pulling
        // it from the ClassIndexEntry avoids a parameter that the success path
        // never reads (-Wunused-parameter is fatal in CI).
        DLOGE("payload order mismatch: dex=%u code=%u payload=%u",
              entry->dexIdx, method.method_idx_delta_, view.methodIdx);
        return;
    }

    patchMethodInsns(begin, view.methodIdx, method.code_off_,
                     view.encryptedInsns, view.insnsSize);
}

DPT_ENCRYPT void patchClass(const char* descriptor,
                 const void* dex_file,
                 const void* dex_class_def) {

    const char *junkClassName = g_shell_config.junk_class_name.empty()
            ? AY_OBFUSCATE(JUNK_CLASS_FULL_NAME)
            : g_shell_config.junk_class_name.c_str();
    if(descriptor != nullptr && UNLIKELY(dpt_strstr(descriptor, junkClassName) != nullptr)) {
        size_t descriptorLength = dpt_strlen(descriptor);
        char ch = descriptor[descriptorLength - 2];
        DLOGD("Attempt patch junk class %s ,char is '%c'",descriptor,ch);
        if(isdigit(ch)) {
            DLOGE("Find illegal call, desc: %s!", descriptor);
            dpt_crash();
            return;
        }

    }

    if(LIKELY(dex_file != nullptr)){
        std::string location;
        uint8_t *begin = nullptr;
        uint64_t dexSize = 0;
        if(g_sdkLevel >= 35) {
            auto* dexFileV35 = (V35::DexFile *)dex_file;
            location = dexFileV35->location_;
            begin = (uint8_t *)dexFileV35->begin_;
            dexSize = dexFileV35->header_->file_size_;
        }
        else if(g_sdkLevel >= __ANDROID_API_P__){
            auto* dexFileV28 = (V28::DexFile *)dex_file;
            location = dexFileV28->location_;
            begin = (uint8_t *)dexFileV28->begin_;
            dexSize = dexFileV28->size_ == 0 ? dexFileV28->header_->file_size_ : dexFileV28->size_;
        }
        else {
            auto* dexFileV21 = (V21::DexFile *)dex_file;
            location = dexFileV21->location_;
            begin = (uint8_t *)dexFileV21->begin_;
            dexSize = dexFileV21->size_ == 0 ? dexFileV21->header_->file_size_ : dexFileV21->size_;
        }

        if(UNLIKELY(begin == nullptr || dexSize == 0)) {
            DLOGW("bad dex file: begin=%p size=%llu", begin, (unsigned long long)dexSize);
            return;
        }

        if(is_shell_dex_location(location, begin) && dex_class_def){
            int dexIndex = parse_dex_number(location);

            auto* class_def = (dex::ClassDef *)dex_class_def;
            NLOG("class_desc = '%s', class_idx_ = 0x%x, class data off = 0x%x",descriptor,class_def->class_idx_,class_def->class_data_off_);

            if(LIKELY(class_def->class_data_off_ != 0)) {
                // Look the class up before touching page permissions: a dex
                // outside the payload (e.g. a keep dex living beside the
                // shell dex) must not be mprotect'ed or written at all.
                auto *dexCode = data::MultiDexCode::getInst();
                const auto *entry = dexCode->findClassIndex(
                        (uint8_t) dexIndex, class_def->class_data_off_);
                if (UNLIKELY(entry == nullptr)) {
                    // Class was not protected (excluded by rules, or a new class).
                    return;
                }

                // Restoring instructions writes into the dex mapping, which ART
                // mapped read-only. Make it writable once per mapping before the
                // first patch. hook_mmap's PROT_WRITE upgrade is not a substitute:
                // it only covers dexes mapped through the hooked libc mmap.
                auto dexMemIt = dexMemMap.find(begin);
                if(UNLIKELY(dexMemIt == dexMemMap.end())) {
                    change_dex_protective(begin, dexSize, dexIndex);
                    dexMemMap.insert(begin);
                }

                // One binary search per class replaces the old per-method lookup
                // into a 65536-entry table.
                uint16_t entryCursor = 0;

                size_t read = 0;
                auto *class_data = (uint8_t *) ((uint8_t *) begin + class_def->class_data_off_);

                uint64_t static_fields_size = 0;
                read += DexFileUtils::readUleb128(class_data, &static_fields_size);

                uint64_t instance_fields_size = 0;
                read += DexFileUtils::readUleb128(class_data + read, &instance_fields_size);

                uint64_t direct_methods_size = 0;
                read += DexFileUtils::readUleb128(class_data + read, &direct_methods_size);

                uint64_t virtual_methods_size = 0;
                read += DexFileUtils::readUleb128(class_data + read, &virtual_methods_size);

                // staticFields
                read += DexFileUtils::getFieldsSize(class_data + read, static_fields_size);

                // instanceFields
                read += DexFileUtils::getFieldsSize(class_data + read, instance_fields_size);

                auto *directMethods = new dex::ClassDataMethod[direct_methods_size];
                read += DexFileUtils::readMethods(class_data + read, directMethods,
                                                  direct_methods_size);

                auto *virtualMethods = new dex::ClassDataMethod[virtual_methods_size];
                read += DexFileUtils::readMethods(class_data + read, virtualMethods,
                                                  virtual_methods_size);

                for (uint64_t i = 0; i < direct_methods_size; i++) {
                    patchOneClassMethod(begin, entry, &entryCursor,
                                        directMethods[i]);
                }

                for (uint64_t i = 0; i < virtual_methods_size; i++) {
                    patchOneClassMethod(begin, entry, &entryCursor,
                                        virtualMethods[i]);
                }

                delete[] directMethods;
                delete[] virtualMethods;
            }
            else {
                NLOG("class_def->class_data_off_ is zero");
            }
        }
    }
}

DPT_ENCRYPT void LoadClassV23(void* thiz,
                               const void* self,
                               const void* dex_file,
                               const void* dex_class_def,
                               const char* klass) {
    if(LIKELY(g_originLoadClassV23 != nullptr)) {

        const char *descriptor = getClassDescriptor(dex_file, dex_class_def);

        DLOGD("desc: %s", descriptor);
        patchClass(descriptor, dex_file, dex_class_def);
        g_originLoadClassV23(thiz, self, dex_file, dex_class_def, klass);
    }
}

DPT_ENCRYPT bool hook_LoadClass() {
    if(g_sdkLevel < __ANDROID_API_M__) {
        return false;
    }

    void* loadClassAddress = nullptr;
    const char *classLinkerPath = GetClassLinkerDefineClassLibPath();

    char sym[256] = {0};
    find_symbol_in_elf_file(classLinkerPath, sym, ARRAY_LENGTH(sym), 2, "ClassLinker", "LoadClass");

    if(strlen(sym) == 0) {
        DLOGW("cannot find symbol: LoadClass");
        return false;
    }

    DLOGI("DobbySymbolResolver(LoadClass) image=%s sym=%s", classLinkerPath, sym);
    loadClassAddress = DobbySymbolResolver(classLinkerPath, sym);

    if(loadClassAddress == nullptr) {
        DLOGE("LoadClass address is null, sym: %s", sym);
        return false;
    }

    int hookResult = DobbyHook(loadClassAddress, (dobby_dummy_func_t) LoadClassV23, (dobby_dummy_func_t *) &g_originLoadClassV23);
    DLOGD("hook_LoadClass result: %d", hookResult);
    return hookResult == 0;
}

DPT_ENCRYPT void *DefineClassV22(void* thiz,void* self,
                 const char* descriptor,
                 size_t hash,
                 void* class_loader,
                 const void* dex_file,
                 const void* dex_class_def) {

    if(LIKELY(g_originDefineClassV22 != nullptr)) {

        patchClass(descriptor,dex_file,dex_class_def);

        return g_originDefineClassV22( thiz,self,descriptor,hash,class_loader, dex_file, dex_class_def);

    }
    return nullptr;
}

DPT_ENCRYPT void *DefineClassV21(void* thiz,
                     const char* descriptor,
                     void* class_loader,
                     const void* dex_file,
                     const void* dex_class_def) {

    if(LIKELY(g_originDefineClassV21 != nullptr)) {
        patchClass(descriptor,dex_file,dex_class_def);
        return g_originDefineClassV21( thiz,descriptor,class_loader, dex_file, dex_class_def);

    }
    return nullptr;
}

DPT_ENCRYPT bool hook_DefineClass() {
    const char *classLinkerPath = GetClassLinkerDefineClassLibPath();

    char sym[256] = {0};
    find_symbol_in_elf_file(classLinkerPath, sym, ARRAY_LENGTH(sym), 2, "ClassLinker", "DefineClass");

    if(strlen(sym) == 0) {
        DLOGW("cannot find symbol: DefineClass");
        return false;
    }

    DLOGI("DobbySymbolResolver(DefineClass) image=%s", classLinkerPath);
    void* defineClassAddress = DobbySymbolResolver(classLinkerPath, sym);

    if(defineClassAddress == nullptr) {
        DLOGE("defineClass address is null, sym: %s", sym);
        return false;
    }

    int hookResult;
    if(g_sdkLevel >= __ANDROID_API_L_MR1__) {
        hookResult = DobbyHook(defineClassAddress, (dobby_dummy_func_t) DefineClassV22, (dobby_dummy_func_t *) &g_originDefineClassV22);
    }
    else {
        hookResult = DobbyHook(defineClassAddress, (dobby_dummy_func_t) DefineClassV21, (dobby_dummy_func_t *) &g_originDefineClassV21);
    }

    if(hookResult == 0) {
        DLOGD("hook success.");
        return true;
    }
    else {
        DLOGE("hook fail!");
        return false;
    }
}

const char *getArtLibName() {
    if (g_sdkLevel >= 29) {
        return "libartbase.so";
    }
    return "libart.so";
}

DPT_ENCRYPT void* fake_mmap(void* __addr, size_t __size, int __prot, int __flags, int __fd, off_t __offset){
    BYTEHOOK_STACK_SCOPE();

    int prot = __prot;
    int hasRead = (__prot & PROT_READ) == PROT_READ;
    int hasWrite = (__prot & PROT_WRITE) == PROT_WRITE;

    char fd_path[256] = {0};
    dpt_readlink(__fd,fd_path, ARRAY_LENGTH(fd_path));

    std::string fd_path_str = fd_path;
    if(checkWebViewInFilename(fd_path_str)) {
        DLOGW("link path: %s, no need to change prot",fd_path);
        goto tail;
    }

    if(hasRead && !hasWrite) {
        prot = prot | PROT_WRITE;
        DLOGD("append write flag fd = %d, size = %zu, prot = %d, flag = %d",__fd,__size, prot,__flags);
    }

    if(g_sdkLevel == 30){
        if(strstr(fd_path,"base.vdex") != nullptr){
            DLOGE("want to mmap base.vdex");
            __flags = 0;
        }
    }
    tail:
    void *addr = BYTEHOOK_CALL_PREV(fake_mmap,__addr,  __size, prot,  __flags,  __fd,  __offset);
    return addr;
}

DPT_ENCRYPT void hook_mmap(){
    bytehook_stub_t stub = bytehook_hook_single(
            getArtLibName(),
            "libc.so",
            "mmap",
            (void*)fake_mmap,
            nullptr,
            nullptr);
    if(stub != nullptr){
        DLOGD("mmap hook success!");
    }
    else {
        DLOGE("mmap hook fail!");
    }
}

DPT_ENCRYPT int fake_execve(const char *pathname, char *const argv[], char *const envp[]) {
    BYTEHOOK_STACK_SCOPE();
    DLOGD("execve hooked: %s", pathname);
    if (strstr(pathname, "dex2oat") != nullptr) {
        DLOGD("execve blocked: %s", pathname);
        errno = EACCES;
        return -1;
    }
    return BYTEHOOK_CALL_PREV(fake_execve, pathname, argv, envp);
}

DPT_ENCRYPT ssize_t fake_write(int fd, const void *const buf, size_t count) {
    BYTEHOOK_STACK_SCOPE();

    if(buf != nullptr && count > 0x70) {
        uint8_t dex_magic[] = {0x64, 0x65, 0x78, 0x0a};

        if (UNLIKELY(dpt_memcmp(buf, dex_magic, 4) == 0)) {

            std::string hex = to_hex((uint8_t *) buf + 9, 20);
            DLOGD("dex sign: %s", hex.c_str());
            if (dpt_strncasecmp(hex.c_str(), g_shell_config.dex_sign.c_str(), 40) == 0) {
                dpt_crash();
            }
        }
    }

    return BYTEHOOK_CALL_PREV(fake_write, fd, buf, count);
}


DPT_ENCRYPT void hook_execve(){
    bytehook_stub_t stub = bytehook_hook_single(
            getArtLibName(),
            "libc.so",
            "execve",
            (void *) fake_execve,
            nullptr,
            nullptr);
    if (stub != nullptr) {
        DLOGD("execve hook success!");
    }
    else {
        DLOGE("execve hook fail!");
    }
}


DPT_ENCRYPT void hook_write(){
    bytehook_stub_t stub = bytehook_hook_all(
            "libc.so",
            "write",
            (void *) fake_write,
            nullptr,
            nullptr);
    if (stub != nullptr) {
        DLOGD("write hook success!");
    }
    else {
        DLOGE("write hook fail!");
    }
}
