//
// Created by luoyesiqiu
//

#include <set>
#include <string>
#include <cstring>
#include <signal.h>
#include <errno.h>
#include <sys/syscall.h>
#include <cstdint>
#include <iterator>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <utility>
#include <vector>
#include <sys/system_properties.h>
#include <unistd.h>
#include "common/dpt_string.h"
#include "dpt_hook.h"
#include "dpt_risk.h"
#include "dpt_util.h"
#include "bytehook.h"

using namespace dpt;

// Page-level locks for Task 1.5: patchClass takes a lock on every page it
// touches before making it writable, so concurrent class loading of the same
// dex serializes instead of racing on mprotect. The table grows monotonically
// (one entry per page ever touched); the page count is bounded by the dex
// size, so this is acceptable for a process-lifetime table.
std::unordered_map<uintptr_t, std::unique_ptr<std::mutex>> dpt::g_pageLocks;
std::mutex dpt::g_pageLockTableMutex;

std::mutex& dpt::getPageLock(uintptr_t pageAddr) {
    std::lock_guard<std::mutex> lg(g_pageLockTableMutex);
    auto& slot = g_pageLocks[pageAddr];
    if (!slot) slot = std::make_unique<std::mutex>();
    return *slot;
}

int g_sdkLevel = 0;
extern ShellConfig g_shell_config;

// True for dexes the shell wants patched: either loaded from the extracted
// zip on disk, or (Task 1.4) an in-memory buffer this shell registered in
// combineInMemoryDexElements. ART gives ALL in-memory dexes the same
// "Anonymous-DexFile" location prefix, so the registry check (address first,
// dex-header content as fallback; see isShellInMemoryDex) keeps a foreign
// InMemoryDexClassLoader from being mistaken for shell-protected dexes.
static bool is_shell_dex_location(const std::string &location, const uint8_t *begin) {
    if (location.rfind(DEXES_ZIP_NAME) != std::string::npos) {
        return true;
    }
    if (location.rfind(ANONYMOUS_DEX_PREFIX) == std::string::npos) {
        return false;
    }
    if (!isShellInMemoryDex(begin)) {
        // A silent reject here means the protected classes keep their random
        // filler and surface later as a VerifyError with nothing pointing
        // back to this gate (release builds compile this log out).
        ELOG("anonymous dex not registered as shell dex: begin=%p, loc=%s",
              (const void *) begin, location.c_str());
        return false;
    }
    return true;
}

const char *GetArtLibPath();
const char *GetClassLinkerDefineClassLibPath();

// ---------------------------------------------------------------------------
// Crash diagnostics (SIGSEGV/SIGBUS).
//
// A crash inside the instruction-restore path used to surface as a bare
// `#00 pc 0x5c18c` with no state, and the symbolization step (see
// build.gradle debugSymbolLevel / release.yml) only recovers the *function*.
// These variables answer the other half: which dex, and whether the RW window
// was expected to be open.
//
// Diagnostics read from a signal handler. thread_local is deliberate: the
// thread that faults inside patchMethodInsns is the same one that ran
// patchClass, so its slot is already allocated by the time we read it (see
// dpt_install_crash_handler for the pre-touch that covers the install thread).
// POD, never std::string -- the reader must not touch the heap.
static thread_local char g_last_location[128] = {0};
static thread_local int g_last_restore_read = -1;
static thread_local long g_last_method_idx = -1;
static thread_local int g_last_mprotect = -1;

// Guards against re-entering the handler. Deliberately a plain global rather
// than thread_local: it is first written *from inside* the handler, and a
// thread that never ran patchClass would take a TLS allocation there.
static volatile sig_atomic_t g_in_crash_handler = 0;

static struct sigaction g_prev_sigsegv;
static struct sigaction g_prev_sigbus;

// Async-signal-safe integer formatter: no printf, no allocation.
static int dpt_sig_append(char *dst, int off, int cap, const char *s) {
    while (off < cap - 1 && *s != '\0') {
        dst[off++] = *s++;
    }
    return off;
}

static int dpt_sig_append_int(char *dst, int off, int cap, long value) {
    char tmp[24];
    int n = 0;
    const bool negative = value < 0;
    // Two's-complement negation via unsigned: -LONG_MIN is UB on long, but
    // 0UL - (unsigned long) value is well defined.
    unsigned long uvalue = negative ? (0UL - (unsigned long) value)
                                    : (unsigned long) value;
    if (uvalue == 0) {
        tmp[n++] = '0';
    }
    while (uvalue > 0 && n < (int) sizeof(tmp)) {
        tmp[n++] = (char) ('0' + (uvalue % 10));
        uvalue /= 10;
    }
    if (negative && off < cap - 1) {
        dst[off++] = '-';
    }
    while (n > 0 && off < cap - 1) {
        dst[off++] = tmp[--n];
    }
    return off;
}

static int dpt_sig_append_hex(char *dst, int off, int cap, unsigned long long value) {
    static const char digits[] = "0123456789abcdef";
    char tmp[16];
    int n = 0;
    if (value == 0) {
        tmp[n++] = '0';
    }
    while (value > 0 && n < (int) sizeof(tmp)) {
        tmp[n++] = digits[value & 0xf];
        value >>= 4;
    }
    off = dpt_sig_append(dst, off, cap, "0x");
    while (n > 0 && off < cap - 1) {
        dst[off++] = tmp[--n];
    }
    return off;
}

// Formats and emits the one diagnostic line. Kept free of printf/malloc/
// std::string and of any heap or TLS access on the read path. Note that
// __android_log_write() is not strictly POSIX async-signal-safe -- it is used
// because the alternative (write(2)) is invisible for an Android app, whose
// stderr goes to /dev/null. A fault inside liblog would cost this line, but not
// the tombstone, because we forward afterwards.
static void dpt_crash_log_state(int signum, const siginfo_t *info) {
    char buf[384];
    int off = 0;
    const int cap = (int) sizeof(buf);

    off = dpt_sig_append(buf, off, cap, "SIG");
    off = dpt_sig_append_int(buf, off, cap, signum);
    off = dpt_sig_append(buf, off, cap, " addr=");
    off = dpt_sig_append_hex(buf, off, cap,
                             (unsigned long long) (uintptr_t) info->si_addr);
    off = dpt_sig_append(buf, off, cap, " code=");
    off = dpt_sig_append_int(buf, off, cap, info->si_code);
    off = dpt_sig_append(buf, off, cap, " loc=");
    off = dpt_sig_append(buf, off, cap, g_last_location);
    off = dpt_sig_append(buf, off, cap, " restoreRead=");
    off = dpt_sig_append_int(buf, off, cap, g_last_restore_read);
    off = dpt_sig_append(buf, off, cap, " mprotect=");
    off = dpt_sig_append_int(buf, off, cap, g_last_mprotect);
    off = dpt_sig_append(buf, off, cap, " methodIdx=");
    off = dpt_sig_append_int(buf, off, cap, g_last_method_idx);
    off = dpt_sig_append(buf, off, cap, "\n");
    // Every append stops at cap-1, so buf[off] is always inside the array; make
    // the terminator explicit for __android_log_write's C-string contract.
    if (off > cap - 1) {
        off = cap - 1;
    }
    buf[off] = '\0';

    __android_log_write(ANDROID_LOG_FATAL, TAG, buf);
}

static void dpt_crash_handler(int signum, siginfo_t *info, void *context) {
    // Log once per fault. The guard is set before formatting so a fault while
    // formatting cannot recurse, and cleared after the forward below so that a
    // fault ART recovers from (implicit null-check) does not permanently
    // suppress the diagnostic line for every later crash.
    const bool shouldLog = (g_in_crash_handler == 0);
    if (shouldLog) {
        g_in_crash_handler = 1;
        dpt_crash_log_state(signum, info);
    }

    // Hand the signal to whoever held it before us, so debuggerd still produces
    // its tombstone (registers, backtrace, the whole crash.log) and the process
    // dies the way it would have without us. This is why we forward instead of
    // _exit(): exiting here would suppress the tombstone we are trying to
    // enrich.
    //
    // Chain notes, from reading the sources:
    //   * we register through the plain sigaction(), which ART's sigchain
    //     proxies, so our handler sits *inside* the sigchain;
    //   * bhook (bytehook_init, called later by dpt_hook) registers through
    //     sigaction resolved with dlsym(libc), i.e. it bypasses the sigchain and
    //     writes the kernel slot directly (bytesig.c: bytesig_real_sigaction);
    //   * installing before bytehook_init therefore leaves bhook on the outside:
    //     it gets the first look, and only forwards to us for faults it does not
    //     consume -- so BYTESIG_TRY keeps working and we still see real crashes.
    // Installing after bytehook_init would invert that ordering.
    //
    // The exact dispatch order through ART's sigchain is inferred from those
    // sources and is NOT verified on device; see docs/进度与交接.md.
    const struct sigaction *prev = (signum == SIGBUS) ? &g_prev_sigbus : &g_prev_sigsegv;
    if ((prev->sa_flags & SA_SIGINFO) != 0 && prev->sa_sigaction != nullptr) {
        prev->sa_sigaction(signum, info, context);
    } else if (prev->sa_handler == SIG_DFL || prev->sa_handler == nullptr) {
        // Restore the default action and re-raise so debuggerd sees a real
        // crash. tgkill targets this thread: a process-directed kill could
        // deliver to another thread and make the tombstone name the wrong one.
        // syscall() is used because tgkill/gettid need not be declared by the
        // headers we include; bhook resolves them the same way (bytesig.c).
        struct sigaction dfl{};
        dfl.sa_handler = SIG_DFL;
        sigemptyset(&dfl.sa_mask);
        sigaction(signum, &dfl, nullptr);
        syscall(__NR_tgkill, getpid(), syscall(__NR_gettid), signum);
    } else if (prev->sa_handler != SIG_IGN) {
        prev->sa_handler(signum);
    }

    // Reached only if the forwarded action returned without killing the
    // process -- i.e. something recovered the fault (ART's implicit null-check
    // handler, or a bhook siglongjmp). Clear the guard so a later real crash
    // still logs. On a genuinely fatal fault we never get here, which is fine:
    // the process is already going down with the line already written.
    if (shouldLog) {
        g_in_crash_handler = 0;
    }
}

void dpt_install_crash_handler() {
    // Pre-touch the thread_local diagnostics so this thread's TLS block is
    // allocated here, on a normal stack, instead of from inside the handler
    // (bionic resolves a dlopen'd module's TLS through __tls_get_addr, which
    // may call calloc -- not async-signal-safe).
    //
    // This covers the install thread only. A fault on some OTHER thread that
    // ran patchClass is equally safe (patchClass wrote these), but a thread
    // that never ran patchClass -- e.g. one created before this SO loaded --
    // can still take the TLS allocation inside the handler. That residual gap
    // is accepted; see docs/进度与交接.md §11.4.
    g_last_restore_read = -1;
    g_last_mprotect = -1;
    g_last_method_idx = -1;
    g_last_location[0] = '\0';

    struct sigaction sa{};
    sa.sa_sigaction = dpt_crash_handler;
    // SA_ONSTACK is inert here: we run from ART's sigchain, not the kernel
    // slot, and no altstack is installed. Harmless, and correct if that ever
    // changes. A stack-overflow SIGSEGV is therefore still not logged.
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);

    // Installed before dpt_hook() -> before bytehook_init(). See the chain notes
    // in dpt_crash_handler for why the ordering matters.
    if (sigaction(SIGSEGV, &sa, &g_prev_sigsegv) != 0) {
        ELOG("install SIGSEGV handler failed: %d", errno);
    }
    if (sigaction(SIGBUS, &sa, &g_prev_sigbus) != 0) {
        ELOG("install SIGBUS handler failed: %d", errno);
    }
}

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

// Task 1.5: the method collected during the class_data walk, applied after the
// RW window is open. Holding these instead of patching inline is what lets the
// window cover the whole class with a single mprotect pair.
struct PendingPatch {
    uint32_t methodIdx;
    uint32_t codeOff;
    const uint8_t *enc;
    uint32_t insnsSize;              // byte count
};

// Append the pages [insns, insns+insnsSize) to touchedPages. std::set keeps
// them unique and sorted, which is what both the lock loop and the segment
// merge below rely on.
static void collectTouchedPages(std::set<uintptr_t> &touchedPages,
                                const uint8_t *insns,
                                uint32_t insnsSize) {
    if (insns == nullptr || insnsSize == 0) {
        return;
    }
    const uintptr_t pageSize = (uintptr_t) get_cache_page_size();
    const uintptr_t first = DPT_PAGE_START((uintptr_t) insns);
    // Last page is derived from the final byte, not from first+insnsSize, so a
    // range that ends exactly on a page boundary does not add a trailing page.
    const uintptr_t last = DPT_PAGE_START((uintptr_t) insns + insnsSize - 1);
    for (uintptr_t p = first; p <= last; p += pageSize) {
        touchedPages.insert(p);
    }
}

// In-memory dexes (Task 1.4) are backed by heap buffers that share their pages
// with unrelated allocations, and those buffers are writable already. Flipping
// them back to PROT_READ would take the neighbouring allocations down with them
// and fault the next writer, so they only get the locks and the i-cache flush.
// The file-path dex is a private mapping from code_cache/i11111i111.zip, which
// is where the permission flip belongs.
static bool is_file_dex_location(const std::string &location) {
    return location.rfind(DEXES_ZIP_NAME) != std::string::npos;
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
        ELOG("decrypt insns failed, methodIndex = %d, size = %d",
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
 * Collect one method of a class from the v4 payload.
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
 *
 * <p>Task 1.5: nothing is written here. The record is appended to
 * {@code patches} and its pages to {@code touchedPages}; patchClass opens one
 * RW window over the whole set and applies them. That is also why the code item
 * is only read, never dereferenced as writable.
 */
DPT_ENCRYPT
ALWAYS_INLINE
void collectOneClassMethod(uint8_t *begin,
                           const data::ClassIndexEntry *entry,
                           uint16_t *cursor,
                           const dex::ClassDataMethod &method,
                           std::vector<PendingPatch> &patches,
                           std::set<uintptr_t> &touchedPages) {
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
        ELOG("payload order mismatch: dex=%u code=%u payload=%u",
              entry->dexIdx, method.method_idx_delta_, view.methodIdx);
        return;
    }
    if (view.insnsSize == 0 || method.code_off_ == 0) {
        // abstract / native: no code item to restore.
        return;
    }

    PendingPatch patch{};
    patch.methodIdx = view.methodIdx;
    patch.codeOff = method.code_off_;
    patch.enc = view.encryptedInsns;
    patch.insnsSize = view.insnsSize;
    patches.push_back(patch);

    auto *item = (dex::CodeItem *) (begin + patch.codeOff);
    collectTouchedPages(touchedPages, (const uint8_t *) item->insns_,
                        patch.insnsSize);
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
            ELOG("Find illegal call, desc: %s!", descriptor);
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
            ELOG("bad dex file: begin=%p size=%llu", begin, (unsigned long long)dexSize);
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

                // One binary search per class replaces the old per-method lookup
                // into a 65536-entry table.
                uint16_t entryCursor = 0;

                // Task 1.5: collect instead of patching inline, so the whole class
                // can be restored inside a single page-granular RW window.
                std::vector<PendingPatch> patches;
                std::set<uintptr_t> touchedPages;

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
                    collectOneClassMethod(begin, entry, &entryCursor,
                                          directMethods[i], patches,
                                          touchedPages);
                }

                for (uint64_t i = 0; i < virtual_methods_size; i++) {
                    collectOneClassMethod(begin, entry, &entryCursor,
                                          virtualMethods[i], patches,
                                          touchedPages);
                }

                delete[] directMethods;
                delete[] virtualMethods;

                if (!patches.empty()) {
                    // Task 1.5: one RW window for the whole class.
                    //
                    // Lock first, in page order: two threads restoring different
                    // classes that share a page must not interleave their
                    // mprotect/write/restore, and a global lock order is what
                    // keeps two such threads from deadlocking against each other.
                    // unique_lock releases in reverse order on scope exit.
                    std::vector<std::unique_lock<std::mutex>> locks;
                    locks.reserve(touchedPages.size());
                    for (uintptr_t page : touchedPages) {
                        locks.emplace_back(dpt::getPageLock(page));
                    }

                    const bool restoreRead =
                            is_file_dex_location(location);

                    // Crash diagnostics: record the state the fault handler
                    // reports. Assignment only -- no branch, no control flow.
                    g_last_restore_read = restoreRead ? 1 : 0;
                    g_last_mprotect = restoreRead ? 0 : -1;
                    // Reached only inside if (!patches.empty()). Note this is
                    // the FIRST method collected for the class, not necessarily
                    // the one being patched when a fault happens.
                    g_last_method_idx = (long) patches.front().methodIdx;
                    {
                        const char *loc = location.c_str();
                        size_t n = strnlen(loc, sizeof(g_last_location) - 1);
                        memcpy(g_last_location, loc, n);
                        g_last_location[n] = '\0';
                    }

                    // Merge the sorted pages into runs and mprotect each run,
                    // rather than the first-to-last span: the span would also
                    // open pages between two unrelated runs, widening the
                    // writable window for no reason.
                    std::vector<std::pair<uintptr_t, uintptr_t>> segments;
                    segments.reserve(touchedPages.size());
                    const uintptr_t pageSize = (uintptr_t) get_cache_page_size();
                    bool windowOpen = true;
                    for (auto it = touchedPages.begin(); it != touchedPages.end();) {
                        const uintptr_t segStart = *it;
                        auto next = std::next(it);
                        while (next != touchedPages.end() &&
                               *next == *std::prev(next) + pageSize) {
                            ++next;
                        }
                        const uintptr_t segEnd = *std::prev(next) + pageSize;

                        if (restoreRead &&
                            UNLIKELY(dpt_mprotect((void *) segStart, (void *) segEnd,
                                                  PROT_READ | PROT_WRITE) != 0)) {
                            // Crash diagnostics: the RW window never opened for
                            // this class; a later fault here is expected.
                            g_last_mprotect = -2;
                            // All or nothing: undo the segments already opened and
                            // leave every method of this class encrypted, rather
                            // than restoring only part of it.
                            ELOG("mprotect RW fail: dex=%d page=" FMT_POINTER,
                                 dexIndex, segStart);
                            for (const auto &done : segments) {
                                dpt_mprotect((void *) done.first, (void *) done.second,
                                             PROT_READ);
                            }
                            windowOpen = false;
                            break;
                        }
                        segments.emplace_back(segStart, segEnd);
                        it = next;
                    }

                    if (windowOpen) {
                        for (const auto &patch : patches) {
                            patchMethodInsns(begin, patch.methodIdx, patch.codeOff,
                                             patch.enc, patch.insnsSize);
                        }

                        // The restored bytes are live instructions. Flush the
                        // i-cache for each segment before dropping back to
                        // PROT_READ, or ARM64 keeps executing the ciphertext.
                        // In-memory dexes need the flush too -- they are just as
                        // hot -- they only skip the permission flip.
                        for (const auto &segment : segments) {
                            __builtin___clear_cache((char *) segment.first,
                                                    (char *) segment.second);
                        }

                        if (restoreRead) {
                            // Crash diagnostics: entering here means the RW
                            // window is about to close. 1 = closed (or closing);
                            // -3 = the restore to PROT_READ failed, so a fault
                            // after this point means the mapping was still
                            // writable.
                            g_last_mprotect = 1;
                            for (const auto &segment : segments) {
                                if (UNLIKELY(dpt_mprotect((void *) segment.first,
                                                          (void *) segment.second,
                                                          PROT_READ) != 0)) {
                                    g_last_mprotect = -3;
                                    ELOG("mprotect READ restore fail: dex=%d page="
                                         FMT_POINTER, dexIndex, segment.first);
                                }
                            }
                        }
                    }
                }
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
        ELOG("LoadClass address is null, sym: %s", sym);
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
        ELOG("defineClass address is null, sym: %s", sym);
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
        ELOG("hook fail!");
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
        ELOG("mmap hook fail!");
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
        ELOG("execve hook fail!");
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
        ELOG("write hook fail!");
    }
}
