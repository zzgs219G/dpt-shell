//
// Created by luoyesiqiu
//

#ifndef DPT_DPT_MACRO_H
#define DPT_DPT_MACRO_H

#include "banned.h"

inline int get_cache_page_size() {
    static int pagesize = getpagesize();
    return pagesize;
}

#define SECTION_NAME_BITCODE ".bitcode"
#define SECTION_NAME_DATA ".data"

#define SECTION(name) __attribute__ ((section(name), used, retain))
#define KEEP_SYMBOL __attribute__((visibility("default")))
#define INIT_ARRAY_SECTION __attribute__ ((constructor))
#define ALWAYS_INLINE static inline __attribute__((always_inline))
#define NO_INLINE __attribute__((noinline))
#define SYS_INLINE ALWAYS_INLINE
/* DPT_ENCRYPT：进 .bitcode 加密段。
 *
 * used + retain 是【必须】的（2026-10-26 补，修 CMakeLists 里记录的既有隐患）：
 *   - 链接开启 -Wl,--gc-sections（见 CMakeLists.txt），未标记 used/retain 的
 *     段内函数若"看起来没人引用"会被静默回收。
 *   - 回收的后果不是链接报错，而是运行期 SIGILL / 跳到空地址——因为
 *     decrypt_bitcode() 按段范围整段解密，段变短了它不知道。
 *   - DPT_ENCRYPT 函数只被同段函数或经明文 launcher 间接调用，GC 判定不了
 *     "运行期会被解密后调用"，正是最容易被误回收的形态。
 *   - 移植自 apk-protect-action 的同款纪律：段标记必须带 retain,used，
 *     漏掉就会被 --gc-sections 静默回收。
 * 代价：零运行时开销、零体积增量（只是让链接器别删）。 */
#define DPT_ENCRYPT __attribute__ ((section(SECTION_NAME_BITCODE), used, retain))
#define DPT_DATA_SECTION __attribute__ ((section(SECTION_NAME_DATA), used, retain))

#define DEXES_ZIP_NAME "xixin_dexes.zip"
// ART's location prefix for dex loaded through InMemoryDexClassLoader
// (Task 1.4). See is_shell_dex_location in dpt_hook.cpp.
#define ANONYMOUS_DEX_PREFIX "Anonymous-DexFile"
#define CACHE_DIR "code_cache"

#define SHELL_CONFIG_IN_ZIP "assets/xixin_config"
#define CODE_ITEM_NAME_IN_ZIP "assets/xixin_data"
#define COMBINE_DEX_FILES_NAME_IN_ZIP "classes.dex"
#define JUNK_CLASS_FULL_NAME "com/luoye/dpt/junkcode/JunkClass"

#define DPT_PAGE_MASK (~((get_cache_page_size()) - 1))

#define DPT_PAGE_START(addr) ((addr) & (uintptr_t)DPT_PAGE_MASK)

#ifdef __LP64__
#define LIB_DIR "lib64"

#define FMT_POINTER "0x%lx"
#define FMT_UNSIGNED_INT "%u"
#define FMT_UNSIGNED_LONG "%lu"
#define FMT_INT64_T "%ld"
#else
#define LIB_DIR "lib"

#define FMT_POINTER "0x%x"
#define FMT_UNSIGNED_INT "%u"
#define FMT_UNSIGNED_LONG "%lu"
#define FMT_INT64_T "%lld"

#endif

#ifdef __LP64__
#define Elf_Ehdr Elf64_Ehdr
#define Elf_Shdr Elf64_Shdr
#define Elf_Sym  Elf64_Sym
#define Elf_Off  Elf64_Off
#define Elf_Word  Elf64_Word
#define Elf_Half  Elf64_Half
#else
#define Elf_Ehdr Elf32_Ehdr
#define Elf_Shdr Elf32_Shdr
#define Elf_Sym  Elf32_Sym
#define Elf_Off  Elf32_Off
#define Elf_Word  Elf32_Word
#define Elf_Half  Elf32_Half
#endif

#ifndef LIKELY
#define LIKELY(x)   __builtin_expect(!!(x), 1)
#endif
#ifndef UNLIKELY
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#endif

#define ARRAY_LENGTH(array) (sizeof(array) / sizeof((array)[0]))

#define DPT_FREE(addr) do { \
    if(addr) {              \
        free(addr);         \
        addr = nullptr;     \
    }                       \
}                           \
while(0)

#endif //DPT_DPT_MACRO_H
