/* dpt_demangle_stub.c — 顶掉 libc++abi 里 98 KB 的 demangler（2026-11-10）
 *
 * ## 为什么需要这个文件
 *
 * libc++abi 的 cxa_default_handlers.cpp.o 导出了 __cxa_terminate_handler 等
 * 全局符号，链接器会因为它被引用而把这个 .o 拉进来；而该 .o 又引用
 * __cxa_demangle，于是 libc++abi 的 cxa_demangle.cpp.o（606 个符号、
 * .text 里 98,660 B）被整块拉进 so —— 占 .text 的 31.6%。
 *
 * 事实核对（全部实测，非推测）：
 *   · 全 so 反汇编搜 bl 指令，指向 __cxa_demangle 的 = 0 处
 *   · 我们代码 typeid / type_info::name() / std::type_index 用量 = 0
 *   · 全仓库 try/catch/throw 用量 = 0（排除注释后脚本统计）
 *   · 唯一引用者就是 cxa_default_handlers.cpp.o
 *
 * 它存在的唯一目的：未捕获异常时把 mangled 名（如 St9bad_alloc）
 * 变成可读的（std::bad_alloc）。为一个提示文字付 98 KB 不值得。
 *
 * ## 为什么要在这层顶，而不是靠编译选项
 *
 * cxa_default_handlers.cpp.o 在【预编译的 libc++abi.a】里，
 * -fno-exceptions / -fno-rtti 对它无效。唯一能切断的层次是链接期：
 * 本文件在目标文件层面提供了同名强符号，链接器就不再从静态库里拉
 * cxa_demangle.cpp.o。
 *
 * ## 行为
 *
 * __cxa_demangle 的语义是"分配一块内存放 demangled 名，返回指针"。
 * 这里返回 NULL —— 调用方（demangling_terminate_handler）对 NULL 的
 * 处理是退回原始 mangled 名，不会崩。也就是说：崩溃提示从
 *   terminate called after throwing an instance of 'std::bad_alloc'
 * 变成
 *   terminate called after throwing an instance of 'St9bad_alloc'
 * 仅此而已。这个提示本来就只给开发者看，且壳里没有 C++ 异常抛出的路径。
 *
 * ⚠️ 若将来壳里真的要用 typeid().name() 或加了 try/catch，
 *    删掉本文件、并同时移除 CMake 里的 -fno-exceptions -fno-rtti。
 */

#include <stddef.h>

/* 本文件是 .c（C 链接），但会被链进 C++ 的 so。
 * libc++abi 里 __cxa_demangle 是 extern "C" 符号（无 name mangling），
 * 所以这里用 C 定义即可对上；下面的 extern "C" 只是防止将来有人把
 * 文件改名成 .cpp 时符号名漂移（那样就顶不掉了，而且是静默的）。 */
#ifdef __cplusplus
extern "C" {
#endif

/* 签名来自 libc++abi 的 cxxabi.h：
 *   char *__cxa_demangle(const char *mangled_name, char *buf, size_t *n,
 *                        int *status);
 * 返回 NULL 表示失败，调用方会退回 mangled 原名继续（不崩）。 */
char *__cxa_demangle(const char *mangled_name, char *buf, size_t *n, int *status)
{
    (void) mangled_name;
    (void) buf;
    (void) n;
    if (status != NULL) {
        *status = -2;   /* -2 = invalid mangled name（libc++abi 的约定） */
    }
    return NULL;
}

#ifdef __cplusplus
}
#endif
