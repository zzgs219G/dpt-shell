//
// raw_syscall.h — 不经 libc 的 syscall 直调（arm64 x8 / armv7 r7）
//
// 【为什么需要】
//   探针代码里所有"读 /proc、读文件"的操作，一旦走 fopen/fgets/fread/readdir，
//   就是 libc 的 PLT 表项。攻击者用 LD_PRELOAD 或 Frida hook 其中任意一个：
//     · find_in_maps  → 喂一份"没有 frida-agent"的假 maps → 注入检测失明
//     · detectDebugger → 喂一份 TracerPid=0 的假 status → 反调试失明
//   走内联 svc 后，二进制里没有 open@plt/read@plt/getdents64@plt 可改，
//   攻击者只能在指令层逐处 patch，或上内核级 hook——门槛显著抬高。
//
// 【单一真相】
//   本文件是"syscall 直调"的唯一定义处。dpt_risk.cpp 原先自己写了一份
//   risk_raw_syscall（static），dpt_util.cpp 需要同一能力时只能复制一遍——
//   两份实现漂移会让"某个探针还走 libc"这种缺口静默复活。故提取到此处共用。
//
// 【约束】
//   · armv7 的 r7 是保留寄存器，不能声明成 register 变量
//     （clang 报 "write to reserved register 'R7'"），必须显式 push/pop。
//   · 非 ARM（宿主/x86）回退到 libc syscall()——探针可信化只对真机有意义。
//   · 只做"读"这一类无副作用调用；写路径不要走这里（错误处理语义不同）。
#ifndef DPT_RAW_SYSCALL_H
#define DPT_RAW_SYSCALL_H

#include <unistd.h>
#include <sys/syscall.h>

#if defined(__aarch64__)
static inline long dpt_raw_syscall(long n, long a0, long a1, long a2,
                                   long a3, long a4, long a5) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                     : "memory");
    return x0;
}
#elif defined(__arm__)
/* armv7：r7 是 Thumb frame pointer 保留寄存器，不能声明成 register 变量
 * （clang 报 write to reserved register 'R7'，CI 实证），改显式 push/pop。 */
static inline long dpt_raw_syscall(long n, long a0, long a1, long a2,
                                   long a3, long a4, long a5) {
    register long r0 __asm__("r0") = a0;
    __asm__ volatile(
        "push {r7}\n\t"
        "mov  r7, %[nr]\n\t"
        "svc  #0\n\t"
        "pop  {r7}"
        : "+r"(r0)
        : [nr] "r"(n), "r"(a1), "r"(a2), "r"(a3), "r"(a4), "r"(a5)
        : "memory");
    return r0;
}
#else
/* 非 ARM（宿主 / x86 模拟）：走 libc 包装。探针可信化只对真机有意义，
 * 宿主上不存在"被 hook"威胁，保持简单可调试。 */
static inline long dpt_raw_syscall(long n, long a0, long a1, long a2,
                                   long a3, long a4, long a5) {
    return syscall(n, a0, a1, a2, a3, a4, a5);
}
#endif

/* 调用号兜底：部分头文件裁剪环境下 __NR_* 可能缺失。
 * arm64 与 armv7 在这几个调用号上一致（Linux 通用 ABI）。 */
#ifndef __NR_openat
#define __NR_openat 56
#endif
#ifndef __NR_read
#define __NR_read 63
#endif
#ifndef __NR_close
#define __NR_close 57
#endif
#ifndef __NR_getdents64
#define __NR_getdents64 61
#endif

#endif // DPT_RAW_SYSCALL_H
