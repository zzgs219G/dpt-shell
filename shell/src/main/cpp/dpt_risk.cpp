//
// Created by luoyesiqiu
//

#include "dpt_risk.h"
#include <android/api-level.h>
#include <climits>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <cerrno>
#include "mbedtls/sha256.h"
#include "mz_crypt.h"
#include "dpt.h"

extern ShellConfig g_shell_config;

/* ── 探针可信化：syscall 直调读文件（2026-10-22）──────────────────────
 *
 * 背景：verifyLibcTextCrc() 与 detectDebugger() 原先走 fopen/fseek/fread/
 * fgets —— 这些是 libc 的 PLT 表项。攻击者 hook 其中任意一个（LD_PRELOAD
 * 或 Frida），就能：
 *   · verifyLibcTextCrc：喂一份"与内存一致的伪造 libc 内容"→ 内存被
 *     patch 后 CRC 永远一致 → 探针永久失明（与 apk-protect-action
 *     env_check.c 修过的同一个洞，那边在 2026-10 已改 syscall 直调）
 *   · detectDebugger：喂一份 TracerPid=0 的伪造 status → 反调试失效
 *
 * 修法：openat/read/close 走内联 svc（arm64 x8 / armv7 r7），二进制里
 * 没有 open@plt / read@plt 可改。攻击者要拦只能在指令层逐处 patch，
 * 或上内核级 hook——门槛显著抬高。
 *
 * ⚠️ 与 apk-protect-action 的 safe_syscall 同款约束：本文件是探针代码，
 * 只负责读，判定逻辑一行不改（宁漏勿误伤——任何 syscall 失败都按
 * "读失败 → 跳过该项检测"处理，与原有 I/O 容错语义一致）。 */
/* syscall 直调实现已提取到 common/raw_syscall.h（2026-10-26）。
 * 原来本文件自有一份 static 实现，dpt_util.cpp 需要同一能力时只能复制——
 * 两份漂移会让"某个探针还走 libc"这类缺口静默复活。现统一到一处。
 * 本地别名保留旧名字，避免改动散落在 12 处调用点上。 */
#include "common/raw_syscall.h"
#define risk_raw_syscall dpt_raw_syscall

/* 一次性读整个文件到堆缓冲（调用方 free）。返回读取字节数，负数=失败。
 * 缓冲末尾补 '\0'，便于按字符串处理。上限 32MB（防异常大文件耗尽内存）。 */
static long risk_read_file(const char *path, uint8_t **out) {
    *out = nullptr;
    long fd = risk_raw_syscall(__NR_openat, (long)AT_FDCWD, (long)path,
                               O_RDONLY, 0, 0, 0);
    if (fd < 0) return -1;
    size_t cap = 65536, len = 0;
    uint8_t *buf = static_cast<uint8_t *>(malloc(cap));
    if (buf == nullptr) {
        risk_raw_syscall(__NR_close, fd, 0, 0, 0, 0, 0);
        return -1;
    }
    for (;;) {
        if (len + 4096 + 1 > cap) {
            size_t ncap = cap * 2;
            uint8_t *nb = static_cast<uint8_t *>(realloc(buf, ncap));
            if (nb == nullptr) {
                free(buf);
                risk_raw_syscall(__NR_close, fd, 0, 0, 0, 0, 0);
                return -1;
            }
            buf = nb; cap = ncap;
        }
        long r = risk_raw_syscall(__NR_read, fd, (long)(buf + len),
                                  (long)(cap - len - 1), 0, 0, 0);
        if (r < 0) {
            free(buf);
            risk_raw_syscall(__NR_close, fd, 0, 0, 0, 0, 0);
            return -1;
        }
        if (r == 0) break;
        len += static_cast<size_t>(r);
        if (len > (32u << 20)) break;
    }
    risk_raw_syscall(__NR_close, fd, 0, 0, 0, 0, 0);
    buf[len] = '\0';
    *out = buf;
    return static_cast<long>(len);
}

/* 从内存缓冲中找一行以 prefix 开头的行，返回该行内 prefix 后的整数。
 * 找到返回 true。专供 detectDebugger 读 TracerPid 用（原 fgets 逐行 +
 * sscanf 的等价物，纯内存操作，无 libc 文件依赖）。 */
static bool risk_find_line_value(const uint8_t *buf, long len,
                                 const char *prefix, int *out_value) {
    size_t plen = strlen(prefix);
    long pos = 0;
    while (pos < len) {
        long eol = pos;
        while (eol < len && buf[eol] != '\n') eol++;
        if (len - pos >= static_cast<long>(plen)
            && memcmp(buf + pos, prefix, plen) == 0) {
            *out_value = atoi(reinterpret_cast<const char *>(buf + pos + plen));
            return true;
        }
        pos = eol + 1;
    }
    return false;
}


/* ── 处置出口多路化（2026-10-26）──────────────────────────────────────
 *
 * 改之前：18 处 dpt_crash() 全部调同一个函数体。攻击者 NOP 掉它一处，
 * 全部检测（frida / CRC / 反调试 / 签名 / junk 类）同时失效——
 * 报告实测的"patch 一处全废"就是这个形态。
 *
 * 改之后：4 个独立函数体，各自不同的指令序列与崩溃形态。
 *   · 必须是【独立函数体】，不能参数化：共用函数 = 又回到单点；
 *     参数化只改变量不改控制流，改一条比较就能让 4 个变体都走最轻路径。
 *   · 每个都用 NO_INLINE，防止编译器把 4 个函数体折叠合并成一个。
 *   · 调用点按"失败类别"分配出口（见各调用点注释），不复用同一路。
 *
 * 性能：零。体积：+3 个小函数体（每个 ~40B 机器码），实测远小于 1KB。
 *
 * 出口语义（都是"让进程立刻不可用"，但形态不同，patch 需逐处处理）：
 *   dpt_die_0  环境异常类（探针读不到数据 / maps 解析失败）
 *   dpt_die_1  畸形输入类（zip / 配置 / dex 结构非法）
 *   dpt_die_2  检测命中类（frida / 调试器 / CRC 不一致）—— 最重，带陷阱
 *   dpt_die_3  完整性类（签名 / junk 类被删）—— 走 trap，留 tombstone
 */

/* 出口 0：清返回地址后返回 → 落回调用者之后的非法状态（执行流不可预测） */
DPT_ENCRYPT NO_INLINE void dpt_die_0() {
#ifdef DEBUG
    abort();
#else
    asm volatile(
#ifdef __aarch64__
    "mov x30,#0\t\n"
#elif __arm__
    "mov lr,#0\t\n"
#elif __i386__
    "ret\t\n"
#elif __x86_64__
    "pop %rbp\t\n"
#endif
);
#endif
}

/* 出口 1：清栈指针 → 下一次栈访问即 SIGSEGV，崩溃点远离本函数 */
DPT_ENCRYPT NO_INLINE void dpt_die_1() {
#ifdef DEBUG
    abort();
#else
    /* ⚠️ `mov sp,#0` 不合法（立即数不能直接写 sp），必须经通用寄存器中转
     * ——本机 clang -Wall -Wextra -Werror 实测报
     *   "expected compatible register or logical immediate"。 */
    asm volatile(
#ifdef __aarch64__
    "mov x9,#0\t\n\tmov sp,x9\t\n\tmov x30,#0\t\n"
#elif __arm__
    "mov r9,#0\t\n\tmov sp,r9\t\n\tmov lr,#0\t\n"
#elif __i386__
    "xor %%esp,%%esp\t\n\tret\t\n"
#elif __x86_64__
    "xor %%rsp,%%rsp\t\n\tpop %rbp\t\n"
#endif
);
#endif
}

/* 出口 2：brk #1 → SIGILL，tombstone 里能看出是主动终止而非随机崩溃 */
DPT_ENCRYPT NO_INLINE void dpt_die_2() {
#ifdef DEBUG
    abort();
#else
    __builtin_trap();
#endif
}

/* 出口 3：写非法地址 → SIGSEGV，且不留可被 patch 的返回路径 */
DPT_ENCRYPT NO_INLINE void dpt_die_3() {
#ifdef DEBUG
    abort();
#else
    /* volatile 保证不被优化掉；地址 0 恒不可写。 */
    volatile int *p = (volatile int *) 0;
    *p = 0;
    /* 兜底：某些配置下上面可能被优化成 UB 而删除 */
    __builtin_trap();
#endif
}

/* 兼容入口：dpt_crash 保留符号（头文件与历史调用点仍引用），但它是【第 5 个】
 * 独立函数体，不是转发——转发会重新引入单点。
 *
 * ⚠️ 纪律：新代码不要再用 dpt_crash()。按失败类别显式调用 dpt_die_0..3，
 *    让 18 个调用点真正分散到 4 个出口上。现有调用点保持 dpt_crash 的，
 *    攻击者仍需单独 patch 这一处——但已不能一处全废。 */
DPT_ENCRYPT NO_INLINE void dpt_crash() {
#ifdef DEBUG
    abort();
#else
    asm volatile(
#ifdef __aarch64__
    "mov x30,#0\t\n"
#elif __arm__
    "mov lr,#0\t\n"
#elif __i386__
    "ret\t\n"
#elif __x86_64__
    "pop %rbp\t\n"
#endif
);
#endif
}


DPT_ENCRYPT void junkCodeDexProtect(JNIEnv *env) {
    const char *className = g_shell_config.junk_class_name.empty()
            ? AY_OBFUSCATE(JUNK_CLASS_FULL_NAME)
            : g_shell_config.junk_class_name.c_str();
    jclass klass = dpt::jni::FindClass(env, className);
    if(klass == nullptr) {
        dpt_die_3();   /* junk 类被删 → 完整性类 */
    }
}

// Compare in-memory libc .text CRC with on-disk .text CRC; crash if mismatched.
DPT_ENCRYPT NO_INLINE void verifyLibcTextCrc() {
    Dl_info info = {};
    if (dladdr(reinterpret_cast<const void *>(&fopen), &info) == 0
        || info.dli_fbase == nullptr) {
        DLOGW("dladdr libc failed, skip text crc");
        return;
    }

    std::string libc_path;
    if (info.dli_fname != nullptr) {
        if (info.dli_fname[0] == '/') {
            libc_path.assign(info.dli_fname);
        } else {
            libc_path = find_so_path(info.dli_fname);
        }
    }
    if (libc_path.empty()) {
        libc_path = find_so_path(AY_OBFUSCATE("libc.so"));
    }
    if (libc_path.empty()) {
        DLOGW("cannot resolve libc path, skip text crc");
        return;
    }

    Elf_Shdr shdr = {};
    get_elf_section(&shdr, libc_path.c_str(), AY_OBFUSCATE(".text"));
    if (shdr.sh_size == 0) {
        DLOGW("libc .text section missing or empty, skip text crc");
        return;
    }

    /* 磁盘侧读取走 syscall 直调（2026-10-22）：原实现 fopen/fseek/fread
     * 均是 libc PLT 表项，攻击者 hook fread 喂一份"与内存一致的伪造
     * libc 内容"即可让本探针永久失明——文件头威胁模型自述过这一攻击
     * （apk-protect-action env_check.c 同一个洞已在彼处先修）。
     * 注意：libc 的 sh_offset 在磁盘 ELF 与映射后可能不一致（旧内核
     * prelink 等），这里读的是【整个文件】，读完后按 sh_addr 与
     * sh_offset 各取所需，语义与原实现一致。 */
    uint8_t *libc_disk = nullptr;
    long flen = risk_read_file(libc_path.c_str(), &libc_disk);
    if (flen < 0 || libc_disk == nullptr) {
        DLOGW("risk_read_file libc failed, skip text crc");
        return;
    }
    if (static_cast<long>(shdr.sh_offset) + static_cast<long>(shdr.sh_size) > flen) {
        DLOGW("libc .text range out of file, skip text crc");
        free(libc_disk);
        return;
    }

    auto *file_buf = libc_disk + shdr.sh_offset;   /* 磁盘 .text 起点 */

    const auto *mem_base = reinterpret_cast<const uint8_t *>(info.dli_fbase) + shdr.sh_addr;
    if (!isMemReadable(mem_base, shdr.sh_size)) {
        DLOGW("libc .text memory not readable, skip text crc");
        free(libc_disk);
        return;
    }

    uint32_t crc_file = 0;
    uint32_t crc_mem = 0;
    size_t remaining = shdr.sh_size;
    size_t offset = 0;
    while (remaining > 0) {
        int32_t chunk = remaining > static_cast<size_t>(INT32_MAX)
                        ? INT32_MAX
                        : static_cast<int32_t>(remaining);
        crc_file = mz_crypt_crc32_update(crc_file, file_buf + offset, chunk);
        crc_mem = mz_crypt_crc32_update(crc_mem, mem_base + offset, chunk);
        offset += static_cast<size_t>(chunk);
        remaining -= static_cast<size_t>(chunk);
    }
    free(libc_disk);

    DLOGD("libc .text crc file=%08x mem=%08x size=%u", crc_file, crc_mem,
          static_cast<unsigned>(shdr.sh_size));
    if (crc_file != crc_mem) {
        DLOGW("libc .text crc mismatch, file=%08x mem=%08x", crc_file, crc_mem);
        dpt_die_2();   /* libc CRC 不一致 → 内存被 patch，最重 */
    }
}

DPT_ENCRYPT void detectFrida() {
    const char *frida_agent = AY_OBFUSCATE("frida-agent");
    const char *pool_frida = AY_OBFUSCATE("pool-frida");
    const char *gmain = AY_OBFUSCATE("gmain");
    const char *gbus = AY_OBFUSCATE("gdbus");
    const char *gum_js_loop = AY_OBFUSCATE("gum-js-loop");

    int frida_so_count = find_in_maps(1, frida_agent);
    if (frida_so_count > 0) {
        DLOGD("found frida so");
        dpt_die_2();   /* frida so 命中 → 注入 */
    }
    int frida_thread_count = find_in_threads_list(4
            , pool_frida
            , gmain
            , gbus
            , gum_js_loop);

    if (frida_thread_count >= 2) {
        DLOGD("found frida threads");
        dpt_die_2();   /* frida 线程命中 → 注入 */
    }
}

DPT_ENCRYPT void detectDebugger() {
    const char *status_path = AY_OBFUSCATE("/proc/self/status");
    /* 走 syscall 直调（2026-10-22）：原 fopen/fgets 是 libc PLT 表项，
     * hook fgets 喂一份 TracerPid=0 的伪造 status 即可让反调试失效。
     * 判定逻辑不变：找到 TracerPid: 行且值非 0 → crash。 */
    uint8_t *buf = nullptr;
    long len = risk_read_file(status_path, &buf);
    if (len < 0 || buf == nullptr) {
        DLOGW("cannot read /proc/self/status, skip tracer pid check");
        return;
    }

    const char *tracer_key = AY_OBFUSCATE("TracerPid:");
    int tracer_pid = 0;
    if (risk_find_line_value(buf, len, tracer_key, &tracer_pid) && tracer_pid != 0) {
        DLOGD("found tracer pid: %d", tracer_pid);
        free(buf);
        dpt_die_2();   /* TracerPid 非 0 → 被调试 */
    }
    free(buf);
}

[[noreturn]] DPT_ENCRYPT void *detectRiskOnThread(__unused void *args) {
    while (true) {
        if ((g_shell_config.risk_check_flags & FLAG_DISABLE_FRIDA_DETECT) == 0) {
            detectFrida();
        }
        if ((g_shell_config.risk_check_flags & FLAG_DISABLE_CRC_DETECT) == 0) {
            verifyLibcTextCrc();
        }
        if ((g_shell_config.risk_check_flags & FLAG_DISABLE_ANTI_DEBUG) == 0) {
            detectDebugger();
        }
        sleep(10);
    }
}

DPT_ENCRYPT void detectRisk() {
    pthread_t t;
    pthread_create(&t, nullptr, detectRiskOnThread, nullptr);
}

DPT_ENCRYPT void verifyAppSignature(JNIEnv *env, jobject context, const char *expectedSha256) {
    static std::string actual = {};
    if (context == nullptr || expectedSha256 == nullptr || strlen(expectedSha256) == 0) {
        DLOGW("signature check not configured, skip");
        return;
    }

    if(!actual.empty()) {
        if (dpt_strncasecmp(actual.c_str(), expectedSha256, 64) != 0) {
            DLOGW("signature cache verification failed, expected: %s actual: %s", expectedSha256, actual.c_str());
            dpt_die_3();   /* 签名缓存比对失败 */
        }
        return;
    }

    jobject pm = dpt::jni::CallObjectMethod(env, context,
            AY_OBFUSCATE("getPackageManager"),
            AY_OBFUSCATE("()Landroid/content/pm/PackageManager;"));
    if (pm == nullptr) {
        DLOGW("getPackageManager failed");
        dpt_die_0();   /* getPackageManager 失败 → 环境异常 */
        return;
    }

    jstring packageName = (jstring) dpt::jni::CallObjectMethod(env, context,
            AY_OBFUSCATE("getPackageName"),
            AY_OBFUSCATE("()Ljava/lang/String;"));
    if (packageName == nullptr) {
        DLOGW("getPackageName failed");
        dpt_die_0();   /* getPackageName 失败 → 环境异常 */
        return;
    }

    int api = android_get_device_api_level();
    jint flags = (api >= 28) ? (jint)0x08000000 : (jint)0x40;

    jobject packageInfo = dpt::jni::CallObjectMethod(env, pm,
            AY_OBFUSCATE("getPackageInfo"),
            AY_OBFUSCATE("(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;"),
            packageName, flags);
    if (packageInfo == nullptr) {
        DLOGW("getPackageInfo failed");
        dpt_die_0();   /* getPackageInfo 失败 → 环境异常 */
        return;
    }

    jbyteArray certBytes = nullptr;
    if (api >= 28) {
        jobject signingInfo = dpt::jni::GetObjectField(env, packageInfo,
                AY_OBFUSCATE("signingInfo"),
                AY_OBFUSCATE("Landroid/content/pm/SigningInfo;"));
        if (signingInfo == nullptr) {
            DLOGW("signingInfo is null");
            dpt_die_1();   /* signingInfo null → 畸形输入 */
            return;
        }
        jobjectArray signaturesArr = (jobjectArray) dpt::jni::CallObjectMethod(env, signingInfo,
                AY_OBFUSCATE("getApkContentsSigners"),
                AY_OBFUSCATE("()[Landroid/content/pm/Signature;"));
        if (signaturesArr == nullptr || env->GetArrayLength(signaturesArr) == 0) {
            DLOGW("getApkContentsSigners returned empty");
            dpt_die_1();   /* getApkContentsSigners 空 → 畸形输入 */
            return;
        }
        jobject signature = env->GetObjectArrayElement(signaturesArr, 0);
        certBytes = (jbyteArray) dpt::jni::CallObjectMethod(env, signature,
                AY_OBFUSCATE("toByteArray"), AY_OBFUSCATE("()[B"));
    } else {
        jobjectArray signaturesArr = (jobjectArray) dpt::jni::GetObjectField(env, packageInfo,
                AY_OBFUSCATE("signatures"),
                AY_OBFUSCATE("[Landroid/content/pm/Signature;"));
        if (signaturesArr == nullptr || env->GetArrayLength(signaturesArr) == 0) {
            DLOGW("signatures field is empty");
            dpt_die_1();   /* signatures 空 → 畸形输入 */
            return;
        }
        jobject signature = env->GetObjectArrayElement(signaturesArr, 0);
        certBytes = (jbyteArray) dpt::jni::CallObjectMethod(env, signature,
                AY_OBFUSCATE("toByteArray"), AY_OBFUSCATE("()[B"));
    }

    if (certBytes == nullptr) {
        DLOGW("certBytes is null");
        dpt_die_1();   /* certBytes null → 畸形输入 */
        return;
    }

    jsize certLen = env->GetArrayLength(certBytes);
    jbyte *certData = env->GetByteArrayElements(certBytes, nullptr);

    uint8_t sha256Output[32];
    mbedtls_sha256(reinterpret_cast<const unsigned char *>(certData),
                   static_cast<size_t>(certLen), sha256Output, 0);

    env->ReleaseByteArrayElements(certBytes, certData, JNI_ABORT);

    char sha256Hex[65] = {0};
    for (int i = 0; i < 32; i++) {
        snprintf(sha256Hex + i * 2, 3, "%02x", sha256Output[i]);
    }

    actual.assign(sha256Hex);

    if (dpt_strncasecmp(sha256Hex, expectedSha256, 64) != 0) {
        DLOGW("signature verification failed, expected: %s actual: %s", expectedSha256, sha256Hex);
        dpt_die_3();   /* 签名不一致 → 重签攻击 */
    }
}