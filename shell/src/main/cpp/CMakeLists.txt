cmake_minimum_required(VERSION 3.31.1)

project("dpt")

set(DPT_NATIVE_SOURCE
        dpt.cpp
        dpt_hook.cpp
        dpt_jni.cpp
        dpt_util.cpp
        dpt_risk.cpp
        dpt_crypto.cpp
        rc4/rc4.c
        common/dpt_string.c
        dex/dex_file.cpp
        dex/MultiDexCode.cpp
        reflect/dalvik_system_BaseDexClassLoader.cpp
        reflect/dalvik_system_DexPathList.cpp
        reflect/java_io_File.cpp
        reflect/java_util_ArrayList.cpp
        reflect/java_lang_Class.cpp
        reflect/android_app_ActivityThread.cpp
        reflect/android_content_pm_ApplicationInfo.cpp
        reflect/android_app_Application.cpp
        reflect/android_app_LoadedApk.cpp
        reflect/android_app_ContextImpl.cpp
        /* 段加密密钥派生链（自研，2026-10-26）：
         * dpt_keyladder.c 提供 HKDF 派生；dpt_cert.c 从已安装 APK 提证书 DER。
         * 两者共同支撑"key 不落盘、运行期从证书派生"的段加密。 */
        dpt_keyladder.c
        dpt_cert.c
        )

set(MZ_LZMA OFF CACHE BOOL "" FORCE)
set(MZ_ZSTD OFF CACHE BOOL "" FORCE)
set(MZ_OPENSSL OFF CACHE BOOL "" FORCE)

set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)

add_subdirectory(external/mbedtls)
include_directories(external/mbedtls/include)

file(GLOB BHOOK_SOURCE external/bhook/bytehook/src/main/cpp/*.c)
add_library(bytehook STATIC ${BHOOK_SOURCE})
target_include_directories(bytehook PUBLIC
        external/bhook/bytehook/src/main/cpp
        external/bhook/bytehook/src/main/cpp/include
        external/bhook/bytehook/src/main/cpp/third_party/bsd
        external/bhook/bytehook/src/main/cpp/third_party/lss)
target_link_libraries(bytehook log)

add_subdirectory(external/minizip-ng)

if(NOT TARGET dobby)
    set(DOBBY_DIR external/Dobby)
    macro(SET_OPTION option value)
        set(${option} ${value} CACHE INTERNAL "" FORCE)
    endmacro()
    SET_OPTION(DOBBY_DEBUG OFF)
    SET_OPTION(DOBBY_GENERATE_SHARED OFF)
    add_definitions(-DLOGGING_DISABLE)
    add_subdirectory(${DOBBY_DIR} dobby)
    get_property(DOBBY_INCLUDE_DIRECTORIES
            TARGET dobby
            PROPERTY INCLUDE_DIRECTORIES)
    include_directories(
            .
            ${DOBBY_INCLUDE_DIRECTORIES}
            $<TARGET_PROPERTY:dobby,INCLUDE_DIRECTORIES>
    )
endif()


add_definitions(-DDECRYPT_BITCODE)

if(${CMAKE_BUILD_TYPE} STREQUAL "Debug")
    add_definitions(-DDEBUG)
    message(WARNING "!!!WARNNING:opened log!!!")
else()
    set(OPTIMIZATION_LEVEL "-Oz")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fvisibility=hidden ${OPTIMIZATION_LEVEL}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fvisibility=hidden ${OPTIMIZATION_LEVEL}")
    # ── --gc-sections（2026-10 补）──────────────────────────────────
    # NDK 的 CMake 工具链默认已带 -ffunction-sections/-fdata-sections
    # （$NDK/build/cmake/flags.cmake:30、android-legacy.toolchain.cmake:466），
    # 即编译期早就是"一函数一段"。**缺的一直是链接期回收**：
    # 不分段不回收 = 静态库整个 .o 被拉进 .text，用不到的函数也躺着。
    #
    # 实测（arm64 基线 754,480 B，其中 .text 469,048 B = 62.4%）：
    #   · 主工程 6 个 TU 自己的 .text 仅 ~152 KB
    #   · 其余 ~317 KB 来自静态库（mbedtls 82 模块全开 / Dobby / bytehook）
    # 孤立端到端实测（strip 后，只调 ChaCha20/AES/HMAC/SHA256 四个 API）：
    #   mbedtls 全量库 + 无 gc = 365,544 B
    #   mbedtls 全量库 + 本行   =  38,512 B   (-89.5%)
    # 即【仅本行这一个 flag】就能把静态库里未引用的函数全部回收，
    # 不需要先裁 mbedtls_config.h。裁 config 是进一步的优化，不是前提。
    #
    # ⚠️ 风险：被 hook 的函数、JNI 入口、段属性函数若被误回收会运行期崩溃。
    #    JNI_OnLoad/JNI_OnUnload 走 JNIEXPORT → 动态符号表引用，不会回收；
    #    DPT_UNKNOWN_DATA 走 KEEP_SYMBOL 同理。
    #    ⚠️ DPT_ENCRYPT 目前只有 section() 属性、没有 used/retain —— 这是既有的
    #    隐患（本次改动不引入也不修复），须由 CI + 真机验证兜底。
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--exclude-libs,ALL -Wl,--gc-sections")
    message("closed log & stripped so symbols (gc-sections on)")
endif()

message("so name: ${SO_NAME}")

if(NOT DEFINED DPT_BUILD_KEY OR DPT_BUILD_KEY STREQUAL "")
    message(FATAL_ERROR "DPT_BUILD_KEY is required")
endif()
message("dpt build key: ${DPT_BUILD_KEY}")

add_compile_definitions(JNI_BRIDGE_NAME="${JNI_BRIDGE_NAME}")
add_compile_definitions(SO_NAME="lib${SO_NAME}.so")
add_compile_definitions(DPT_BUILD_KEY="${DPT_BUILD_KEY}")

# ── 段加密派生链的编译期种子（2026-10-26）─────────────────────────
# master = SHA256(DPT_KL_SEED || CRC32(.text) || 版本串)
#   · 每个 dpt-shell 版本应不同 → string(RANDOM) 生成
#   · 为什么不写死常量：写死 = 全版本共享一把锁，且源码里查得到
#   · 为什么必须是 16 位 hex：dpt_keyladder.c 按 0x%016llx 解析
if(NOT DEFINED DPT_KL_SEED OR DPT_KL_SEED STREQUAL "")
    # 存进缓存：不缓存的话每次 cmake configure 都重新生成 → 触发全量重编，
    # 且两次构建的 so 派生链不同（无法对拍）。实测缓存生效（二次 configure 值不变）。
    string(RANDOM LENGTH 16 ALPHABET 0123456789abcdef _kl_seed_tmp)
    set(DPT_KL_SEED "${_kl_seed_tmp}" CACHE STRING "keyladder compile seed (16 hex)")
    unset(_kl_seed_tmp)
endif()
# STRIP 必须有：string(RANDOM) 的结果可能带尾随空白，直接喂给
# MATCHES 会误判为非法（本机实测踩过）。
string(STRIP "${DPT_KL_SEED}" DPT_KL_SEED)
if(NOT DPT_KL_SEED MATCHES "^[0-9a-fA-F]{16}$")
    message(FATAL_ERROR "DPT_KL_SEED 必须是 16 位十六进制字符串，当前: ${DPT_KL_SEED}")
endif()
if(NOT DPT_KL_SEED MATCHES "^[0-9a-fA-F]{16}$")
    message(FATAL_ERROR "DPT_KL_SEED 必须是 16 位十六进制字符串，当前: ${DPT_KL_SEED}")
endif()
add_compile_definitions(DPT_KL_SEED=0x${DPT_KL_SEED}ULL)
message("keyladder seed: 0x${DPT_KL_SEED} (per-build, not in source)")

include_directories(./ )
include_directories(./common)

add_library(${SO_NAME} SHARED ${DPT_NATIVE_SOURCE})

find_library(log-lib log)
find_library(android-lib android)

target_compile_options(${SO_NAME} PRIVATE
        -Wall
        -Wextra
        -Werror
)
target_link_options(${SO_NAME} PRIVATE "-Wl,-z,max-page-size=16384")

target_link_libraries(${SO_NAME}
            ${log-lib}
            z
            MINIZIP::minizip
            dobby
            bytehook
            ${android-lib}
            MbedTLS::mbedcrypto
        )

ENABLE_LANGUAGE(ASM)