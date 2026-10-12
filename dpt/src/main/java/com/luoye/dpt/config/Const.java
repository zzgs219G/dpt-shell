package com.luoye.dpt.config;

import com.luoye.dpt.util.StringUtils;

/**
 * @author luoyesiqiu
 */
public class Const {

    public static final String OPTION_OPEN_NOISY_LOG_LONG = "noisy-log";

    public static final String OPTION_NO_SIGN_PACKAGE_LONG = "no-sign";
    public static final String OPTION_NO_SIGN_PACKAGE = "x";

    public static final String OPTION_DUMP_CODE_LONG = "dump-code";

    public static final String OPTION_INPUT_FILE = "f";
    public static final String OPTION_INPUT_FILE_LONG = "package-file";

    public static final String OPTION_DEBUGGABLE_LONG = "debug";

    public static final String OPTION_DISABLE_APP_COMPONENT_FACTORY_LONG = "disable-acf";

    public static final String OPTION_OUTPUT_PATH = "o";
    public static final String OPTION_OUTPUT_PATH_LONG = "output";

    public static final String OPTION_EXCLUDE_ABI = "e";
    public static final String OPTION_EXCLUDE_ABI_LONG = "exclude-abi";

    public static final String OPTION_VERSION = "v";
    public static final String OPTION_VERSION_LONG = "version";

    public static final String OPTION_DO_NOT_PROTECT_CLASSES_RULES = "r";
    public static final String OPTION_DO_NOT_PROTECT_CLASSES_RULES_LONG = "rules-file";

    public static final String OPTION_KEEP_CLASSES = "K";
    public static final String OPTION_KEEP_CLASSES_LONG = "keep-classes";

    public static final String OPTION_SMALLER = "S";
    public static final String OPTION_SMALLER_LONG = "smaller";

    public static final String OPTION_PROTECT_CONFIG = "c";
    public static final String OPTION_PROTECT_CONFIG_LONG = "protect-config";

    public static final String OPTION_VERIFY_SIGN = "vs";
    public static final String OPTION_VERIFY_SIGN_LONG = "verify-sign";

    public static final String OPTION_DISABLE_FRIDA_DETECT_LONG = "disable-frida-detect";
    public static final String OPTION_DISABLE_CRC_DETECT_LONG = "disable-crc-detect";
    public static final String OPTION_DISABLE_ANTI_DEBUG_LONG = "disable-anti-debug";
    // Deprecated no-op, kept for CLI compatibility: the on-disk path is now the
    // default, so there is nothing left to disable.
    public static final String OPTION_DISABLE_INMEMORY_DEX_LONG = "disable-inmemory-dex";
    // Opt in to InMemoryDexClassLoader loading (no code_cache write). Off by
    // default: the on-disk path starts faster and uses less memory on
    // multi-dex apps (Phase 1 findings).
    public static final String OPTION_USE_INMEMORY_DEX_LONG = "use-inmemory-dex";

    // Risk check flags: one int, each bit is a switch (1 = disable)
    public static final int FLAG_DISABLE_FRIDA_DETECT = 1;
    public static final int FLAG_DISABLE_CRC_DETECT = 1 << 1;
    public static final int FLAG_DISABLE_ANTI_DEBUG = 1 << 2;

    public static final String KEY_STORE_ASSET_NAME = "dpt.jks";
    public static final String KEY_STORE_ASSET_PATH = "assets/" + KEY_STORE_ASSET_NAME;
    public static final String STORE_PASSWORD = "android";
    public static final String KEY_PASSWORD = "android";
    public static final String KEY_ALIAS = "key0";
    public static final String DEFAULT_THREAD_NAME = "dpt";

    public static final String ROOT_OF_OUT_DIR = System.getProperty("java.io.tmpdir");

    // xixin_data payload version.
    //   5 = block-compressed MethodData. Per-class records (format unchanged
    //       from v4: u32 methodIdx + u16 insnsSize + insns) are grouped into
    //       class-aligned ~64KB blocks, raw-DEFLATEd, then ChaCha20-encrypted
    //       per block with nonce = block index. Records hold PLAINTEXT insns:
    //       encryption moved from per-method (v4) to per-block, because
    //       deflating ciphertext would be pointless. See MultiDexCodeUtils and
    //       MultiDexCodeV5Test.
    //   (4 = flat per-method records, per-method nonce = methodIdx. Retired:
    //    the runtime only accepts v5. Old packed APKs keep running with their
    //    own embedded so, so no compatibility path is needed.)
    // The runtime rejects anything but v5, so this constant and
    // DPT_MULTI_DEX_CODE_VERSION in shell/src/main/cpp/dex/MultiDexCode.h
    // must be changed together.
    public static final short MULTI_DEX_CODE_VERSION_V5 = 5;
    public static final short MULTI_DEX_CODE_VERSION = MULTI_DEX_CODE_VERSION_V5;

    // 'OOO5' as a little-endian uint32. The runtime compares this before
    // trusting any offset in the payload.
    public static final int MULTI_DEX_CODE_MAGIC = 0x4F4F4F35;

    // Byte sizes fixed by the v5 layout.
    public static final int MULTI_DEX_CODE_HEADER_SIZE = 24;
    public static final int MULTI_DEX_CODE_CLASS_INDEX_ENTRY_SIZE = 16;
    public static final int MULTI_DEX_CODE_BLOCK_ENTRY_SIZE = 16;
    // Target uncompressed size of one method-record block. Blocks are
    // class-aligned; a single class larger than this gets a dedicated block.
    public static final int MULTI_DEX_CODE_BLOCK_TARGET_SIZE = 64 * 1024;
    // Runtime-side sanity bound when materializing a block from mapped memory.
    public static final int MULTI_DEX_CODE_BLOCK_MAX_RAW_SIZE = 16 * 1024 * 1024;

    public static final String RC4_KEY_SYMBOL = "DPT_UNKNOWN_DATA";

    public static final String KEY_SHELL_CONFIG_STORE_NAME = "xixin_config";
    public static final String KEY_BUILD_KEY_FILE_NAME = "build-key";
    public static final String KEY_DEXES_STORE_NAME = "xixin_dexes.zip";
    public static final String KEY_DEXES_STORE_UNALIGNED_NAME = "xixin_dexes_unaligned.zip";
    public static final String KEY_CODE_ITEM_STORE_NAME = "xixin_data";
    /** Assets dir holding the shell SO; pairs with Global.ZIP_LIB_DIR on the runtime side. */
    public static final String KEY_LIBS_DIR_NAME = "xixin";
    public static final String KEY_JNI_BASE_CLASS_NAME = "JniBridge";
    public static final String DEFAULT_SHELL_PACKAGE_NAME = "com/luoyesiqiu/shell";
    /** Auto shell package placeholder; resolved to "{appPackage}.shell" after package name is known. */
    public static final String SHELL_PACKAGE_NAME_AUTO = "<random>";
    public static final String RANDOM_DIR_NAME = StringUtils.generateIdentifier(16);

}