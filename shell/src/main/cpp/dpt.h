//
// Created by luoyesiqiu
//

#ifndef DPT_DPT_H
#define DPT_DPT_H

#include <jni.h>
#include <string>
#include <inttypes.h>
#include <map>
#include <unordered_map>
#include <vector>
#include <dlfcn.h>
#include <elf.h>
#include <unistd.h>
#include <pthread.h>
#include <android/asset_manager.h>
#include <android/asset_manager_jni.h>
#include <random>

#include "dpt_jni.h"
#include "dpt_util.h"
#include "dpt_risk.h"
#include "common/dpt_log.h"
#include "common/dpt_macro.h"
#include "common/obfuscate.h"
#include "rc4/rc4.h"
#include "dpt_hook.h"
#include "dex/MultiDexCode.h"

#include "reflect/dalvik_system_BaseDexClassLoader.h"
#include "reflect/dalvik_system_DexPathList.h"
#include "reflect/java_util_ArrayList.h"
#include "reflect/java_io_File.h"
#include "reflect/android_app_Application.h"
#include "reflect/android_app_LoadedApk.h"

using namespace dpt;


// Risk check flags: one int, each bit is a switch (1 = disable)
#define FLAG_DISABLE_FRIDA_DETECT (1u << 0)
#define FLAG_DISABLE_CRC_DETECT   (1u << 1)
#define FLAG_DISABLE_ANTI_DEBUG   (1u << 2)

struct ShellConfig {
    std::string application_name;
    std::string application_component_factory;
    std::string jni_class_name;
    std::string app_sign_sha256;
    std::string dex_sign;
    std::string junk_class_name;
    uint8_t aes_key[32] = {};
    uint32_t risk_check_flags = 0;
    // CLI/config switch: opt in to loading the protected dex through
    // InMemoryDexClassLoader instead of writing the zip to code_cache. Off by
    // default (on-disk is the default path).
    bool use_inmemory_dex = false;
};

// Decided once in read_shell_config: true when the protected dexes are loaded
// from the zip embedded in classes.dex through InMemoryDexClassLoader elements
// instead of being extracted to code_cache. See combineInMemoryDexElements.
extern bool g_use_in_memory_dex;

// True when `begin` is a dex buffer this shell handed to ART (registered by
// combineInMemoryDexElements). Guards the location gate in dpt_hook.cpp
// against foreign in-memory dexes, whose location shares the
// "Anonymous-DexFile" prefix. Matches the registered address range first,
// then falls back to the registered dex-header content: on Android 16 the
// DexFile ART passes to DefineClass does not expose our buffer address.
bool isShellInMemoryDex(const uint8_t *begin);

void callRealApplicationOnCreate(JNIEnv *env, jclass, jstring realApplicationClassName);

INIT_ARRAY_SECTION void init_dpt();
void init_app(JNIEnv* env,jclass __unused);
void readCodeItem(uint8_t *data,size_t data_len);
jstring readAppComponentFactory(JNIEnv *env,jclass __unused);
jstring readApplicationName(JNIEnv *env, jclass __unused);
jobjectArray makePathElements(JNIEnv* env,const char *pathChs);
void combineDexElement(JNIEnv* env, jclass __unused, jobject targetClassLoader, const char* pathChs);
void combineDexElements(JNIEnv* env, jclass __unused klass, jobject targetClassLoader);
void removeDexElements(JNIEnv* env,jclass __unused,jobject classLoader,jstring elementName);
jobject replaceApplication(JNIEnv *env, jclass __unused, jstring originApplication);
void replaceApplicationOnActivityThread(JNIEnv *env,jclass __unused, jobject realApplication);
jobject replaceApplicationOnLoadedApk(JNIEnv *env, jclass __unused, jstring realApplicationClassName);

void veritySignature(JNIEnv *env);

void clinit(__unused JNIEnv *env, __unused jclass);

#endif //DPT_DPT_H
