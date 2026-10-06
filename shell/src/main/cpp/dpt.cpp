//
// Created by luoyesiqiu
//

#include "dpt.h"
#include "dpt_crypto.h"
#include "external/json/json.hpp"

#include <mz_strm.h>

#include <memory>
#include <mutex>

using namespace dpt;

static pthread_mutex_t g_write_dexes_mutex = PTHREAD_MUTEX_INITIALIZER;

// Defined further down with the Task 1.8 package cache and the Task 1.4
// in-memory path; declared here because combineDexElements sits above their
// definitions.
static void ensure_package_loaded(JNIEnv *env, void **package_addr, size_t *package_size);
static void release_package(void *package_addr, size_t package_size);
DPT_ENCRYPT static bool combineInMemoryDexElements(JNIEnv *env, jobject targetClassLoader);

static jobject g_realApplicationInstance = nullptr;
static jclass g_realApplicationClass = nullptr;

std::optional<std::tuple<uint8_t *,size_t>> g_codeItemFileData;

DPT_DATA_SECTION uint8_t DATA_SECTION_BITCODE[] = ".bitcode";
DPT_DATA_SECTION uint8_t DATA_SECTION_RO_DATA[] = ".rodata";
KEEP_SYMBOL DPT_DATA_SECTION uint8_t DPT_UNKNOWN_DATA[] = "1234567890abcdef";

ShellConfig g_shell_config;

// Task 1.4: when true, the protected dexes are loaded from the zip embedded
// in classes.dex through InMemoryDexClassLoader elements instead of being
// written to code_cache. Decided once in read_shell_config (API >= 29 and not
// disabled by --disable-inmemory-dex); combineDexElements may only turn it
// off, when it falls back to the on-disk path.
bool g_use_in_memory_dex = false;

static JNINativeMethod gMethods[] = {
        {"craoc", "(Ljava/lang/String;)V",                               (void *) callRealApplicationOnCreate},
        {"ia",    "()V", (void *) init_app},
        {"gap",   "()Ljava/lang/String;",         (void *) getSourceDirExport},
        {"gdp",   "()Ljava/lang/String;",         (void *) getCompressedDexesPathExport},
        {"rcf",   "()Ljava/lang/String;",         (void *) readAppComponentFactory},
        {"rapn",   "()Ljava/lang/String;",        (void *) readApplicationName},
        {"cbde",   "(Ljava/lang/ClassLoader;)V",  (void *) combineDexElements},
        {"rde",   "(Ljava/lang/ClassLoader;Ljava/lang/String;)V",        (void *) removeDexElements},
        {"ra", "(Ljava/lang/String;)Ljava/lang/Object;",                               (void *) replaceApplication},
        {"clinit", "()V",                               (void *) clinit}
};

DPT_ENCRYPT jobjectArray makePathElements(JNIEnv* env,const char *pathChs) {
    jstring path = env->NewStringUTF(pathChs);
    java_io_File file(env,path);

    java_util_ArrayList files(env);
    files.add(file.getInstance());
    java_util_ArrayList suppressedExceptions(env);

    clock_t cl = clock();
    jobjectArray elements;
    if(android_get_device_api_level() >= __ANDROID_API_M__) {
        elements = dalvik_system_DexPathList::makePathElements(env,
                                                    files.getInstance(),
                                                    nullptr,
                                                    suppressedExceptions.getInstance());
    }
    else {
        elements = dalvik_system_DexPathList::makeDexElements(env,
                                                    files.getInstance(),
                                                    nullptr,
                                                    suppressedExceptions.getInstance());
    }
    printTime("makePathElements success, took = ", cl);
    return elements;
}

DPT_ENCRYPT void combineDexElement(JNIEnv* env, jclass __unused, jobject targetClassLoader, const char* pathChs) {
    jobjectArray extraDexElements = makePathElements(env,pathChs);

    dalvik_system_BaseDexClassLoader targetBaseDexClassLoader(env,targetClassLoader);

    jobject originDexPathListObj = targetBaseDexClassLoader.getPathList();

    dalvik_system_DexPathList targetDexPathList(env,originDexPathListObj);

    jobjectArray originDexElements = targetDexPathList.getDexElements();

    jsize extraSize = env->GetArrayLength(extraDexElements);
    jsize originSize = env->GetArrayLength(originDexElements);

    dalvik_system_DexPathList::Element element(env, nullptr);
    jclass ElementClass = element.getClass();
    jobjectArray  newDexElements = env->NewObjectArray(originSize + extraSize,ElementClass, nullptr);

    for(int i = 0;i < originSize;i++) {
        jobject elementObj = env->GetObjectArrayElement(originDexElements, i);
        env->SetObjectArrayElement(newDexElements,i,elementObj);
    }

    for(int i = originSize;i < originSize + extraSize;i++) {
        jobject elementObj = env->GetObjectArrayElement(extraDexElements, i - originSize);
        env->SetObjectArrayElement(newDexElements,i,elementObj);
    }

    targetDexPathList.setDexElements(newDexElements);

    DLOGD("success");
}

DPT_ENCRYPT void combineDexElements(JNIEnv* env, jclass klass, jobject targetClassLoader) {
    if(g_use_in_memory_dex && !combineInMemoryDexElements(env, targetClassLoader)) {
        // Task 1.4 fallback: in-memory loading failed, so the zip was never
        // (or could not be) prepared. Write it now, then take the regular
        // on-disk path below.
        DLOGW("in-memory dex combine failed, falling back to %s", DEXES_ZIP_NAME);
        g_use_in_memory_dex = false;
        pthread_mutex_lock(&g_write_dexes_mutex);
        void *package_addr = nullptr;
        size_t package_size = 0;
        ensure_package_loaded(env, &package_addr, &package_size);
        extractDexesInNeeded(env, package_addr, package_size);
        release_package(package_addr, package_size);
        pthread_mutex_unlock(&g_write_dexes_mutex);
    }

    if(!g_use_in_memory_dex) {
        char compressedDexesPathChs[256] = {0};
        getCompressedDexesPath(env,compressedDexesPathChs, ARRAY_LENGTH(compressedDexesPathChs));
        combineDexElement(env, klass, targetClassLoader, compressedDexesPathChs);
    }

#ifndef DEBUG
    junkCodeDexProtect(env);
#endif
    DLOGD("success");
}

DPT_ENCRYPT void removeDexElements(JNIEnv* env,jclass __unused,jobject classLoader,jstring elementName){
    dalvik_system_BaseDexClassLoader oldBaseDexClassLoader(env,classLoader);

    jobject dexPathListObj = oldBaseDexClassLoader.getPathList();

    dalvik_system_DexPathList dexPathList(env,dexPathListObj);

    jobjectArray dexElements = dexPathList.getDexElements();

    jint oldLen = env->GetArrayLength(dexElements);

    jint newLen = oldLen;
    const char *removeElementNameChs = env->GetStringUTFChars(elementName,nullptr);

    for(int i = 0;i < oldLen;i++) {
        jobject elementObj = env->GetObjectArrayElement(dexElements, i);

        dalvik_system_DexPathList::Element element(env,elementObj);
        jobject fileObj = element.getPath();
        java_io_File javaIoFile(env,fileObj);
        jstring fileName = javaIoFile.getName();
        if(fileName == nullptr){
            DLOGW("got an empty file name");
            continue;
        }
        const char* fileNameChs = env->GetStringUTFChars(fileName,nullptr);
        DLOGD("removeDexElements[%d] old path = %s",i,fileNameChs);

        if(strncmp(fileNameChs,removeElementNameChs,256) == 0){
            newLen--;
        }
        env->ReleaseStringUTFChars(fileName,fileNameChs);
    }

    dalvik_system_DexPathList::Element arrayElement(env, nullptr);
    jclass ElementClass = arrayElement.getClass();
    jobjectArray newElementArray = env->NewObjectArray(newLen,ElementClass,nullptr);

    DLOGD("oldlen = %d , newlen = %d",oldLen,newLen);

    jint newArrayIndex = 0;

    for(int i = 0;i < oldLen;i++) {
        jobject elementObj = env->GetObjectArrayElement(dexElements, i);

        dalvik_system_DexPathList::Element element(env,elementObj);
        jobject fileObj = element.getPath();
        java_io_File javaIoFile(env,fileObj);
        jstring fileName = javaIoFile.getName();
        if(fileName == nullptr){
            DLOGW("got an empty file name");
            continue;
        }
        const char* fileNameChs = env->GetStringUTFChars(fileName,nullptr);

        if(strncmp(fileNameChs,removeElementNameChs,256) == 0){
            DLOGD("will remove item: %s",fileNameChs);
            env->ReleaseStringUTFChars(fileName,fileNameChs);
            continue;
        }
        env->ReleaseStringUTFChars(fileName,fileNameChs);

        env->SetObjectArrayElement(newElementArray,newArrayIndex++,elementObj);
    }

    dexPathList.setDexElements(newElementArray);
    DLOGD("success");
}

DPT_ENCRYPT jstring readAppComponentFactory(JNIEnv *env, jclass __unused) {
    DLOGD("result: '%s'", g_shell_config.application_component_factory.c_str());
    return env->NewStringUTF(g_shell_config.application_component_factory.c_str());
}

DPT_ENCRYPT jstring readApplicationName(JNIEnv *env, jclass __unused) {

    DLOGD("result: '%s'", g_shell_config.application_name.c_str());
    return env->NewStringUTF(g_shell_config.application_name.c_str());
}

DPT_ENCRYPT void antiRisk() {
    bool needDetect = ((g_shell_config.risk_check_flags & FLAG_DISABLE_FRIDA_DETECT) == 0)
            || ((g_shell_config.risk_check_flags & FLAG_DISABLE_CRC_DETECT) == 0)
            || ((g_shell_config.risk_check_flags & FLAG_DISABLE_ANTI_DEBUG) == 0);
    if (needDetect) {
        detectRisk();
    }
}

void decrypt_section(const char* section_name, int temp_prot, int target_prot) {
    Dl_info info;
    dladdr((const void *)decrypt_section,&info);
    std::string so_path = {};

    if (info.dli_fname != nullptr) {
        if (info.dli_fname[0] == '/') {
            so_path.assign(info.dli_fname);
        } else {
            auto path = find_so_path(info.dli_fname);
            so_path.assign(path);
        }
    }

    if(so_path.empty()) {
        auto path = find_so_path(SO_NAME);
        so_path.assign(path);
    }

    Elf_Shdr shdr = {};

    get_elf_section(&shdr, so_path.c_str(), section_name);
    Elf_Off offset = shdr.sh_offset;
    Elf_Word size = shdr.sh_size;

    DLOGD("section name: %s, offset: %p, size: %d", section_name, (uint8_t *)offset, size);
    void *target = (u_char *)info.dli_fbase + offset;

    int ret = dpt_mprotect(target, (void *)((uint8_t *)target + size), temp_prot);
    if(ret == -1) {
        abort();
    }

    u_char *bitcode = (u_char *)malloc(size);
    struct rc4_state dec_state;
    rc4_init(&dec_state, reinterpret_cast<const u_char *>(DPT_UNKNOWN_DATA), 16);
    rc4_crypt(&dec_state, reinterpret_cast<const u_char *>(target),
              reinterpret_cast<u_char *>(bitcode),
              size);

    memcpy(target,bitcode,size);
    DPT_FREE(bitcode);

    int mprotect_ret = dpt_mprotect(target,(void *)((uint8_t *)target + size),target_prot);
    if(mprotect_ret == -1) {
        abort();
    }
}

void decrypt_bitcode() {
    decrypt_section((char *)DATA_SECTION_BITCODE, PROT_READ | PROT_WRITE | PROT_EXEC, PROT_READ | PROT_EXEC);
}

void init_dpt() {
#ifdef DECRYPT_BITCODE
    decrypt_bitcode();
#endif
    DLOGI("call!");

    dpt_hook();
}

jclass getRealApplicationClass(JNIEnv *env, const char *applicationClassName) {
    if (g_realApplicationClass == nullptr) {
        jclass applicationClass = env->FindClass(applicationClassName);
        g_realApplicationClass = (jclass) env->NewGlobalRef(applicationClass);
    }
    return g_realApplicationClass;
}

DPT_ENCRYPT jobject getApplicationInstance(JNIEnv *env, jstring applicationClassName) {
    if (g_realApplicationInstance == nullptr) {
        const char *applicationClassNameChs = env->GetStringUTFChars(applicationClassName, nullptr);

        size_t len = strnlen(applicationClassNameChs,128) + 1;
        char *appNameChs = static_cast<char *>(calloc(len, 1));
        parseClassName(applicationClassNameChs, appNameChs);

        DLOGD("getApplicationInstance %s -> %s",applicationClassNameChs,appNameChs);


        jclass appClass = getRealApplicationClass(env, appNameChs);
        jmethodID _init = env->GetMethodID(appClass, "<init>", "()V");
        jobject appInstance = env->NewObject(appClass, _init);
        if (env->ExceptionCheck() || nullptr == appInstance) {
            env->ExceptionClear();
            DLOGW("getApplicationInstance fail!");
            return nullptr;
        }
        g_realApplicationInstance = env->NewGlobalRef(appInstance);

        free(appNameChs);
        DLOGD("getApplicationInstance success!");

    }
    return g_realApplicationInstance;
}

int getRandom(int l, int r) {
    static std::mt19937 gen(std::random_device{}());
    std::uniform_int_distribution<> dist(l, r);
    return dist(gen);
}

DPT_ENCRYPT void clinit(JNIEnv *env, jclass) {
    int rand = getRandom(1, 100);
    if(rand % 2 == 0) {
        veritySignature(env);
    }
}

DPT_ENCRYPT void callRealApplicationOnCreate(JNIEnv *env, jclass, jstring realApplicationClassName) {

    jobject appInstance = getApplicationInstance(env,realApplicationClassName);
    android_app_Application application(env,appInstance);
    application.onCreate();

    DLOGD("Application.onCreate() called!");

}

DPT_ENCRYPT jobject replaceApplication(JNIEnv *env, jclass klass, jstring realApplicationClassName){

    // replaceApplicationOnLoadedApk now creates the real Application via makeApplication()
    // and calls attach() on it internally. Use that single instance everywhere to avoid
    // the two-instance problem that caused SDK initialization state mismatches on API < 28.
    jobject appInstance = replaceApplicationOnLoadedApk(env, klass, realApplicationClassName);
    if (appInstance == nullptr) {
        DLOGW("replaceApplicationOnLoadedApk returned null!");
        return nullptr;
    }

    // Cache the correct instance so callRealApplicationOnCreate can find it later.
    if (g_realApplicationInstance != nullptr) {
        env->DeleteGlobalRef(g_realApplicationInstance);
    }
    g_realApplicationInstance = env->NewGlobalRef(appInstance);

    replaceApplicationOnActivityThread(env, klass, appInstance);
    DLOGD("replace application success");
    return appInstance;
}

DPT_ENCRYPT void replaceApplicationOnActivityThread(JNIEnv *env,jclass __unused, jobject realApplication){
    android_app_ActivityThread activityThread(env);
    activityThread.setInitialApplication(realApplication);
    DLOGD("setInitialApplication() called!");
}

DPT_ENCRYPT jobject replaceApplicationOnLoadedApk(JNIEnv *env, jclass __unused, jstring realApplicationClassName) {
    android_app_ActivityThread activityThread(env);

    jobject mBoundApplicationObj = activityThread.getBoundApplication();

    android_app_ActivityThread::AppBindData appBindData(env,mBoundApplicationObj);
    jobject loadedApkObj = appBindData.getInfo();

    android_app_LoadedApk loadedApk(env,loadedApkObj);

    //make it null
    loadedApk.setApplication(nullptr);

    jobject mAllApplicationsObj = activityThread.getAllApplication();

    java_util_ArrayList arrayList(env,mAllApplicationsObj);

    jobject removed = (jobject)arrayList.remove(0);
    if(removed != nullptr){
        DLOGD("proxy application removed");
    }

    jobject ApplicationInfoObj = loadedApk.getApplicationInfo();

    android_content_pm_ApplicationInfo applicationInfo(env,ApplicationInfoObj);

    // Get class name from the jstring parameter directly
    const char *applicationNameChs = env->GetStringUTFChars(realApplicationClassName, nullptr);
    DLOGD("applicationName = %s", applicationNameChs);
    char realApplicationNameChs[128] = {0};
    parseClassName(applicationNameChs, realApplicationNameChs);
    env->ReleaseStringUTFChars(realApplicationClassName, applicationNameChs);

    jstring realApplicationName = env->NewStringUTF(realApplicationNameChs);
    auto realApplicationNameGlobal = (jstring)env->NewGlobalRef(realApplicationName);

    android_content_pm_ApplicationInfo appInfo(env,appBindData.getAppInfo());

    //replace class name
    applicationInfo.setClassName(realApplicationNameGlobal);
    appInfo.setClassName(realApplicationNameGlobal);

    // makeApplication creates the real Application instance and calls attach() on it.
    // Capture and return the newly created instance so callers can use the same object.
    jobject newApp = loadedApk.makeApplication(JNI_FALSE, nullptr);

    DLOGD("makeApplication() called, newApp = %p", newApp);
    return newApp;
}


DPT_ENCRYPT static bool registerNativeMethods(JNIEnv *env) {
    jclass JniBridgeClass = env->FindClass(g_shell_config.jni_class_name.c_str());
    if(JniBridgeClass == nullptr) {
        DLOGF("cannot find class: %s!", g_shell_config.jni_class_name.c_str());
    }
    if (env->RegisterNatives(JniBridgeClass, gMethods, sizeof(gMethods) / sizeof(gMethods[0])) ==
        0) {
        return JNI_TRUE;
    }
    return JNI_FALSE;
}


// Map the APK once per process instead of once per caller (Task 1.8).
//
// read_shell_config (JNI_OnLoad) and init_app (JniBridge.ia) used to each do
// load_package + unload_package, mmap'ing the whole APK twice per startup.
// Everything either of them keeps is copied out of the mapping first, so
// holding the mapping alive is safe:
//   - g_codeItemFileData / writeDexAchieve get heap copies from
//     read_zip_file_entry (new uint8_t[])
//   - g_shell_config stores std::string copies of the decrypted JSON
//
// The mutex is heap-allocated so it outlives cleanup_package at process exit;
// the risk-detection thread may still be alive then.
#ifndef DPT_DISABLE_MMAP_CACHE
static std::mutex *g_package_mutex = new std::mutex();
static void *g_cached_package_addr = nullptr;
static size_t g_cached_package_size = 0;

static void ensure_package_loaded(JNIEnv *env, void **package_addr, size_t *package_size) {
    std::lock_guard<std::mutex> lg(*g_package_mutex);
    if (g_cached_package_addr != nullptr) {
        *package_addr = g_cached_package_addr;
        *package_size = g_cached_package_size;
        return;
    }
    // Loading inside the lock keeps two concurrent callers from mmap'ing twice
    // and one of the mappings leaking. A failed load is not cached, so the next
    // caller retries instead of getting a null mapping forever.
    load_package(env, package_addr, package_size);
    if (*package_addr != nullptr && *package_size > 0) {
        g_cached_package_addr = *package_addr;
        g_cached_package_size = *package_size;
    }
}

static void release_package(void *package_addr, size_t package_size) {
    // Intentionally does not unmap: the mapping is shared with the other
    // caller and stays valid until process exit (cleanup_package below).
    (void) package_addr;
    (void) package_size;
}

__attribute__((destructor)) static void cleanup_package() {
    std::lock_guard<std::mutex> lg(*g_package_mutex);
    if (g_cached_package_addr != nullptr) {
        unload_package(g_cached_package_addr, g_cached_package_size);
        g_cached_package_addr = nullptr;
        g_cached_package_size = 0;
    }
}
#else
// -DDPT_DISABLE_MMAP_CACHE restores the pre-Task-1.8 behaviour: map on every
// use, unmap immediately after.
static void ensure_package_loaded(JNIEnv *env, void **package_addr, size_t *package_size) {
    load_package(env, package_addr, package_size);
}

static void release_package(void *package_addr, size_t package_size) {
    unload_package(package_addr, package_size);
}
#endif

// ---- Task 1.4: InMemoryDexClassLoader ---------------------------------
//
// Instead of writing the zip out of classes.dex and combining the file, the
// protected dexes are handed to ART as direct ByteBuffers wrapped in a
// temporary InMemoryDexClassLoader; its dex elements are then appended to the
// app's DexPathList (a splice), exactly the way combineDexElement appends the
// extracted zip. The zip is never written to code_cache unless the fallback
// in combineDexElements triggers.

// Every dex buffer this shell handed to ART, with a snapshot of the dex
// header taken at registration. The location gate in dpt_hook.cpp consults
// this: ART gives every in-memory dex a location starting with
// "Anonymous-DexFile", including dexes loaded by the app itself, and only
// buffers registered here may be patched.
struct RegisteredInMemDex {
    const uint8_t *begin;
    size_t size;
    uint8_t header[sizeof(dex::Header)];
};
static std::mutex g_inmem_dex_mutex;
static std::vector<RegisteredInMemDex> g_inmem_dexes;

bool isShellInMemoryDex(const uint8_t *begin) {
    std::lock_guard<std::mutex> lg(g_inmem_dex_mutex);
    for (const auto &rec : g_inmem_dexes) {
        if (begin >= rec.begin && begin < rec.begin + rec.size) {
            return true;
        }
    }
    // Android 16 (v1.0.5): the in-memory DexFile ART passes to DefineClass
    // has a begin_ outside the registered buffer range, so the address check
    // alone rejected every protected class, the random filler was never
    // replaced, and ART's verifier rejected the Application with VerifyError.
    // Whatever ART did with the buffer, its dex still starts with the exact
    // header bytes we registered (dex header carries the file checksum and
    // SHA-1 signature, so a foreign in-memory dex cannot collide), so fall
    // back to matching on content.
    for (const auto &rec : g_inmem_dexes) {
        if (memcmp(begin, rec.header, sizeof(rec.header)) == 0) {
            return true;
        }
    }
    return false;
}

static void registerShellInMemoryDex(const uint8_t *begin, size_t size) {
    std::lock_guard<std::mutex> lg(g_inmem_dex_mutex);
    RegisteredInMemDex rec{};
    rec.begin = begin;
    rec.size = size;
    if (begin != nullptr && size >= sizeof(rec.header)) {
        memcpy(rec.header, begin, sizeof(rec.header));
    }
    g_inmem_dexes.push_back(rec);
}

// "classes.dex" -> 0, "classesN.dex" -> N-1, anything else -> -1.
// Mirrors DexUtils.getDexNumber on the packing side: the payload indexes each
// dex with exactly this number, and ART derives the runtime multidex suffix
// from the buffer's position inside the ByteBuffer[], so buffer position must
// equal payload dex index.
static int in_memory_dex_number(const char *name) {
    if (name == nullptr) {
        return -1;
    }
    static const std::string prefix = "classes";
    static const std::string suffix = ".dex";
    std::string s(name);
    if (s.size() < prefix.size() + suffix.size()
            || s.compare(0, prefix.size(), prefix) != 0
            || s.compare(s.size() - suffix.size(), suffix.size(), suffix) != 0) {
        return -1;
    }
    std::string digits = s.substr(prefix.size(), s.size() - prefix.size() - suffix.size());
    for (char c : digits) {
        if (c < '0' || c > '9') {
            return -1;
        }
    }
    if (digits.empty()) {
        return 0;
    }
    if (digits.size() > 4) {
        return -1;
    }
    return atoi(digits.c_str()) - 1;
}

// Read the embedded zip out of classes.dex, turn each classesN.dex entry into
// a direct ByteBuffer, and splice the resulting elements into
// targetClassLoader. Returns false on any problem; the caller then falls back
// to writing the zip and combining it the old way.
DPT_ENCRYPT static bool combineInMemoryDexElements(JNIEnv *env, jobject targetClassLoader) {
    void *package_addr = nullptr;
    size_t package_size = 0;
    ensure_package_loaded(env, &package_addr, &package_size);
    if (package_addr == nullptr || package_size == 0) {
        DLOGE("in-memory dex: apk mapping unavailable");
        release_package(package_addr, package_size);
        return false;
    }

    auto entry = read_zip_file_entry(package_addr, package_size,
                                     AY_OBFUSCATE(COMBINE_DEX_FILES_NAME_IN_ZIP));
    release_package(package_addr, package_size);
    if (!entry.has_value()) {
        DLOGE("in-memory dex: no %s in apk", COMBINE_DEX_FILES_NAME_IN_ZIP);
        return false;
    }

    auto [entry_data, entry_size] = entry.value();
    // Owns the classes.dex bytes for the whole call; every buffer below is a
    // copy out of it, so nothing points into this memory once we return.
    std::unique_ptr<uint8_t[]> entry_guard(entry_data);

    uint32_t zip_len = readZipLength(entry_data, entry_size);
    if (zip_len == 0 || entry_size <= (size_t) zip_len + 4) {
        DLOGE("in-memory dex: bad embedded zip length %u (entry size %zu)",
              zip_len, entry_size);
        return false;
    }
    const uint8_t *zip_start = entry_data + (entry_size - zip_len - 4);

    // dex number -> (buffer, size). std::map iterates in index order, which
    // is the order the buffers must be handed to ART.
    std::map<int, std::pair<std::unique_ptr<uint8_t[]>, size_t>> dexes;

    void *mem_stream = mz_stream_mem_create();
    void *zip_handle = mem_stream != nullptr ? mz_zip_create() : nullptr;
    if (mem_stream == nullptr || zip_handle == nullptr) {
        DLOGE("in-memory dex: minizip alloc failed");
        mz_zip_delete(&zip_handle);
        mz_stream_mem_delete(&mem_stream);
        return false;
    }
    mz_stream_mem_set_buffer(mem_stream, (void *) zip_start, zip_len);
    mz_stream_open(mem_stream, nullptr, MZ_OPEN_MODE_READ);

    bool entry_names_ok = true;
    int32_t err = mz_zip_open(zip_handle, mem_stream, MZ_OPEN_MODE_READ);
    if (err == MZ_OK) {
        err = mz_zip_goto_first_entry(zip_handle);
        while (err == MZ_OK) {
            mz_zip_file *file_info = nullptr;
            err = mz_zip_entry_get_info(zip_handle, &file_info);
            if (err != MZ_OK || file_info == nullptr) {
                break;
            }

            int dex_number = in_memory_dex_number(file_info->filename);
            if (dex_number < 0 || dex_number > 255) {
                // e.g. a stray junkcode.dex; the on-disk path handles those.
                DLOGE("in-memory dex: unexpected entry name '%s'", file_info->filename);
                entry_names_ok = false;
                break;
            }

            if (file_info->uncompressed_size > 0) {
                err = mz_zip_entry_read_open(zip_handle, 0, nullptr);
                if (err != MZ_OK) {
                    DLOGE("in-memory dex: open '%s' failed: %d", file_info->filename, err);
                    break;
                }
                auto buffer = std::make_unique<uint8_t[]>(file_info->uncompressed_size);
                int32_t nread = mz_zip_entry_read(zip_handle, buffer.get(),
                                                  (int32_t) file_info->uncompressed_size);
                mz_zip_entry_close(zip_handle);
                if (nread != (int32_t) file_info->uncompressed_size) {
                    DLOGE("in-memory dex: short read of '%s' (%d/" FMT_INT64_T ")",
                          file_info->filename, nread, file_info->uncompressed_size);
                    break;
                }
                dexes[dex_number] = {std::move(buffer), (size_t) file_info->uncompressed_size};
            }
            err = mz_zip_goto_next_entry(zip_handle);
        }
    } else {
        DLOGE("in-memory dex: embedded zip open failed: %d", err);
    }

    bool iterate_ok = (err == MZ_END_OF_LIST);
    mz_zip_close(zip_handle);
    mz_zip_delete(&zip_handle);
    mz_stream_mem_delete(&mem_stream);

    if (!entry_names_ok || !iterate_ok || dexes.empty()) {
        DLOGE("in-memory dex: zip read failed (names=%d, done=%d, count=%zu)",
              entry_names_ok, iterate_ok, dexes.size());
        return false;
    }

    // Buffer positions drive the runtime's multidex suffix, and the payload
    // was built with dexIndex == DexUtils.getDexNumber(entry name); a hole
    // would silently shift every later dex's index.
    int expect = 0;
    for (auto &kv : dexes) {
        if (kv.first != expect) {
            DLOGE("in-memory dex: dex indices not contiguous (%d != %d)", kv.first, expect);
            return false;
        }
        expect++;
    }

    // ByteBuffer[] in dex-number order. ART gives the i-th buffer the runtime
    // multidex suffix that parse_dex_number turns back into i -- buffer
    // position IS the payload's dex index.
    jclass byteBufferCls = jni::FindClass(env, "java/nio/ByteBuffer");
    if (byteBufferCls == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        DLOGE("in-memory dex: java/nio/ByteBuffer not found");
        return false;
    }
    jobjectArray buffers = env->NewObjectArray((jsize) dexes.size(), byteBufferCls, nullptr);
    if (buffers == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        DLOGE("in-memory dex: NewObjectArray failed");
        return false;
    }

    jsize buffer_index = 0;
    for (auto &kv : dexes) {
        jobject direct_buffer = env->NewDirectByteBuffer(kv.second.first.get(),
                                                          (jlong) kv.second.second);
        if (direct_buffer == nullptr) {
            if (env->ExceptionCheck()) env->ExceptionClear();
            DLOGE("in-memory dex: NewDirectByteBuffer failed for dex %d", kv.first);
            return false;
        }
        env->SetObjectArrayElement(buffers, buffer_index++, direct_buffer);
        env->DeleteLocalRef(direct_buffer);
    }

    jclass loaderCls = jni::FindClass(env, "dalvik/system/InMemoryDexClassLoader");
    if (loaderCls == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        DLOGE("in-memory dex: InMemoryDexClassLoader not found");
        return false;
    }
    jobject memLoader = jni::NewObject(env, loaderCls,
                                       "([Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V",
                                       buffers, targetClassLoader);
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (memLoader == nullptr) {
        DLOGE("in-memory dex: InMemoryDexClassLoader construction failed");
        return false;
    }

    // The buffers and the loader owning the elements must live for the whole
    // process: on some releases ART's in-memory DexFiles reference the buffer
    // memory directly (Android 10+ NonOwningMemoryRegion), and the spliced
    // elements keep pointing into the loader either way. cbde runs at most
    // once per process, so this is a single intentional leak; the buffers are
    // released from unique_ptr ownership at the same time.
    static jobject g_mem_loader_global = nullptr;
    if (g_mem_loader_global == nullptr) {
        g_mem_loader_global = env->NewGlobalRef(memLoader);
    }
    if (g_mem_loader_global == nullptr) {
        // OOM: the loader could be collected while the spliced elements still
        // point into it. Bail out before the buffers leave unique_ptr
        // ownership, so the fallback path frees them normally.
        DLOGE("in-memory dex: NewGlobalRef failed");
        return false;
    }
    for (auto &kv : dexes) {
        registerShellInMemoryDex(kv.second.first.get(), kv.second.second);
        kv.second.first.release();
    }

    // Splice: append the temporary loader's elements to the target's
    // DexPathList, the same construction combineDexElement uses.
    reflect::dalvik_system_BaseDexClassLoader memBase(env, memLoader);
    jobject memPathListObj = memBase.getPathList();
    if (memPathListObj == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        DLOGE("in-memory dex: temporary loader has no pathList");
        return false;
    }
    reflect::dalvik_system_DexPathList memPathList(env, memPathListObj);
    jobjectArray memElements = memPathList.getDexElements();
    if (memElements == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        DLOGE("in-memory dex: temporary loader has no elements");
        return false;
    }
    jsize memSize = env->GetArrayLength(memElements);
    if (memSize <= 0) {
        DLOGE("in-memory dex: no elements produced");
        return false;
    }

    reflect::dalvik_system_BaseDexClassLoader targetBase(env, targetClassLoader);
    jobject targetPathListObj = targetBase.getPathList();
    if (targetPathListObj == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        DLOGE("in-memory dex: target pathList missing");
        return false;
    }
    reflect::dalvik_system_DexPathList targetPathList(env, targetPathListObj);
    jobjectArray originElements = targetPathList.getDexElements();
    if (originElements == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        DLOGE("in-memory dex: target dexElements missing");
        return false;
    }
    jsize originSize = env->GetArrayLength(originElements);

    reflect::dalvik_system_DexPathList::Element element(env, nullptr);
    jclass elementClass = element.getClass();
    if (elementClass == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        DLOGE("in-memory dex: DexPathList$Element not found");
        return false;
    }
    jobjectArray newElements = env->NewObjectArray(originSize + memSize, elementClass, nullptr);
    if (newElements == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        DLOGE("in-memory dex: NewObjectArray failed");
        return false;
    }

    for (jsize i = 0; i < originSize; i++) {
        jobject elementObj = env->GetObjectArrayElement(originElements, i);
        env->SetObjectArrayElement(newElements, i, elementObj);
        if (elementObj != nullptr) {
            env->DeleteLocalRef(elementObj);
        }
    }
    for (jsize i = 0; i < memSize; i++) {
        jobject elementObj = env->GetObjectArrayElement(memElements, i);
        env->SetObjectArrayElement(newElements, originSize + i, elementObj);
        if (elementObj != nullptr) {
            env->DeleteLocalRef(elementObj);
        }
    }

    targetPathList.setDexElements(newElements);
    DLOGI("in-memory dex elements combined: origin=%d, in-memory=%d",
          originSize, memSize);
    return true;
}

DPT_ENCRYPT void init_app(JNIEnv *env, jclass __unused) {
    DLOGD("called!");
    clock_t start = clock();

    void *package_addr = nullptr;
    size_t package_size = 0;
    ensure_package_loaded(env, &package_addr, &package_size);

    if(!g_codeItemFileData.has_value()) {
        auto entry_data = read_zip_file_entry(package_addr, package_size, AY_OBFUSCATE(CODE_ITEM_NAME_IN_ZIP));
        if(entry_data.has_value()) {
            g_codeItemFileData = std::move(entry_data);
        }
        printTime("read codeitem data took =" , start);

    }
    else {
        DLOGD("no need read codeitem from zip");
    }
    auto [entry_data, entry_size] = g_codeItemFileData.value();
    readCodeItem((uint8_t *)entry_data, entry_size);

    if (g_use_in_memory_dex) {
        // Task 1.4: in-memory mode never writes code_cache. If the in-memory
        // combine later fails, combineDexElements writes the zip itself as
        // part of its fallback.
        DLOGI("in-memory dex mode, skip extracting %s", DEXES_ZIP_NAME);
    } else {
        pthread_mutex_lock(&g_write_dexes_mutex);
        extractDexesInNeeded(env, package_addr, package_size);
        pthread_mutex_unlock(&g_write_dexes_mutex);
    }

    release_package(package_addr, package_size);
    printTime("read package data took =" , start);
}

DPT_ENCRYPT void readCodeItem(uint8_t *data,size_t data_len) {

    if (data == nullptr || data_len < 16) {
        DLOGE("OoooooOooo invalid: data=%p len=%zu", data, data_len);
        return;
    }

    // v4 keeps everything in the mapped payload: patchClass binary-searches the
    // class index on demand, so there is no per-dex 65536-entry table to build
    // and nothing to free at teardown.
    auto* dexCode = data::MultiDexCode::getInst();
    dexCode->init(data, data_len);

    if (!dexCode->isValid()) {
        DLOGE("OoooooOooo rejected by init; insns will not be restored");
        return;
    }
    DLOGI("OoooooOooo v4 ready: version = %d, dexCount = %d, classes = %u",
          dexCode->getVersion(), dexCode->getDexCount(), dexCode->getClassCount());
}

DPT_ENCRYPT void read_shell_config(JNIEnv *env) {
    void *package_addr = nullptr;
    size_t package_size = 0;
    ensure_package_loaded(env, &package_addr, &package_size);

    auto entry = read_zip_file_entry(package_addr, package_size , AY_OBFUSCATE(SHELL_CONFIG_IN_ZIP));
    if(entry.has_value()) {
        auto [entry_data, entry_size] = entry.value();
        std::unique_ptr<uint8_t[]> entry_guard(entry_data);
        if(entry_size > 0) {
            reflect::android_app_ActivityThread activityThread(env);
            jobject mBoundApplicationObj = activityThread.getBoundApplication();
            if (mBoundApplicationObj == nullptr) {
                DLOGE("bound application is null");
                release_package(package_addr, package_size);
                return;
            }

            reflect::android_app_ActivityThread::AppBindData appBindData(env, mBoundApplicationObj);
            jobject appInfoObj = appBindData.getAppInfo();
            if (appInfoObj == nullptr) {
                DLOGE("app info is null");
                release_package(package_addr, package_size);
                return;
            }

            reflect::android_content_pm_ApplicationInfo applicationInfo(env, appInfoObj);
            jstring packageNameJstr = applicationInfo.getPackageName();
            if (packageNameJstr == nullptr) {
                DLOGE("package name is null");
                release_package(package_addr, package_size);
                return;
            }

            const char *packageNameChs = env->GetStringUTFChars(packageNameJstr, nullptr);
            if (packageNameChs == nullptr || packageNameChs[0] == '\0') {
                DLOGE("package name is empty");
                if (packageNameChs != nullptr) {
                    env->ReleaseStringUTFChars(packageNameJstr, packageNameChs);
                }
                release_package(package_addr, package_size);
                return;
            }

            std::string packageName(packageNameChs);
            env->ReleaseStringUTFChars(packageNameJstr, packageNameChs);
            const char *buildKey = AY_OBFUSCATE(DPT_BUILD_KEY);
            const char *keySep = AY_OBFUSCATE("_");
            std::string key_material = packageName + keySep + buildKey;
            DLOGD("key material for config key: %s", key_material.c_str());

            auto aes_key = hmac_sha256(DPT_UNKNOWN_DATA,
                                       16,
                                       reinterpret_cast<const uint8_t *>(key_material.data()),
                                       key_material.size());
            if (aes_key.size() != 32) {
                DLOGE("derive config aes key failed");
                release_package(package_addr, package_size);
                return;
            }
            memcpy(g_shell_config.aes_key, aes_key.data(), sizeof(g_shell_config.aes_key));

            std::vector<uint8_t> indata(entry_data, entry_data + entry_size);

            uint8_t iv[16] = {0};
            memcpy(iv, DPT_UNKNOWN_DATA, 16);
            iv[3] = 0x2f;
            iv[9] = 0x76;
            auto decrypted_data = aes_cbc_decrypt(aes_key.data(), 256, iv, indata.data(), entry_size);
            if (decrypted_data.empty()) {
                DLOGE("decrypt shell config failed");
                release_package(package_addr, package_size);
                return;
            }

            try {
                std::string jsonStr = std::string(decrypted_data.begin(), decrypted_data.end());
                DLOGD("raw config: '%s'", jsonStr.c_str());

                nlohmann::json shell_config = nlohmann::json::parse(jsonStr);
                const char *keyAppName = AY_OBFUSCATE("app_name");
                const char *keyAcfName = AY_OBFUSCATE("acf_name");
                const char *keyJniClsName = AY_OBFUSCATE("jni_cls_name");
                const char *keyAppSignSha256 = AY_OBFUSCATE("app_sign_sha256");
                const char *keyDexSign = AY_OBFUSCATE("dex_sign");
                const char *keyJunkClsName = AY_OBFUSCATE("junk_cls_name");
                const char *keyRiskCheckFlags = AY_OBFUSCATE("risk_check_flags");
                const char *keyDisableInMemoryDex = AY_OBFUSCATE("disable_inmemory_dex");
                g_shell_config.application_name = shell_config.value(keyAppName, "");
                g_shell_config.application_component_factory = shell_config.value(keyAcfName, "");
                g_shell_config.jni_class_name = shell_config.value(keyJniClsName, "");
                g_shell_config.app_sign_sha256 = shell_config.value(keyAppSignSha256, "");
                g_shell_config.dex_sign = shell_config.value(keyDexSign, "");
                g_shell_config.junk_class_name = shell_config.value(keyJunkClsName, "");
                g_shell_config.risk_check_flags = shell_config.value(keyRiskCheckFlags, 0);
                g_shell_config.disable_inmemory_dex = shell_config.value(keyDisableInMemoryDex, false);

                DLOGD("application_name = %s", g_shell_config.application_name.c_str());
                DLOGD("application_component_factory = %s", g_shell_config.application_component_factory.c_str());
                DLOGD("jni_class_name = %s", g_shell_config.jni_class_name.c_str());
                DLOGD("app_sign_sha256 = %s", g_shell_config.app_sign_sha256.c_str());
                DLOGD("dex_sign = %s", g_shell_config.dex_sign.c_str());
                DLOGD("junk_class_name = %s", g_shell_config.junk_class_name.c_str());
                DLOGD("risk_check_flags = 0x%x", g_shell_config.risk_check_flags);
                DLOGD("disable_inmemory_dex = %d", g_shell_config.disable_inmemory_dex ? 1 : 0);
            } catch (const std::exception &e) {
                DLOGE("parse shell config failed: %s", e.what());
            }
        }
    }

    release_package(package_addr, package_size);

    // Task 1.4: decide the dex loading mode once, before anything can call
    // cbde/ia. In-memory needs the multidex location suffix that ART only
    // gives buffer-array loaders from Android 10 on; on older releases every
    // buffer would parse as dex 0 and the wrong payload would be restored.
    // A parse failure above leaves the flag false, i.e. the safe on-disk path.
    g_use_in_memory_dex = !g_shell_config.disable_inmemory_dex
            && android_get_device_api_level() >= __ANDROID_API_Q__;
    DLOGI("in-memory dex mode: %s (api=%d, disabled=%d)",
          g_use_in_memory_dex ? "on" : "off",
          android_get_device_api_level(),
          g_shell_config.disable_inmemory_dex ? 1 : 0);
}


void veritySignature(JNIEnv *env) {
    if (!g_shell_config.app_sign_sha256.empty()) {
        jobject application = android_app_ActivityThread::currentApplication(env);

        verifyAppSignature(env, application, g_shell_config.app_sign_sha256.c_str());
    }
}

DPT_ENCRYPT JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *) {

    JNIEnv *env = nullptr;
    if (vm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        DLOGF("GetEnv() fail!");
        return JNI_ERR;
    }

    read_shell_config(env);

    antiRisk();

    if (registerNativeMethods(env) == JNI_FALSE) {
        DLOGF("register native methods fail!");
        return JNI_ERR;
    }

    DLOGI("called!");
    return JNI_VERSION_1_6;
}

JNIEXPORT void JNI_OnUnload(__unused JavaVM* vm,__unused void* reserved) {
    DLOGI("called!");
}