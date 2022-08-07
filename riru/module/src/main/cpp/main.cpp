#include <jni.h>
#include <sys/types.h>
#include <riru.h>
#include <malloc.h>
#include <cstdlib>
#include <unistd.h>
#include <string>
#include <vector>
#include <fcntl.h>
#include <stdio.h>
#include <cerrno>

#include <cstring>
#include <sys/mman.h>
#include <android/log.h>

#include "logging.h"
#include "nativehelper/scoped_utf_chars.h"
#include "android_filesystem_config.h"
#include <sys/system_properties.h>

const char* MODDIR = nullptr;
const char* FINGERPRINT = nullptr;
char* FINGERPRINT_ORIG = new char [1024];
static void *moduleDex;
static size_t moduleDexSize;
static bool gmsSpecializePending = false;
static bool finger_inject = false;

void injectBuild(const char *package_name,const char *finger1, JNIEnv *env) {
    if (env == nullptr) {
        LOGW("failed to inject android.os.Build for %s due to env is null", package_name);
        return;
    }
    	
    jclass build_class = env->FindClass("android/os/Build");
    if (build_class == nullptr) {
        LOGW("failed to inject android.os.Build for %s due to build is null", package_name);
        return;
    } else {
    	LOGI("inject android.os.Build for %s with \nFINGERPRINT:%s", package_name, finger1);
    }

    jstring finger = env->NewStringUTF(finger1);

    if (strcmp(finger1,"") != 0) {
	        jfieldID finger_id = env->GetStaticFieldID(build_class, "FINGERPRINT", "Ljava/lang/String;");
	        if (finger_id != nullptr) {
	            env->SetStaticObjectField(build_class, finger_id, finger);
	        }
	}

    if(env->ExceptionCheck())
    {
        env->ExceptionClear();
    }

    if (strcmp(finger1,"") != 0) {
    	env->DeleteLocalRef(finger);
    }
}

const char* ReadConfig(){
    const char* config = "google/marlin/marlin:7.1.2/NJH47F/4146041:user/release-keys";
    char path[128];
    snprintf(path, 127, "%s/fingerprint.txt", MODDIR);
    FILE* fp = fopen(path, "re");
    if (fp) {
        char tmp[2048];
        fseek(fp, 0, SEEK_END);
        long size = ftell(fp);
        rewind(fp);

        if (size == fread(tmp, 1, static_cast<size_t>(size), fp)) {
            tmp[size] = '\0';
            config = strdup(tmp);
        } else {
            LOGE("Failed to read config file: %s", strerror(errno));
        }
        fclose(fp);
    } else {
        LOGE("Failed to open config file: %s", strerror(errno));
        return nullptr;
    }
    LOGI("Fingerprint is %s", config);
    finger_inject = true;
    return config;
}

static void specializeCommon(JNIEnv *env) {
    if (!moduleDex || !gmsSpecializePending) {
        // dex null or specialize not pending
        riru_set_unload_allowed(true);
        return;
    }

    LOGI("get system classloader");
    // First, get the system classloader
    jclass clClass = env->FindClass("java/lang/ClassLoader");
    jmethodID getSystemClassLoader = env->GetStaticMethodID(clClass, "getSystemClassLoader", "()Ljava/lang/ClassLoader;");
    jobject systemClassLoader = env->CallStaticObjectMethod(clClass, getSystemClassLoader);

    LOGI("create buf");
    // Assuming we have a valid mapped module, load it. This is similar to the approach used for
    // Dynamite modules in GmsCompat, except we can use InMemoryDexClassLoader directly instead of
    // tampering with DelegateLastClassLoader's DexPathList.
    jobject buf = env->NewDirectByteBuffer(moduleDex, moduleDexSize);
    LOGI("construct dex cl");
    jclass dexClClass = env->FindClass("dalvik/system/InMemoryDexClassLoader");
    jmethodID dexClInit = env->GetMethodID(dexClClass, "<init>", "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
    jobject dexCl = env->NewObject(dexClClass, dexClInit, buf, systemClassLoader);

    // Load the class
    LOGI("load class method lookup");
    jmethodID loadClass = env->GetMethodID(clClass, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    LOGI("call load class");
    jstring entryClassName = env->NewStringUTF("dev.kdrag0n.safetynetriru.EntryPoint");
    jobject entryClassObj = env->CallObjectMethod(dexCl, loadClass, entryClassName);

    // Call init. Static initializers don't run when merely calling loadClass from JNI.
    LOGI("call init");
    auto entryClass = (jclass) entryClassObj;
    jmethodID entryInit = env->GetStaticMethodID(entryClass, "init", "()V");
    env->CallStaticVoidMethod(entryClass, entryInit);
    LOGI("specializeCommon end");
}

static void *readFile(char *path, size_t *fileSize) {
    int fd = open(path, O_RDONLY, 0);
    if (fd < 0) {
        LOGE("open fail");
        return nullptr;
    }

    // Get size
    LOGI("get size");
    *fileSize = lseek(fd, 0, SEEK_END);
    if (*fileSize < 0) {
        LOGE("seek fail");
        return nullptr;
    }
    lseek(fd, 0, SEEK_SET);

    // Map
    /*
    LOGI("mmap");
    moduleDex = mmap(nullptr, *fileSize, PROT_READ, MAP_PRIVATE, fd, 0);
    if (moduleDex == MAP_FAILED) {
        LOGE("mmap fail");
    }*/

    // Read the entire file into a buffer
    // TODO: see if mmap path is visible in /proc/pid/maps after closing and forking
    char *data = (char *) malloc(*fileSize);
    int bytes = 0;
    while (bytes < *fileSize) {
        bytes += read(fd, data + bytes, *fileSize - bytes);
    }

    // Close the fd. This doesn't destroy the mapping.
    LOGI("close");
    close(fd);

    return data;
}

//

static void preSpecialize(const char *process, JNIEnv *env){
    std::string package_name = process;
    // Inject marlin prop to pass Play Integrity
    gmsSpecializePending = false;
    if (strcmp(process,"com.google.android.gms.unstable") == 0) {
        LOGI("Process is Safetynet");
        if (finger_inject) injectBuild(process,FINGERPRINT, env);
        gmsSpecializePending = true;
    } else {
        injectBuild(process,FINGERPRINT_ORIG, env);
        gmsSpecializePending = false;
    }
}

static void forkAndSpecializePre(
        JNIEnv *env, jclass clazz, jint *uid, jint *gid, jintArray *gids, jint *runtimeFlags,
        jobjectArray *rlimits, jint *mountExternal, jstring *seInfo, jstring *niceName,
        jintArray *fdsToClose, jintArray *fdsToIgnore, jboolean *is_child_zygote,
        jstring *instructionSet, jstring *appDataDir, jboolean *isTopApp, jobjectArray *pkgDataInfoList,
        jobjectArray *whitelistedDataInfoList, jboolean *bindMountAppDataDirs, jboolean *bindMountAppStorageDirs) {
    ScopedUtfChars process(env, *niceName);
    char processName[1024];
    sprintf(processName, "%s", process.c_str());
    preSpecialize(processName, env);
}

static void forkAndSpecializePost(JNIEnv *env, jclass clazz, jint res) {
    if (res == 0) {
        specializeCommon(env);
    }
}

static void specializeAppProcessPre(
        JNIEnv *env, jclass clazz, jint *uid, jint *gid, jintArray *gids, jint *runtimeFlags,
        jobjectArray *rlimits, jint *mountExternal, jstring *seInfo, jstring *niceName,
        jboolean *startChildZygote, jstring *instructionSet, jstring *appDataDir,
        jboolean *isTopApp, jobjectArray *pkgDataInfoList, jobjectArray *whitelistedDataInfoList,
        jboolean *bindMountAppDataDirs, jboolean *bindMountAppStorageDirs) {
    ScopedUtfChars process(env, *niceName);
    char processName[1024];
    sprintf(processName, "%s", process.c_str());
    preSpecialize(processName, env);
}

static void specializeAppProcessPost(JNIEnv *env, jclass clazz) {
    specializeCommon(env);
}

void onModuleLoaded() {
    // Load
    LOGI("onModuleLoaded, loading file");
    char pathBuf[128];
    snprintf(pathBuf, 128, "%s/%s", MODDIR, "classes.dex");

    moduleDex = readFile(pathBuf, &moduleDexSize);
    if (!moduleDex) {
        LOGE("classes.dex not found!");
        return;
    }

    LOGI("module loaded");
    FINGERPRINT = ReadConfig();
    __system_property_get("ro.build.fingerprint", FINGERPRINT_ORIG);
    LOGI("Original fingerprint is %s", FINGERPRINT_ORIG);
}


extern "C" {

int riru_api_version;
const char *riru_magisk_module_path = nullptr;
int *riru_allow_unload = nullptr;

static auto module = RiruVersionedModuleInfo{
        .moduleApiVersion = RIRU_MODULE_API_VERSION,
        .moduleInfo= RiruModuleInfo{
                .supportHide = true,
                .version = RIRU_MODULE_VERSION,
                .versionName = RIRU_MODULE_VERSION_NAME,
                .onModuleLoaded = onModuleLoaded,
                .forkAndSpecializePre = forkAndSpecializePre,
                .forkAndSpecializePost = forkAndSpecializePost,
                .forkSystemServerPre = nullptr,
                .forkSystemServerPost = nullptr,
                .specializeAppProcessPre = specializeAppProcessPre,
                .specializeAppProcessPost = specializeAppProcessPost
        }
};

#ifndef RIRU_MODULE_LEGACY_INIT
RiruVersionedModuleInfo *init(Riru *riru) {
    auto core_max_api_version = riru->riruApiVersion;
    riru_api_version = core_max_api_version <= RIRU_MODULE_API_VERSION ? core_max_api_version : RIRU_MODULE_API_VERSION;
    module.moduleApiVersion = riru_api_version;

    riru_magisk_module_path = strdup(riru->magiskModulePath);
    MODDIR = riru_magisk_module_path;
    if (riru_api_version >= 25) {
        riru_allow_unload = riru->allowUnload;
    }
    return &module;
}
#else
RiruVersionedModuleInfo *init(Riru *riru) {
    static int step = 0;
    step += 1;

    switch (step) {
        case 1: {
            auto core_max_api_version = riru->riruApiVersion;
            riru_api_version = core_max_api_version <= RIRU_MODULE_API_VERSION ? core_max_api_version : RIRU_MODULE_API_VERSION;
            if (riru_api_version >= 25) {
                riru_allow_unload = riru->allowUnload;
            }
            if (riru_api_version >= 24) {
                module.moduleApiVersion = riru_api_version;
                riru_magisk_module_path = strdup(riru->magiskModulePath);
                MODDIR = riru_magisk_module_path;
                return &module;
            } else {
                return (RiruVersionedModuleInfo *) &riru_api_version;
            }
        }
        case 2: {
            return (RiruVersionedModuleInfo *) &module.moduleInfo;
        }
        case 3:
        default: {
            return nullptr;
        }
    }
}
#endif
}
