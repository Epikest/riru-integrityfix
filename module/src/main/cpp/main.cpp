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

#include "logging.h"
#include "nativehelper/scoped_utf_chars.h"
#include "android_filesystem_config.h"

const char* MODDIR = nullptr;
const char* FINGERPRINT = nullptr;

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
    	LOGI("Spoof for %s with \nFINGERPRINT:%s", package_name, finger1);
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
    }
    return config;
}

static void preSpecialize(const char *process, JNIEnv *env){
    std::string package_name = process;
    // Inject marlin prop to pass Play Integrity
    if (strcmp(process,"com.google.android.gms") == 0 || strcmp(process,"com.google.android.gms.unstable") == 0) {
        injectBuild(process,FINGERPRINT, env);
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
        riru_set_unload_allowed(true);
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
    riru_set_unload_allowed(true);
}

void onModuleLoaded() {
    LOGI("MODDIR is %s", MODDIR);
    FINGERPRINT = ReadConfig();
    LOGI("Fingerprint is %s", FINGERPRINT);
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
