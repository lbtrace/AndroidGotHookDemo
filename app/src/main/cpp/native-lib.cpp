#include <jni.h>
#include <string>
#include <android/log.h>

#include "got_hook.h"


extern "C" {
static const char *log_tag = "native-lib";

void got_hook_handle(void)
{
    return;
}

static void test_got_hook(const char *apk_path)
{
    char lib_path[128];

#if defined(__LP64__)
    snprintf(lib_path, 128, "%s/lib/arm64/libnative-lib.so", apk_path);
#else
    snprintf(lib_path, 128, "%s/lib/arm/libnative-lib.so", apk_path);
#endif

    got_hook(lib_path, "__android_log_print", got_hook_handle);
    __android_log_print(ANDROID_LOG_INFO, log_tag, "hook demo");
}

JNIEXPORT jstring JNICALL
Java_lbtrace_hookdemo_MainActivity_stringFromJNI(
        JNIEnv *env,
        jobject /* this */, jstring apkPath) {
    std::string hello = "Hello from C++";
    const char *apk_path = env->GetStringUTFChars(apkPath, NULL);

    test_got_hook(apk_path);

    return env->NewStringUTF(hello.c_str());
}
}
