#include <capstone/capstone.h>
#include <jni.h>

#include <string>

#include "mint/base/log.h"
#include "mint/base/status.h"
#include "mint/base/types.h"

namespace {

jstring toJavaString(JNIEnv* env, const std::string& value) {
    return env->NewStringUTF(value.c_str());
}

}  // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_com_ccs_mint_core_NativeCore_nativeEngineInfo(JNIEnv* env, jclass) {
    int major = 0;
    int minor = 0;
    cs_version(&major, &minor);

    std::string info = "mintcore/1 capstone/" + std::to_string(major) + "." +
                       std::to_string(minor);

    // If a decoder we depend on were compiled out, everything above the
    // disassembler would produce plausible-looking nonsense instead of failing,
    // so the presence of both is checked once here at startup.
    info += cs_support(CS_ARCH_AARCH64) ? " arm64:yes" : " arm64:NO";
    info += cs_support(CS_ARCH_X86) ? " x86:yes" : " x86:NO";

    MINT_LOGI("%s", info.c_str());
    return toJavaString(env, info);
}
