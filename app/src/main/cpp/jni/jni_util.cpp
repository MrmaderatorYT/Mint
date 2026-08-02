#include "jni/jni_util.h"

namespace mint::jni {
namespace {

void throwByName(JNIEnv* env, const char* className, const std::string& message) {
    jclass clazz = env->FindClass(className);
    if (clazz == nullptr) return;  // A pending ClassNotFound is already set.
    env->ThrowNew(clazz, message.c_str());
    env->DeleteLocalRef(clazz);
}

}  // namespace

void throwIllegalState(JNIEnv* env, const std::string& message) {
    throwByName(env, "java/lang/IllegalStateException", message);
}

void throwIllegalArgument(JNIEnv* env, const std::string& message) {
    throwByName(env, "java/lang/IllegalArgumentException", message);
}

void throwIoException(JNIEnv* env, const std::string& message) {
    throwByName(env, "java/io/IOException", message);
}

}  // namespace mint::jni
