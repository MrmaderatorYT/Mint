#pragma once

#include <jni.h>

#include <string>

namespace mint::jni {

/// Scoped accessor for a Java primitive array.
///
/// JNI's Get/Release pairing is a leak waiting to happen on every early return,
/// and the analysis code has plenty of those. Wrapping it means a bounds check
/// can `return` freely without leaving a pinned array behind.
template <typename T, typename JArray>
class ArrayRef {
public:
    ArrayRef(JNIEnv* env, JArray array, T* (JNIEnv::*get)(JArray, jboolean*),
             void (JNIEnv::*release)(JArray, T*, jint))
        : env_(env), array_(array), release_(release) {
        if (array_ != nullptr) {
            data_ = (env_->*get)(array_, nullptr);
            length_ = env_->GetArrayLength(array_);
        }
    }

    ~ArrayRef() {
        if (data_ != nullptr) {
            // 0 commits the changes back, which is what an out-parameter needs.
            (env_->*release_)(array_, data_, 0);
        }
    }

    ArrayRef(const ArrayRef&) = delete;
    ArrayRef& operator=(const ArrayRef&) = delete;

    T* data() const { return data_; }
    jsize length() const { return length_; }
    bool valid() const { return data_ != nullptr; }

private:
    JNIEnv* env_;
    JArray array_;
    void (JNIEnv::*release_)(JArray, T*, jint);
    T* data_ = nullptr;
    jsize length_ = 0;
};

using LongArrayRef = ArrayRef<jlong, jlongArray>;
using IntArrayRef = ArrayRef<jint, jintArray>;

inline LongArrayRef longArray(JNIEnv* env, jlongArray array) {
    return LongArrayRef(env, array, &JNIEnv::GetLongArrayElements,
                        &JNIEnv::ReleaseLongArrayElements);
}

inline IntArrayRef intArray(JNIEnv* env, jintArray array) {
    return IntArrayRef(env, array, &JNIEnv::GetIntArrayElements,
                       &JNIEnv::ReleaseIntArrayElements);
}

inline jstring toJava(JNIEnv* env, const std::string& value) {
    return env->NewStringUTF(value.c_str());
}

inline std::string fromJava(JNIEnv* env, jstring value) {
    if (value == nullptr) return {};
    const char* chars = env->GetStringUTFChars(value, nullptr);
    if (chars == nullptr) return {};
    std::string result(chars);
    env->ReleaseStringUTFChars(value, chars);
    return result;
}

/// Throws a Java exception. Callers must return to the JVM immediately after.
void throwIllegalState(JNIEnv* env, const std::string& message);
void throwIllegalArgument(JNIEnv* env, const std::string& message);
void throwIoException(JNIEnv* env, const std::string& message);

}  // namespace mint::jni
