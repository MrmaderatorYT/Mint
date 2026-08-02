#pragma once

#include <android/log.h>

#define MINT_LOG_TAG "MintCore"

#define MINT_LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, MINT_LOG_TAG, __VA_ARGS__)
#define MINT_LOGI(...) __android_log_print(ANDROID_LOG_INFO, MINT_LOG_TAG, __VA_ARGS__)
#define MINT_LOGW(...) __android_log_print(ANDROID_LOG_WARN, MINT_LOG_TAG, __VA_ARGS__)
#define MINT_LOGE(...) __android_log_print(ANDROID_LOG_ERROR, MINT_LOG_TAG, __VA_ARGS__)
