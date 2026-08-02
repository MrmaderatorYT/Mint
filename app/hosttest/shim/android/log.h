// Minimal stand-in for the NDK's <android/log.h> so the engine can be compiled
// and run on a development host.
//
// The point of the host build is a fast test loop: an emulator round-trip per
// change would make iterating on a decompiler impractical, and the analysis code
// is ordinary C++ with no Android dependency beyond logging.
#pragma once

#include <stdarg.h>
#include <stdio.h>

enum android_LogPriority {
    ANDROID_LOG_UNKNOWN = 0,
    ANDROID_LOG_DEFAULT,
    ANDROID_LOG_VERBOSE,
    ANDROID_LOG_DEBUG,
    ANDROID_LOG_INFO,
    ANDROID_LOG_WARN,
    ANDROID_LOG_ERROR,
    ANDROID_LOG_FATAL,
    ANDROID_LOG_SILENT,
};

static inline int __android_log_print(int priority, const char* tag,
                                      const char* format, ...) {
    const char* level = "?";
    switch (priority) {
        case ANDROID_LOG_DEBUG: level = "D"; break;
        case ANDROID_LOG_INFO: level = "I"; break;
        case ANDROID_LOG_WARN: level = "W"; break;
        case ANDROID_LOG_ERROR: level = "E"; break;
        default: break;
    }
    fprintf(stderr, "%s/%s: ", level, tag);
    va_list args;
    va_start(args, format);
    const int written = vfprintf(stderr, format, args);
    va_end(args);
    fputc('\n', stderr);
    return written;
}
