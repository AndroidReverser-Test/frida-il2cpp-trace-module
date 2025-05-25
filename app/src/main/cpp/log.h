//
// Created by wuwenhui on 2025/5/19.
//

#ifndef IL2CPP_TRACE_MODULE_LOG_H
#define IL2CPP_TRACE_MODULE_LOG_H

#include <android/log.h>

#define LOG_TAG "Test-Log"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)


#endif //IL2CPP_TRACE_MODULE_LOG_H
