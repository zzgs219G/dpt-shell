//
// Created by luoyesiqiu
//

#ifndef DPT_DPT_RISK_H
#define DPT_DPT_RISK_H

#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include <jni.h>

#include "dpt_util.h"
#include "dpt_log.h"
#include "dpt_jni.h"
#include "linux_syscall_support.h"
#include "common/obfuscate.h"

/* 处置出口（2026-10-26 多路化，防"patch 一处全废"）。
 * 按失败类别选用，不要都指向同一个——那等于把 4 个出口又合成 1 个单点。
 *   dpt_die_0  环境异常（探针读不到数据 / JNI 取 PM 失败）
 *   dpt_die_1  畸形输入（zip / 配置 / dex 结构非法）
 *   dpt_die_2  检测命中（frida / 调试器 / libc CRC 不一致）——最重
 *   dpt_die_3  完整性（签名不符 / junk 类被删 / dex 签名被重打包）
 * dpt_crash 保留为兼容入口（第 5 个独立函数体），新代码勿用。 */
void dpt_die_0();
void dpt_die_1();
void dpt_die_2();
void dpt_die_3();
void dpt_crash();
void detectFrida();
void detectDebugger();
void detectRisk();
void junkCodeDexProtect(JNIEnv *env);
void verifyAppSignature(JNIEnv *env, jobject context, const char *expectedSha256);
void verifyLibcTextCrc();

#endif //DPT_DPT_RISK_H
