/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   http2_debug.h
 * Author: justinjack
 *
 * Created on June 21, 2019, 6:39 AM
 */

#ifndef HTTP2_DEBUG_H
#define HTTP2_DEBUG_H




#include <stdio.h>
#include <sys/types.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/syscall.h>




/* Debugging Constants ******************************************************/
/* Bits for which certain functions' debugging messages appear              */
/****************************************************************************/
#define HTTP2_INIT                              1
#define HTTP2_CONNECTION_THREAD                 0X2
#define DELEGATE_NEW_CONNECTION                 0X4
#define SCHEDULE_HTTP2_CONNECTION_DESTRUCTION   0X8
#define RETIRE_HTTP2_CONNECTION_THREAD          0X10
#define CREATE_HTTP2_CONNECTION_THREAD          0X20
#define HTTP2_REMOVE_THREAD_FROM_LIST           0X40
#define HTTP2_LOCK                              0X80
#define HTTP2_UNLOCK                            0X100
#define HTTP2_FREE_MUTEX                        0X200
#define HTTP2_RETIRE_MUTEX                      0X400
#define HTTP2_NEW_MUTEX                         0X800
#define HTTP2_POP_CONNECTION                    0X1000
#define HTTP2_PUSH_CONNECTION                   0X2000
#define HTTP2_WORKER_SIGNAL_HANDLER             0X4000
#define HTTP2_SHUTDOWN_ALL                      0x8000
#define HTTP2_TCP_SOCKET_WRITER                 0x10000
#define HTTP2_PROCESS_SETTINGS_FRAME            0x20000
//#define HTTP2_                                  0x40000
//#define HTTP2_                                  0x80000
//#define HTTP2_                                  0x100000
//#define HTTP2_                                  0x200000
//#define HTTP2_                                  0x400000
//#define HTTP2_                                  0x800000
//#define HTTP2_                                  0x1000000
//#define HTTP2_                                  0x2000000
//#define HTTP2_                                  0x4000000
//#define HTTP2_                                  0x8000000
//#define HTTP2_                                  0x10000000
//#define HTTP2_                                  0x20000000
//#define HTTP2_                                  0x40000000
//#define HTTP2_                                  0x80000000
//#define HTTP2_                                  0x100000000
//#define HTTP2_                                  0x200000000
//#define HTTP2_                                  0x400000000
//#define HTTP2_                                  0x800000000
//#define HTTP2_                                  0x1000000000
//#define HTTP2_                                  0x2000000000
//#define HTTP2_                                  0x4000000000
//#define HTTP2_                                  0x8000000000
//#define HTTP2_                                  0x10000000000
//#define HTTP2_                                  0x20000000000
//#define HTTP2_                                  0x40000000000
//#define HTTP2_                                  0x80000000000
//#define HTTP2_                                  0x100000000000
//#define HTTP2_                                  0x200000000000
//#define HTTP2_                                  0x400000000000
//#define HTTP2_                                  0x800000000000
//#define HTTP2_                                  0x100000000000
//#define HTTP2_                                  0x200000000000
//#define HTTP2_                                  0x400000000000
//#define HTTP2_                                  0x800000000000
//#define HTTP2_                                  0x1000000000000
//#define HTTP2_                                  0x2000000000000
//#define HTTP2_                                  0x4000000000000
//#define HTTP2_                                  0x8000000000000
//#define HTTP2_                                  0x10000000000000
//#define HTTP2_                                  0x20000000000000
//#define HTTP2_                                  0x40000000000000
//#define HTTP2_                                  0x80000000000000
//#define HTTP2_                                  0x100000000000000
//#define HTTP2_                                  0x200000000000000
//#define HTTP2_                                  0x400000000000000
//#define HTTP2_                                  0x800000000000000
//#define HTTP2_                                  0x1000000000000000
//#define HTTP2_                                  0x2000000000000000
//#define HTTP2_                                  0x4000000000000000
#define HTTP2_VERY_IMPORTANT                    0x8000000000000000
//#define 
/****************************************************************************/


static int HTTP2_LOG_LEVEL =    HTTP2_CONNECTION_THREAD|
                                HTTP2_TCP_SOCKET_WRITER|
                                HTTP2_PROCESS_SETTINGS_FRAME|
                                /*DELEGATE_NEW_CONNECTION|*/
                                /*SCHEDULE_HTTP2_CONNECTION_DESTRUCTION|*/
                                /*RETIRE_HTTP2_CONNECTION_THREAD|*/
                                /*CREATE_HTTP2_CONNECTION_THREAD|*/
                                /*HTTP2_REMOVE_THREAD_FROM_LIST|*/
                                /*HTTP2_SHUTDOWN_ALL|*/
                                HTTP2_POP_CONNECTION|
                                HTTP2_PUSH_CONNECTION|
                                HTTP2_WORKER_SIGNAL_HANDLER;

static pthread_mutex_t http2_debug_mutex = PTHREAD_MUTEX_INITIALIZER;

#ifndef gettid
    #define gettid() syscall(SYS_gettid)
#endif

#define http2_debug(level, ...) {\
                                    if ( ((level & HTTP2_LOG_LEVEL) == level) ||\
                                         ((level & HTTP2_VERY_IMPORTANT) == HTTP2_VERY_IMPORTANT) )\
                                    {\
                                        pthread_mutex_lock(&http2_debug_mutex);\
                                        printf("%s:%d [Thread: %lu ] in function %s() - ", __FILE__, __LINE__, gettid(), __FUNCTION__);\
                                        printf(__VA_ARGS__);\
                                        fflush(stdout);\
                                        pthread_mutex_unlock(&http2_debug_mutex);\
                                    }\
                                }
    

#define http2_error(...) {\
                            pthread_mutex_lock(&http2_debug_mutex);\
                            printf("** ERROR ** %s:%d [Thread: %lu] in function: %s() - ", __FILE__, __LINE__, gettid(), __FUNCTION__);\
                            printf(__VA_ARGS__);\
                            pthread_mutex_unlock(&http2_debug_mutex);\
                            fflush(stdout);\
                         }\
    




#endif /* HTTP2_DEBUG_H */

