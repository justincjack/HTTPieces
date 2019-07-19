
/* 
 * File:   debug.h
 * Author: justinjack
 *
 * Created on July 10, 2019, 6:34 AM
 */

#ifndef DEBUG_H
#define DEBUG_H

#include <sys/syscall.h>
#include <stdio.h>
#include <pthread.h>


#ifndef DEBUG_LEVEL
static int DEBUG_LEVEL              = 7;
#endif

#ifndef gettid
    #define gettid() syscall(SYS_gettid)
#endif

static pthread_mutex_t debug_mutex      = PTHREAD_MUTEX_INITIALIZER;

#define debug(level, ...) {\
                                    if ( level <= CGI_DEBUG_LEVEL )\
                                    {\
                                        pthread_mutex_lock(&debug_mutex);\
                                        printf("%s:%d [Thread: %lu ] in function %s() - ", __FILE__, __LINE__, gettid(), __FUNCTION__);\
                                        printf(__VA_ARGS__);\
                                        fflush(stdout);\
                                        pthread_mutex_unlock(&debug_mutex);\
                                    }\
                                }
    

#define error(...) {\
                            pthread_mutex_lock(&debug_mutex);\
                            fprintf(stderr, "** ERROR ** %s:%d [Thread: %lu] in function: %s() - ", __FILE__, __LINE__, gettid(), __FUNCTION__);\
                            fprintf(stderr, __VA_ARGS__);\
                            pthread_mutex_unlock(&debug_mutex);\
                            fflush(stderr);\
                         }
    



#endif /* DEBUG_H */

