/* 
 * File:   httpieces_version.h
 * Author: justinjack
 *
 * Created on May 9, 2019, 7:06 PM
 */


/* Version and revision information 
 * 
 * 1.0.0 - Initial build
 * 
 * https://github.com/justincjack/HTTPieces.git
 * 
 * git@github.com:justincjack/HTTPieces.git
 * 
 */

#ifndef HTTPIECES_VERSION_H
#define HTTPIECES_VERSION_H

#include <stdio.h>

typedef struct httpieces_version {
    int major, minor, patch;
} HTTPIECES_VERSION;


static HTTPIECES_VERSION VERSION = {1,0,0};

const char *version( void );
const HTTPIECES_VERSION *get_version( void );

#ifdef __cplusplus
extern "C" {
#endif




#ifdef __cplusplus
}
#endif

#endif /* HTTPIECES_VERSION_H */

