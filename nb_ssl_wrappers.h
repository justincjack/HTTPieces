/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   nb_ssl_wrappers.h
 * Author: justinjack
 *
 * Created on June 21, 2019, 3:14 PM
 */

#ifndef NB_SSL_WRAPPERS_H
#define NB_SSL_WRAPPERS_H


#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#ifdef __cplusplus
extern "C" {
#endif

int ssl_accept( SSL *ssl );


#ifdef __cplusplus
}
#endif

#endif /* NB_SSL_WRAPPERS_H */

