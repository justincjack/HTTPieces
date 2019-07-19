/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   htp_message_processor.h
 * Author: justinjack
 *
 * Created on June 9, 2019, 12:05 PM
 */

#ifndef HTP_MESSAGE_PROCESSOR_H
#define HTP_MESSAGE_PROCESSOR_H

#include "connection_manager.h"

typedef struct _message_processor {
    int processor_socket;
    
    
} MESSAGE_PROCESSOR;


void process_message(PCONNECTION_MESSAGE con_msg);

//
//#ifdef __cplusplus
//extern "C" {
//#endif
//
//
//
//
//#ifdef __cplusplus
//}
//#endif
//
#endif /* HTP_MESSAGE_PROCESSOR_H */

