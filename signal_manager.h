/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   signal_manager.h
 * Author: justinjack
 *
 * Created on June 19, 2019, 10:23 AM
 */

#ifndef SIGNAL_MANAGER_H
#define SIGNAL_MANAGER_H

#include <signal.h>
#include <stdio.h>
#include <semaphore.h>


#define HTP_SIG_FAILURE 0

static sem_t shutdown_sem;

static int *ok_2_run = 0;

#ifdef __cplusplus
extern "C" {
#endif

void htp_sig_hand( int signum );
sem_t *configure_shutdown_signals( int *okay_to_run );



#ifdef __cplusplus
}
#endif

#endif /* SIGNAL_MANAGER_H */

