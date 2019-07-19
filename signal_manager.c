
#include "signal_manager.h"

void htp_sig_hand( int signum ) {
    switch (signum) {
        case SIGHUP:
            break;
        case SIGTERM:
            *ok_2_run = 0;
            sem_post(&shutdown_sem);
            break;
        case SIGINT:
            *ok_2_run = 0;
            printf("\nCtrl-C\n\n");
            sem_post(&shutdown_sem);
            break;
        default:
            break;
    }
    return;
}


/* Returns SEMAPHORE on success, or NULL on error */
sem_t *configure_shutdown_signals( int *okay_to_run ) {
    struct sigaction sa;
    int i = 0;
    if (sem_init(&shutdown_sem, 0, 0)) {
        printf("Failed to initialize the shutdown semaphore!\n");
        return HTP_SIG_FAILURE;
    }
    
    for (; i < sizeof(sa); i++) ((char *)(&sa))[i] = 0;
    sa.sa_handler = &htp_sig_hand;
    
    if (sigaction(SIGINT, &sa, 0)) {
        sem_destroy(&shutdown_sem);
        return HTP_SIG_FAILURE;
    }
    
    if (sigaction(SIGTERM, &sa, 0)) {
        sem_destroy(&shutdown_sem);
        return HTP_SIG_FAILURE;
    }
    
    if (sigaction(SIGHUP, &sa, 0)) {
        sem_destroy(&shutdown_sem);
        return HTP_SIG_FAILURE;
    }
    
    
    ok_2_run = okay_to_run;
    if (okay_to_run) {
        *okay_to_run = 1;
    }
    return &shutdown_sem;
}