#include "pieces.h"



void pieces_signals( int s ) {
    p_stat_checker_run = 0;
    return;
}


inline uint64_t p_index( const char *ptr ) {
    return 0;
}


size_t pieces_load_file( const char *file, char **outbuffer) {
    return 0;
}

char *pieces_get_resource( const char *filename, size_t *outbuflen, int *is_compressed) {
    char *retbuffer = 0;
    struct sigaction sigact;
    
    if (!p_stat_checker_run) {
        /* Perform setup code */
        p_stat_checker_run = 1;
        memset(&sigact, 0, sizeof(struct sigaction));
        sigact.sa_handler = &pieces_signals;
        sigaction(SIGPIPE, &sigact, NULL);
        
    }
    
    
    
}
