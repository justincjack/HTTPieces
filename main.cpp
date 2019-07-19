/*
 * HTTPieces is a multi-threaded HTTP(S) server build to server the
 * CyberOnline software platform.
 * 
 * HTTPieces makes collaboration easier by being able to 
 * have the server compile the HTML document before serves the request 
 * by reading special INCLUDE comment directives in the source code and
 * including the specified files into the served documents.
 * 
 * For example:
 * 
 * "Bob" and "Alice" are working on an HTML project.  Bob is tasked with
 * creating the main page and Alice is tasked with designing a certain dialog
 * window that pops up when Bob's javascript calls a certain function.  To
 * keep the project clean, Bob puts a directive into his code telling HTTPieces
 * to load Alice's work into his own:
 * 
 * <!-- include: alices_popup.html -->
 * 
 * When HTTPieces serves the request, it will replace the directive with the
 * contents of Alice's files making all the functions available to Bob's code.
 * 
 * 
 * 
 * 
 * 
 * 
 */
#include "main.h"
//#include <stdint.h>
//#include "md5.h"
//#include <arpa/inet.h>
//#include <ifaddrs.h>
//#include <net/if.h>

/* 
 * Notes:
 * 
 * Handle command-line directives
 * Check if we're already running.
 * Load settings.
 * Create initial thread pool. 
 * Start server(s)  
 * Handle Signals
 * Clean up
 * 
 */



int main(int argc, char **argv) {
    /* Set up signaling semaphores */
    sem_t *shutdown_semaphore;
    PCERTIFICATE_INFO certs = 0;
    int i = 0, r = 0;
    int okay_to_run = 1;
    SETTINGS s("/home/justin/httpieces.conf");
    char misc[100];
    
    /* Semaphore signalled when a SIGNAL comes in */
    shutdown_semaphore = configure_shutdown_signals( &okay_to_run );
    if (shutdown_semaphore == HTP_SIG_FAILURE) {
        htp_error("Failed to configure execution control semaphore!\n");
        return EXIT_FAILURE;
    }
    
    printf("HTTPieces PID: %zu\n", getpid());
    
    
    
    /******* Testing settings here ********/
    
    for (i = 0; s.listener(i); i++) {
        if (s.listener(i)->http_cors.count() > 0) {
            printf("HTTP CORS domains:\n");
            printf("------------------\n");
            for (r = 0; s.listener(i)->http_cors.index(r); r++) {
                printf("%s\n", s.listener(i)->http_cors.index(r)->val());
            }
            printf("\n\n");
        } else {
            printf("No HTTP CORS policy for this listener.\n");
        }
    }
    
    printf("Press [ENTER] when debugger is attached.");
    
    do {
        misc[0] = getchar();
    } while (misc[0] != 0x0a && misc[0] != 0x0d);
    
    printf("Breakpoint...\n");
    
    printf("\n");
    return 0;
    
    while (okay_to_run) {
        
        /* If we're restarting... 
         * 
         * (Lots of work to do here)
         * 
         */
        if (shutdown_all_listeners() == HTPCM_ERROR_STOP_LISTENERS) {
            htp_error("Error shutting down network listeners!\n\n");
            return EXIT_FAILURE;
        }


        
        /* Loop through listener types creating them *****************************************************************/

        
        
        for (i = 0; s.listener(i); i++) {
            r = start_listening(s.listener(i));
            if (r != HTPCM_SUCCESS) {
                error("Failed to launch listener named \"%s\"\n", ((s.listener(i)->name.length() > 0)?"<< Unnamed >>":s.listener(i)->name.val()));
            }
        }

        
        /*** End listener creation loop *****************************************************************************/
        

        /* Wait for the signal to shut down or restart */
        htp_debug(1, "**** Waiting on CTRL-C to be pressed, or a signal ****\n");
        sem_wait(shutdown_semaphore);
    }
    /* Shut down all threads in a connection info list */
    if (shutdown_all_listeners() == HTPCM_ERROR_STOP_LISTENERS) {
        htp_error("Error shutting down network listeners!\n\n");
        return EXIT_FAILURE;
    }
    htp_debug(3, "Shutdown all listeners!\n");
    
    /* Clean up and exit */
    
    sem_destroy(shutdown_semaphore);
    return (EXIT_SUCCESS);
}

