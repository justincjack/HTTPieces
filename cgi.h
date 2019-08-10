/* (c) 2019 Justin Jack - MIT License */
/* 
 * File:   cgi.h
 * Author: justinjack
 *
 * Created on July 1, 2019, 12:50 PM
 * 
 * 
 * TODO:
 * Carefully go through the CGI/1.1 spec ( https://tools.ietf.org/html/rfc3875 )
 * and make this meet them.
 * 
 */

#ifndef CGI_H
#define CGI_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <semaphore.h>
#include "http.h"
#include "huffman.h"

#define SCRIPT_THREAD_COUNT             10  /* PER interpreter */
#define DEFAULT_CGI_TIMEOUT             30 /* 30 Seconds max for script by default */
#define CGI_READ                        0
#define CGI_WRITE                       1
#define CGI_UNLIMITED                   -1


typedef enum _cgi_state_ {
    CGI_IMMATURE,
    CGI_IDLE,
    CGI_RUNNING,
    CGI_DEAD
} CGI_STATE;


#ifndef CGI_COUNT_MAX_WORKER
static int CGI_MAX_WORKERS              = 50;
#else
static int CGI_MAX_WORKERS              = CGI_COUNT_MAX_WORKER;
#endif


#ifndef CGI_DEBUG_LEVEL
static int CGI_DEBUG_LEVEL              = 7;
#endif

#ifndef gettid
    #define gettid() syscall(SYS_gettid)
#endif

static PHTTP_MUTEX cgi_debug_mutex      = http_new_mutex(0);

#define cgi_debug(level, ...) {\
                                    if ( level <= CGI_DEBUG_LEVEL )\
                                    {\
                                        http_lock(cgi_debug_mutex);\
                                        printf("%s:%d [Thread: %lu ] in function %s() - ", __FILE__, __LINE__, gettid(), __FUNCTION__);\
                                        printf(__VA_ARGS__);\
                                        fflush(stdout);\
                                        http_unlock(cgi_debug_mutex);\
                                    }\
                                }
    

#define cgi_error(...) {\
                            http_lock(cgi_debug_mutex);\
                            printf("** ERROR ** %s:%d [Thread: %lu] in function: %s() - ", __FILE__, __LINE__, gettid(), __FUNCTION__);\
                            printf(__VA_ARGS__);\
                            http_unlock(cgi_debug_mutex);\
                            fflush(stdout);\
                         }
    




static int DEFAULT_CGI_THREAD_COUNT     = SCRIPT_THREAD_COUNT;

static int CGI_TIMEOUT                  = DEFAULT_CGI_TIMEOUT;



typedef struct _cgi_env {
    char **envp;
    char *path;
    char *user;
    char *homedir;
    char *working_dir;
    char *hostname;
    size_t vcount;
} CGI_ENV, *PCGI_ENV;


typedef struct _cgi_id_ {
    char        **argv;
    char        **envp;
    int         initial_worker_count;
} *CGI_ID;


typedef struct _cgi_ {
    CGI_STATE                           state;
    CGI_ID                              cgi_id;
    int                                 script_in[2];
    int                                 script_out[2];
    int                                 script_err[2];
    FILE                                *fscript_in;
    FILE                                *fscript_out;
    FILE                                *fscript_err;
    pid_t                               script_pid;                      
} CGI, *PCGI;



/* Registered CGI_IDs *****************************************************************************************************/
/*                  This section only has to do with the registration of CGI interpreters.  And access to its lists       */
/**************************************************************************************************************************/
static CGI_ID                           *_cgi_list = 0;                             /*
                                                                                     * The master list of available CGI interpreters that
                                                                                     * have been registered.  An array of pointers;
                                                                                     **/

static size_t                           num_cgis_reg = 0;                           /*
                                                                                     * The number of CGI interpreters that have been registered.
                                                                                     **/

static PHTTP_MUTEX                      cgi_reg_mutex = http_new_mutex(0);


/******************************************************************************************************************************/


//static PHTTP_MUTEX                      cgi_spawn_mutex = 0;    

static PCGI                             *cgi_worker_list = 0;                       /* Array of pointers to CGI structures */

static size_t                           cgi_worker_num = 0;                         /* The number of slots in the worker_list */

static PHTTP_MUTEX                      cgi_list_mutex = 0;                         /* Mutex that protects access to the list of available CGI
                                                                                     * workers.  Used when spawning new CGI processes or delegating
                                                                                     * a job to one of those workers. We're NOT setting this
                                                                                     * up here even though it's static because we'll use it to
                                                                                     * signal that we need to create our semaphore 'cgi_process_watcher_action'
                                                                                     * defined a bit below
                                                                                     **/

static pthread_t                        cgi_thread_watcher = 0;

static sem_t                            cgi_process_watcher_action;

static int                              cgi_monitor_running = 0;

#ifdef __cplusplus
extern "C" {
#endif
    
    /*!
     * \brief Adds an environmental to or CGI_ENV object used to register
     *        a CGI interpreter.
     * 
     * \param env         - A pointer to a CGI_ENV structure created by calling
     *                      cgi_set_environment().
     * 
     * \param name        - A pointer to a NULL-terminated buffer that contains
     *                      the name of the environmental variable to set
     * 
     * \param value       - A pointer to a buffer that contains the value of 
     *                      the environmental variable.
     * 
     * 
     * \return On Success - ONE
     * 
     * \return On Failure - ZERO
     * 
     * 
     * 
     */
    int cgi_add_env_var(PCGI_ENV env, const char *name, const char *value);
    
    /*!
     * \brief A signal handler used to block SIGPIPE.  We need to think about this
     *        some more.  As far as I can imagine, we'd want the entire application
     *        to ignore SIGPIPE and just test errno.  With the handler, any blocking
     *        operations should still return...hmmm
     * 
     * \param s         - The signal rec'd
     * 
     * \return Nothing.
     * 
     */
    void cgi_no_sigpipe( int s );
    
    /*!
     * \brief A quick-and-dirty way (in leiu of spending a lot of time now building the settings functionality)
     *        way to configure CGI interpreter environmental variables.
     * 
     * 
     * \param cgi_id                            - A CGI_ID returned by calling cgi_register_interpreter()
     * 
     * \param path                              - A pointer to a string used for the PATH used for the CGI script
     * 
     * \param user                              - A pointer to a string used for the user name for the environment
     * 
     * \param homedir                           - A pointer to a string used for the HOME environmental variable
     * 
     * \param working_dir                       - A pointer to a string used for the PWD environmental variable
     * 
     * \param hostname                          - A pointer to a string used for the HOSTNAME environmental variable
     * 
     * 
     * \return On success                       - A pointer to a CGI_ENV structure used when registering CGI interpreters.
     * 
     * \return On failure                       - ZERO
     * 
     */
    PCGI_ENV cgi_set_environment(const char *path, const char *user, const char *homedir, const char *working_dir, const char *hostname);
    
    /*!
     * \brief Registers a new interpreter to be used for CGI
     * 
     * 
     * \param env               - A CGI_ENV structure containting environmental variables to
     *                            be passed to the CGI script.  At bare-minimum, you can obtain
     *                            this object with a call to cgi_set_environment()
     * 
     * \param worker_count      - The number of CGI worked processes spawned and ready to service
     *                            scripts.
     * 
     * \param argv              - A NULL-terminated list of pointers to pass as **argv to the
     *                            CGI process.  The first pointer in the array ( argv[0] ) must
     *                            be the path-to the interpreter executable including its filename.
     * 
     * \return On SUCCESS       - A CGI_ID value that is to be referenced whenever a call to 
     *                            "cgi()" is made to execute a script.
     * 
     * \return On Failure       - ZERO
     *
     **/
    CGI_ID          cgi_register_interpreter_argv(PCGI_ENV env, int worker_count, char **argv );
    
    /* 
     * va_args wrapper version of "cgi_register_interpreter_argv()" 
     * 
     * It just builds the variable arguments into an **argv array.
     * 
     */
    CGI_ID          cgi_register_interpreter(PCGI_ENV env, int worker_count, int num_args, const char *filename, ...);
    
    /*!
     * \brief Executes a CGI script and returns its output.
     * 
     * \param cgi_id        - An identifier returned via cgi_register_interpreter()
     *                        that lets the CGI system know what interpreter to use.
     * 
     * \param pscript       - A pointer to a buffer containing the script to process.
     * 
     * \param script_len    - The size in bytes of the script.
     * 
     * \param output_size   - A pointer to a size_t variable which (upon function return)
     *                        will containt the size in bytes of the script's output.
     * 
     * \return On SUCCESS   - A pointer to a NULL-terminated buffer containing
     *                        the output of the script.
     * \return On FAILURE   - A NULL pointer (ZERO)
     **/
    char            *cgi_exec(CGI_ID cgi_id, const char *pscript, size_t script_len, size_t *output_size);
    
    /*!
     * \brief Loads a file from into a memory buffer.
     * 
     * \param script_name   - The complete path to the file to load.
     * 
     * \param output_len    - A pointer to a size_t variable that will be set
     *                        to represent the number of bytes contained in the
     *                        returned buffer.
     * 
     * \return ON SUCCESS   - A pointer to a buffer containing the script to be
     *                        processed.  The application must free this pointer.
     * 
     * \return ON FAILURE   - A NULL pointer (ZERO)
     * 
     **/
    char            *cgi_load_file( const char *script_name, size_t *output_len );
    
    
    /*!
     * \brief Sets up a new CGI worker
     * 
     * \param A pointer to a CGI structure.
     * 
     * 
     * \return On SUCCESS   - Returns 1 meaning the child CGI process is ready to process CGI requests.
     * 
     * \return On FAILURE   - Returns 0 meaning we should NOT add this to the READY list.
     * 
     **/
    int cgi_worker( PCGI pcgi );
    
    
    void shutdown_cgi( CGI_ID cgi_id );
    
    /*!
     * \brief This thread runs and watches a semaphore that is signaled every time
     *        a result is returned and a CGI process completes so that it can start
     *        another process that will be ready to process CGI requests.
     **/
    void *cgi_proc_monitor( void * );
    
    /*!
     * \brief Initialize a new PCGI object for use spinning up a new CGI worker.
     * 
     * \param cgi_id        - A, well, CGI_ID
     * 
     * \return On SUCCESS   - A pointer to a newly minted CGI structure.
     * \return On FAILURE   - ZERO
     * 
     **/
    PCGI cgi_new( CGI_ID cgi_id );


#ifdef __cplusplus
}
#endif

#endif /* CGI_H */

