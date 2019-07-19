/* (c) 2019 Justin Jack - MIT License */

#include "cgi.h"
#include "huffman.h"

//#define CGI_NO_RESPAWN


void shutdown_cgi( void ) {
    int i = 0, j = 0;
    PCGI p = 0;
    CGI_ID cgi_id = 0;
    
    
    /* ISSUE - Memory leak.
     * 
     * The cgi_proc_monitor() is responsible for 
     * freeing CGI structures after they've been
     * used as well as respawning their new, 
     * replacement CGI processes.
     * 
     * In the code immediately below here, we tell
     * the monitor to shut down.  Thus, when any
     * outstanding CGI processes complete and signal
     * the "cgi_process_watcher_action" semaphore,
     * the monitor won't clean up after them.
     * 
     * For the most part, this will only be called 
     * when the program is shutting down so it might
     * not be a big deal, but if we want to reset the
     * state of things internally (thinking SIGHUP),
     * we will need to devise a more graceful way
     * of doing this.
     * 
     */
    
    cgi_monitor_running = 0;
    sem_post(&cgi_process_watcher_action);
    
    http_lock(cgi_list_mutex);
    for (; i < cgi_worker_num; i++) {
        p = cgi_worker_list[i];
        if (p->state == CGI_IDLE) {
            p->state = CGI_DEAD;
            kill(p->script_pid, SIGKILL);
            if ( p->script_err[CGI_READ] != -1) {
                close(p->script_err[CGI_READ]);
                fclose(p->fscript_err);
            }
            
            if ( p->script_in[CGI_WRITE] != -1) {
                fclose(p->fscript_in);
                close(p->script_in[CGI_WRITE]);
            }
            
            if ( p->script_out[CGI_READ] != -1) {
                fclose(p->fscript_out);
                close(p->script_out[CGI_READ]);
            }
            free(p);
        } 
    }
    free(cgi_worker_list);
    cgi_worker_num = 0;
    http_unlock(cgi_list_mutex);
    
    http_lock(cgi_reg_mutex);
    for (i = 0; i < num_cgis_reg; i++) {
        cgi_id = _cgi_list[i];
        for (j = 0; cgi_id->argv[j]; j++) {
            free(cgi_id->argv[j]);
        }
        free(cgi_id->argv);
        free(cgi_id);
    }
    free(_cgi_list);
    num_cgis_reg = 0;
    http_unlock(cgi_reg_mutex);
}

void free_pcgi( PCGI pcgi ) {
    if (pcgi->fscript_out) fclose(pcgi->fscript_out);
    if (pcgi->fscript_in) fclose(pcgi->fscript_in);
    if (pcgi->fscript_err) fclose(pcgi->fscript_err);
    if ( pcgi->script_in[CGI_WRITE] != -1) close(pcgi->script_in[CGI_WRITE]);
    if ( pcgi->script_out[CGI_READ] != -1) close(pcgi->script_out[CGI_READ]);
    if ( pcgi->script_err[CGI_READ] != -1) close(pcgi->script_err[CGI_READ]);
    if ( pcgi->script_in[CGI_READ] != -1) close(pcgi->script_in[CGI_READ]);
    if ( pcgi->script_out[CGI_WRITE] != -1) close(pcgi->script_out[CGI_WRITE]);
    if ( pcgi->script_err[CGI_WRITE] != -1) close(pcgi->script_err[CGI_WRITE]);
    free(pcgi);
}

int cgi_worker( PCGI pcgi ) {
    int i = 0;
    
    pcgi->fscript_err = 0;
    pcgi->fscript_in = 0;
    pcgi->fscript_err = 0;
    
    pcgi->script_in[CGI_READ] = -1;
    pcgi->script_in[CGI_WRITE] = -1;
    
    pcgi->script_out[CGI_READ] = -1;
    pcgi->script_out[CGI_WRITE] = -1;
    
    pcgi->script_err[CGI_READ] = -1;
    pcgi->script_err[CGI_WRITE] = -1;
    
    if (pipe(pcgi->script_in) == -1) {
        cgi_error("**** ERROR calling pipe()\n");
        pcgi->state = CGI_DEAD;
        return 0;
    }; 
    
    if (pipe(pcgi->script_out) == -1) {
        cgi_error("**** ERROR calling pipe()\n");
        pcgi->state = CGI_DEAD;
        return 0;
    }; 
    
    if (pipe(pcgi->script_err) == -1){
        cgi_error("**** ERROR calling pipe()\n");
        pcgi->state = CGI_DEAD;
        return 0;
    }; 
    
    pcgi->script_pid = fork();
    
    if (pcgi->script_pid == -1) {
        cgi_error("Failed to fork().  Destroying CGI object.\n");
        pcgi->state = CGI_DEAD;
        return 0;
    }
    
    if (pcgi->script_pid == 0) {
        close(pcgi->script_out[CGI_READ]);
        pcgi->script_out[CGI_READ] = -1;
        
        close(pcgi->script_err[CGI_READ]);
        pcgi->script_err[CGI_READ] = -1;
        
        close(pcgi->script_in[CGI_WRITE]);
        pcgi->script_in[CGI_WRITE] = -1;

        /* Close all other child handles that we just closed above*/

        for (i = 0; i < cgi_worker_num; i++) {
            if (!cgi_worker_list[i]) continue;
            if (cgi_worker_list[i]->state == CGI_DEAD) continue;
            if (cgi_worker_list[i]->script_out[CGI_READ] != -1) close(cgi_worker_list[i]->script_out[CGI_READ]);
            if (cgi_worker_list[i]->script_out[CGI_READ] != -1) close(cgi_worker_list[i]->script_err[CGI_READ]);
            if (cgi_worker_list[i]->script_out[CGI_READ] != -1) close(cgi_worker_list[i]->script_in[CGI_WRITE]);
        }

        
        dup2(pcgi->script_in[CGI_READ], STDIN_FILENO);
        dup2(pcgi->script_out[CGI_WRITE], STDOUT_FILENO);
        dup2(pcgi->script_err[CGI_WRITE], STDERR_FILENO);

        execvpe(pcgi->cgi_id->argv[0], pcgi->cgi_id->argv, pcgi->cgi_id->envp);
        printf("Error: Failed to run script.\n\n");
        exit(0);
    }
    
    close(pcgi->script_err[CGI_WRITE]);
    close(pcgi->script_out[CGI_WRITE]);
    close(pcgi->script_in[CGI_READ]);
    
    pcgi->fscript_in  = fdopen(pcgi->script_in[CGI_WRITE], "wb");
    pcgi->fscript_out = fdopen(pcgi->script_out[CGI_READ], "rb");
    pcgi->fscript_err = fdopen(pcgi->script_err[CGI_READ], "rb");
    
    if (!pcgi->fscript_out || !pcgi->fscript_in || !pcgi->fscript_err) {
        cgi_error("Failed to open STREAMS for new CGI processor. Destroying CGI object\n");
        kill(pcgi->script_pid, SIGKILL);
        pcgi->state = CGI_DEAD;
        return 0;
    } else {
        pcgi->state = CGI_IDLE;
    }
    return 1;
}

int cgi_add_env_var(PCGI_ENV env, const char *name, const char *value) {
    size_t req_size = 0;
    if (!env || !name || !value) return 0;
    if (env->vcount == 100) {
        cgi_error("Max environmental variables reached.  Cannot add more.\n");
        return 0;
    }
    req_size = strlen(name)+10+strlen(value);
    env->envp[env->vcount] = (char *)malloc(req_size);
    if (!env->envp[env->vcount]) {
        cgi_error("Failed to allocate memory to add the requested environmental variable.\n");
        return 0;
    }
    sprintf(env->envp[env->vcount++], "%s=%s", name, value);
    return 1;
}

PCGI_ENV cgi_set_environment(const char *path, const char *user, const char *homedir, const char *working_dir, const char *hostname) {
    int i = 0;
    PCGI_ENV env = (PCGI_ENV)malloc(sizeof(CGI_ENV));
    if (!env) {
        cgi_error("Failed to allocate an CGI_ENV instance!\n");
        return 0;
    }
    
    huffman_zero_mem(env, sizeof(CGI_ENV));
    
    env->envp = (char **)malloc( sizeof(char *) * 100 );
    if (!env->envp) {
        cgi_error("Failed to allocate space for CGI environmental variables!\n");
        free(env);
        return 0;
    }
    huffman_zero_mem(env->envp, sizeof(char *) * 100);
    
    if (path) {
        env->path = (char *)malloc(strlen(path) + 6);
        sprintf(env->path, "PATH=");
        strcat(env->path, path);
        env->envp[i++] = env->path;
    }
    
    if (user) {
        env->user = (char *)malloc(strlen(user) + 6);
        sprintf(env->user, "USER=");
        strcat(env->user, user);
        env->envp[i++] = env->user;
                
        env->envp[i] = (char *)malloc(strlen(user) + 9);
        sprintf(env->envp[i], "LOGNAME=");
        strcat(env->envp[i++], user);
    }
    
    if (homedir) {
        env->homedir = (char *)malloc(strlen(homedir) + 6);
        sprintf(env->homedir, "HOME=");
        strcat(env->homedir, homedir);
        env->envp[i++] = env->homedir;
    }
    
    if (working_dir) {
        env->working_dir = (char *)malloc(strlen(working_dir) + 5);
        sprintf(env->working_dir, "PWD=");
        strcat(env->working_dir, working_dir);
        env->envp[i++] = env->working_dir;
    }
    
    if (hostname) {
        env->hostname = (char *)malloc(strlen(hostname) + 9);
        sprintf(env->hostname, "HOSTNAME=");
        strcat(env->hostname, hostname);
        env->envp[i++] = env->hostname;
    }
    env->vcount = i;
    return env;
}

void cgi_no_sigpipe( int s ) {
    return;
}


CGI_ID cgi_register_interpreter_argv(PCGI_ENV env, int worker_count, char **argv ) {
    CGI_ID cgi = 0, cgi_reg = 0;
    struct stat sb;
    int r = 0, i = 0, j = 0, k = 0, num_args = 0;
    int okay_to_go = 0;
    size_t arglen = 0, swap_len = 0;
    size_t workers_started = 0;
    PCGI pcgi = 0, *swap = 0;
    int error_condition = 0;
    struct sigaction sigact;
    
    if (!argv) {
        return 0;
    }
    
    cgi = (CGI_ID)malloc(sizeof(struct _cgi_id_));
    if (!cgi) return 0;
    cgi->initial_worker_count = ((worker_count <= 0)?DEFAULT_CGI_THREAD_COUNT:worker_count);
    cgi->argv = 0;
    cgi->envp = env->envp;
    
    /* Set */
    
    http_lock(cgi_reg_mutex);

    /* Make sure our interpreter exists */
    if (!argv[0]) return 0;
    memset(&sb, 0, sizeof(struct stat));
    r = stat(argv[0], &sb);
    if (r) return 0;
    if ( (sb.st_mode & S_IFREG) == S_IFREG ) {
        okay_to_go = 1;
    }
    if ( (sb.st_mode & S_IFLNK) == S_IFLNK ) {
        okay_to_go = 1;
    }
    if ((sb.st_mode & S_IFDIR) == S_IFDIR) {
        cgi_error("Um...that's a directory...\n");
    }
    if (!okay_to_go) {
        cgi_error("We can't use this as an interpreter...Sorry..\n");
        free(cgi);
        return 0;
    }
    
    
    
    if (cgi_list_mutex == 0) {

        memset(&sigact, 0, sizeof(struct sigaction));
        sigact.sa_handler = &cgi_no_sigpipe;
        sigaction(SIGPIPE, &sigact, NULL);

        
        cgi_list_mutex = http_new_mutex(0);
        printf("\n========================================================================\n");
        printf("= SETTING UP cgi_process_watcher_action SEMAPHORE!\n");
        printf("========================================================================\n\n");
        
        r = sem_init(&cgi_process_watcher_action, 0, 0);
        if (r) {
            printf("Error: ");
            switch (errno) {
                case EINVAL:
                    printf("EINVAL\n");
                    break;
                case ENOSYS:
                    printf("ENOSYS\n");
                    break;
                default:
                    printf("errno=%d\n", errno);
                    break;
            }
            printf("*** FAILED to initialize semaphore ***\n");
            return 0;
        } else {
            printf("* SEMPAHORE set up OKAY\n");
            if (!cgi_monitor_running) {
                pthread_create(&cgi_thread_watcher, 0, &cgi_proc_monitor, 0);
                HTTP_WAIT( cgi_monitor_running > 0, 250 ) {
                    printf("***** THREAD MONITOR STARTED *****\n\n");
                }
            }
        }
    }
    
    for (num_args = 0; argv[num_args]; num_args++);
    
    /* We're going to give our *cgi->argv[] a little more 
     * memory than just the length of the strings.  Juuuuuuussttt
     * in case the target processes want an modify them for
     * some reason.
     * 
     */
    
    cgi->argv = (char **)malloc( (num_args + 1) * sizeof(char *));
    if (!cgi->argv) return 0;
    for (i = 0; i < num_args; i++) {
        cgi->argv[i] = (char *)malloc(strlen(argv[i]) + 100);
        if (!cgi->argv[i]) {
            for (j = i; j >= 0; j--) free(cgi->argv[j]);
            free(cgi->argv);
            return 0;
        }
        strcpy(cgi->argv[i], argv[i]);
    }
    cgi->argv[i] = 0;
    
    
    
    /* Look for duplicate registries, first compare argv, then envp */
    for (i = 0; i < num_cgis_reg; i++) {
        cgi_reg = _cgi_list[i];
        for (j = 0; cgi_reg->argv[j] && cgi->argv[j]; j++) {
            if (strcmp(cgi_reg->argv[j], cgi->argv[j])) break;
        }
        if (!cgi_reg->argv[j] && !cgi->argv[j]) {
            
            /* They are the same! Now compare environmental variables. */
            
            for (k = 0; cgi_reg->envp[k] && cgi->envp[k]; k++) {
                if (strcmp(cgi_reg->envp[k], cgi->envp[k])) break;
            }
            
            if (!cgi_reg->envp[k] && !cgi->envp[k]) {
                cgi_debug(3, "CGI - Trying to register the same interpreter twice!\n");
                for (j = 0; cgi->envp[j]; j++) {
                    free(cgi->envp[j]);
                }
                free(cgi->envp);
                for (j = 0; cgi->argv[j]; j++) {
                    free(cgi->argv[j]);
                }
                free(cgi->argv);
                free(cgi);
                return cgi_reg;
            }
        }
    }
    
    
    /* Add the new CGI_ID to the list */
    if (num_cgis_reg == 0) {
        _cgi_list = (CGI_ID *)malloc(sizeof(CGI_ID));
        if (!_cgi_list) {
            for (j = 0; cgi->argv[j]; j++) {
                free(cgi->argv[j]);
            }
            free(cgi);
            free(cgi->argv);
            return 0;
        }
        _cgi_list[0] = cgi;
        num_cgis_reg = 1;
    } else {
        for (i = 0; i < num_cgis_reg; i++) {
            if (_cgi_list[i] == 0) {
                _cgi_list[i] = cgi;
            }
        }
        if (i == num_cgis_reg) {
            CGI_ID *swap = (CGI_ID *)realloc(_cgi_list, (num_cgis_reg+1) * sizeof(CGI_ID));
            if (!swap) {
                for (j = 0; cgi->argv[j]; j++) {
                    free(cgi->argv[j]);
                }
                free(cgi->argv);
                free(cgi);
                return 0;
            }
            _cgi_list = swap;
            _cgi_list[num_cgis_reg] = cgi;
            num_cgis_reg++;
        }
    }
    
    
    http_unlock(cgi_reg_mutex);
    
    http_lock(cgi_list_mutex);
    
    if (cgi_worker_num == 0) {
        cgi_worker_list = (PCGI *)malloc(sizeof(PCGI) * cgi->initial_worker_count);
        if (!cgi_worker_list) {
            cgi_error("Failed to allocate memory for PCGI worker list!\n");
            for (i = 0; cgi->argv[i]; i++) {
                free(cgi->argv[i]);
            }
            free(cgi->argv);
            
            http_lock(cgi_reg_mutex);
            for (i = 0; i < num_cgis_reg; i++) {
                if (_cgi_list[i] == cgi) {
                    _cgi_list[i] = 0;
                    break;
                }
            }
            http_unlock(cgi_reg_mutex);
            free(cgi);
            http_unlock(cgi_list_mutex);
            return 0;
        }
        
        for (i = 0; i < cgi->initial_worker_count; i++) {
            pcgi = cgi_new(cgi);
            cgi_worker_list[i] = pcgi;
            if (!cgi_worker(pcgi)) {
                cgi_worker_list[i] = 0;
            } else {
                workers_started++;
            }
            cgi_worker_num++;
        }
    } else {
        /* There are already workers. */
        for (i = 0; i < cgi_worker_num; i++) {
            if (cgi_worker_list[i] == 0) {
                cgi_worker_list[i] = cgi_new(cgi);
                if (!cgi_worker(cgi_worker_list[i])) {
                    cgi_worker_list[i]->state = CGI_DEAD;
                    error_condition = 1;
                    break;
                } else {
                    workers_started++;
                    cgi_worker_num++;
                }
            }
        }
        
        if (workers_started < cgi->initial_worker_count) {
            if (cgi_worker_num < CGI_MAX_WORKERS || CGI_MAX_WORKERS == CGI_UNLIMITED) {
                swap_len = cgi_worker_num + cgi->initial_worker_count;
                swap = (PCGI *)realloc(cgi_worker_list, sizeof(PCGI) * swap_len);
                if (swap) {
                    memset(&swap[cgi_worker_num], 0, ((swap_len - cgi_worker_num) * sizeof(PCGI) ));
                    
                    i = cgi_worker_num;
                    cgi_worker_list = swap;
                    cgi_worker_num = swap_len;
                    
                    for (; i < cgi_worker_num; i++) {
                        cgi_worker_list[i] = cgi_new(cgi);
                        if (cgi_worker_list[i]) {
                            if (!cgi_worker(cgi_worker_list[i])) {
                                cgi_worker_list[i]->state = CGI_DEAD;
                            } else {
                                workers_started++;
                            }
                        }
                    }
                    
                }
            } 
        }
    }
    
    /* If we didn't create any new processes, clean up everything we've allocated here */
    if (workers_started == 0) {
        for (i = 0; cgi->argv[i]; i++) {
            free(cgi->argv[i]);
        }
        free(cgi->argv);
        /* Remove all references to this CGI_ID from the list */
        http_lock(cgi_reg_mutex);
        for (i = 0; i < num_cgis_reg; i++) {
            if (_cgi_list[i] == cgi) {
                _cgi_list[i] = 0;
                break;
            }
        }
        free(cgi);
        http_unlock(cgi_reg_mutex);
        http_unlock(cgi_list_mutex);
        return 0;
    }
    http_unlock(cgi_list_mutex);
    return cgi;
}






CGI_ID cgi_register_interpreter(PCGI_ENV env, int worker_count, int num_args, const char *filename, ...) {
    struct stat sb;
    int i = 0, j = 0, r = 0, okay_to_go = 0;
    size_t arglen = 0;
    va_list va;
    char *arg = 0, **argv = 0;
    
    /* Make sure our interpreter exists */
    if (!filename) return 0;
    
    memset(&sb, 0, sizeof(struct stat));
    
    r = stat(filename, &sb);
    if (r) return 0;
    if ( (sb.st_mode & S_IFREG) == S_IFREG ) {
        okay_to_go = 1;
    }
    if ( (sb.st_mode & S_IFLNK) == S_IFLNK ) {
        okay_to_go = 1;
    }
    if ((sb.st_mode & S_IFDIR) == S_IFDIR) {
        cgi_error("Um...that's a directory...\n");
    }
    if (!okay_to_go) {
        cgi_error("We can't use this as an interpreter...Sorry..\n");
        return 0;
    }
    
    
    argv = (char **)malloc( (num_args+2) * sizeof(char *));
    if (!argv) return 0;
    for (i = 0; i < (num_args+2); i++) {
        argv[i] = 0;
    }
    
    argv[0] = (char *)malloc((strlen(filename)+100));
    if (!argv[0]) {
        free(argv);
        return 0;
    }
    memcpy(argv[0], filename, strlen(filename));
    va_start(va, filename);
    for (i = 0; i < num_args; i++) {
        arg = va_arg(va, char *);
        if (!arg) {
            break;
        }
        arglen = strlen(arg);
        if (arglen > 0) {
            argv[i+1] = (char *)malloc(arglen+100);
            if (!argv[i+1]) {
                for (j = (i+1); j >= 0; j++) free(argv[j]);
                free(argv);
                return 0;
            }
            strcpy(argv[i+1], arg);
        } else {
            break;
        }
    }
    va_end(va);
    
    return cgi_register_interpreter_argv(env, worker_count, argv);
}

char *cgi(CGI_ID cgi_id, const char *pscript, size_t script_len, size_t *output_size) {
    PCGI pcgi = 0, *pcgi_swap = 0;
    char *swap = 0, *ret_buffer = 0;
    size_t pcgi_swap_size = 0;
    time_t script_timeout = time(0) + CGI_TIMEOUT;
    size_t bytes_written = 0, bytes_read = 0;
    struct timeval tv;
    fd_set fds;
    int rv = 0;
    int i = 0;
    int out = -1, err = -1;
    size_t ret_buffer_size = 0;
    
    if (output_size) *output_size = 0;
    
    if (!cgi_monitor_running) {
        cgi_debug(1, "Cannot execute a CGI script right now because the cgi_proc_monitor() is not running.\n");
        return 0;
    }
    
    http_lock(cgi_list_mutex);
    
    /* Find a waiting CGI processor */
    for (i=0; i < cgi_worker_num; i++) {
        cgi_debug(7,"Comparing requested cgi_id (0x%x) against registered one of: 0x%x\tState='%s'\n", cgi_id, cgi_worker_list[i]->cgi_id, 
                ((cgi_worker_list[i]->state == CGI_IMMATURE)?"IMMATURE":      
                    ((cgi_worker_list[i]->state == CGI_IDLE)?"IDLE":
                        ((cgi_worker_list[i]->state == CGI_RUNNING)?"RUNNING":"DEAD"))));
        
        if ((cgi_worker_list[i]->cgi_id == cgi_id) && (cgi_worker_list[i]->state == CGI_IDLE)) {
            cgi_debug(7,"\t*** Worker found!\n");
            pcgi = cgi_worker_list[i];
            break;
        }
    }
    
    if (!pcgi) { /* We couldn't find any available CGI processes! */
#ifdef CGI_NO_RESPAWN
        cgi_error("cgi() ----- MAX WORKER limit reached. Cannot spawn new interpreter instance.\n\n");
        http_unlock(cgi_list_mutex);
        return 0;
#endif        
        if (cgi_worker_num == CGI_MAX_WORKERS && CGI_MAX_WORKERS != CGI_UNLIMITED) {
            cgi_error("cgi() ----- MAX WORKER limit reached. Cannot spawn new interpreter instance.\n\n");
            http_unlock(cgi_list_mutex);
            return 0;
        }
        pcgi = cgi_new(cgi_id);
        if (!pcgi) {
            cgi_error("Failed to allocate memory to create a new CGI structure!");
            http_unlock(cgi_list_mutex);
            return 0;
        }
        pcgi_swap_size = (sizeof(PCGI) * (cgi_worker_num + 1));
        pcgi_swap = (PCGI *)realloc(cgi_worker_list, pcgi_swap_size);
        if (!pcgi_swap) {
            cgi_error("** ERROR: Could not allocate more memory for CGI pool.\n");
            free(pcgi);
            http_unlock(cgi_list_mutex);
            return 0;
        }
        cgi_worker_list = pcgi_swap;
        cgi_worker_list[cgi_worker_num] = pcgi;
        if (!cgi_worker(cgi_worker_list[cgi_worker_num])) {
            cgi_error("Failed to launch new CGI process (\"%s\")!\n", cgi_id->argv[0]);
            pcgi->state = CGI_DEAD;
            sem_post(&cgi_process_watcher_action); 
            return 0;
        }
        
        /* The new worker has started */
        usleep(5000); /* ISSUE
                       * 
                       * Here, we should use a system-wide semaphore to signal when the
                       * child process is ready to receive input.  Or something.  Instead,
                       * for the sake of speed, I'm going to put a brief usleep() here to
                       * attempt to mitigate race conditions.
                       * 
                       * The OS may buffer the pipe's data anyways and still feed it to the
                       * interpreter if we get to the fwrite() below first anyways but still..
                       * 
                       **/
        cgi_worker_num++;
    }
    
    pcgi->state = CGI_RUNNING;
    
    http_unlock(cgi_list_mutex);
    
    if (!pcgi->fscript_out || !pcgi->fscript_in || !pcgi->fscript_err) {
        cgi_error("One or more stream pointer is invalid!\n");
        if (pcgi->fscript_out) fclose(pcgi->fscript_out);
        if (pcgi->fscript_in) fclose(pcgi->fscript_in);
        if (pcgi->fscript_err) fclose(pcgi->fscript_err);
        close(pcgi->script_in[CGI_WRITE]);
        close(pcgi->script_out[CGI_READ]);
        close(pcgi->script_err[CGI_READ]);
        kill(pcgi->script_pid, SIGKILL);
        pcgi->state = CGI_DEAD;
        sem_post(&cgi_process_watcher_action); 
        return 0;
    }
    
    
    out = pcgi->script_out[CGI_READ];
    err = pcgi->script_err[CGI_READ];
    

    do {
        cgi_debug(7, "Writing %zu bytes.\n", (script_len-bytes_written));
        bytes_written+= fwrite(&pscript[bytes_written], 1, (script_len-bytes_written), pcgi->fscript_in);
    } while ( (bytes_written < script_len) && !ferror(pcgi->fscript_in));

    

    if (bytes_written > 0) {

        tv.tv_sec = 2;
        tv.tv_usec = 0;

        /* Finish off and close the WRITING pipe */
        fwrite("\0x0", 1, 1, pcgi->fscript_in);
        fclose(pcgi->fscript_in);
        close(pcgi->script_in[CGI_WRITE]);
        
        
        ret_buffer_size = 65535;
        ret_buffer = (char *)malloc(ret_buffer_size+1);
        
        if (ret_buffer) {
            tv.tv_sec = 2;
            tv.tv_usec = 0;
            while ( time(0) < script_timeout ) {
                FD_ZERO(&fds);
                if (out != -1) FD_SET(out, &fds);
                if (err != -1) FD_SET(err, &fds);
                rv = select( (((out > err)?out:err) + 1), &fds, 0, 0, &tv);
                if (rv) {
                    if (out != -1) {
                        if (FD_ISSET(out, &fds)) {
                            cgi_debug(7, "Reading from STDOUT pipe %d. Buffer size is %zu bytes.\n", out, ret_buffer_size-(*output_size));
                            bytes_read = fread(&ret_buffer[(*output_size)], 1, ret_buffer_size-(*output_size), pcgi->fscript_out);
                            cgi_debug(7, "%zu bytes read from STDOUT\n", bytes_read);
                            if (bytes_read > 0) {
                                (*output_size)+=bytes_read;
                                if (*output_size == ret_buffer_size) {
                                    ret_buffer_size+=65535;
                                    swap = (char *)realloc(ret_buffer, (ret_buffer_size+1));
                                    if (!swap) {
                                        cgi_error("Ran out of memory reading CGI script's output.\n");
                                        break;
                                    }
                                    ret_buffer = swap;
                                }
                            } 
                            if (feof(pcgi->fscript_out) || ferror(pcgi->fscript_out)) {
                                out = -1;
                            }
                        }
                    }

                    if (err != -1) {
                        if (FD_ISSET(err, &fds)) {
                            cgi_debug(7, "Reading from STDERR pipe %d. Buffer size is %zu bytes.\n", err, ret_buffer_size-(*output_size));
                            bytes_read = fread(&ret_buffer[(*output_size)], 1, ret_buffer_size-(*output_size), pcgi->fscript_err);
                            cgi_debug(7, "%zu bytes read from STDERR\n", bytes_read);
                            if (bytes_read > 0) {
                                (*output_size)+=bytes_read;
                                if (*output_size == ret_buffer_size) {
                                    ret_buffer_size+=65535;
                                    swap = (char *)realloc(ret_buffer, (ret_buffer_size+1));
                                    if (!swap) {
                                        cgi_error("Ran out of memory reading CGI script's output.\n");
                                        break;
                                    }
                                    ret_buffer = swap;
                                }
                            } 
                            if (feof(pcgi->fscript_err) || ferror(pcgi->fscript_err)) {
                                err = -1;
                            }
                        }
                    }
                } 
                if (err == -1 && out == -1) break;
            }
        }
        fclose(pcgi->fscript_out);
        fclose(pcgi->fscript_err);
        close(pcgi->script_out[CGI_READ]);
        close(pcgi->script_err[CGI_READ]);
    } else {
        cgi_error("Failed to write to pcgi->fscript_in.  Closing all open streams and FDs\n");
        if (pcgi->fscript_in) fclose(pcgi->fscript_in);
        if (pcgi->fscript_out) fclose(pcgi->fscript_out);
        if (pcgi->fscript_err) fclose(pcgi->fscript_err);
        close(pcgi->script_in[CGI_WRITE]);
        close(pcgi->script_out[CGI_READ]);
        close(pcgi->script_err[CGI_READ]);
    }    
    
    if (*output_size == 0) {
        cgi_debug(2, "*output_size was ZERO! Freeing 'ret_buffer'\n");
        if (ret_buffer) {
            free(ret_buffer);
            ret_buffer = 0;
        }
    }
    
    cgi_debug(7, "About to leave cgi().  Making sure the child process we used is dead with kill()\n");
    kill(pcgi->script_pid, SIGKILL);
    pcgi->state = CGI_DEAD;
    sem_post(&cgi_process_watcher_action); 
    return ret_buffer;
}

PCGI cgi_new( CGI_ID cgi_id ) {
    PCGI pcgi = 0;
    if (!cgi_id) return 0;
    pcgi = (PCGI)malloc(sizeof(CGI));
    if (!pcgi) return 0;
    memset(pcgi, 0, sizeof(CGI));
    pcgi->cgi_id = cgi_id;
    return pcgi;
}

void *cgi_proc_monitor( void * ) {
    CGI_ID cgi_id = 0;
    int i = 0;
    cgi_monitor_running = 1;
    while (cgi_monitor_running) {
        cgi_debug(7, "Waiting for semaphore to be signaled!\n");
        sem_wait(&cgi_process_watcher_action);
#ifdef CGI_NO_RESPAWN
        cgi_debug(3, "** NOT RESPAWNING CGI DUE TO \"CGI_NO_RESPAWN\" **\n");
        continue;
#endif
        if (!cgi_monitor_running) {
            cgi_debug(7, "Semaphore signaled, but we've been told to shut down. So that's what I'm doing!\n");
            break;
        }
        http_lock(cgi_list_mutex);
        for (i = 0; i < cgi_worker_num; i++) {
            if (cgi_worker_list[i] == 0) {
                cgi_debug(1, "We've found an EMPTY CGI worker slot.  We need to look through registered CGI interpreters and see which one we should try to spawn!\n");
                continue;
            }
            if (cgi_worker_list[i]->state == CGI_DEAD) {
                cgi_debug(7, "Found completed CGI process slot open at index %d.  Spawning a new CGI process.\n", i);
                cgi_id = cgi_worker_list[i]->cgi_id;
                free(cgi_worker_list[i]);
                cgi_worker_list[i] = cgi_new(cgi_id);
                if (!cgi_worker(cgi_worker_list[i])) {
                    cgi_error("Failed to launch new worker CGI process!\n");
                    cgi_worker_list[i]->state = CGI_DEAD;
                } else {
                    cgi_debug(7, "New worker \"%s\" CGI process started okay!\n", cgi_worker_list[i]->cgi_id->argv[0]);
                }
            }
        }
        http_unlock(cgi_list_mutex);
    }
    cgi_debug(3,"\n\n***********************************************************************\n");
    cgi_debug(3,"** EXITING cgi_proc_monitor()\n");
    cgi_debug(3,"*************************************************************************\n\n");
    return 0;
}

    