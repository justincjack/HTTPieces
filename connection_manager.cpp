/* (c) 2019 Justin Jack - MIT License */
#include "connection_manager.h"

int server_time( char *output, size_t len ) {
    time_t now = time(0);
    struct tm tms = *gmtime(&now);
    strftime(output, len, "%a, %d %b %Y %H:%M:%S %Z", &tms);
    return 1;
}


int shutdown_server( void ) {
    
}


/* Thread for NON-TLS connections */
void *listener( void *pconnection_info ) {
    
}

/* Thread for TLS connections */
void *listener_tls( void *pconnection_info ) {
    PCONNECTION_INFO ci = (PCONNECTION_INFO)pconnection_info;
    LISTENER            *plistener = ci->plistener;
    const SSL_METHOD *method = 0;
    PHTTP2_CONNECTION http2 = 0;
    SSL_CTX *ctx = 0;
    SOCKET s = 0, new_socket = 0;
    time_t server_start_time = time(0);
    fd_set fds;
    struct timeval tv;
    int select_value = 0, i = 0, j = 0;
    struct sockaddr_in ca, sa;
    struct sockaddr_in6 ca6, sa6;
    socklen_t sockaddr_len = 0;
    int socket_failed = 0;
    int sock_opt = 1;
    PCGI_ENV env = 0;
            
    /* Client SSL contexts */
    SSL_CTX *client_ctx = 0;
    SSL *client_ssl = 0;

    if (!ci) {
        return 0;
    }
    
    
    /* Start up CGI Modules (if any) */
    if (plistener->cgi_list_size > 0) {
        for (i = 0; i < plistener->cgi_list_size; i++) {
            if (!plistener->cgi_list[i]->start()) {
                for (; i >=0; i--) {
                    plistener->cgi_list[i]->stop();
                }
                return 0;
            }
        }
    }
    
    ci->okay_to_run = 1;
    
    /* Check for validity of IP version */
    if (plistener->ipaddr.version != 4 && plistener->ipaddr.version != 6 && plistener->ipaddr.version != HTPCM_MAX_IP_VERSION) {
        sprintf(ci->string_error, "HTPCM_INVALID_IP_VERSION");
        ci->startup_error = HTPCM_INVALID_IP_VERSION;
        return 0;
    }
        
    switch (http2_init()) {
        case HTTP2_SUCCESS:
            htp_debug(3, "http2_init() success!\n");
            break;
        case HTTP2_ERROR_INVALID_INITIAL_THREAD_COUNT:
            ci->startup_error = HTTP2_ERROR_INVALID_INITIAL_THREAD_COUNT;
            htp_error("HTTP2_ERROR_INVALID_INITIAL_THREAD_COUNT\n");
            sprintf(ci->string_error, "HTTP2_ERROR_INVALID_INITIAL_THREAD_COUNT");
            return 0;
        case HTTP2_ERROR_NO_MEMORY:
            ci->startup_error = HTTP2_ERROR_NO_MEMORY;
            htp_error("HTTP2_ERROR_NO_MEMORY\n");
            sprintf(ci->string_error, "HTTP2_ERROR_NO_MEMORY");
            return 0;
        case HTTP2_ERROR_MUTEX_FAILED:
            ci->startup_error = HTTP2_ERROR_MUTEX_FAILED;
            htp_error("HTTP2_ERROR_MUTEX_FAILED\n");
            sprintf(ci->string_error, "HTTP2_ERROR_MUTEX_FAILED");
            return 0;
        case HTTP2_ERROR_FAILED_TO_CREATE_THREAD_POOL:
            ci->startup_error = HTTP2_ERROR_FAILED_TO_CREATE_THREAD_POOL;
            sprintf(ci->string_error, "HTTP2_ERROR_FAILED_TO_CREATE_THREAD_POOL");
            htp_error("HTTP2_ERROR_FAILED_TO_CREATE_THREAD_POOL\n");
            return 0;
        default:
            htp_error("Another error occured calling http2_init()\n");
            ci->startup_error = HTPCM_ERROR_LISTENER_FAILURE;
            return 0;
    }
    
    OPENSSL_init_ssl(0, 0);
    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    
    method = TLS_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        ci->startup_error = ERR_get_error();
        ERR_error_string(ci->startup_error, ci->string_error);
	return 0;
    }
    
//    if ( (plistener->protocol_list & TLSv12) != TLSv12 ) {
//        SSL_CTX_set_op
//    }
//    
    SSL_CTX_set_min_proto_version(ctx, plistener->security_min_proto);
    SSL_CTX_set_max_proto_version(ctx, plistener->security_max_proto);
    
    
    /* TLS 1.3 Ciphersuites
     * ------------------------- 
     * TLS_AES_256_GCM_SHA384
     * TLS_CHACHA20_POLY1305_SHA256
     * TLS_AES_128_GCM_SHA256
     * TLS_AES_128_CCM_8_SHA256
     * TLS_AES_128_CCM_SHA256* 
     */
    
    
    SSL_CTX_set_cipher_list(ctx, "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4");
    
    SSL_CTX_set_ecdh_auto(ctx, 1);
    
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);    
    
    /* Set up the ALPN protos */

//    SSL_CTX_set_alpn_protos(ctx, ssl_proto_vector, (sizeof(ssl_proto_vector) - 1));
    
    
    
//    SSL_CTX_set_alpn_select_cb(ctx, &alpn_select, (void *)PROTOCOL_VERSION[HTTP2_0].alpn);
    SSL_CTX_set_alpn_select_cb(ctx, &alpn_select, (void *)ci);
    
    
    
//    SSL_CTX_set_next_protos_advertised_cb(ctx, &protos_advertised_cb, 0);
    
    /* Set certificate file that contains the trust chain file also */
    if (SSL_CTX_use_certificate_file(ctx, plistener->certificate_info.cert_file_name(), SSL_FILETYPE_PEM) <= 0) {
        ci->startup_error = ERR_get_error();
        ERR_error_string(ci->startup_error, ci->string_error);
	return 0;
    }
    
    /* Set the TLS key file */
    if (SSL_CTX_use_PrivateKey_file(ctx, plistener->certificate_info.key_file_name(), SSL_FILETYPE_PEM) <= 0 ) {
        ci->startup_error = ERR_get_error();
        ERR_error_string(ci->startup_error, ci->string_error);
	return 0;
    }    
    
    
    if (plistener->ipaddr.version == 4) {
    
        memset(&sa, 0, sizeof(struct sockaddr_in));

        sa.sin_addr.s_addr = plistener->ipaddr.to_unsigned_long();
        sa.sin_family = AF_INET;
        sa.sin_port = htons(plistener->port);

        s = socket(AF_INET, SOCK_STREAM, 0);
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &sock_opt, sizeof(int));
        if (s) {
            if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0 ) {
                sprintf(ci->string_error, "bind() failed.  Check listener_errno for more info.\n");
                ci->listener_errno = errno;
                htp_debug(3, "bind() failed.\n");
                closesocket(s);
                socket_failed = 1;
            } else {
                if (listen(s, 10) < 0 ) {
                    sprintf(ci->string_error, "listen() failed.  Check listener_errno for more info.\n");
                    ci->listener_errno = errno;
                    htp_debug(3, "listen() failed.\n");
                    closesocket(s);
                    socket_failed = 1;
                }
            }
        } else {
            sprintf(ci->string_error, "socket() failed.  Check listener_errno for more info.\n");
            htp_debug(3, "socket() failed.\n");
            socket_failed = 1;
        }

        if (socket_failed) {
            ci->startup_error = HTPCM_ERROR_LISTENER_FAILURE;
            htp_debug(3, "Failed to start listening.\n");
            SSL_CTX_free(ctx);
            EVP_cleanup();
            return 0;
        }

    
    } else if (plistener->ipaddr.version == 6) {
    
        memset(&sa6, 0, sizeof(struct sockaddr_in6));

        //sa6.sin6_family
        plistener->ipaddr.copy_into(sa6.sin6_addr.__in6_u.__u6_addr8);
        sa6.sin6_family = AF_INET6;
        sa6.sin6_flowinfo = 0;
        sa6.sin6_scope_id = 0;
        sa6.sin6_port = htons(plistener->port);

        s = socket(AF_INET6, SOCK_STREAM, 0);
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &sock_opt, sizeof(int));
        
        if (s) {
            if (bind(s, (struct sockaddr *)&sa6, sizeof(sa6)) < 0 ) {
                sprintf(ci->string_error, "bind() failed.  Check listener_errno for more info.\n");
                ci->listener_errno = errno;
                htp_debug(3, "bind() failed.\n");
                closesocket(s);
                socket_failed = 1;
            } else {
                if (listen(s, 10) < 0 ) {
                    sprintf(ci->string_error, "listen() failed.  Check listener_errno for more info.\n");
                    ci->listener_errno = errno;
                    htp_debug(3, "listen() failed.\n");
                    closesocket(s);
                    socket_failed = 1;
                }
            }
        } else {
            sprintf(ci->string_error, "socket() failed.  Check listener_errno for more info.\n");
            htp_debug(3, "socket() failed.\n");
            socket_failed = 1;
        }

        if (socket_failed) {
            ci->startup_error = HTPCM_ERROR_LISTENER_FAILURE;
            htp_debug(3, "Failed to start listening.\n");
            SSL_CTX_free(ctx);
            EVP_cleanup();
            return 0;
        }
        
    }
    
    set_socket_blocking_state(s, 0);
    
    
    
    ci->thread_listening = 1; /* Let the launcher know we've started! */
    
    htp_debug(3, "Listening on port %u\n", plistener->port);
    
    htp_debug(1, "Change the accepting sockaddr_in to check for IPv6...\n");
    
    /* Register CGI handlers for this listener */
    
    for (; plistener->cgi_list[i]; i++) {
        env = cgi_set_environment(
                plistener->cgi_list[i]->path_to_interpreter.val(), 
                plistener->cgi_list[i]->run_as_user.val(), 
                plistener->cgi_list[i]->home_dir.val(), 
                plistener->cgi_list[i]->working_dir.val(), 
                plistener->server_name.val());
        for (j = 0; j < plistener->cgi_list[i]->env_args_used; j++) {
            cgi_add_env_var(env, plistener->cgi_list[i]->cgi_env[i].name.to_upper(), plistener->cgi_list[i]->cgi_env[i].value.val()); 
        }
        cgi_register_interpreter_argv(env, plistener->cgi_list[i]->worker_count, plistener->cgi_list[i]->args.argv());
    }
    
    while (ci->okay_to_run) {
        FD_ZERO(&fds);
        FD_SET(s, &fds);
        tv.tv_sec = 0;
        tv.tv_usec = 250000; /* We'll set out value at 250 ms */
        
        select_value = select( (s+1), &fds, 0, 0, &tv );
        if (select_value > 0) {
            htp_debug(3, "select() returned: %d\n", select_value);
            if (plistener->ipversion == 4) {
                memset(&ca, 0, sizeof(struct sockaddr_in));
                sockaddr_len = sizeof(ca);
                new_socket = accept(s, (struct sockaddr *)&ca, &sockaddr_len);
            } else {
                memset(&ca6, 0, sizeof(struct sockaddr_in6));
                sockaddr_len = sizeof(ca6);
                new_socket = accept(s, (struct sockaddr *)&ca6, &sockaddr_len);
            }
            if (new_socket > 0) {
                /* Check this IP Address against our blacklist */
                
                set_socket_blocking_state(new_socket, 0);
                set_socket_keepalive(new_socket);
                client_ssl = SSL_new(ctx); /* Clone the server's CTX */
                SSL_set_fd(client_ssl, new_socket);
                
                /* Here we don't know what type of protocol we're receiving,
                 * I guess if it's set up for HTTP, we just need to hand the connection off
                 * to the HTTP module to service it, even though we just build the HTTP2
                 * module to be threaded to do just this!  Maybe we should hand it off to the 
                 * HTTP2 module and it should BECOME the HTTP module... handling all versions
                 * of HTTP <= 2.  I like this idea.
                 * */
                http2 = (PHTTP2_CONNECTION)malloc(sizeof(HTTP2_CONNECTION));
                http2_zero(http2, sizeof(HTTP2_CONNECTION));
                if (http2) {
                    http2->plistener = ci->plistener;
                    http2->socket = new_socket;
                    http2->next_stream_id = 1;
                    
                    http2->ip_version = ci->ip_version;
                    
                    if (ci->ip_version == 4) {
                        http2->client_ip_address.set_ipv4(ca.sin_addr.s_addr);
                        http2->remote_port = ntohs(ca.sin_port);
                    } else if (ci->ip_version == 6) {
                        http2->client_ip_address.set_ipv6(ca6.sin6_addr.__in6_u.__u6_addr8);
                        http2->remote_port = ntohs(ca6.sin6_port);
                    }
                    
                    
                    http2->ssl = client_ssl;
                    http2->streams = 0;
                    if (delegate_new_connection(http2) == HTTP2_SUCCESS) {
                        htp_debug(3, "New connection successfully delegated to an HTTP2 thread!\n");
                        continue;
                    }
                    htp_error("delegate_new_connection() failed.  Closing connection.\n");
                    http2_free_mutex(http2->output_buffer_mutex);
                    free(http2);
                } 
                SSL_shutdown(client_ssl);
                SSL_free(client_ssl);
                closesocket(new_socket);
            }
        }
    }
    ci->thread_listening = 0;
    
    htp_debug(3, "Exiting listener thread!\n");
    closesocket(s);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    htp_debug(3, "Exiting start_listening()\n");
    
    return 0;    
}


int alpn_select(SSL *ssl, 
        const unsigned char **out, 
        unsigned char *outlen,
        const unsigned char *in,
        unsigned int inlen,
        void *arg) {
    int i = 0, len = 0, j = 0;
    int k = 0;
    const unsigned char *proto = 0;
    PCONNECTION_INFO ci = (PCONNECTION_INFO)arg;
    
    printf("This connection accpets: ");
    j = 0;
    for (k = (HTTP_PROTOCOL_VERSION_COUNT - 1); k >= 0; k--) {
        if ((ci->plistener->protocol_list & PROTOCOL_VERSION[k].bitmask) == PROTOCOL_VERSION[k].bitmask) {
            if (j++ > 0) printf(", ");
            printf("%s", PROTOCOL_VERSION[k].on_wire);
        }
    }
    printf("\n\n");
    
    j = 1; /* For the ALPN protocol info from OpenSSL */
    while (i < inlen) {
        len = in[i++];
        proto = &in[i];
        i+=len;
        printf("\tProto #%d: \"%.*s\"\n", (++j), len, proto);
        for (j = (HTTP_PROTOCOL_VERSION_COUNT - 1); j >= 0; j--) {
            if ((ci->plistener->protocol_list & PROTOCOL_VERSION[j].bitmask) == PROTOCOL_VERSION[j].bitmask) {
                if (!strncmp((const char *)PROTOCOL_VERSION[j].alpn, (const char *)proto, len)) {
                    printf(" <-- ALPN Negotiated Protocol: %s (%.*s)\n\n", PROTOCOL_VERSION[j].on_wire, len, proto);
                    *out = proto;
                    *outlen = len;
                    return SSL_TLSEXT_ERR_OK;
                }
            }
        }
    }
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

//int protos_advertised_cb(SSL *ssl,
//        const unsigned char **out, 
//        unsigned int *outlen,
//        void *arg) {
//    int i = 0;
//    htp_debug(3, "Setting advertised protocols to: %.*s", (sizeof(ssl_proto_vector) - 1), ssl_proto_vector);
//    *out = ssl_proto_vector;
//    *outlen = sizeof(ssl_proto_vector) - 1;
//    return SSL_TLSEXT_ERR_OK;
//}
//


/*
 * Starts listening for connections as specified by 
 * the CONNECTION_INFO structure pointer to by "ci"
 * 
 * Returns a pointer to a flag that should be set
 * to ZERO when this thread should shut down.
 */
int start_listening( LISTENER *plistener ) 
{
    PCONNECTION_INFO *swap = 0;
    PCONNECTION_INFO c = 0;
    size_t swap_len = 0;
    
    void *(*_listener)(void *) = &listener;
    
    if (!plistener) return HTPCM_ERROR_LISTENER_FAILURE;
    
    
    if (  plistener->ipaddr.version < 0 || plistener->ipaddr.version > HTPCM_MAX_IP_VERSION) {
        return HTPCM_INVALID_IP_VERSION;
    }
    
    if (plistener->listener_type == LT_TLS || plistener->listener_type == LT_DTLS) {
        if (!plistener->certificate_info.cert_okay()) {
            return plistener->certificate_info.error;
        }
    }
    
    /* Allocate or reallocate listener list */
    if (listener_list_size == 0) {
        listener_list_size = 20;
        listener_list = (PCONNECTION_INFO *)malloc(sizeof(PCONNECTION_INFO) * listener_list_size);
        if (!listener_list) {
            listener_list_size = 0;
            return HTPCM_ERROR_NO_MEMORY;
        }
    } else if (listener_list_size == listener_list_count) {
        swap_len = listener_list_size + 20;
        swap = (PCONNECTION_INFO *)realloc(listener_list, sizeof(PCONNECTION_INFO) * listener_list_size);
        if (!swap) {
            return HTPCM_ERROR_NO_MEMORY;
        }
        listener_list = swap;
        listener_list_size = swap_len;
    }
    
    if (plistener->port == 0) {
        return HTPCM_ERROR_INVALID_PORT;
    }
    
    
    c = (PCONNECTION_INFO)malloc(sizeof(CONNECTION_INFO));
    huffman_zero_mem(c, sizeof(CONNECTION_INFO));
    if (!c) {
        return HTPCM_ERROR_NO_MEMORY;
    }
    c->plistener = plistener;
    
    c->join_expected = 1;
    
    if (!pthread_create(&c->thread_id, 0, _listener, c)) {
        
        HTTP2_WAIT( (c->thread_listening || c->startup_error) , 500) {
            if (c->startup_error != HTPCM_LISTENER_STARTUP_NO_ERROR) {
                /* There was an error starting up! */
                htp_error("%s\n", c->string_error);
                htp_error("Listener thread reported a startup error: %d\n\tWe're instructing it to shutdown.", c->startup_error);
                c->join_expected = 0;
                c->okay_to_run = 0;
                return c->startup_error;
            } else {
                /* Listener launched okay! */
                listener_list[listener_list_count++] = c;
                return HTPCM_SUCCESS;
            }
        } else {
            /* Listener failed to start! */
            htp_error("Listener failed to start!!!\n");
            c->join_expected = 0;
            c->okay_to_run = 0;
        }
    }
    return HTPCM_ERROR_LISTENER_FAILURE;
}


int shutdown_all_listeners( void ) {
    int r = HTPCM_SUCCESS;
    size_t i = 0;
    if (!listener_list_size) {
        htp_debug(3, "No listeners to shut down!\n");
        return HTPCM_SUCCESS;
    }
    /* Shut down the listeners so they don't try to process any more */
    for (; i < listener_list_count; i++) {
        listener_list[i]->okay_to_run = 0;
        htp_debug(3, "Waiting for listener thread to shutdown...\n");
        HTTP2_WAIT( !listener_list[i]->thread_listening, 1000 ) {
            htp_debug(3, "Listener thread has advised it is no longer listening...\n");
            pthread_join(listener_list[i]->thread_id, 0);
            htp_debug(3, "Listener thread has shut down...\n");
            free(listener_list[i]);
            listener_list[i] = 0;
        } else {
            htp_error("Listener thread has gone rogue.  It's on its own.\n");
            listener_list[i]->join_expected = 0;
            r = HTPCM_ERROR_STOP_LISTENERS;
        }
    }
    free(listener_list);
    listener_list = 0;
    listener_list_count = 0;
    listener_list_size = 0;
    
    /* Shutdown all current connections */
    http2_shutdown_all();
    return r;
}

