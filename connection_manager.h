/* (c) 2019 Justin Jack - MIT License */
/*
 * connection_manager
 * ------------------
 * 
 * This aspect of the program is responsible for 
 * receiving complete HTTP messages from the internet
 * and passing them dutifully to whomever is requesting 
 * them.  It will also send out messages that have been
 * queued to be sent back to clients.
 * 
 * 
 * The listener will get a message and run it through
 * HTTP.  When HTTP says it has a complete message, we'll
 * remove the bytes from the message from the buffer and
 * fire the callback specified in the CONNECTION_INFO for
 * that listener with the HTTP object.
 * 
 * HTTP/1.x - 
 * 
 * 
 * 
 */


/* 
 * File:   connection_manager.h
 * Author: justinjack
 *
 * Created on May 9, 2019, 7:30 PM
 */

#ifndef CONNECTION_MANAGER_H
#define CONNECTION_MANAGER_H

#include "httpieces_debug.h"
#include "db_x_platform.h"
#include "nb_ssl_wrappers.h"
#include "http.h"
#include "http2.h"
#include "settings.h"
#include <errno.h>
#include <sys/time.h>
#include <sys/select.h>
#include <sys/types.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>


#define HTTPS 1
#define CM_DEFAULT_BUFFER_SIZE 65535

/*
 * The default MAX Internet Protocol version this 
 * version of HTTPieces will support.
 * 
 **/
#define HTPCM_MAX_IP_VERSION 6



/***** ERRORS *****************************************************************/
#define HTPCM_INVALID_IP_VERSION                                    -9
#define HTPCM_ERROR_LISTENER_FAILURE                                -8
#define HTPCM_ERROR_NO_MESSAGE_CALLBACK                             -7
#define HTPCM_ERROR_INVALID_PORT                                    -6
#define HTPCM_ERROR_NO_MEMORY                                       -5
#define HTPCM_ERROR_KEYFILE                                         -4
#define HTPCM_ERROR_CERTFILE                                        -3
#define HTPCM_ERROR_CHAINFILE                                       -2
#define HTPCM_ERROR_HTTP2_DIDNT_START                               -1

/******************************************************************************/



/***** ZERO-VALUE RESULTS *****************************************************/

#define HTPCM_OK                                                    0
#define HTPCM_ERROR_CERTIFICATE_INFO                                0
#define HTPCM_LISTENER_STARTUP_NO_ERROR                             0
#define HTPCM_ERRNO_NO_ERROR                                        0
#define HTPCM_ERROR_STOP_LISTENERS                                  0

/******************************************************************************/



/***** POSITIVE RESULTS *******************************************************/
#define HTPCM_SUCCESS                                               1


/******************************************************************************/
/******************************************************************************/

static int htpcm_errno = 0;



/* For advertising protocols during TLS/DTLS negotiation */
//static unsigned char ssl_proto_vector[] = {
//    2, 'h', '2',
//    8, 'h', 't', 't','p', '/', '1', '.', '1',
//};



/* Send to the callback when a complete message is received */
typedef struct _connection_message {
    PROTOCOL_ID pv;                     /* The HTTP protocol version of the message */
    char *raw_message;                       /* A pointer to the raw message */
    HTTP *http;                              /* A pointer to the HTTP object */
} CONNECTION_MESSAGE, *PCONNECTION_MESSAGE;


typedef struct _connection_info {
    int                 okay_to_run;        /*
                                             * The listener will terminate if this
                                             * value is set to ZERO.
                                             * 
                                             **/
    
    int                 join_expected;      /*
                                             * This is internally set to ZERO if there
                                             * was a problem with the thread owning
                                             * this CONNECTION_INFO structure.  That was
                                             * the thread can be removed from the list
                                             * and expected to clean itself up.
                                             * 
                                             * Default: ONE
                                             * 
                                             **/ 
    
    pthread_t           thread_id;          /*
                                             * The thread ID of the listener
                                             * 
                                             **/
    
    int                 ip_version;         /*
                                             * The internet protocol version number
                                             * we're using on this connection.
                                             **/
    
    int                 thread_listening;   /*
                                             * Set by the listener() thread so that
                                             * 'start_listening()' can return with a 
                                             * value letting main() know whether or not
                                             * this listener() started successfully
                                             **/
    
    char                string_error[255];  /*
                                             * Sometimes, the 'listener()' puts a human-
                                             * readable string in here as to why it failed.
                                             * 
                                             **/
    
    int                 startup_error;      /*
                                             * If there is an error launching a listener,
                                             * it will be placed in here.  Listeners
                                             * that haven't been confirmed as started will
                                             * be pthread_detached() and they will try to
                                             * die a cold, lonely death.
                                             * 
                                             **/
    
    int                 listener_errno;     /*
                                             * The 'errno' set when trying to set up the 
                                             * socket.
                                             * 
                                             **/

    LISTENER            *plistener;         /*
                                             * A pointer to the listener object.
                                             **/
} CONNECTION_INFO, *PCONNECTION_INFO;

typedef struct connection {
    CONNECTION_INFO ci;                     /* The information describing the connection */
    SOCKET socket;                          /* The socket for communication */
    size_t rxb_size;                        /* The size in bytes of the RX buffer */
    size_t rxb_cached;                      /* The number of bytes currently in the buffer */
    char *rx_buffer;                        /* Buffer containing the data to be processed */
} CONNECTION;


static PCONNECTION_INFO         *listener_list          = 0;
static size_t                   listener_list_size      = 0;
static size_t                   listener_list_count     = 0;





/**** Functions **********/

/* alpn_select()
 * 
 * Called by OpenSSL with a list of protocols advertised by the client as 
 * accepted.  We are to set the pointer pointed to by 'out' to equal
 * the first character of the protocol we wish to accept that we've found inside
 * of 'in'.
 * 
 * 'in' example:
 * 
 * 2h28http/1.1
 * |^^|^______^
 * ||||    |
 * ||||    |
 * |/ |   /
 * |  |  /
 * |  | /
 * |  |/
 * |  |
 * |  +--- 8 chars
 * |
 * +- 2 chars
 * 
 * So if we wanted to only accept HTTP/1.1, we'd set:
 *
 *      *out    = &in[4];
 *      *outlen = 8;
 * 
 * PARAMETERS:
 * 
 *              out     - A pointer to a pointer that will hold the first
 *                        character of the string representing the application-layer 
 *                        protocol we'd like to receive over TLS
 * 
 *              outlen  - A pointer to a buffer that we set to equal the length
 *                        of the string pointer at by the pointer contained in 'out'
 * 
 *              in      - A string of string-length/string-value pairs representing
 *                        the applications-layer protocols that the client is prepared
 *                        to use.
 * 
 *              inlen   - The length in bytes of the string pointed at by 'in'
 * 
 *              arg     - A pointer passed to this function that was defined when an
 *                        earlier call to OpenSSL's SSL_CTX_set_alpn_select_cb() was
 *                        made to let OpenSSL know that we wanted it to call this callback
 *                        so that we could take our pick of available protocols.  We set
 *                        this 'arg' pointer value ourselves.
 * 
 * RETURNS:
 *          SSL_TLSEXT_ERR_OK
 * 
 **/
int alpn_select(SSL *ssl, 
        const unsigned char **out, 
        unsigned char *outlen,
        const unsigned char *in,
        unsigned int inlen,
        void *arg);


/* *listener( void *listener_type )
 * 
 * Thread that runs accepting connections.
 * 
 **/
void *listener( void *pconnection_info );

/* *listener_tls( void *listener_type )
 * 
 * Thread that runs accepting TLS connetions.
 * 
 **/
void *listener_tls( void *pconnection_info );

/* start_listening()
 * 
 * This function sets up a listener() thread that accepts incoming connections according to
 * how it was set up.  When a new connection is successfully established, it looks at the
 * data received and matches its type to the protocol mask it has.  If the listener is 
 * configured to handle that protocol, it will proceed accordingly.  If it is not, it will
 * close the connection.
 * 
 * Todo: Identify and blacklist badly behaving clients, either here in the program, or log, or somehow...
 * 
 * 
 * PARAMETERS:
 * 
 *              l                           - A pointer to a LISTENER object configured
 *                                            by the settings.
 * 
 * RETURNS:
 *              HTPCM_SUCESS                - If the listener was successfully launched.
 * 
 *              HTPCM_INVALID_IP_VERSION    - Internet protocol version is set too high or too low.
 * 
 * 
 * 
 * 
 * 
 * 
 **/
int start_listening( LISTENER *l );


/* shutdown_all_listeners( void )
 * 
 * 
 * 
 * RETURNS:
 *              HTPCM_SUCCESS
 *              HTPCM_ERROR_STOP_LISTENERS
 * 
 **/
int shutdown_all_listeners( void );




#endif /* CONNECTION_MANAGER_H */

