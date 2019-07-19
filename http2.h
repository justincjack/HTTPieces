/* (c) 2019 Justin Jack - MIT License */
/* 
 * File:   http2.h
 * Author: justinjack
 *
 * Created on June 19, 2019, 10:39 AM
 */

#ifndef HTTP2_HEADER_H
#define HTTP2_HEADER_H

#include "httpieces_debug.h"
#include "db_x_platform.h"
#include "huffman.h"
#include "nb_ssl_wrappers.h"
#include "http.h"
#include "settings.h"
#include "cgi.h"
#include <stdint.h>
#include <signal.h>
#include <pthread.h>
#include <semaphore.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#define http2_zero( ptr, size ) memset((void *)ptr, 0, (size_t)size)

#define http2_malloc( ppvoid, size )    {\
                                            if (size) {\
                                                *ppvoid = malloc(size);\
                                                if (*ppvoid) {\
                                                    memset(*ppvoid, 0, size);\
                                                } else {\
                                                    http2_error("Failed to allocate %zu bytes!\n", size);\
                                                    return 0;\
                                                }\
                                            } else {\
                                                http2_error("Tried to allocate memory of size ZERO!\n");\
                                                return 0;\
                                            }\
                                        }

/* HTTP2_WAIT( condition, ms_timeout )
 * 
 * A comparison MACRO that waits up to 100ms for a certain condition to become 
 * NON-ZERO and evaluates the NEXT statement/block if the condition becomes
 * NON-ZERO during the 'ms_timeout'
 * 
 * It is NOT used as a function, and does NOT return a value.
 * 
 * 
 * 
 * PARAMETERS:
 *              condition       - An expression that is waited on to evaluate
 *                                to NON-ZERO
 * 
 *              ms_timeout      - The time in milliseconds to wait for the
 *                                'condition' to become NON-ZERO.
 * 
 * Example:
 * 
 * HTTP2_WAIT( 1, 100 ) {
 *      printf("The condition is true!\n");
 * } else {
 *      printf("The condition is still NOT true after 100 milliseconds!\n");
 * }
 * 
 * 
 */
#define HTTP2_WAIT( condition, ms_timeout ) if (!(condition)) {\
                                    int __waiter__ = 0;\
                                    for (; __waiter__ < ms_timeout; __waiter__++) {\
                                        if (condition) break;\
                                        usleep(1000);\
                                    }\
                                } if (condition)



#define HTTP2_STREAM_OPEN                   0x00
#define HTTP2_STREAM_IDLE                   0x02
#define HTTP2_STREAM_RESERVED_LOCAL         0x04
#define HTTP2_STREAM_RESERVED_REMOTE        0x08
#define HTTP2_STREAM_HALF_CLOSED_LOCAL      0x10
#define HTTP2_STREAM_HALF_CLOSED_REMOTE     0x20
#define HTTP2_STREAM_CLOSED                 0x30




/* HTTP2_SETTINGS_UNLIMITED
 * 
 * Used for certain settings related to how HTTP2 streams and
 * connections are handled in place of a SIGNED INTEGER to indicate
 * that there is no limit.
 * 
 **/
#define HTTP2_SETTINGS_UNLIMITED                                -1

/* HTTP2 Module Errors */
#define HTTP2_ERROR_WORKER_NOT_FOUND                            -12
#define HTTP2_ERROR_BACKLOG_FULL                                -11
#define HTTP2_ERROR_INVALID_BACKLOG_COUNT                       -10
#define HTTP2_ERROR_FAILED_TO_CREATE_THREAD_POOL                -9
#define HTTP2_ERROR_CANNOT_SERVICE_CONNECTION                   -8
#define HTTP2_ERROR_INVALID_MUTEX                               -7
#define HTTP2_ERROR_NOT_OWNED                                   -6
#define HTTP2_ERROR_NO_MEMORY                                   -5
#define HTTP2_ERROR_INVALID_INITIAL_THREAD_COUNT                -4
#define HTTP2_ERROR_MUTEX_FAILED                                -3
#define HTTP2_INVALID_ARG                                       -2
/***** All zero constants *****************************************************/

#define HTTP2_NO_BACKLOG                                         0
#define HTTP2_ERROR_MAX_WORKER_THREADS                           0
#define HTTP2_INVALID_MUTEX                                      0
#define HTTP2_OK                                                 0

/******************************************************************************/
#define HTTP2_SUCCESS                                            1
#define HTTP2_MUTEX_ALREADY_OWNED                                2
#define HTTP2_CONNECTION_QUEUED                                  3

/* Worker Thread States ********************************************************/

#define HTTP2_THREAD_NOT_ACTIVE         0
#define HTTP2_THREAD_ACTIVE             1
#define HTTP2_THREAD_DIE                2
#define HTTP2_THREAD_JOIN               4
#define HTTP2_THREAD_DIE_AND_JOIN       6
#define HTTP2_THREAD_SHUTTING_DOWN      8
#define HTTP2_THREAD_DEAD               16

/******************************************************************************/


static const struct _http2_int_decode_mask {
    uint8_t         mask;           /*
                                     * The mask to apply against prefix
                                     **/
                                     
    uint8_t         reverse_mask;   /*
                                     * The mask to save the bits in the prefix
                                     **/
} HTTP2_IDC_MASK[] = {
    {.mask = 0xFF, .reverse_mask = 0x00},
    {.mask = 0x7F, .reverse_mask = 0x80},
    {.mask = 0x3F, .reverse_mask = 0xC0},
    {.mask = 0x1F, .reverse_mask = 0xE0},
    {.mask = 0x0F, .reverse_mask = 0xF0},
    {.mask = 0x07, .reverse_mask = 0xF8},
    {.mask = 0x03, .reverse_mask = 0xFC},
    {.mask = 0x01, .reverse_mask = 0xFE}
};


static const char HTTP2_CLIENT_PREFACE[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"; 
static const size_t HTTP2_CLIENT_PREFACE_LEN = strlen(HTTP2_CLIENT_PREFACE);


typedef int HTTP2_WORKER_THREAD_STATUS;


typedef HTTP_MUTEX HTTP2_MUTEX, *PHTTP2_MUTEX;

#define http2_new_mutex( x )    http_new_mutex( x )
#define http2_lock( x )         http_lock( x )
#define http2_unlock( x )       http_unlock( x )
#define http2_retire_mutex( x ) http_retire_mutex( x )
#define http2_free_mutex( x )   http_free_mutex( x )



/* static struct _http2_module_settings HTTP2_MODULE_SETTINGS
 * 
 * Settings that dictate how this HTTP2 module behaves and
 * how it should allocate resources and handle connections.
 * 
 **/
static struct _http2_module_settings {
    int max_connection_threads;         /*
                                         * The maximum number of threads
                                         * that http2_connection_thread() will be allowed
                                         * to spawn.
                                         * 
                                         * Default: 40
                                         * 
                                         **/
    
    int max_connection_backlog;         /*
                                         * The size of the 'http2_connection_backlog_queue' from which
                                         * each http2_connection_thread() will accept a 
                                         * connection to serve if 'max_connection_threads' has
                                         * been met and http2_connection_thread() can't spawn
                                         * any new worker threads.
                                         * 
                                         * If there are already 'max_connection_backlog' connections
                                         * waiting to be served, the server MUST reject (immediately
                                         * close) any new connections.
                                         * 
                                         * Default: 20
                                         * 
                                         **/
        
    int initial_connection_threads;     /*
                                         * The initial number of http2_connection_thread() threads 
                                         * we will spawn to service connections.
                                         * 
                                         * Default: 10
                                         * 
                                         **/
    
    
    int stream_timeout;                 /* 
                                         * The number of seconds after which, if no data is received 
                                         * or sent, we will shut down a stream.
                                         * 
                                         * Default: 120 
                                         * 
                                         **/
    
    int connection_timeout;             /*
                                         * The number of seconds after which, if no data is received
                                         * or sent, we will shutdown the connection.
                                         * 
                                         * Before the http2_connection_thread() flushes all its
                                         * buffers and cache and returns to its ready state,
                                         * it should attempt to gracefully close all of its
                                         * streams.
                                         * 
                                         * Default: 30
                                         * 
                                         **/
    
    
} HTTP2_MODULE_SETTINGS = {
    .max_connection_threads     = HTTP2_SETTINGS_UNLIMITED,
    .max_connection_backlog     = 20, /* Doesn't matter when 'max_connection_threads' is set to 'HTTP2_SETTINGS_UNLIMITED' */
    .initial_connection_threads = 10,
    .stream_timeout             = 120,
    .connection_timeout         = 30,
    
};


/* enum _http2_error_codes
 * 
 * HTTP2 error codes / values
 * 
 **/
typedef enum _http2_error_codes {
    HTTP2_ERROR_NO_ERROR,           
    HTTP2_ERROR_PROTOCOL_ERROR,     
    HTTP2_ERROR_INTERNAL_ERROR,
    HTTP2_ERROR_FLOW_CONTROL_ERROR,
    HTTP2_ERROR_SETTINGS_TIMEOUT,
    HTTP2_ERROR_STREAM_CLOSED,
    HTTP2_ERROR_FRAME_SIZE_ERROR,
    HTTP2_ERROR_REFUSED_STREAM,
    HTTP2_ERROR_CANCEL,
    HTTP2_ERROR_COMPRESSION_ERROR,
    HTTP2_ERROR_CONNECT_ERROR,
    HTTP2_ERROR_ENHANCE_YOUR_CALM,      /* LOL. The endpoint detected that its 
                                         * peer is exhibiting a behavior that 
                                         * might be generating excessive load.
                                         **/ 
    HTTP2_ERROR_INADEQUATE_SECURITY,
    HTTP2_ERROR_HTTP_1_1_REQUIRED,
} HTTP2_ERROR_CODE;

/* enum _http2_frame_types
 * 
 * HTTP2 frame types.
 * 
 **/
typedef enum _http2_frame_types {
    HTTP2_FRAME_DATA,           /* Contains the data of an HTTP message 
                                 * DATA frames are the only frames subject
                                 * to flow control.
                                 * 
                                 **/
    
    HTTP2_FRAME_HEADER,         /* Contains a header for an HTTP message */
    
    HTTP2_FRAME_PRIORITY,       /*  */
    
    HTTP2_FRAME_RST_STREAM,     /* Immediate termination of a stream */
    
    HTTP2_FRAME_SETTINGS,
    
    HTTP2_FRAME_PUSH_PROMISE,   /* Contains a PUSH PROMISE, which comprises
                                 * The future stream ID that will be coming,
                                 * a list of REQUEST header fields.
                                 **/
    HTTP2_FRAME_PING,
    HTTP2_FRAME_GOAWAY,         /* https://tools.ietf.org/html/rfc7540#section-6.8
                                 * 
                                 * Used to initiate a shutdown of a CONNECTION or
                                 * to signal serious error conditions.  This
                                 * allows an endpoint to gracefully stop accepting
                                 * new streams while still finishing processing of
                                 * previously established streams.
                                 * 
                                 * Endpoints should send a GOAWAY frame before
                                 * closing a connection.
                                 * 
                                 * An endpoint might choose to close a connection 
                                 * without sending a GOAWAY for misbehaving peers.
                                 * 
                                 **/
    
    HTTP2_FRAME_WINDOW_UPDATE,   /* Used for flow control.
                                  * 
                                  * This indicates the MAX number of bytes that
                                  * can be sent in a frame.  The purpose of this
                                  * is so that if one stream has a MASSIVE chunk
                                  * of DATA to send, it doesn't block the other
                                  * streams and they can be multiplexed.  If the
                                  * frame's stream ID is 0 (ZERO), then this
                                  * applies to the entire connection.  Otherwise,
                                  * it applies to the stream identified by the
                                  * stream ID.
                                  * 
                                  **/ 
    
    HTTP2_FRAME_CONTINUATION,     /* https://tools.ietf.org/html/rfc7540#section-6.10
                                   * 
                                   * Used to continue a sequence of header
                                   * block fragments.  Any number of CONTINUATION
                                   * frames can be sent as long as the preceding
                                   * frame is on the same stream and is a HEADERS,
                                   * PUSH_PROMISE, or CONTINUATION frame without
                                   * the END_HEADERS flag being set.
                                   * 
                                   * If the END_HEADERS bit is not set, the frame
                                   * MUST be followed by another CONTINUATION
                                   * frame.  A receiver MUST treat the receipt
                                   * of any other type of frame, or a frame on a 
                                   * different stream as a connection error of
                                   * type PROTOCOL_ERROR.
                                   * 
                                   * !!! Important !!!
                                   * 
                                   * This means that there can be NO multiplexing
                                   * at all on a connection while an endpoint is
                                   * sending HEADERs for a new stream !!!
                                   * 
                                   * 
                                   * 
                                   **/ 
    
} HTTP2_FRAME_TYPE;

/* static const struct _http2_header_table HTTP2_STATIC_TABLE
 * 
 * The HTTP2 static table of HTTP header values
 * 
 **/
static const struct _http2_header_table {
    const char *headername;
    const char *headervalue;
} HTTP2_STATIC_TABLE[] = {
    {"", ""}, /* Empty because the indexing is 1-based */
    {":authority",                      ""},    {":method",                      "GET"},    {":method",                     "POST"},    {":path",                          "/"},
    {":path",                "/index.html"},    {":scheme",                     "http"},    {":scheme",                    "https"},    {":status",                      "200"},
    {":status",                      "204"},    {":status",                      "206"},    {":status",                      "304"},    {":status",                      "400"},
    {":status",                      "404"},    {":status",                      "500"},    {"accept-charset",                  ""},    {"accept-encoding",                 ""},
    {"accept-language",                 ""},    {"accept-ranges",                   ""},    {"accept",                          ""},    {"access-control-allow-origin",     ""},
    {"age",                             ""},    {"allow",                           ""},    {"authorization",                   ""},    {"cache-control",                   ""},
    {"content-disposition",             ""},    {"content-encoding",                ""},    {"content-language",                ""},    {"content-length",                  ""},
    {"content-location",                ""},    {"content-range",                   ""},    {"content-type",                    ""},    {"cookie",                          ""},
    {"date",                            ""},    {"etag",                            ""},    {"expect",                          ""},    {"expires",                         ""},
    {"from",                            ""},    {"host",                            ""},    {"if-match",                        ""},    {"if-modified-since",               ""},
    {"if-none-match",                   ""},    {"if-range",                        ""},    {"if-unmodified-since",             ""},    {"last-modified",                   ""},
    {"link",                            ""},    {"location",                        ""},    {"max-forwards",                    ""},    {"proxy-authenticate",              ""},
    {"proxy-authorization",             ""},    {"range",                           ""},    {"referer",                         ""},    {"refresh",                         ""},
    {"retry-after",                     ""},    {"server",                          ""},    {"set-cookie",                      ""},    {"strict-transport-security",       ""},
    {"transfer-encoding",               ""},    {"user-agent",                      ""},    {"vary",                            ""},    {"via",                             ""},
    {"www-authenticate",                ""},
};

typedef struct _http2_dyn_table {
    struct _http2_header {
        char *ptr;
        size_t size;
        size_t len;
    } name, value;
} HTTP2_DYN_TABLE, *PHTTP2_DYN_TABLE;

typedef struct _http2_conv_table {
    size_t size;
    size_t used;
    PHTTP2_DYN_TABLE table;
} HTTP2_CONV_TABLE, *PHTTP2_CONV_TABLE;



static const int HTTP2_STATIC_HEADER_SIZE = sizeof(HTTP2_STATIC_TABLE) / sizeof(struct _http2_header_table);

static HTTP2_CONV_TABLE http2_header_table_prototype = {
  .size = (HTTP2_STATIC_HEADER_SIZE * 2),
  .used = HTTP2_STATIC_HEADER_SIZE,
  .table = 0
};



typedef enum http2_settings {
    SETTINGS_NONE,
    SETTINGS_HEADER_TABLE_SIZE,
    SETTINGS_ENABLE_PUSH,
    SETTINGS_MAX_CONCURRENT_STREAMS,
    SETTINGS_INITIAL_WINDOW_SIZE,
    SETTINGS_MAX_FRAME_SIZE,
    SETTINGS_MAX_HEADER_LIST_SIZE,
} HTTP2_SETTINGS;

/* struct _http2_settings http2_settings
 * 
 * The SETTINGS structure for HTTP2 connections and/or streams
 * and it defines their default values.
 * 
 **/
static struct _http2_settings {
    int reserved;
    int SETTINGS_HEADER_TABLE_SIZE;      /* Similar to SETTINGS_MAX_HEADER_LIST_SIZE.
                                          * 
                                          * This is the max size (in octets) of the 
                                          * dynamic TABLE to be used to
                                          * translate header fields.  If this is smaller,
                                          * then more references will be evicted to decode
                                          * the actual textual completed header fields
                                          * that are passed to the HTTP processor.
                                          * 
                                          * The default is 4096
                                          * 
                                          **/ 
    int SETTINGS_ENABLE_PUSH;
    int SETTINGS_MAX_CONCURRENT_STREAMS; /* https://tools.ietf.org/html/rfc7540#section-6.5.2 
                                          * This value of zero means no new streams can be created
                                          * for the sender.  If the max number of streams has been
                                          * reached, a receiver MAY send this so that it gets no
                                          * new streams until it resets the value indicating that it
                                          * is ready to receive new streams.
                                          * 
                                          * Initial value is HTTP2_SETTINGS_UNLIMITED.
                                          * 
                                          **/
    
    int SETTINGS_INITIAL_WINDOW_SIZE;    /* Must be a value between (0xFF-1) and (0xFFFFFF - 1) 
                                          * A value OVER the max, is a connection error of type
                                          * FLOW_CONTROL_ERROR
                                          **/
    int SETTINGS_MAX_FRAME_SIZE;
    int SETTINGS_MAX_HEADER_LIST_SIZE;   /* Size of the header list the sender is prepared to accept
                                          * in octets.  This determines the size of the UNCOMPRESSED,
                                          * finalized headers that are in a complete HTTP request.  The
                                          * sender must evaluate this when it's putting together the HTTP
                                          * request before any encoding.
                                          * 
                                          * value = ( ((length of name + length of value) + 32) * number of fields )
                                          * 
                                          * The initial value is HTTP2_SETTINGS_UNLIMITED.  
                                          * 
                                          **/ 
    
} http2_settings = {
    0,                          /* Reserved */
    4096,                       /* SETTINGS_HEADER_TABLE_SIZE           - SEND ON HANDSHAKE */
    1,                          /* SETTINGS_ENABLE_PUSH */
    HTTP2_SETTINGS_UNLIMITED,   /* SETTINGS_MAX_CONCURRENT_STREAMS */
    65535,                      /* SETTINGS_INITIAL_WINDOW_SIZE         - SEND ON HANDSHAKE */
    16384,                      /* SETTINGS_MAX_FRAME_SIZE              - SEND ON HANDSHAKE */
    HTTP2_SETTINGS_UNLIMITED    /* SETTINGS_MAX_HEADER_LIST_SIZE */
};


typedef struct _http2_stream HTTP2_STREAM, *PHTTP2_STREAM;

/* HTTP2_CONNECTION, *PHTTP2_CONNECTION
 * 
 * This structure defines the context for each TCP/TLS connection.  It
 * keeps track of the status of all streams and the settings for the connection.
 * 
 * This will be created and initialized when a new connection is started.
 * 
 **/
typedef struct _http2_connection {
    
    int                         protocol_identified;            /*
                                                                 * A flag that is set to ONE, when the protocol has been identified.
                                                                 **/
    
    PROTOCOL_ID                 protocol_id;                    /*
                                                                 * This variable is set when we know which protocol this connection is
                                                                 * handling.
                                                                 * 
                                                                 **/
    
    pthread_t                   creator;                        /*
                                                                 * The thread ID of the listener that's establishing this connection.
                                                                 **/

    int                         connection_is_valid;            /*
                                                                 * Set to ZERO by logic processing a connection to indicate that the 
                                                                 * connection is no longer valid and the worker thread should reset 
                                                                 * itself to a ready state.
                                                                 **/
    
    int                         connection_id_dead;             /*
                                                                 * Set by the worker thread to ONE, when the http2_tcp_socket_writer() should
                                                                 * dispose of this connection and its references.
                                                                 **/
    
    int                         ip_version;                     /*
                                                                 * The integer Internet Protocol version being serviced by this
                                                                 * connections.
                                                                 * 
                                                                 **/
    
    time_t                      connection_start_time;
    
    time_t                      connection_last_operation;
    
    IP_ADDRESS                  client_ip_address;              /* The client's IP Address */
    
    uint16_t                    remote_port;                    /* 
                                                                 * The port from which the client is sending
                                                                 * data.
                                                                 **/
    
    int                         socket;                         /*
                                                                 * The underlying socket via which all communication
                                                                 * is taking place.
                                                                 * 
                                                                 **/
    
    
    SSL                         *ssl;                           /* 
                                                                 * The connected SSL object from which we'll
                                                                 * read our data
                                                                 **/
    
    PHTTP2_STREAM               *streams;                       /*
                                                                 * Array of active streams.
                                                                 * 
                                                                 **/
    
    size_t                      streams_allocated;              /*
                                                                 * The number of pointers we have allocated in 'streams'
                                                                 **/
    
    
    uint32_t                    next_stream_id;                 /* 
                                                                 * The next stream ID we will assign to a stream
                                                                 * that we've initiated.  
                                                                 * 
                                                                 * Initial value: 1
                                                                 * 
                                                                 * !! Remember, when we increment the stream ID,
                                                                 * if it reaches (2^31 - 1), we MUST send
                                                                 * set MAX_STREAMS to ZERO, send an HTTP2_FRAME_GOAWAY,
                                                                 * finish processing any existing streams and close
                                                                 * the connection !!
                                                                 * 
                                                                 **/
    
    struct _http2_settings      local_connection_settings;      /* 
                                                                 * Connection settings, if these are modified, 
                                                                 * all the stream settings must be changed 
                                                                 * downstream.
                                                                 **/
    
    struct _http2_settings      remote_connection_settings;     /* 
                                                                 * Connection settings, if these are modified, 
                                                                 * all the stream settings must be changed 
                                                                 * downstream.
                                                                 **/
    
    uint32_t                    peer_window_size;               /*
                                                                 * The number of bytes the client has available in their buffer.
                                                                 * 
                                                                 **/
    
    
    struct timeval              tv;                             /* For our select() */
    
    fd_set                      fdr;                            /* For our select() */
    
    size_t                      bytes_read;                     /* To hold the bytes read from SSL_read() */
    
    char                        read_buffer[65535];             /*
                                                                 * The buffer that SSL_read() write into.  We take
                                                                 * whatever is in this buffer and push it onto our
                                                                 * 'service_buffer'
                                                                 * 
                                                                 **/
    
    char                        *swap;                          /*
                                                                 * swap buffer for realloc()ing of service_buffer;
                                                                 **/
    
    char                        *service_buffer;                /*
                                                                 * This is the buffer that our application-layer
                                                                 * analyzers look at.  When they're done looking at
                                                                 * the top of it, they will remove their messages
                                                                 * and leave whatever is next for the next configured
                                                                 * protocol analyzer to look at.
                                                                 **/
    
    size_t                      service_buffer_size;            /*
                                                                 * The allocated size of the 'service_buffer'
                                                                 **/
    
    size_t                      swap_len;                       /*
                                                                 * The size needed to reallocate the swap buffer
                                                                 * to accomodate the new data.
                                                                 **/
    
    
    size_t                      service_buffer_len;             /*
                                                                 * The count of octets TLS decoded octets in the 'service_buffer'
                                                                 * ready to be processed.
                                                                 **/
    
    
    PHTTP2_MUTEX                output_buffer_mutex;            /*
                                                                 * The mutex protecting this connection's output buffer
                                                                 **/
    
    uint8_t                     *output_buffer;                 /* Buffer containing data to send */
    
    size_t                      output_buffer_size;             /* The allocated size in bytes of 'output_buffer' */
    
    size_t                      output_len;                     /* The size in octets of the data buffered to send in 'output_buffer' */    
    
    char                        *header_decode_buffer;          /* The buffer we use for this connection to huffman decode HEADERs */
    
    size_t                      header_decode_len;              /* The size in bytes of the memory allocated in header_decode_buffer */
    
    LISTENER                    *plistener;                     /* A pointer to the listener */
    
    HTTP                        *phttp;                         /* The HTTP context for this connection (ONLY applies for < HTTP/2) */
    
    
    HTTP                        **http_request_list;            /* An array of pointers to HTTP objects that we're serving (Mainly for HTTP/1.1 pipelining */
    
    
} HTTP2_CONNECTION, *PHTTP2_CONNECTION;



/* HTTP2_STREAM
 * 
 * A stream is a simple REQUEST / RESPONSE sequence.  A stream is 
 * created by a connection when:
 * 
 * A. It receives a request.
 * B. It sends a message such as a
 *      1. SETTINGS
 *      2. PUSH_PROMISE
 *      3. WINDOW_UPDATE
 *      4. PRIORITY
 * 
 **/
struct _http2_stream {
    
    PHTTP2_CONNECTION           pconnection;                    /* A pointer to the HTTP2_CONNECTION structure governing
                                                                 * this stream.
                                                                 **/
    
    PROTOCOL_ID                 protocol_id;                    /*
                                                                 * Indicates which sub-protocol (if any) this stream is handling.
                                                                 * 
                                                                 * Right now, either: 
                                                                 * 
                                                                 * HTTP2_0 or WEBSOCKET
                                                                 * 
                                                                 **/
    
    uint32_t                    stream_id;                      /*
                                                                 * The 32 bit integer stream ID
                                                                 **/
    
    uint32_t                    depends_on_stream_id;           /*
                                                                 * The id of the stream that needs to be completed before
                                                                 * this stream can be sent
                                                                 **/
    
    uint8_t                     weight;                         /* The weight of this stream, from 1 to 256 */
    
    
    uint8_t                     exclusive_bit;                  /*
                                                                 * The "E" (exclusive) bit.
                                                                 **/
    
    uint32_t                    peer_window_size;               /*
                                                                 * The number of bytes the client has available in their buffer.
                                                                 * 
                                                                 **/
    
    
    struct _http2_settings      remote_stream_settings;         /*
                                                                 * The settings we've been given by the remote peer.
                                                                 * 
                                                                 **/
    
    struct _http2_settings      local_stream_settings;          /* Settings for this stream.  This will be created 
                                                                 * with the default stream settings, but may be 
                                                                 * modified by a SETTINGS frame for this stream, OR
                                                                 * by the connection.
                                                                 * 
                                                                 * When looking at settings to prepare what to send,
                                                                 * the stream must compare its settings to the 
                                                                 * CONNECTION's settings and if the CONNECTION's 
                                                                 * settings are LOWER than this stream, we must
                                                                 * honor the CONNECTION's settings.
                                                                 * 
                                                                 **/
    
    int                         stream_status;                  /*
                                                                 * Stream status. Can be one or possibly a combo of:
                                                                 * 
                                                                 * HTTP2_STREAM_OPEN
                                                                 * HTTP2_STREAM_IDLE
                                                                 * HTTP2_STREAM_RESERVED_LOCAL
                                                                 * HTTP2_STREAM_RESERVED_REMOTE
                                                                 * HTTP2_STREAM_HALF_CLOSED_LOCAL
                                                                 * HTTP2_STREAM_HALF_CLOSED_REMOTE
                                                                 * HTTP2_STREAM_CLOSED
                                                                 * 
                                                                 **/

    uint8_t                     *header_buffer;                 /*
                                                                 * The buffer wherein we store all the HEADER payload info for this connection
                                                                 * to decode when we get END_HEADERS
                                                                 **/
    
    size_t                      header_buffer_size;             /*
                                                                 * The size (in octets) of the HEADER buffer
                                                                 **/
    
    size_t                      header_buffer_len;              /*
                                                                 * The number of octets that comprises the HEADER buffer.
                                                                 **/
    
    
    HTTP2_CONV_TABLE            decoding_table;                 /* The HPACK decoding table */
    
    LISTENER                    *plistener;
    
    HTTP                        *phttp;                         /* The HTTP context for this stream */
    
    
};/* HTTP2_STREAM, *PHTTP2_STREAM;*/





/* HTTP2_CONNECTION_THREAD_CONTROL, *PHTTP2_CONNECTION_THREAD_CONTROL
 * 
 * The control structure for each http2_connection_thread()
 **/
typedef struct _http2_connection_thread_control {
    
    pthread_t                   thread;                         /*
                                                                 * The worker thread's thread identifier.
                                                                 **/
    
    time_t                      start_time;                     /*
                                                                 * The time that this worker thread was launched.
                                                                 * 
                                                                 **/
    
    int                         is_fundamental;                 /*
                                                                 * create_http2_connection_thread() sets this value to ZERO
                                                                 * 
                                                                 * This flag is set to ONE by http2_init() when the initial
                                                                 * worker threads are created so that the thread itself knows
                                                                 * that it is one of the fundamental service threads and doesn't
                                                                 * ever consider shutting itself down.
                                                                 * 
                                                                 * Threads whose flags is set to ZERO can decide to shutdown to
                                                                 * conserve system resources if they determine that the current
                                                                 * workload doesn't justify their existence.
                                                                 * 
                                                                 **/ 
    
    HTTP2_WORKER_THREAD_STATUS  status;                         /*
                                                                 * Set to HTTP2_THREAD_NOT_ACTIVE when the thread's control structure is created.
                                                                 * The thread itself will set this flag to HTTP2_THREAD_HALF_ACTIVE to let the
                                                                 * function creating the thread know that it has been successfully
                                                                 * created and is ready to join the worker thread pool.  
                                                                 * 
                                                                 * Once create_http2_connection_thread() has seen that the thread has
                                                                 * achieved HTTP2_THREAD_HALF_ACTIVE in a timely manner, create_http2_connection_thread()
                                                                 * will mark the thread as HTTP2_THREAD_ACTIVE which will let the THREAD know in turn
                                                                 * that its initialization is complete and it is clear to proceed
                                                                 * with connection service.
                                                                 * 
                                                                 **/
    
    int                         available;                      /*
                                                                 * A flag set to let delegate_new_connection() know if the thread
                                                                 * is busy or not.
                                                                 * 
                                                                 * Initial value is ZERO.  It is set to ONE by the thread itself 
                                                                 * when it's ready for work.
                                                                 * 
                                                                 **/
    
    sem_t                       new_job;                        /*
                                                                 * This semaphore will be signalled when the connection
                                                                 * thread has a new connection to serve.
                                                                 * 
                                                                 **/ 
    
    PHTTP2_CONNECTION           connection;                     /*
                                                                 * A pointer to the connection to start serving.  With every
                                                                 * iteration of the thread's main loop, before the thread
                                                                 * sets its availability to ONE, but before it waits on its
                                                                 * semaphore 'new_job', this will be set back to ZERO.
                                                                 * 
                                                                 **/
    
    
    
    
} HTTP2_CONNECTION_THREAD_CONTROL, *PHTTP2_CONNECTION_THREAD_CONTROL;


static sem_t                    http2_sem_output_available;     /*
                                                                 * Semaphore, a pointer to which is set in the HTTP2_TCP_WRITER_CONTROL
                                                                 * structure used by http2_tcp_socket_writer()
                                                                 * 
                                                                 **/

static PHTTP2_CONNECTION        *http2_connection_list = 0;     /*
                                                                 * Master list of connections being handled.  Connections are added to this list
                                                                 * in delegate_new_connection(), and are removed by http2_tcp_socket_writer() when
                                                                 * the connections are marked for removal.
                                                                 * 
                                                                 **/

static size_t                   http2_connection_list_size = 0; /* The number of pointers to HTTP2_CONNECTION structures contained in the array */

static PHTTP2_MUTEX             http2_connection_list_mtx = 0;  /* 
                                                                 * The mutex to be locked whenever this connection list is updated.
                                                                 **/


static int                      http2_tcp_writer_die       = 0; /*
                                                                 * Set to ONE when it's time for the http2_tcp_socket_writer() thread to die
                                                                 **/


static pthread_t                http2_tcp_writer_thread    = 0; /*
                                                                 * The identifier for the writer thread.  We use this to send it SIGUSR2 when there's
                                                                 * data to write.
                                                                 **/

/* http2_connection_thread_list
 * 
 * An array of to hold pointers to active 
 * 'http2_connection_thread' threads that are available
 * for serving HTTP2 requests.
 * 
 * 
 * There are two functions that modify this list:
 * 
 * 1. create_http2_connection_thread() in 'http2.c'
 * 2. retire_http2_connection_thread() in 'http2.c'
 * 
 * 
 * The possible call stacks for access to this are as follows:
 * 
 * 
 * !! Creating worker threads !!
 * 
 * #1 - listener() thread #2
 * 
 * create_http2_connection_thread()                         'http2.c'
 *      <= http2_init()                                     'http2.c'
 *          <= listener()                                   'connection_manager.c'
 *              <= start_listening()                        'connection_manager.c'
 *                  <= main()                               'main.c'
 * 
 * 
 * #2 - listener() thread #2
 * 
 * create_http2_connection_thread()                         'http2.c'
 *      <= delegate_new_connection()                        'http2.c'
 *          <= listener()                                   'connection_manager.c'
 *              <= start_listening()                        'connection_manager.c'
 *                  <= main()                               'main.c'
 * 
 * 
 * 
 * !! Retiring (destroying) worker threads !!
 * 
 * #3 - listener() thread #2
 *   
 * retire_http2_connection_thread()                         'http2.c'
 *      <= http2_init()                                     'http2.c'
 *          <= listener()                                   'connection_manager.c'
 *              <= start_listening()                        'connection_manager.c'
 *                  <= main()                               'main.c'
 * 
 * 
 * #4 - http2_connection_thread() thread #n
 * 
 * retire_http2_connection_thread()                         'http2.c'
 *      <= http2_connection_thread()                        'http2.c'
 *          <= create_http2_connection_thread()             'http2.c'
 *              <= delegate_new_connection()                'http2.c'
 *                  <= listener()                           'connection_manager.c'
 *                      <= start_listening()                'connection_manager.c'
 *                          <= main()                       'main.c'
 * 
 * 
 * 
 * This list is only modified from the 'listner()'s thread by calls to
 * either delegate_new_connection(), or a call to http2_init()
 * 
 * It's size is limited by HTTP2_MODULE_SETTINGS.max_connection_threads
 * ( if this value is not HTTP2_SETTINGS_UNLIMITED )
 * 
 * 
 **/
static PHTTP2_CONNECTION_THREAD_CONTROL 
                            *http2_connection_thread_list = 0;

/*
 * The number of elements in the http2_connection_thread_list
 **/
static size_t               http2_connection_thread_list_size = 0;


/* http2_active_worker_threads
 * 
 * The number of active worker threads contained in the 
 * 'http2_connection_thread_list' array.
 * 
 **/
static size_t               http2_active_worker_threads = 0;



/* http2_active_worker_mutex
 * 
 * The mutex that protects access to the 'http2_connection_thread_list'
 * array.
 * 
 **/
static PHTTP2_MUTEX         http2_active_worker_mutex;


/* http2_library_initialized
 * 
 * Set to ZERO if http2_init() hasn't been successfully called, or
 * ONE if the library is ready.
 * 
 **/
static int                  http2_library_initialized = 0;

/* http2_connection_backlog_queue
 * 
 * The array of pointers to connections waiting to be serviced.  
 * 
 * It is allocated when http2_init() is called.
 * 
 * This array is 
 * populated when delegate_new_connection() cannot immediately assign a new 
 * connection to an 'http2_connection_thread'.
 * 
 **/
static PHTTP2_CONNECTION    *http2_connection_backlog_queue;

/* http2_connection_backlog_count
 * 
 * The number of connections that are waiting to be serviced.
 * 
 **/
static size_t               http2_connection_backlog_count = 0;


/* http2_connection_backlog_mutex
 * 
 * The mutex that protects access to the backlog queue.  The individual
 * 'http2_connection_thread's will lock this and pull any connections
 * to serve off the stack before they enter their idle waiting state.
 * 
 **/
static PHTTP2_MUTEX         http2_connection_backlog_mutex;


#ifdef __cplusplus
extern "C" {
#endif
    
    /*----- PRIVATE INTERNAL FUNCTIONS --------------------------------------------------------------------------*/
    /*
     * Process headers for a particular HTTP/2 request.
     * 
     **/
    void http2_process_headers( PHTTP2_STREAM s);
    
    /*
     * Encodes an integer into a buffer, preserving the prefix and returns the number of bytes
     * written.
     * 
     **/
    int http2_encode_integer( uint32_t integer, uint8_t prefix, uint8_t *buff);
    
    /*!
     * 
     * \brief Returns the integer starting at octet 'pin', bit 'bit_offset'
     * 
     * This function takes a pointer to an octet 'pin' and looks at bit_offset
     * for the integer.  
     * 
     * \param       pin             - A pointer to the octet wherein the integer starts
     * \param       prefix          - The number of bits that comprise the prefix (depending on field type)
     * \param       read_length_out - The number of bytes (including 'pin' that the interger comprises)
     * 
     * \return      The integer value
     * 
     **/
    int http2_read_integer(uint8_t *pin, uint8_t prefix, size_t *read_length_out );
    
    
    /*
     * Sends SETTINGS to a new connection.
     **/
    int http2_connection_send_settings(PHTTP2_CONNECTION c);
    
    /*
     * Adds a new stream to an HTTP2_CONNECTION
     **/
    PHTTP2_STREAM http2_connection_add_stream(PHTTP2_CONNECTION c, uint32_t stream_id);
    
    /*
     * Start a stream and start parsing headers.
     **/
    void http2_process_header_frame(PHTTP2_CONNECTION c, uint32_t stream_id, uint32_t flags, uint8_t *pdata, size_t length);
    
    /*
     * Sends a GO_AWAY frame with the error code and closes the connection.
     **/
    void http2_connection_error( PHTTP2_CONNECTION c, uint32_t error_code);
    
    /*
     * Sends a stream error on a connection.
     **/
    void http2_stream_error(PHTTP2_CONNECTION c, uint32_t stream_id, uint32_t error_code);
    
    /*
     * Builds an HTTP/2 frame for sending.
     **/
    uint8_t *http2_build_frame( 
        HTTP2_FRAME_TYPE ft, 
        uint8_t flags, 
        uint32_t stream_id,
        size_t payload_length, 
        void *payload,
        size_t *frame_size_out);
    
    
    /*
     * Handles window update settings messages.
     **/
    void http2_process_window_update( PHTTP2_CONNECTION c, uint32_t stream_id, uint32_t *pdata);
    
    /*
     * Processes a SETTINGS frame for a connection or stream.
     **/
    void http2_process_settings_frame( PHTTP2_CONNECTION c, uint32_t stream_id, uint8_t *pdata, size_t data_len);
    
    /*! http2_buffer_output( PHTTP2_CONNECTION c, void *pdata, size_t len_data)
     * 
     * 
     * \brief Buffers data onto a connection output buffer.
     * 
     * 
     * \param   c        - Pointer to HTTP2_CONNECTION struct
     * \param   pdata    - Pointer to memory address containing the data
     *                     to send.
     * \param   len_data - The length in bytes of the data to buffer.
     * 
     * 
     * \return  1    - Success
     * \return  0    - Unsuccessful
     * 
     **/
    int http2_buffer_output( PHTTP2_CONNECTION c, void *pdata, size_t len_data);
    
    /* http2_tcp_output_available( void );
     * 
     * Called to let our TCP writer know that
     * it has data to serve.
     * 
     **/
    void http2_tcp_output_available( void );
    
    /*!
     * \brief Called when an error is detected on a stream or connection.
     * 
     * This sends a RST_STREAM message to the client and terminates the stream.
     * 
     * \param s     - A pointer to the stream
     * \param error - The error code to send with the RST_STREAM frame.
     * 
     * \return Nothing.
     * 
     * 
     **/
    void http2_reset_stream( PHTTP2_STREAM s, HTTP2_ERROR_CODE error);
    
    /*!
     * 
     * \brief Processes data from the top of an HTTP/2 input buffer
     * 
     * This is one of the set of xxxx_process_stream() functions that 
     * processes data from the HTTP2_CONNECTION::service_buffer.
     * 
     * Is is responsible for handling HTTP/2 connections.
     * 
     * 
     * \param c - A pointer to an HTTP2_CONNECTION structure
     * 
     * \return Nothing
     * 
     * 
     **/
    void http2_process_stream( PHTTP2_CONNECTION c);
    
    
    /* http2_pop_connection( void )
     * 
     * This function is called by 
     * Retrieves a connection to be serviced from the 'http2_connection_backlog_queue'.
     * 
     * PARAMETERS:  None
     * 
     * RETURNS:
     *              On success (if there are any connections waiting), this
     *              function returns a pointer to an HTTP2_CONNECTION
     *              structure.
     * 
     *              On failure (if the queue is empty), this function returns
     *              ZERO.
     * 
     **/
    static PHTTP2_CONNECTION http2_pop_connection( void );
    
    
    /* http2_push_connection( PHTTP2_CONNECTION c )
     * 
     * Pushes a connection to be serviced into the
     * 'http2_connection_backlog_queue'.
     * 
     * PARAMETERS:
     *              c - A pointer to an HTTP2_CONNECTION structure.
     * 
     * RETURNS:
     *              1 - The connection has been successfully queued.
     *  
     *              0 - The 'http2_connection_backlog_queue' is full
     *                  and we cannot accept any new connections at
     *                  this time. :(
     * 
     **/
    int http2_push_connection( PHTTP2_CONNECTION c );
    
    
    /* get_default_connection_settings( struct _http2_settings *s )
     * 
     * Used when creating a new HTTP2_CONNECTION object to pass to
     * 'delegate_new_connection()'.  It clones the HTTP2 module's
     * default settings.
     * 
     * Need more documentation!
     *
     */
    void http2_get_default_connection_settings( struct _http2_settings *s );
    
    
    /* http2_remove_thread_from_list( PHTTP2_CONNECTION_THREAD_CONTROL thread )
     * 
     * This function locks the 'http2_active_worker_mutex' mutex and removes the
     * HTTP2_CONNECTION_THREAD_CONTROL referenced by 'thread' from the list of 
     * active worker thread.
     * 
     * PARAMETERS:
     *              thread        - A pointer to a HTTP2_CONNECTION_THREAD_CONTROL
     *                              structure
     * 
     * RETURNS:
     *              HTTP2_SUCCESS - The thread's reference was successfully 
     *                              remove.
     * 
     *              ON ERROR      - Any return value defined by either http2_lock()
     *                              or http2_unlock()
     * 
     **/
    int http2_remove_thread_from_list( PHTTP2_CONNECTION_THREAD_CONTROL thread );
    
    
    /* http2_worker_signal_handler( int signum )
     * 
     * For right now, this is just a function that receives signals sent to the
     * worker threads and returns.  Later, we may have it do something based on the
     * pthread_self() that receives that signal but for now, it just basically keeps
     * the threads' signals from getting forwarded to the main process' thread.
     * 
     **/
    void http2_worker_signal_handler( int signum );
    
    /*! tcp_based_socket_writer( void * )
     * 
     * \brief This thread runs and is responsible for writing all output to clients.
     * 
     * It will maintain a semaphore to be signaled when there is data ready to be 
     * written.  When its semaphore is signaled, it will iterate through all
     * active connections and, if there is output available, send up to 65k out
     * for each connection per iteration.  
     * 
     * If it encounters errors sending data, it can signal the connection to close
     * by changing the connection's status.
     * 
     * I decided not to have the service threads do their own writing because 
     * this way we can, in essence, keep our resources load-balanced.  
     * 
     * The writer will also be responsible for freeing HTTP2_CONNECTION_THREAD_CONTROL
     * structures that have been shutdown.
     * 
     * \param void *
     * 
     * \return NULL
     * 
     * 
     **/
    void *http2_tcp_socket_writer( void * );
    
    
    /*-----------------------------------------------------------------------------------------------------------*/
    
    
    
    
    
    
    /*===== PUBLIC API FUNCTIONS ================================================================================*/
    
    /* http2_init()
     * 
     * Initialized the HTTP/2 library.  Creates
     * mutexes and semaphores.  Creates tables
     * and such.
     * 
     * PARAMETERS:
     *              None.
     * 
     * RETURNS: 
     *              HTTP2_SUCCESS - The HTTP2 module / subsystem has been successfully
     *                              initialized and is ready for use.
     * 
     *              HTTP2_ERROR_INVALID_INITIAL_THREAD_COUNT
     * 
     *              HTTP2_ERROR_NO_MEMORY
     * 
     *              HTTP2_ERROR_MUTEX_FAILED
     * 
     *              HTTP2_ERROR_FAILED_TO_CREATE_THREAD_POOL
     * 
     **/
    int         http2_init( void ); 
    
    
    /* create_http2_connection_thread( PHTTP2_CONNECTION_THREAD_CONTROL *control )
     * 
     * Creates a new 'http2_connection_thread' and adds a pointer to its
     * HTTP2_CONNECTION_THREAD_CONTROL structure to the list of active worker
     * threads.
     * 
     * PARAMETERS:
     *              None
     * 
     * RETURNS:     
     *              A pointer to a new HTTP2_CONNECTION_THREAD_CONTROL structure
     *              that has been inserted into the 'http2_connection_thread_list'
     *              array. When this function returns, the worker is guaranteed
     *              to be ready to serve connections.
     * 
     *              HTTP2_ERROR_MAX_WORKER_THREADS - The maximum number of worker threads
     *                                               has been reached and no new workers can
     *                                               be created right now, or the memory
     *                                               required to launch the worker cannot be
     *                                               allocated.
     * 
     * 
     **/
    PHTTP2_CONNECTION_THREAD_CONTROL
                create_http2_connection_thread( void );
    
    
    /* retire_http2_connection_thread( PHTTP2_CONNECTION_THREAD_CONTROL *control )
     * 
     * This function shuts down and de-allocates all resources associated with
     * an 'http2_connection_thread' - releasing resources back to the OS.
     * 
     * 
     * PARAMETERS:
     *              control     - A pointer to an HTTP2_CONNECTION_THREAD_CONTROL
     *                            structure representing an 'http2_connection_thread'
     *                            instance.
     * 
     * RETURNS:
     * 
     *              HTTP2_SUCCESS - The worker was successfully shut down and is
     *                              guaranteed to have been removed from the array
     *                              running workers.
     * 
     *              HTTP2_OK      - The thread was told to shut down but did not
     *                              shut down in a timely manner.  It will probably
     *                              still shut down on its own, but no confirmation
     *                              was provided.  It is still taking up space in
     *                              the list of workers albeit it's not showing
     *                              that it's available for work...
     *
     */
    int         retire_http2_connection_thread( PHTTP2_CONNECTION_THREAD_CONTROL control );
    
    
    /* schedule_http2_connection_destruction( PHTTP2_CONNECTION_THREAD_CONTROL *control )
     * 
     * Tells the thread to die on its own.  Probably because it was busy.  This will tell
     * it to shut itself down and return.  We should build in some oversight to assure that
     * it's shut itself down properly.
     * 
     * 
     **/
    int         schedule_http2_connection_destruction( PHTTP2_CONNECTION_THREAD_CONTROL control );
    
    /* delegate_new_connection( PHTTP2_CONNECTION c )
     * 
     * Called by the listener() thread in 'connection_manager.c' to assign
     * the new HTTP2 connection to a 'http2_connection_thread' to be serviced.
     * 
     * If there are no threads available to process the connection, this function
     * calls 'create_http2_connection_thread()' which tries to create a new 
     * 'http2_connection_thread' if the new quantity of worker threads doesn't 
     * exceed HTTP2_MODULE_SETTINGS.max_connection_threads.
     * 
     * If it fails to create a new worker thread, it will use http2_push_connection()
     * to try to queue the connection to be serviced when a worker becomes available.
     * 
     * If it fails to both create a new worker thread, AND fails to queue the connection
     * for service, it will fail and listener() will have to deal with the connection
     * somehow (probably by closing the connection).
     * 
     * PARAMETERS:
     *              c       - A pointer to an HTTP2_CONNECTION structure.
     * 
     * RETURNS:
     * 
     *              HTTP2_SUCCESS                         - Success
     * 
     *              HTTP2_CONNECTION_QUEUED               - All worker threads are busy
     *                                                      but the connection will be serviced
     *                                                      when a worker becomes available.
     * 
     *              HTTP2_ERROR_CANNOT_SERVICE_CONNECTION - All resources are busy and 
     *                                                      the connection cannot be serviced.
     * 
     * 
     **/
    int         delegate_new_connection( PHTTP2_CONNECTION c ); 
    
    
    /* http2_connection_thread( void *p )
     * 
     * This is the thread function that serves connections assigned to it.
     * 
     * 
     * PARAMETERS:
     *              p       - A pointer (cast as void *) to an
     *                        HTTP2_CONNECTION_THREAD_CONTROL structure that 
     *                        the thread uses to accept commands and
     *                        receive information about the connections it should
     *                        serve
     * 
     * RETURNS:
     *              0 when the thread terminates.
     * 
     **/
    void        *http2_connection_thread( void *p );
    
    /* http2_shutdown_all( void )
     * 
     * Starts by locking the 'http2_active_worker_mutex'.  Then goes through
     * each worker thread and calls retire_http2_connection_thread().  If the retirement
     * fails, then it calls schedule_http2_connection_destruction() on the
     * misbehaving thread. (Which removes all its global references and basically sets it
     * on its own.
     * 
     * 
     * NEED TO DO THIS so it can be called from 'connection_manager.'
     * 
     **/
    void        http2_shutdown_all( void );
    
    /*!
     * \breif Removes bytes that have been processed from the top of a buffer.
     * 
     * \param c           - A pointer to the HTTP2_CONNECTION structure.
     * \param octet_count - The number of octets processed.
     * 
     * \return Nothing.
     * 
     **/
    void        http2_buffer_evict_octets( PHTTP2_CONNECTION c, size_t octet_count);
    
    /*===========================================================================================================*/

#ifdef __cplusplus
}
#endif

#endif /* HTTP2_HEADER_H */

