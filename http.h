/* (c) 2019 Justin Jack - MIT License */
/* 
 * File:   http.h
 * Author: justinjack
 *
 * Created on May 9, 2019, 7:25 PM
 */

#ifndef HTTP_H
#define HTTP_H

#include "jstring.h"
#include "db_x_platform.h"
#include <pthread.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <sys/time.h>
#include <signal.h>
#include <pthread.h>
#include <semaphore.h>

/* To dictate how many HTTP_SERVER threads will be running you can:
 * 
 * A. Leave it at the default of 10.  As soon as an HTTP object is created,
 *    if there is no HTTP_SERVER instance running, one will come online with
 *    the default quantity of 10
 * 
 * B. Start up the server with a pre-determined number from settings or elsewhere.
 * 
 *      1. #define HTTP_DEFAULT_SERVER_THREADS xxx
 * 
 *      2. Specify the following in you application code:
 *          i. HTTP_SERVER_THREADS = xxxx;
 *         ii. HTTP_SERVER::START_SERVER();
 * 
 *      3. Start the server explicitly using: HTTP_SERVER::START_SERVER(xxxx);
 * 
 **/

class LISTENER; /* Defined in settings.h */

#define HTTP_LOWER(x) ((x>='A' && x <= 'Z')?(x+32):x)
#define HTTP_UPPER(x) ((x>='a' && x <= 'z')?(x-32):x)

typedef struct _http2_frame {
    unsigned int length;
    unsigned char type;
    unsigned char flags;
    char reserved;
    unsigned long stream_identifier;
    char payload;
} HTTP2_FRAME, *PHTTP2_FRAME;

typedef class _http_string HTTP_STRING, *PHTTP_STRING;

class HTTP;
class HTTP_SERVER;
struct _http_server_thread;
typedef struct _http_server_thread HTTP_SERVER_THREAD, *PHTTP_SERVER_THREAD;

typedef struct _http_hdrl_ {
    PHTTP_STRING name, value;
} HTTP_HEADER, *PHTTP_HEADER;

typedef enum _protocol_mask {
    RAW_APP_LAYER    = 0x00, /* To forward all data to the handler callback */
    HTTP10           = 0x01,
    HTTP11           = 0x02,
    WEBSOCKET        = 0x04,
    HTTP11_WEBSOCKET = 0x06,  /* Includes HTTP1_1 */
    HTTP12           = 0x08,
    HTTP12_WEBSOCKET = 0x0C,  /* Includes HTTP1_2 */
    HTTP20           = 0x20,
    HTTP20_WEBSOCKET = 0x24,  /* Includes HTTP2_0 */
    HTTP30           = 0x80,
    HTTP30_WEBSOCKET = 0x84,  /* Includes HTTP3_0 */
} PROTOCOL_MASK;

typedef enum _protocol_id {
    HTTP1_0,
    HTTP1_1,
    HTTP1_2,
    HTTP2_0,
    HTTP3_0,
    WEBSOCKET_ID,
} PROTOCOL_ID;

/*
 * Be sure to change this when we add new protocols!
 * 
 * Leave WEBSOCKET_ID last, because we don't count it when
 * trying to figure out HTTP protocol versions!
 * 
 **/
#define HTTP_PROTOCOL_VERSION_COUNT 5

static const struct _protocol_versions {
	PROTOCOL_ID id;
        const char *alpn;
        const char *on_wire;
        int bitmask;
} PROTOCOL_VERSION[] = {
	{ HTTP1_0,      "http/1.0", "HTTP/1.0",  0x01},
	{ HTTP1_1,      "http/1.1", "HTTP/1.1",  0x02},
	{ HTTP1_2,      "http/1.2", "HTTP/1.2",  0x08},
	{ HTTP2_0,      "h2",       "HTTP/2.0",  0x20},
	{ HTTP3_0,      "h3",       "HTTP/3.0",  0x80},
	{ WEBSOCKET_ID, "",         "",          0x04},
};

#define HTTP_WAIT( condition, ms_timeout ) if (!(condition)) {\
                                    int __waiter__ = 0;\
                                    for (; __waiter__ < ms_timeout; __waiter__++) {\
                                        if (condition) break;\
                                        usleep(1000);\
                                    }\
                                } if (condition)



/* HTTP Methods bitwise */
#define HTTP_GET_BIT            0x00
#define HTTP_HEAD_BIT           0x01
#define HTTP_POST_BIT           0x02
#define HTTP_PUT_BIT            0x04
#define HTTP_DELETE_BIT         0x08
#define HTTP_CONNECT_BIT        0x10
#define HTTP_OPTIONS_BIT        0x20
#define HTTP_TRACE_BIT          0x40




#define HTTP_ERROR_INVALID_MUTEX                               -7
#define HTTP_ERROR_NOT_OWNED                                   -6
#define HTTP_ERROR_NO_MEMORY                                   -5
#define HTTP_ERROR_MUTEX_FAILED                                -3
#define HTTP_INVALID_ARG                                       -2
#define HTTP_INVALID_MUTEX                                      0
#define HTTP_OK                                                 0
#define HTTP_SUCCESS                                            1
#define HTTP_MUTEX_ALREADY_OWNED                                2

/* Enumerated Methods */
#define HTTP_GET            0
#define HTTP_HEAD           1
#define HTTP_POST           2
#define HTTP_PUT            3
#define HTTP_DELETE         4
#define HTTP_CONNECT        5
#define HTTP_OPTIONS        6
#define HTTP_TRACE          7

#define IDEMPOTENT_SAFE (HTTP_OPTIONS_BIT|HTTP_GET_BIT|HTTP_HEAD_BIT|HTTP_TRACE_BIT)
#define IDEMPOTENT      (HTTP_OPTIONS_BIT|HTTP_GET_BIT|HTTP_HEAD_BIT|HTTP_TRACE_BIT|HTTP_PUT_BIT|HTTP_DELETE_BIT)
#define NON_IDEMPOTENT  (HTTP_POST_BIT|HTTP_CONNECT_BIT)
#define ALL_METHODS     (HTTP_TRACE_BIT|HTTP_OPTIONS_BIT|HTTP_CONNECT_BIT|HTTP_DELETE_BIT|HTTP_PUT_BIT|HTTP_POST_BIT|HTTP_HEAD_BIT|HTTP_GET_BIT)
#define METHODS_NONE    0

static const char *HTTP_METHODS[] = {
    "GET",
    "HEAD",
    "POST",
    "PUT",
    "DELETE",
    "CONNECT",
    "OPTIONS",
    "TRACE"};

#define HTTP_METHOD_NAME(x) HTTP_METHODS[x]

#define HTTP_METHOD_COUNT (sizeof(HTTP_METHODS) / sizeof(char *))

class _http_string {
    private:
        char        *ptr;
        size_t      size;                                  /* The allocated size of the buffer */
        size_t      len;                                   /* The effective length of the string in the buffer. */
        void        init( size_t init_bytes );
    public:
        ~_http_string();
        _http_string( size_t init_bytes);
        _http_string( void );
        /* For concatenating to the existing value */
        size_t      concat( const char *ptr, size_t len );
        size_t      concat( const char *ptr );
        size_t      concat( char *ptr, size_t len );
        size_t      concat( char *ptr );
        
        /* Clear out the string */
        void        clear( void );
        
        /* Get a pointer to the string */
        char        *val( void );
        
        /* Duplicate the string into an upper-case buffer */
        char        *to_upper( void );
        
        size_t      get( char * );
        
        
        /* Get the length of the string */
        size_t      length( void );
        
        /* ::contains() returns ONE if the text (case-insensitive) is contained
         * in the value, or ZERO if it isn't
         **/
        int         contains( const char *search );
        int         contains( char *search );
        int         contains( const char *search, size_t len);
        int         contains( char *search, size_t len );
        
        virtual int set(const char *val, size_t len);
        virtual int set(char *val, size_t len);
        virtual int set(const char *val);
        virtual int set(char *val);
    
        
        int         set_lower(const char *val, size_t len);
        int         set_lower(char *val, size_t len);
        int         set_lower(const char *val);
        int         set_lower(char *val);
        
        
        int         equals(const char *e, size_t len);
        int         equals(const char *e);
        int         equals(char *e, size_t len);
        int         equals(char *e);
        
};

typedef class _http_header_list {
    private:
        PHTTP_HEADER        header_list;
        size_t              header_list_size;
        size_t              header_list_length;
        HTTP_STRING         empty_header;
        size_t              req_buffer_size;
        int                 end_headers;
    public:
        _http_header_list();
        ~_http_header_list();
        
        
        /*!
         *  \brief This should be called when the header list is complete.
         * 
         * This function marks the header list as complete.  It should be called
         * after (in HTTP/1.x) the first BLANK line i.e. "\\r\\n" is received.
         * 
         * In HTTP/2, it should be called when the END_HEADERS flag is received
         * in a frame.
         * 
         * This function will automatically be called if 'add_header()' is called
         * with a blank line.
         * 
         * \param Set to a positive integer if the header list has been fully received, or
         *        ZERO, if it is not complete.  The default value is ZERO.
         * 
         * \return None
         * 
         **/
        void                complete( int );
        /*!
         *  \brief This function will let you know if the header list is complete
         * 
         * 
         * \param None
         * 
         * \return Returns ONE if the header list is complete, and ZERO if it's not
         *         yet complete.
         * 
         **/
        int                 complete( void );
        
        int                 add_header( char *name, char *value );
        int                 add_header( char *name, size_t name_len, char *value, size_t value_len );
        int                 add_header( const char *name, const char *value );
        int                 add_header( const char *name, size_t name_len, const char *value, size_t value_len );
        
        int                 add_header_line( const char *line, size_t length);
        int                 add_header_line( char *line, size_t length);
        int                 add_header_line( const char *line);
        int                 add_header_line( char *line);
        
        
        PHTTP_HEADER        get( char *header_name );
        PHTTP_HEADER        get( char *header_name, size_t len );
        PHTTP_HEADER        get( const char *header_name );
        PHTTP_HEADER        get( const char *header_name, size_t len );
        
        /*!
         * \brief This function populates an output buffer with a '\\r\\n' delimited string representation of the header list.
         * 
         * Although 'output_buffer' cannot be NULL, it CAN point to a pointer that is NULL.  In this case, when ::get_header_list
         * returns (if it is successful), it will contain a pointer that was allocated by this function.  That pointer must be
         * freed by the application.
         * 
         * 
         * \param output_buffer       - A pointer to a 'char *' pointer into which
         *                              the resulting string will be placed.  The pointer
         *                              whose address you pass MUST have been dynamically
         *                              allocated on the heap because 'get_header_list' might
         *                              resize the buffer if it needs to be large.  The resulting
         *                              pointer (pointed at by 'output_buffer') must be freed
         *                              by the application.
         * 
         * \param buffer_size         - The size (in bytes) that are already allocated to hold
         *                              the header string.
         * 
         * \return size_t             - The size in bytes of the header list (not including the NULL
         *                              terminating character.
         * 
         **/
        size_t              get_header_list( char **output_buffer, size_t buffer_size);
        
        HTTP                *http_parent;
        
    
    
} HTTP_HEADER_LIST, *PHTTP_HEADER_LIST;

#ifndef HTTP_DEFAULT_SERVER_THREADS
static int HTTP_SERVER_THREADS = 10;
#else
static int HTTP_SERVER_THREADS = HTTP_DEFAULT_SERVER_THREADS;
#endif


static HTTP_SERVER *phttp_server = 0;



typedef struct _http_mutex {
    int             mutex_valid; /*
                                  * If the mutex is valid, this will be set to 
                                  * ONE and can be locked.
                                  * 
                                  * If the mutex is being destoryed, this will
                                  * be ZERO, and it cannot be locked.
                                  * 
                                  **/ 
    
    pthread_t       current_owner;/*
                                   * The thread that has acquired the lock on
                                   * this mutex.
                                   **/
    
    int             lock_count;   /*
                                   * The lock count for the current thread
                                   * owner.
                                   **/
    
    pthread_mutex_t mutex;        /*
                                   * The mutex object.
                                   **/
} HTTP_MUTEX, *PHTTP_MUTEX;



class HTTP_SETTINGS {
    public:
        HTTP_STRING     document_root;
};


typedef struct _http_server_interface {
    
    pthread_t           owner;              /* The thread identifier of the thread that created this
                                             * HTTP object.  This is so we can send it a SIGUSR2 signal
                                             * so that it can process the response to this request when 
                                             * it's done being processed.
                                             **/
    
    PHTTP_MUTEX         pmutex;             /* The mutex that syncs communication between
                                             * the HTTP object and the HTTP_SERVER thread that's
                                             * processing its request.  This is necessarry because this
                                             * HTTP object can be freed by either:
                                             *      1. The http2_connection_thread() that initialized the
                                             *         HTTP object if the request is successfully processed
                                             * 
                                             *      2. The server() thread that is actually processing the
                                             *         request if the HTTP request is marked as dead because 
                                             *         the underlying connection or stream that initiated the
                                             *         HTTP request has encountered an error and shut down
                                             *         the connection or stream thus stranding the request.
                                             **/
    
    int                 request_processed;  /* Will be set to ONE when the HTTP_SERVER thread is done processing
                                             * this HTTP request.
                                             **/
    
    HTTP_SERVER_THREAD  *pserver_thread;    /*
                                             * A pointer to information about the HTTP_SERVER thread that is
                                             * processing this request.
                                             * 
                                             **/
    
    HTTP                *presponse;         /* Initially set to ZERO, the HTTP_SERVER thread will populate this
                                             * with a pointer to the HTTP response object that needs to be
                                             * served.
                                             **/
    
    int                 connection_valid;   /*
                                             * The underlying connection or stream responsible for this request
                                             * will set this to ZERO if this request has been stranded and it has
                                             * moved on or entered an idle state due to a connection/protocol error.
                                             * 
                                             * In this case, the HTTP_SERVER thread will be responsible for freeing this HTTP request.
                                             **/
} HTTP_S_INTERFACE, *PHTTP_S_INTERFACE;

class HTTP {
private:
    
    int                 is_request;         /* 1 = This is a REQUEST.
                                             * 
                                             * 0 = This is a RESPONSE.
                                             * 
                                             **/
    
    HTTP_S_INTERFACE    service;            /*
                                             * A pointer to the data structure that the HTTP_SERVER thread will
                                             * use.
                                             **/
    
    size_t              lines_parsed;       /*
                                             * An internal tracker to keep track of
                                             * the number of '\\r\\n' lines we've
                                             * received via '::parse_line()'
                                             **/
public:
    HTTP( LISTENER * );
    ~HTTP();
    int                 status_code;
    int                 authenticated;
    HTTP_STRING         method;
    HTTP_STRING         http_version;
    PROTOCOL_ID         ihttp_version;
    HTTP_STRING         cookies;
    HTTP_STRING         path;
    HTTP_STRING         filename;
    HTTP_STRING         query_string;
    size_t              content_length;
    HTTP_STRING         body;
    HTTP_HEADER_LIST    headers;
    LISTENER            *plistener;
    
    
    /* Methods */
    int                 is_complete( void );
    
    int                 parse_line( const char *line, size_t length);
    int                 parse_line(       char *line, size_t length);
    int                 parse_line( const char *line );
    int                 parse_line(       char *line );
    
    /*!
     * \brief This method will look at the top of a buffer and see if it contains the beginning of an HTTP/1.x message.
     * 
     * If there is an indication that there is a new HTTP request, it
     * will return the offset in bytes of the start of the new message and the application can create 
     * a new HTTP object and start calling
     * '::pull_http()' with that buffer's info to start parsing the HTTP message.
     * 
     * \param buffer        - A pointer to a buffer to check for HTTP
     * \param length        - The number of bytes in the buffer to check.
     * 
     * \return 1            - There is the start of an HTTP message.  We should create a new
     *                        HTTP object and call '::pull_http()' with the same info passed
     *                        to '::check_buffer()' and keep calling '::pull_http()' until
     *                        '::is_complete()' returns TRUE
     * \return 0            - There is no beginning of an HTTP message at the start of this
     *                        buffer.
     * 
     **/
    static int          check_buffer( const char *buffer, size_t length);
    
    /*!
     * \brief Buffer HTTP off of the stream, or parse it as it comes in.
     * 
     * \return The number of HTTP bytes processed.
     * 
     **/
    int                 buffer_http( const char *buffer, size_t bytes);
    
    /*!
     * \brief This function can be called to initiate processing of this HTTP request.
     *        This function will only succeed if the COMPLETE message has been received
     *        i.e. a call to 'HTTP::is_complete()' returns ONE.
     * 
     *        If processing has already been started, it will still return TRUE.
     * 
     * \param None
     * 
     * \return On success, or if the request is ALREADY processing, it will
     *         return ONE.
     * 
     * \return On failure, it will return ZERO.
     * 
     * 
     **/
    int                 process_request( void );
    
    /*!
     * \brief       This function returns a pointer to a buffer containing the HTTP response.
     * 
     * \param       None
     * 
     * \return      On Success it returns a pointer to the HTTP response object.
     * \return      On Failure or if the response isn't done processing, it returns ZERO.
     **/
    HTTP                *response( void ); /* Returns a buffer containing the HTTP response to this request */
    
    int                 abort_connection( void ); /*!
                                                   * \brief Marks the HTTP object as orphaned.  The underlying connection or 
                                                   *        stream has been terminated.
                                                   * 
                                                   * /param Nothing
                                                   * 
                                                   * /return 1 - The calling thread should call "delete" on this object.
                                                   * 
                                                   * /return 0 - The thread will be deleted by the HTTP_SERVER processing
                                                   *             thread and the calling thread should NOT call delete on this
                                                   *             HTTP object.
                                                   * 
                                                   **/

    int                 is_processing(void);       /* Returns 1 if this has been processed, or ZERO if not */
    

    
}; /* End BASE_HTTP() */


struct _http_server_thread {
    public:
        pthread_t               thread_id;
        time_t                  last_used;
        sem_t                   new_http_available;
        int                     available;
        int                     alive;
        int                     okay_to_run;
        HTTP                    *http_to_process;
        int                     fundamental;
        
        /**********/
        HTTP_S_INTERFACE        *pservice_interface;
};

class HTTP_SERVER {
    private:
        PHTTP_SERVER_THREAD pthreads;               /* An array of HTTP_SERVER_THREAD objects 
                                                     *
                                                     **/
        
        size_t              thread_size;            /*
                                                     * The number of pointers allocated in pthreads
                                                     **/
        
        PHTTP_MUTEX         thread_mutex;           /*
                                                     * Mutex protecting HTTP worker thread list.
                                                     **/
        
        HTTP_SERVER_THREAD  *start_thread( void );  /*
                                                     * Launches a new HTTP worker thread.  Returns a pointer to
                                                     * its HTTP_SERVER_THREAD structure in case you want to assign
                                                     * it a job.
                                                     **/
        
    public:
        HTTP_SERVER();
        ~HTTP_SERVER();
        
        static void             START_SERVER( void );
        static void             START_SERVER( int initial_server_threads );
        
        /*
         * Static function that processes HTTP messages.
         **/
        static void             *server( void * );
        
        int                     get_thread_count( void );
        
        /*
         * Add the HTTP object and pointers
         * to its private variables so the worker can
         * set the private info.
         **/
        int                     add_job( HTTP *http_to_process, PHTTP_S_INTERFACE server_interface );
        
};




class IP_ADDRESS: public HTTP_STRING {
private:
    uint32_t net_range;
    union {
        uint32_t ipv4_addr;
        uint8_t  ipv4_char[4];
    } ipv4_address, ipv4_mask;
    union {
        uint8_t  ipv6_8[16];
        uint16_t ipv6_16[8];
        uint32_t ipv6_32[4];
        uint64_t ipv6_64[2];
    } ipv6_address, ipv6_mask;
public:
    int version;
    IP_ADDRESS() {
        this->ipv4_address.ipv4_addr    = 0;
        this->ipv4_mask.ipv4_addr       = 0;
        this->ipv6_address.ipv6_64[0]   = 0;
        this->ipv6_address.ipv6_64[1]   = 0;
        this->ipv6_mask.ipv6_64[0]      = 0;
        this->ipv6_mask.ipv6_64[1]      = 0;
        this->net_range = -1;
        this->version = 0;
    }
    IP_ADDRESS( const char *ptr, size_t len ) {
        this->set(ptr, len);
        this->parse_addr(ptr, len);
    };
    IP_ADDRESS( const char *ptr ) {
        this->set(ptr);
        this->parse_addr(ptr, strlen(ptr));
    };
    /*
     * This construction method is for creating an IP_ADDRESS object
     * from a "struct in_addr" or "struct in_addr6" structure, or any
     * other memory buffer that stores an IP address in binary format.
     *
     * Just be sure to set "ip_version", correctly!
     *
     * \param binary_pointer            - A pointer to the buffer containing
     *                                    the binary IP address information
     *
     * \param ip_version                - The IP version.  This is how this
     *                                    function decides how far into the
     *                                    buffer pointer to by "binary_pointer"
     *                                    to read!
     **/
    IP_ADDRESS( void *binary_pointer, int ip_version );
    
    IP_ADDRESS( uint32_t ipaddr32_bit );

    int set( const char *ptr, size_t len ) {
        HTTP_STRING::set(ptr, len);
        this->parse_addr(ptr, len);
    }
    int set( const char *ptr ) {
        HTTP_STRING::set(ptr);
        this->parse_addr(ptr, strlen(ptr));
    }
    int set( char *ptr, size_t len ) {
        HTTP_STRING::set(ptr, len);
        this->parse_addr(ptr, len);
    }
    int set( char *ptr ) {
        HTTP_STRING::set(ptr);
        this->parse_addr(ptr, strlen(ptr));
    }

    /*
     * Call automatically whenever an IP address is detected.  You can 
     * also call it manually if for some reason you initialized the
     * object with nothing or a partial IP address and completed it.
     * 
     */
    void parse_addr( const char *ptr, size_t len);
    
    uint32_t to_unsigned_long(void) {
        return this->ipv4_address.ipv4_addr;
    }
    /*
     * Returns a pointer the can be used for networking
     * functions.
     */
    void *to_pointer( void ) {
        if (this->version == 4) {
            return this->ipv4_address.ipv4_char;
        } else {
            return this->ipv6_address.ipv6_64;
        }
    }
    /*
     * Returns the string representation of the IP address
     */
    int copy_into( void *ptr ) {
        if (this->version == 4) {
            *((uint32_t *)ptr) = this->ipv4_address.ipv4_addr;
        } else {
            memcpy(ptr, this->ipv6_address.ipv6_8, 16);
        }
    }
    
    int set_ipv4( uint32_t ipv4_address) {
        this->version = 4;
        this->ipv4_address.ipv4_addr = ipv4_address;
        HTTP_STRING::set(this->ip_string());
    }
    
    int set_ipv6( void *pmem ) {
        memcpy(this->ipv6_address.ipv6_8, pmem, 16);
        HTTP_STRING::set(this->ip_string());
    }
    
    const char *ip_string( void );
    
    
};

    
void http_server_thread_signal_handler( int signum );


/* http_new_mutex( int lock_now )
 * 
 * This function create a new HTTP_MUTEX locking/synchronization 
 * object.
 * 
 * PARAMETERS:
 *              lock_now - Set to NON-ZERO if the calling thread
 *                         should immediately obtain a lock on the
 *                         newly created object.
 * 
 *                         Set to ZERO if the newly created object
 *                         should be initialized in an unlocked
 *                         state.
 * 
 * RETURNS:
 *              On success, this function will return a pointer to a 
 *              newly created HTTP_MUTEX object.
 * 
 *              HTTP2_INVALID_MUTEX - The mutex object could not be created.
 *                                    Possibly due to not having enough memory,
 *                                    or due to another (unspecified) error.
 * 
 **/
PHTTP_MUTEX http_new_mutex( int lock_now );



/* http_retire_mutex( PHTTP_MUTEX m )
 * 
 * Retires an HTTP_MUTEX object.
 * 
 * First this function acquires a lock on the mutex to destroy. This
 * function WILL WAIT to to acquire the lock.  It calls http_lock().
 * 
 * When the lock is acquired, it marks the mutex as no longer valid so
 * no other threads can lock it.  It then unlocks the mutex and unregisters
 * its underlying components with the operating system.
 * 
 * If a program tries to call http_lock() on an HTTP_MUTEX object that
 * has been retired, it will receive 'HTTP2_ERROR_INVALID_MUTEX'.
 * 
 * It does NOT free the memory associated with the mutex so that if any
 * other threads hold a reference to the mutex, they will simply not
 * be able to lock it, but they will not crash the program by trying
 * to access freed memory.
 * 
 * PARAMETERS:
 *              m - A reference to an HTTP_MUTEX object to be destroyed
 * 
 * RETURNS:
 *              HTTP2_SUCCESS               - Success.  The mutex has been retired.
 * 
 *              HTTP2_INVALID_ARG           - The 'm' parameter was NULL.
 * 
 *              HTTP2_ERROR_INVALID_MUTEX   - http_retire_mutex() is being called on
 *                                            a mutex that has already been retired.
 * 
 *              HTTP2_ERROR_MUTEX_FAILED    - There is something wrong with the mutex. Its
 *                                            state is indeterminate. This error could have 
 *                                            been raised during http_retire_mutex()'s
 *                                            attempt to lock the mutex, or during its
 *                                            subsequent attempt to retire it.  This 
 *                                            mutex should no longer be used.
 * 
 **/
int http_retire_mutex( PHTTP_MUTEX m );



/* http_free_mutex( PHTTP_MUTEX m )
 * 
 * This function frees the memory associated with the HTTP_MUTEX
 * object referenced by the parameter 'm'.
 * 
 * If the mutex object is still valid, it calls http_retire_mutex()
 * first before freeing the memory associated with it.
 * 
 * If any other threads hold a reference to this mutex and try to
 * access it the behavior is unspecified and may cause the program
 * to crash.
 * 
 * PARAMETERS:
 *              m                           - The 'm' parameter was NULL
 * 
 * RETURNS:
 * 
 *              HTTP2_SUCCESS               - Success.  The mutex was destroyed (if it had
 *                                            not already been) and freed.  The memory
 *                                            allocated for the HTTP_MUTEX structure has
 *                                            been released.
 * 
 *              HTTP2_INVALID_ARG           - 'm' was NULL
 * 
 *              HTTP2_ERROR_MUTEX_FAILED    - An internal call to http_retire_mutex()
 *                                            failed and the mutex could not be freed.
 *                                            The memory, therefore associated with the
 *                                            HTTP_MUTEX structure is still allocated.
 * 
 *              HTTP2_ERROR_INVALID_MUTEX   - The mutex passed as the argument 'm' is not
 *                                            valid.  It may have been destroyed by a call
 *                                            to http_retire_mutex()
 * 
 **/
int http_free_mutex( PHTTP_MUTEX m );



/* http_lock( PHTTP_MUTEX m)
 * 
 * Locks a protected resource for exclusive access.
 * 
 * PARAMETERS:
 *                  m       - A pointer to an HTTP_MUTEX object created
 *                            with http_new_mutex()
 * 
 * RETURNS:         ( A positive value on success )
 * 
 *                  HTTP2_SUCCESS               - The calling thread now owns the mutex and 
 *                                                has exclusive access to the protected resource
 * 
 *                  HTTP_MUTEX_ALREADY_OWNED   - This is SUCCESS, but be advised that
 *                                                the calling thread ALREADY owns the mutex and
 *                                                has exclusive access to the protected resource.
 * 
 *                  HTTP2_INVALID_ARG           - The argument 'm' was NULL
 * 
 *                  HTTP2_ERROR_INVALID_MUTEX   - The mutex passed as the argument 'm' is not
 *                                                valid.  It may have been destroyed by a call
 *                                                to http_destroy_mutex()
 * 
 *                  HTTP2_ERROR_MUTEX_FAILED    - An unspecified error occured and you should not
 *                                                assume that you have exclusive access to the
 *                                                resource protected by the mutex 'm'
 * 
 **/
int http_lock( PHTTP_MUTEX m);


/* http_unlock( PHTTP_MUTEX m)
 * 
 * Unlocks a protected resource allowing other threads to obtain a lock
 * by calling http_lock()
 * 
 * PARAMETERS:
 *              m       - A pointer to an HTTP_MUTEX object created with
 *                        http_new_mutex()
 * 
 * RETURNS:
 * 
 *              HTTP2_SUCCESS               - The mutex was successfully unlocked.
 * 
 *              HTTP2_INVALID_ARG           - 'm' was NULL
 * 
 *              HTTP2_ERROR_NOT_OWNED       - Another thread has a lock
 *                                            on the specified mutex.
 * 
 *              HTTP2_ERROR_MUTEX_FAILED    - An unspecified error occured and
 *                                            the mutex could not be unlocked.
 * 
 **/
int http_unlock( PHTTP_MUTEX m);




#endif /* HTTP_H */

