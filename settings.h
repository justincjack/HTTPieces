/* 
 * File:   settings.h
 * Author: justinjack
 *
 * Created on July 10, 2019, 9:41 AM
 * 
 * 
 * NOTES!
 * 
 * We need to make this also take into account their OS permissions.  So
 * it can be configured as follows:
 * 
 * 1.   Allow file system permissions ONLY. e.g. "john" owns "/var/www/johns_dir"
 *      and all the files in it.  Regardless of the other settings, he can GET, POST,
 *      PUT, DELETE files to his directory with no problem.  If he has a READONLY file
 *      in there, then even after he authenticates with his UNIX password, he can't
 *      DELETE that file.
 * 
 *      Questions:
 * 
 *      Should we allow him to execute CGI files based on their executable mode?
 * 
 * 2.   Use the SETTINGS configuration, but allow the file system permissions 
 *      to override them.
 * 
 * 3.   Make the SETTINGS authoritative and have THEM override the file system
 *      permissions...
 * 
 * 
 * But for now, I'm beginning it this way.  Other contributors would be great to
 * speed things along!
 * 
 * 
 */

#ifndef SETTINGS_H
#define SETTINGS_H

#include <stdint.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include "http.h"
#include "debug.h"
#include "cgi.h"

/** Forward Decs ******************************************************************/
class SETTINGS;
class GENERAL;
class SETTINGS_PERMISSIONS;
class SETTINGS_DIRECTORY;
class SETTINGS_FILE;
class LISTENER;
class DELEGATE;
/**********************************************************************************/

#define SETTINGS_INVALID_KEYFILE                            -5
#define SETTINGS_INVALID_CERTFILE                           -4
#define SETTINGS_INVALID_CHAINFILE                          -3
#define SETTINGS_NO_CERTIFICATES                            -3
#define SETTINGS_OUT_OF_MEMORY                              -2
#define SETTINGS_FILE_NOT_FOUND                             -1
#define SETTINGS_NO_ERROR                                    0



/* TLS version bits */
#define TLSv12                                               0x01
#define TLSv13                                               0x02

static const struct _tls_map {
    const char *version;
    int TLS_VERSION;
        
} TLS_MAP[] = {
        {"TLSv1.2",  TLS1_2_VERSION},
        {"TLSv1.3",  TLS1_3_VERSION},
        {"DTLSv1",   DTLS1_VERSION},
        {"DTLSv1.2", DTLS1_2_VERSION},
        {0, 0},
};

#define AUTH_TRUE(char_ptr) (JSTRING::matches((char *)char_ptr, "true") ||\
                             JSTRING::matches((char *)char_ptr,  "yes") ||\
                             JSTRING::matches((char *)char_ptr,    "1"))\

#define AUTH_FALSE(char_ptr) (JSTRING::matches((char *)char_ptr, "false") ||\
                              JSTRING::matches((char *)char_ptr,    "no") ||\
                              JSTRING::matches((char *)char_ptr,     "0"))\

typedef enum _settings_context_ {
    SC_UNDEFINED = -1,
    SC_GENERAL,
    SC_LISTENER,
    SC_DIRECTORY,
    SC_FILE,
    SC_DELEGATE,
    SC_CGI,
} SETTINGS_CONTEXT;


typedef enum _auth_type {
    AUTH_OPEN,
    AUTH_USER_PASS,
    AUTH_USER_PASS_DIGEST,
    AUTH_UNIX,
} AUTH_TYPE;


class CERTIFICATE_NAMES {
    public:
    HTTP_STRING tls_chain_file;
    HTTP_STRING tls_key_file;
    HTTP_STRING tls_crt_file;
};

typedef class _cert_info : protected CERTIFICATE_NAMES {
    private:
        int key_valid;
        int chain_valid;
        int cert_valid;
        void check_tls_validity();
    public:
        _cert_info() {
            this->cert_valid = 0;
            this->key_valid = 0;
            this->chain_valid = 0;
            this->error = SETTINGS_NO_CERTIFICATES;
        }
        int error;
        int cert_okay();
        int set_chain_file( char *chain_file );
        int set_cert_file( char *cert_file );
        int set_key_file( char *key_file );
        int set_chain_file( char *chain_file, size_t len );
        int set_cert_file( char *cert_file, size_t len);
        int set_key_file( char *key_file, size_t len);
        char *chain_file_name(void);
        char *cert_file_name(void);
        char *key_file_name(void);
} CERTIFICATE_INFO, *PCERTIFICATE_INFO;



typedef enum _listener_type {
    LT_TCP,                         /* Instructs the listener to use TCP (no TLS)        */
    LT_UDP,                         /* Instructs the listener to use UDP (no encryption) */
    LT_TLS,                         /* Instructs the listener to use TLS                 */
    LT_DTLS,                        /* Instructs the listener to use DTLS                */
} LISTENER_TYPE;

class SETTINGS_PERMISSIONS {
public:
                                SETTINGS_PERMISSIONS() {
                                    this->allowed_methods = HTTP_GET_BIT;
                                    this->auth_failover_to_default = 1;
                                    this->protected_methods = METHODS_NONE;
                                    this->auth_type = AUTH_UNIX;
                                }
    
    AUTH_TYPE                   auth_type;                  /* The type of auth we'll use. */
                                
    uint32_t                    allowed_methods;            /*
                                                             * Variable containing ORd values of HTTP methods for
                                                             * determining if a resource is protected or not.  Methods
                                                             * falling under THIS category, acting on THIS directory DO
                                                             * NOT need any type of authentication. 
                                                             * 
                                                             **/
    
    uint8_t                     auth_failover_to_default;   /*
                                                             * DEFAULT: TRUE
                                                             * 
                                                             * If this is set to TRUE, and NO ::username or ::password
                                                             * properties are set here, the logic will compare auth attempts
                                                             * against the SETTINGS::default_username and 
                                                             * SETTINGS::default_password.  i.e. The default username/password
                                                             * combo is inherited by each sub-directory of the document root.
                                                             * 
                                                             * If this value is FALSE, and either the ::username or ::password
                                                             * property of this class is empty, any private methods requests
                                                             * will be rejected.
                                                             * 
                                                             **/
    
    uint32_t                    protected_methods;            /*
                                                             * Variable containing ORd values of HTTP methods for
                                                             * determining if a resource is protected or not.  Methods
                                                             * falling under THIS category, acting on THIS directory DO
                                                             * REQUIRE authentication. 
                                                             * 
                                                             **/

    HTTP_STRING                 password;                   /*
                                                             * The hash of the password to be checked for access to this
                                                             * directory upon receipt of any PRIVATE methods.  If this
                                                             * HTTP_STRING is empty, but the directory HAS PRIVATE methods,
                                                             * we will look to the "SETTINGS" default password / username combo.
                                                             * 
                                                             * If this PASSWORD field is empty, we will ignore whatever is in
                                                             * the SETTINGS_DIRECTORY::username field.
                                                             * 
                                                             **/
    
    HTTP_STRING                 username;                   /*
                                                             * The username configured to allow methods marked as PRIVATE for
                                                             * this directory (if any).
                                                             * 
                                                             **/    
};


class SETTINGS_FILE {
public:
    
    HTTP_STRING                 filename;                   
    
    SETTINGS_PERMISSIONS        permissions;
    
};


class SETTINGS_DIRECTORY {
public:
                                SETTINGS_DIRECTORY() {
                                    this->files = 0;
                                }
    
    HTTP_STRING                 name;                       /*
                                                             * The name of the directory
                                                             * 
                                                             **/
    
    SETTINGS_FILE               **files;                    /*
                                                             * Settings for any particular files in this directory.
                                                             **/
    
    size_t                      file_count;                 /*
                                                             * Number of elements allocated in **files/
                                                             **/
    
    
    SETTINGS_DIRECTORY          **directories;              /*
                                                             * List of sub directories
                                                             **/
    
    size_t                      directory_count;            /*
                                                             * Number of elements allocated in **directories.
                                                             **/
    
    SETTINGS_PERMISSIONS        permissions;
    
    
};

/* The DELEGATE class represents another program running
 * on the server that is part of an application that needs
 * to perform an internet-based service e.g. a REST API, 
 * handle chat messages or user events via WebSocket.
 * 
 * It can be registered as a DELEGATE.  When HTTPieces
 * establishes a connection with a client, the data will
 * be transparently passed back and forth between that
 * client and the DELEGATE.
 * 
 * This takes a lot of the workload off of the service applet
 * as far as deciphering WebSocket and HTTP/2 frames.
 * 
 * Delegates can also register to accept raw TCP segments or
 * raw UDP datagrams.
 * 
 * 
 **/
class DELEGATE {
public:
                                DELEGATE() {
                                    memset(this->unix_socket_path, 0, 1024);
                                    this->max_connections = -1; // Unlimited
                                    this->desired_protocols = (HTTP10|HTTP11|HTTP20);
                                    this->desired_methods = METHODS_NONE;
                                    memset(this->desired_specific_request_path, 0, 1024);
                                    memset(this->delegate_username, 0, 1024);
                                    this->delegate_uid = -1;
                                };
                                
    char                        unix_socket_path[1024];                 // UNIX socket path
    int                         max_connections;                        // The max number of connections that HTTPieces will establish 
                                                                        // to the DELEGATE.  Default is -1 (unlimited)
    int                         desired_protocols;                      // The protocol(s) the DELEGATE is wanting to process. An "OR"d list of:
                                                                                                // RAW_APP_LAYER 
                                                                                                // HTTP10
                                                                                                // HTTP11
                                                                                                // WEBSOCKET
                                                                                                // HTTP11_WEBSOCKET    ( HTTP11 | WEBSOCKET )
                                                                                                // HTTP20
                                                                                                // HTTP20_WEBSOCKET    ( HTTP20 | WEBSOCKET )
                                                                                                // HTTP30                                      * For future use
                                                                                                // HTTP30_WEBSOCKET    ( HTTP30 | WEBSOCKET )  * For future use
    
    uint32_t                    desired_methods;                        // OPTIONAL - If the DELEGATE only wants to accept certain HTTP methods
                                                                        //            Values can be "OR"d "|" together...
    
                                                                                                // HTTP_GET_BIT
                                                                                                // HTTP_HEAD_BIT
                                                                                                // HTTP_POST_BIT
                                                                                                // HTTP_PUT_BIT
                                                                                                // HTTP_DELETE_BIT
                                                                                                // HTTP_CONNECT_BIT
                                                                                                // HTTP_OPTIONS_BIT
                                                                                                // HTTP_TRACE_BIT
    
    char                        desired_specific_request_path[1024];    // If the DELEGATE only wants to process HTTP request to a certain request path, and leave the rest
                                                                        // to be served from within HTTPieces.
    char                        delegate_username[255];                 // The local user to be used to connect to the DELEGATE
    int                         delegate_uid;                           // The UID to be used to connect to the DELEGATE
};

/*
 * Quick and dirty HTTP_STRING array for remembering settings.
 **/
class SETTINGS_STRING_ARRAY {
private:
    int                         init( void );
    HTTP_STRING                 **array;
    size_t                      cnt;
    size_t                      num;
public:
                                SETTINGS_STRING_ARRAY();
                                SETTINGS_STRING_ARRAY( char *string );
                                SETTINGS_STRING_ARRAY( const char *string );
                                SETTINGS_STRING_ARRAY( HTTP_STRING *string );
                                
                                ~SETTINGS_STRING_ARRAY();
                                
    HTTP_STRING                 *push( char *string );
    HTTP_STRING                 *push( const char *string );
    HTTP_STRING                 *push( char *string, size_t len );
    HTTP_STRING                 *push( const char *string, size_t len );
    HTTP_STRING                 *push( HTTP_STRING *string );
    
    int                         value_exists( char *value_to_find );
    size_t                      count( void );
    
    char                        **argv( void );
    
    HTTP_STRING                 *index( size_t n );
};



class SETTINGS_CGI {
public:
                                SETTINGS_CGI() {
                                    this->worker_count = 0;
                                    this->cgi = 0;
                                    this->env_args_used = 0;
                                }
    int                         worker_count;
    HTTP_STRING                 name;
    HTTP_STRING                 path_to_interpreter;
    HTTP_STRING                 run_as_user;
    HTTP_STRING                 home_dir;
    HTTP_STRING                 working_dir;
    SETTINGS_STRING_ARRAY       args;
    struct _cgi_env_ {
        HTTP_STRING             name;
        HTTP_STRING             value;
    } cgi_env[30];
    size_t                      env_args_used;
    SETTINGS_STRING_ARRAY       file_types; /*
                                             * List of file extensions to be run through this interpreter.
                                             **/
    CGI_ID                      cgi;
};

class LISTENER {
private:
public:
                                LISTENER( SETTINGS *s );
    SETTINGS                    *psettings;             // A pointer to the SETTINGS class to which this listener belongs.
    HTTP_STRING                 name;
    int                         ipversion;              // 4
    IP_ADDRESS                  ipaddr;
    uint32_t                    security_min_proto;     // TLSv1.2, TLSv1.3
    uint32_t                    security_max_proto;     // Not Set
    LISTENER_TYPE               listener_type;          // LT_TLS
    int                         protocol_list;          // HTTP11|HTTP20
    uint16_t                    port;                   // 443
    CERTIFICATE_INFO            certificate_info;       
    HTTP_STRING                 document_root;          // /var/www
    uint32_t                    allowed_methods;        // GET by default
    HTTP_STRING                 server_name;            // Default is the machine's hostname
    SETTINGS_STRING_ARRAY       http_cors;              // The list of Origins allowed for REST API calls or other cross-origin requests.
    DELEGATE                    *pdelegate;             // If another process wants to process data from this connection.
    SETTINGS_PERMISSIONS        listener_permissions;
    
    
    /* CLEAN UP HERE!!! MAKE SURE WE MAINTAIN THE STATE OF THESE LISTS */
    
    SETTINGS_DIRECTORY          **directories;          // Null-terminated array of directories with explicit permissions.
    SETTINGS_CGI                **cgi_list;             // Null-terminated array of pointers to use to register CGI handlers.
    
    int                         get_tls_value( const char *ptr );
    int                         get_tls_value( char *ptr );
};


class GENERAL {
public:
                                GENERAL() {
                                    this->prohibit_all_methods_by_default = 1;
                                };
    int                         prohibit_all_methods_by_default;
    SETTINGS_PERMISSIONS        default_permissions;
};


class SETTINGS {
    
private:
    void                        init( void );
    int                         listener_count;
    int                         listeners_used;
    LISTENER                    **listeners;
public:
    
                                SETTINGS( const char *path_to_settings );
                                SETTINGS( void );
    int                         load( const char *path_to_settings );
    GENERAL                     general;
    int                         settings_error;             /* Set if there is an error condition, invalid, or missing settings */
    
    /*!
     * \brief Adds a new listener to the private array "listeners"
     * 
     * \param Nothing
     * 
     * \return On Success                   - A pointer to a new listener
     * 
     * \return On Failure                   - ZERO and the variable "settings_error" is
     *                                        set to indicate the type of error that occured
     *                                        which, in this case, can only be: SETTINGS_OUT_OF_MEMORY
     **/
    LISTENER                    *new_listener( void );
    
    /*!
     * \brief Obtains a pointer to the listener specified at index "listener_number".
     *        This function is array-out-of-bounds safe; you can start at zero, and 
     *        iterate through listeners until NULL (ZERO) is returned.
     * 
     * \param listener_number               - A zero-based index of a listener for which a pointer
     *                                        is to be returned.
     * 
     * \return On Success                   - A pointer to a listener object.
     * 
     * \return On Failure                   - NULL (ZERO)
     * 
     **/
    LISTENER                    *listener( size_t listener_number);
    
    
    /******************************************************************************************************************************/
    /******************************************************************************************************************************/
    
    
    
    
};




#endif /* SETTINGS_H */

