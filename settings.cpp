#include "settings.h"
#include "http2.h"
#include "jstring.h"


size_t SETTINGS_STRING_ARRAY::count() {
    return this->num;
}

int SETTINGS_STRING_ARRAY::init() {
    this->array = (HTTP_STRING **)malloc(sizeof(HTTP_STRING *) * 20);
    if (this->array) {
        memset(this->array, 0, sizeof(HTTP_STRING *) * 20);
        this->cnt = 20;
        this->num = 0;
        return 1;
    } else {
        this->cnt = 0;
        this->num = 0;
    }
    return 0;
}

SETTINGS_STRING_ARRAY::SETTINGS_STRING_ARRAY() {
    this->init();
}

SETTINGS_STRING_ARRAY::SETTINGS_STRING_ARRAY( const char *string ) {
    if (!this->init()) return;
    this->push((char *)string);
}

SETTINGS_STRING_ARRAY::SETTINGS_STRING_ARRAY( char *string ) {
    if (!this->init()) return;
    this->push(string);
}

SETTINGS_STRING_ARRAY::SETTINGS_STRING_ARRAY( HTTP_STRING *string ) {
    if (!this->init()) return;
    this->push(string);
}

HTTP_STRING *SETTINGS_STRING_ARRAY::push( HTTP_STRING *string ) {
    HTTP_STRING **swap = 0;
    if (!string || !this->array) return 0;
    if (this->num == this->cnt) {
        swap = (HTTP_STRING **)realloc(this->array, sizeof(HTTP_STRING *) * ( this->cnt + 20));
        if (!swap) return 0;
        this->array = swap;
        this->cnt+=20;
    }
    this->array[this->num++] = string;
    return string;
}


HTTP_STRING *SETTINGS_STRING_ARRAY::push( char *string ) {
    HTTP_STRING *s = 0;
    if (!string || !this->array) return 0;
    s = new HTTP_STRING();
    s->concat(string);
    if (!this->push(s)) {
        delete s;
        return 0;
    }
    return s;
}

HTTP_STRING *SETTINGS_STRING_ARRAY::push( const char *string ) {
    HTTP_STRING *s = 0;
    if (!string || !this->array) return 0;
    s = new HTTP_STRING();
    s->concat(string);
    if (!this->push(s)) {
        delete s;
        return 0;
    }
    return s;
}

HTTP_STRING *SETTINGS_STRING_ARRAY::push( char *string, size_t len ) {
    HTTP_STRING *s = 0;
    if (!string || !this->array) return 0;
    s = new HTTP_STRING();
    s->concat(string, len);
    if (!this->push(s)) {
        delete s;
        return 0;
    }
    return s;
}

HTTP_STRING *SETTINGS_STRING_ARRAY::push( const char *string, size_t len ) {
    HTTP_STRING *s = 0;
    if (!string || !this->array) return 0;
    s = new HTTP_STRING();
    s->concat(string, len);
    if (!this->push(s)) {
        delete s;
        return 0;
    }
    return s;
}

HTTP_STRING *SETTINGS_STRING_ARRAY::index( size_t n ) {
    if (n >= this->num) return 0;
    return this->array[n];
}

int SETTINGS_STRING_ARRAY::value_exists( char *value_to_find ) {
    int i = 0;
    if (!value_to_find) return -1;
    for (; i < this->num; i++) {
        if (this->array[i]->equals(value_to_find)) return i;
    }
    return -1;
}

SETTINGS_STRING_ARRAY::~SETTINGS_STRING_ARRAY() {
    int i = 0;
    for (; i < this->num; i++) {
        if (this->array[i]) delete this->array[i];
    }
    this->num = 0;
    free(this->array);
    this->array = 0;
    this->cnt = 0;
}


char **SETTINGS_STRING_ARRAY::argv( void ) {
    int i = 0;
    char **retval = 0;
    if (this->cnt == 0) return 0;
    retval = (char **)malloc(sizeof(char *) * (this->cnt + 1));
    for (; i < this->cnt; i++) {
        retval[i] = strdup(this->array[i]->val());
    }
    retval[i] = 0;
    return retval;
}



char *CERTIFICATE_INFO::chain_file_name(void) {
    return this->tls_chain_file.val();
}

char *CERTIFICATE_INFO::cert_file_name(void) {
    return this->tls_crt_file.val();
}

char *CERTIFICATE_INFO::key_file_name(void) {
    return this->tls_key_file.val();
}


int CERTIFICATE_INFO::cert_okay() {
    return ((this->cert_valid & this->chain_valid) & this->key_valid);
}

void CERTIFICATE_INFO::check_tls_validity() {
    FILE *f;
    
    this->error = SETTINGS_NO_ERROR;
    
    if (this->tls_chain_file.length() > 0) {
        if (!this->chain_valid) {
            /* Check the chain file */
            f = fopen(this->tls_chain_file.val(), "r");
            if (!f) {
                this->error = SETTINGS_INVALID_CHAINFILE;
            } else {
                this->chain_valid = 1;
                fclose(f);
            }
        }
    }
    
    if (this->tls_crt_file.length() > 0) {
        if (!this->cert_valid) {
            /* Check the cert file */
            f = fopen(this->tls_crt_file.val(), "r");
            if (!f) {
                this->error = SETTINGS_INVALID_CERTFILE;
            } else {
                this->cert_valid = 1;
                fclose(f);
            }
        }
    }
    
    if (this->tls_key_file.length() > 0) {
        if (!this->key_valid) {
            /* Check the key file */
            f = fopen(this->tls_key_file.val(), "r");
            if (!f) {
                this->error = SETTINGS_INVALID_KEYFILE;
            } else {
                this->key_valid = 1;
                fclose(f);
            }
        }
    }
}

int CERTIFICATE_INFO::set_chain_file(char *chain_file) {
    int x = this->tls_chain_file.set(chain_file);
    this->check_tls_validity();
    return x;
}

int CERTIFICATE_INFO::set_cert_file(char *cert_file) {
    int x = this->tls_crt_file.set(cert_file);
    this->check_tls_validity();
    return x;
}

int CERTIFICATE_INFO::set_key_file(char *key_file) {
    int x = this->tls_key_file.set(key_file);
    this->check_tls_validity();
    return x;
}

int CERTIFICATE_INFO::set_chain_file(char *chain_file, size_t len) {
    int x = this->tls_chain_file.set(chain_file, len);
    this->check_tls_validity();
    return x;
}

int CERTIFICATE_INFO::set_cert_file(char *cert_file, size_t len) {
    int x = this->tls_crt_file.set(cert_file, len);
    this->check_tls_validity();
    return x;
}

int CERTIFICATE_INFO::set_key_file(char *key_file, size_t len) {
    int x = this->tls_key_file.set(key_file, len);
    this->check_tls_validity();
    return x;
}

int LISTENER::get_tls_value( const char *ptr ) {
    int i = 0;
    for (; TLS_MAP[i].version; i++) {
        if (JSTRING::matches(TLS_MAP[i].version, ptr)) {
            return TLS_MAP[i].TLS_VERSION;
        }
    }
    return 0;
}
int LISTENER::get_tls_value( char *ptr ) {
    return this->get_tls_value((const char *)ptr);
}

LISTENER::LISTENER( SETTINGS *s ) {
    char hostname[1024];
    this->psettings       = s;
    this->ipversion       = 4;
    this->directories     = (SETTINGS_DIRECTORY **)malloc(sizeof(SETTINGS_DIRECTORY *) * 10);
    if (this->directories) {
        memset(this->directories, 0, sizeof(SETTINGS_DIRECTORY *) * 10);
    }
    
    this->cgi_list        = (SETTINGS_CGI **)malloc(sizeof(SETTINGS_CGI *) * 10);
    if (this->cgi_list) {
        memset(this->cgi_list, 0, sizeof(SETTINGS_CGI *) * 10);
    }
    
    
    this->security_min_proto = this->get_tls_value("TLSv1.2");
    this->security_max_proto = 0;
    this->listener_type   = LT_TLS;
    this->protocol_list   = (PROTOCOL_MASK)(HTTP11|HTTP20);
    this->port            = 443;
    this->document_root.set("/var/www");
    if (this->psettings->general.prohibit_all_methods_by_default == 1) {
        this->allowed_methods = METHODS_NONE;
    } else {
        this->allowed_methods = HTTP_GET_BIT;
    }
    gethostname(hostname, 1024);
    this->server_name.set(hostname);
    this->pdelegate       = 0;
};





void SETTINGS::init() {
    this->settings_error = SETTINGS_NO_ERROR;
    this->listeners = 0;
    this->listener_count = 0;
    this->listeners_used = 0;
    this->listeners = (LISTENER **)malloc(sizeof(LISTENER *) * 20);
    if (this->listeners) {
        this->listener_count = 20;
    }
}


LISTENER *SETTINGS::listener( size_t listener_number) {
    if (listener_number < this->listeners_used) return this->listeners[listener_number];
    return 0;
}


LISTENER *SETTINGS::new_listener( void ) {
    LISTENER *l = 0, **swap = 0;
    
    if (!this->listeners) {
        this->listeners = (LISTENER **)malloc(sizeof(LISTENER *) * 20);
        if (!this->listeners) {
            this->settings_error = SETTINGS_OUT_OF_MEMORY;
            return 0;
        }
        this->listener_count = 20;
        this->listeners_used = 0;
    }
    
    if (this->listeners_used == this->listener_count) {
        swap = (LISTENER **)realloc( this->listeners, sizeof(LISTENER *) * (this->listener_count+20)) ;
        if (!swap) {
            this->settings_error = SETTINGS_OUT_OF_MEMORY;
            return 0;
        }
        this->listeners = swap;
        this->listener_count+=20;
    }
    l = new LISTENER(this);
    this->listeners[this->listeners_used++] = l;
    return l;
}


int SETTINGS::load( const char *path_to_settings ) {
    FILE *f = 0;
    char settings_line[1000], *pline = 0;
    LISTENER *l = 0;
    int current_line_number = 0, listener_line_number = 0, sub_itr = 0;
    SETTINGS_CONTEXT main = SC_UNDEFINED, sub_list[100], *sub = &sub_list[0];
    SETTINGS_PERMISSIONS *permissions = &this->general.default_permissions;
    SETTINGS_CGI *psetting_cgi = 0;
    size_t line_length = 0;
    JSTRING::jsstring val, key, string,  **list = 0;
    int i = 0;
    
    memset(sub_list, SC_UNDEFINED, sizeof(sub_list));
    f = fopen(path_to_settings, "r");
    while (!feof(f)) {
        if ((pline = fgets(settings_line, 1000, f))) {
            pline = JSTRING::trim(pline, &line_length);
            ++current_line_number;
            if (pline[0] == '#' || 
                    pline[0] == ';' ||
                    pline[0] == '\r' ||
                    pline[0] == '\n' ||
                    line_length == 0)
            {
                continue;
            }
            
            if (JSTRING::matches(pline, "[general]")) {
                debug(3, "Entering [general] context.\n");
                main = SC_GENERAL;
                continue;
            } else if (JSTRING::matches(pline, "[listener]")) {
                debug(3, "Entering [listener] context.\n");
                main = SC_LISTENER;
                listener_line_number = current_line_number;
                l = this->new_listener();
                permissions = &l->listener_permissions;
                continue;
            }
            
            if (main == SC_GENERAL) {
                val.ptr = JSTRING::keyvalue(pline, line_length, &val.length);
//                val.ptr = JSTRING::trim(val.ptr, &val.length);
                if (JSTRING::matches(pline, "prohibit_all_methods_by_default")) {
                    if (AUTH_FALSE(val.ptr)){
                        this->general.prohibit_all_methods_by_default = 0;
                    } else {
                        this->general.prohibit_all_methods_by_default = 1;
                    }
                } else if (JSTRING::matches(pline, "auth_failover_to_default")) {
                    if (AUTH_FALSE(val.ptr)) {
                        permissions->auth_failover_to_default = 0;
                    } else {
                        permissions->auth_failover_to_default = 1;
                    }
                } else if (JSTRING::matches(pline, "default_auth_type")) {
                    if (val.is("open")) {
                        permissions->auth_type = AUTH_OPEN;
                    } else if (val.is("userpass")) {
                        permissions->auth_type = AUTH_USER_PASS;
                    } else if (val.is("userpass_digest")) {
                        permissions->auth_type = AUTH_USER_PASS_DIGEST;
                    }
                } else if (JSTRING::matches(pline, "default_username")) {
                    permissions->username.set(val.ptr, val.length);
                } else if (JSTRING::matches(pline, "default_password")) {
                    permissions->password.set(val.ptr, val.length);
                } else {
                    debug(3, "Unknown setting \"%.*s\" in httpieces.conf on line %d\n", line_length, pline, current_line_number);
                }
                
            } else if (main == SC_LISTENER) {
                if (pline[0] != '<') {
                    key.ptr = JSTRING::keyname(pline, &key.length);
                    val.ptr = JSTRING::keyvalue(pline, line_length, &val.length);
//                    val.ptr = JSTRING::trim(val.ptr, &val.length, &val.length);
                    if (*sub == SC_UNDEFINED || *sub == SC_DIRECTORY || *sub == SC_FILE) {
                        debug(3, "In [listener] %scontext looking at \"%.*s\" = \"%.*s\"\n", 
                                ((*sub==SC_UNDEFINED)?"":((*sub==SC_DIRECTORY)?"[DIRECTORY] ":"[FILE] ")),
                            (int)key.length, key.ptr,
                            (int)val.length, val.ptr
                            );
                        if (key.is("name")) {
                            l->name.set(val.ptr, val.length);
                        } else if (key.is("ipversion")) {
                            l->ipversion = val.toint();
                            l->ipaddr.version = l->ipversion;
                        } else if (key.is("ipaddr")) {              
                            l->ipaddr.set(val.ptr, val.length);
                        } else if (key.is("security-min-proto")) {      
                            l->security_min_proto = l->get_tls_value(val.ptr);
                        } else if (key.is("security-max-proto")) {      
                            l->security_max_proto = l->get_tls_value(val.ptr);
                        } else if (key.is("listener_type")) {
                            if (val.is("LT_TLS")) {
                                l->listener_type = LT_TLS;
                            } else if (val.is("LT_TCP")) {
                                l->listener_type = LT_TCP;
                            } else if (val.is("LT_UDP")) {
                                l->listener_type = LT_UDP;
                            } else if (val.is("LT_DTLS")) {
                                l->listener_type = LT_DTLS;
                            }
                        } else if (key.is("protocol_list")) {       /* Comma delimited */
                            list = JSTRING::split(val.ptr, ',', val.length);
                            if (list) {
                                for (i = 0; list[i]; i++) {
                                    string.ptr = JSTRING::trim(list[i]->ptr, list[i]->length, &string.length);
                                    if (string.is("HTTP11")) {
                                        l->protocol_list|=HTTP11;
                                    } else if (string.is("RAW_APP_LAYER")) {
                                        l->protocol_list|=RAW_APP_LAYER;
                                    } else if (string.is("WEBSOCKET")) {
                                        l->protocol_list|=WEBSOCKET;
                                    } else if (string.is("HTTP20")) {
                                        l->protocol_list|=HTTP20;
                                    } else if (string.is("HTTP30")) {
                                        l->protocol_list|=HTTP30;
                                    } else {
                                        debug(3, "Unknown protocol type '%.*s' in settings file, line: %d\n", (int)string.length, string.ptr, current_line_number);
                                    }
                                }
                                JSTRING::freesplit(list);
                            }
                            printf("\n");
                        } else if (key.is("port")) {
                            l->port = (uint16_t)val.toint();
                        } else if (key.is("tls_cert_file")) {
                            l->certificate_info.set_cert_file(val.ptr, val.length);
                        } else if (key.is("tls_chain_file")) {
                            l->certificate_info.set_chain_file(val.ptr, val.length);
                        } else if (key.is("tls_key_file")) {
                            l->certificate_info.set_key_file(val.ptr, val.length);
                        } else if (key.is("http_document_root")) {
                            l->document_root.set(val.ptr, val.length);
                        } else if (key.is("allowed_methods")) {     /* Comma delimited */
                            list = JSTRING::split(val.ptr, ',', val.length);
                            if (list) {
                                for (i = 0; list[i]; i++) {
                                    string.ptr = JSTRING::trim(list[i]->ptr, list[i]->length, &string.length);
                                    if (string.is("GET")) {
                                        permissions->allowed_methods|=HTTP_GET_BIT;
                                    } else if (string.is("POST")) {
                                        permissions->allowed_methods|=HTTP_POST_BIT;
                                    } else if (string.is("DELETE")) {
                                        permissions->allowed_methods|=HTTP_DELETE_BIT;
                                    } else if (string.is("TRACE")) {
                                        permissions->allowed_methods|=HTTP_TRACE_BIT;
                                    } else if (string.is("CONNECT")) {
                                        permissions->allowed_methods|=HTTP_CONNECT_BIT;
                                    } else if (string.is("HEAD")) {
                                        permissions->allowed_methods|=HTTP_HEAD_BIT;
                                    } else if (string.is("PUT")) {
                                        permissions->allowed_methods|=HTTP_PUT_BIT;
                                    } else if (string.is("OPTIONS")) {
                                        permissions->allowed_methods|=HTTP_OPTIONS_BIT;
                                    } else if (string.is("ALL")) {
                                        permissions->allowed_methods|=ALL_METHODS;
                                    } else if (string.is("NONE")) {
                                        permissions->allowed_methods=0;
                                    } else if (string.is("IDEMPOTENT")) {
                                        permissions->allowed_methods|=IDEMPOTENT;
                                    } else if (string.is("NON_IDEMPOTENT")) {
                                        permissions->allowed_methods|=NON_IDEMPOTENT;
                                    } else if (string.is("IDEMPOTENT_SAFE")) {
                                        permissions->allowed_methods|=IDEMPOTENT_SAFE;
                                    } else {
                                        debug(3, "Unknown option '%.*s' defining allowed HTTP methods in configuration file at line %d.\n", (int)string.length, string.ptr, current_line_number);
                                    }
                                }
                                JSTRING::freesplit(list);
                            }
                        } else if (key.is("protected_methods")) {   /* Comma delimited */
                            list = JSTRING::split(val.ptr, ',', val.length);
                            if (list) {
                                for (i = 0; list[i]; i++) {
                                    string.ptr = JSTRING::trim(list[i]->ptr, list[i]->length, &string.length);
                                    if (string.is("GET")) {
                                        permissions->protected_methods|=HTTP_GET_BIT;
                                    } else if (string.is("POST")) {
                                        permissions->protected_methods|=HTTP_POST_BIT;
                                    } else if (string.is("DELETE")) {
                                        permissions->protected_methods|=HTTP_DELETE_BIT;
                                    } else if (string.is("TRACE")) {
                                        permissions->protected_methods|=HTTP_TRACE_BIT;
                                    } else if (string.is("CONNECT")) {
                                        permissions->protected_methods|=HTTP_CONNECT_BIT;
                                    } else if (string.is("HEAD")) {
                                        permissions->protected_methods|=HTTP_HEAD_BIT;
                                    } else if (string.is("PUT")) {
                                        permissions->protected_methods|=HTTP_PUT_BIT;
                                    } else if (string.is("OPTIONS")) {
                                        permissions->protected_methods|=HTTP_OPTIONS_BIT;
                                    } else if (string.is("ALL")) {
                                        permissions->protected_methods|=ALL_METHODS;
                                    } else if (string.is("NONE")) {
                                        permissions->protected_methods=0;
                                    } else if (string.is("IDEMPOTENT")) {
                                        permissions->protected_methods|=IDEMPOTENT;
                                    } else if (string.is("NON_IDEMPOTENT")) {
                                        permissions->protected_methods|=NON_IDEMPOTENT;
                                    } else if (string.is("IDEMPOTENT_SAFE")) {
                                        permissions->protected_methods|=IDEMPOTENT_SAFE;
                                    } else {
                                        debug(3, "Unknown option '%.*s' defining protected HTTP methods in configuration file at line %d.\n", (int)string.length, string.ptr, current_line_number);
                                    }
                                }
                                JSTRING::freesplit(list);
                            }
                            
                        } else if (key.is("http_cors")) {           /* Comma delimited */
                            list = JSTRING::split(val.ptr, ',', val.length);
                            if (list) {
                                for (i = 0; list[i]; i++) {
                                    string.ptr = JSTRING::trim(list[i]->ptr, list[i]->length, &string.length);
                                    if (string.length > 0) {
                                        l->http_cors.push(string.ptr, string.length);
                                    }
                                }
                                JSTRING::freesplit(list);
                            }
                        } else if (key.is("server_name")) {
                            if (!val.is("$hostname")) {
                                l->server_name.set(val.ptr, val.length);
                            }
                        } else if (key.is("auth_type")) {
                            if (val.is("open")) {
                                permissions->auth_type = AUTH_OPEN;
                            } else if (val.is("userpass")) {
                                permissions->auth_type = AUTH_USER_PASS;
                            } else if (val.is("userpass_digest")) {
                                permissions->auth_type = AUTH_USER_PASS_DIGEST;
                            }
                        } else if (key.is("username")) {
                            permissions->username.set(val.ptr, val.length);
                        } else if (key.is("password")) {
                            permissions->password.set(val.ptr, val.length);
                        }
                    } else if (*sub == SC_DELEGATE) {
                        /* We've decended into a delegate.  This setting is for it. */
                        debug(3, "In [listener] <delegate> context looking at \"%.*s\" = \"%.*s\"\n", 
                            (int)key.length, key.ptr,
                            (int)val.length, val.ptr
                            );
                    } else if (*sub == SC_CGI) {
                        debug(3, "In [listener] <cgi> context looking at \"%.*s\" = \"%.*s\"\n", 
                            (int)key.length, key.ptr,
                            (int)val.length, val.ptr
                            );
                        if (key.is("env_")) { /* Add a new environmental variable */
                            if (psetting_cgi->env_args_used < 30) {
                                psetting_cgi->cgi_env[psetting_cgi->env_args_used].name.set( &key.ptr[4], key.length-4);
                                psetting_cgi->cgi_env[(psetting_cgi->env_args_used++)].value.set(val.ptr, val.length);
                            } else {
                                error("Only 30 (thirty) max environmental variables allowed per registered CGI interpreter.  Over the limit at line %d\n", current_line_number);
                            }
                        } else if (key.is("interpreter_path")) {
                        } else if (key.is("accept_type")) {             /* Comma delimited list */
                            list = JSTRING::split(val.ptr, ',', val.length);
                            if (list) {
                                for (i = 0; list[i]; i++) {
                                    string.ptr = JSTRING::trim(list[i]->ptr, list[i]->length, &string.length);
                                    if (string.length > 0) {
                                        if (string.ptr[0] == '.') { /* Normalize...remove the "." */
                                            psetting_cgi->file_types.push(&string.ptr[1], (string.length - 1));
                                        } else {
                                            psetting_cgi->file_types.push(string.ptr, string.length);
                                        }
                                    }
                                }
                                JSTRING::freesplit(list);
                            }
                        } else if (key.is("worker_count")) {
                        } else if (key.is("working_directory")) {
                        } else if (key.is("run_as_user")) {
                            /* Try to get user's home directory */
                            
                        } else {
                            debug(3, "Unrecognized setting \"%.*s\" for sub category <cgi> in configuration file on line %d\n",
                                    (int)key.length,
                                    key.ptr,
                                    current_line_number);
                        }
                        
                    }
                    
                } else {
                    /* We're maybe either entering or exiting a sub-category */
                    if (pline[1] == '/') {
                        /* We're stepping out of a sub category */
                        if (sub_itr == 0) {
                            error("Error parsing configuration file. Unexpected closing tag: \"%.*s\" at line: %d\n", (int)line_length, pline, current_line_number);
                            continue;
                        }
                        string.ptr = JSTRING::between(pline, "/>", &string.length);
                        if (
                                !(string.is("directory") && *sub == SC_DIRECTORY) &&
                                !(string.is("delegate") && *sub == SC_DELEGATE) &&
                                !(string.is("cgi") && *sub == SC_CGI) &&
                                !(string.is("file") && *sub == SC_FILE))
                        {
                            error("Mismatched closing tag \"</%.*s>\", while looking for \"%s\" in configuration file at line: %d\n",
                                    (int)string.length,
                                    string.ptr,
                                    ((*sub==SC_DIRECTORY)?"</directory>":((*sub==SC_FILE)?"</file>":"</delegate>")),
                                    current_line_number
                                    );
                            continue;
                        }
                        sub = &sub_list[--sub_itr];
                    } else {
                        /* We're stepping into a sub category */
                        string.ptr = JSTRING::between(pline, "<>", &string.length);
                        if (string.ptr && string.length > 0) {
                            if (string.is("directory")) {
                                sub_list[++sub_itr] = SC_DIRECTORY;
                                sub = &sub_list[sub_itr];
                            } else if (string.is("delegate")) {
                                debug(3, "Entered <delegate> sub category at line %d, but ths DELEGATE class is not yet implemented!\n", current_line_number);
                                sub_list[++sub_itr] = SC_DELEGATE;
                                sub = &sub_list[sub_itr];
                            } else if (string.is("cgi")) {
                                sub_list[++sub_itr] = SC_CGI;
                                sub = &sub_list[sub_itr];
                                if (l->cgi_list == 0) {
                                    
                                } else {
                                    
                                }
                            } else if (string.is("file")) {
                                sub_list[++sub_itr] = SC_FILE;
                                sub = &sub_list[sub_itr];
                            } else {
                                debug(3, "Unrecognized sub-category: \"%.*s\" in configuration file on line %d\n", (int)string.length, string.ptr, current_line_number);
                            }
                        }
                    }
                    
                }
                
            }
            
            
            
            
            
        }
    }
    fclose(f);
    return 1;
}

SETTINGS::SETTINGS(const char *path_to_settings) {
    this->init();
    this->load(path_to_settings);
}

SETTINGS::SETTINGS( void ) {
    char *filepath = 0;
    char *path = getcwd(0, 0);
    size_t filepathlen = 0;
    this->init();
    if (!path) {
        this->settings_error = SETTINGS_FILE_NOT_FOUND;
        return;
    }
    
    filepathlen = strlen(path) + 17;
    
    filepath = (char *)malloc(filepathlen);
    
    if (!filepath) {
        this->settings_error = SETTINGS_OUT_OF_MEMORY;
        free(path);
        return;
    }
    memset(filepath, 0, filepathlen);
    strcpy(filepath, path);
    sprintf(filepath, "%s%shttpieces.conf", path, ((path[strlen(path)-1]=='/')?"":"/"));
    free(path);
    this->load(filepath);
    free(filepath);
}