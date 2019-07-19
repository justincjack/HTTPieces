/* (c) 2019 Justin Jack - MIT License */
#include "http.h"
#include "db_x_platform.h"



void http_server_thread_signal_handler( int signum ) {
    return;
}


IP_ADDRESS::IP_ADDRESS( void *binary_pointer, int ip_version ) {
    uint64_t *p = (uint64_t *)binary_pointer;
    if (ip_version == 4) {
        this->ipv4_address.ipv4_addr = *((uint32_t *)binary_pointer);
    } else if (ip_version == 6) {
        this->ipv6_address.ipv6_64[0] = p[0];
        this->ipv6_address.ipv6_64[1] = p[1];
    }
    this->set(this->ip_string());
};

IP_ADDRESS::IP_ADDRESS( uint32_t ipaddr32_bit ) {
    this->ipv4_address.ipv4_addr = ipaddr32_bit;
    this->set(this->ip_string());
};

const char *IP_ADDRESS::ip_string( void ) {
        static const char mt[] = "";
        static char ipv6_readable[25] = { 0 };
        static char ipv4_readable[16] = { 0 };
        char bfr[10];
        int i = 0;

        if (this->version == 4) {
            for (; i < 4; i++) {
                sprintf(bfr, "%d", this->ipv4_address.ipv4_char[i]);
                strcat(ipv4_readable, bfr);
                if (i < 3) {
                    strcat(ipv4_readable, ".");
                }
            }
            return ipv4_readable;
        } else if (this->version == 6) {
            for (; i < 8; i++) {
                sprintf(bfr, "%.4x", (unsigned short)ntohs(this->ipv6_address.ipv6_16[i]));
                strcat(ipv6_readable, bfr);
                if (i < 7) {
                    strcat(ipv6_readable, ":");
                }
            }
            return ipv6_readable;

        } else {
            return (char *)mt;
        }
    }


void IP_ADDRESS::parse_addr(const char *ptr, size_t len) {
    size_t i = 0, d = 0, s = 0;
    int nmbc = 0, nmbyte = 0, bits_to_set = 0;
    char num_buf[6] = {'0', '0', '0', '0', '0', '0'};
    this->ipv4_address.ipv4_addr    = 0;
    this->ipv4_mask.ipv4_addr       = 0;
    this->ipv6_address.ipv6_64[0]   = 0;
    this->ipv6_address.ipv6_64[1]   = 0;
    this->ipv6_mask.ipv6_64[0]      = 0;
    this->ipv6_mask.ipv6_64[1]      = 0;
    this->net_range = -1;
    this->version = 0;
    int placeholder = -1;
    int placeholder_end = -1;
    int valid_values = 0;
    
    if (!ptr || len == 0) return;
    for (; i < len; i++) {
        if (ptr[i] == '.') {
            num_buf[s] = 0;
            this->version = 4;
            this->ipv4_address.ipv4_char[d++] = (uint8_t)strtol(num_buf, 0, 10);
            memset(num_buf, 0, 6);
            s = 0;
            continue;
        } else if (ptr[i] == ':') {
            if (i > 0 && ptr[i-1] == ':') {
                if (placeholder != -1) {
                    this->ipv6_address.ipv6_64[0]   = 0;
                    this->ipv6_address.ipv6_64[1]   = 0;
                    memset(num_buf, 0, 6);
                    break;
                }
                placeholder = (int)d; /* The place where we'll fill in zeroes */
            }
            num_buf[s] = 0;
            this->version = 6;
            this->ipv6_address.ipv6_16[d] = htons((uint16_t)strtol(num_buf, 0, 16));
            if ( this->ipv6_address.ipv6_16[d] != 0 ) {
                valid_values++;
                if (placeholder >= 0 && placeholder_end == -1) {
                    placeholder_end = (int)d;
                }
            }
            d++;
            memset(num_buf, 0, 6);
            s = 0;
            continue;
        } else if (ptr[i] == '/') {
            this->net_range = (int)strtol(&ptr[i+1], 0, 10);
            memset(num_buf, 0, 6);
            s = 0;
            break;
        }
        num_buf[s++] = ptr[i];
    }
    if (this->version == 4 && d == 3) {
        this->ipv4_address.ipv4_char[d] = (uint8_t)strtol(num_buf, 0, 10);
        if (this->net_range > 0 && this->net_range <= 32) {
            bits_to_set = this->net_range;
            for (nmbc = 0; nmbc < bits_to_set; nmbc++) {
                nmbyte = (int)((float)((bits_to_set-1) - nmbc) / (float)8);
                this->ipv4_mask.ipv4_char[nmbyte] |= (1 << ((8 - (nmbc % 8)) - 1) );
            }
        } else {
            this->net_range = 0;
        }
    } else if (this->version == 6) {
        int spots_to_move = 0;
        this->ipv6_address.ipv6_16[d] = htons((uint16_t)strtol(num_buf, 0, 16));
        if (this->ipv6_address.ipv6_16[d] != 0) valid_values++;
        if (placeholder > -1) {
            spots_to_move = ((8 - valid_values) - 1);
            for (; spots_to_move; spots_to_move--, placeholder_end++) {
                for (i = 7; i > placeholder_end > 0; i--) {
                    this->ipv6_address.ipv6_16[i] =
                        this->ipv6_address.ipv6_16[i-1];
                }
                this->ipv6_address.ipv6_16[i] = 0;
            }
        }
        if (this->net_range > 0 && this->net_range <= 128) {
            bits_to_set = this->net_range;
            for (nmbc = 0; nmbc < bits_to_set; nmbc++) {
                nmbyte = (int)((float)((bits_to_set-1) - nmbc) / (float)8);
                this->ipv6_mask.ipv6_8[nmbyte] |= (1 << ((8 - (nmbc % 8)) - 1) );
            }
        } else {
            this->net_range = 0;
        }
    }
}



/* Class _http_string (aka HTTP_STRING) *****************************************/

void _http_string::init( size_t init_bytes ) {
    this->size = (size_t)init_bytes;
    this->len = 0;
    this->ptr = (char *)malloc(this->size);
    if (!this->ptr) this->size = 0;
}

_http_string::_http_string(size_t init_bytes) {
    this->init(init_bytes);
}

_http_string::_http_string(void) {
    this->init(200);
}

_http_string::~_http_string() {
    this->size = 0;
    free(this->ptr);
}

size_t _http_string::concat(const char *ptr, size_t len) {
    size_t newlen = this->size + ((size_t)len + 200);
    char *swap = 0;
    if (!len) return 0;
    if ((this->len + len) >= this->size ) {
        swap = (char *)realloc((char *)this->ptr, (size_t)newlen);
        if (!swap) {
            return 0;
        }
        this->ptr = swap;
        this->size = newlen;
    }
    memcpy(&this->ptr[this->len], ptr, len);
    this->len+=len;
    this->ptr[this->len] = 0;
    return len;
}

size_t _http_string::concat(const char *ptr ) {
    return _http_string::concat((const char *)ptr, strlen((const char *)ptr));
}

size_t _http_string::concat(char *ptr, size_t len ) {
    return _http_string::concat((const char *)ptr, len);
}

size_t _http_string::concat( char *ptr ) {
    return _http_string::concat((const char *)ptr, strlen((const char *)ptr));
}

void _http_string::clear(void) {
    if (!this->ptr) return;
    this->len = 0;
    this->ptr[0] = 0;
    return;
}

size_t _http_string::length( void ) {
    return this->len;
}

char *_http_string::val( void ) {
    static const char MT[] = "";
    if (this->len == 0) return (char *)MT;
    return this->ptr;
}

char *_http_string::to_upper( void ) {
    static const char MT[] = "";
    char *upper = 0;
    int i = 0;
    if (this->len == 0) return (char *)MT;
    upper = strdup(this->val());
    for (; i < strlen(upper); i++) upper[i] = HTTP_UPPER(i);
    return upper;
}


size_t _http_string::get( char *buff ) {
    int i = 0;
    for (; i < this->len; i++) {
        buff[i] = this->ptr[i];
    }
    return i;
}

int _http_string::contains(const char *search, size_t len) {
    if (!search || !len || len > this->len) {
        return 0;
    }
    size_t i = 0, j = 0;
    for (i = 0; ((i < (this->len - len)) && j==0) || ((i < this->len) && j > 0) ; i++) {
        if ( HTTP_LOWER(this->ptr[i]) == HTTP_LOWER(search[j])) {
            if (++j == len) return (i-len);
        } else {
            if (j > 0) {
                j = 0;
                i--;
            }
        }
    }
    return 0;
}

int _http_string::contains(const char *search) {
    return this->contains((const char *)search, strlen((const char *)search));
}

int _http_string::contains(char *search) {
    return this->contains((const char *)search, strlen((const char *)search));
}

int _http_string::contains(char *search, size_t len) {
    return this->contains((const char *)search, len);
}

int _http_string::set(const char *val, size_t len) {
    this->clear();
    return this->concat(val, len);
}

int _http_string::set(char *val, size_t len) {
    return this->set((const char *)val, (size_t)len);
}

int _http_string::set(const char *val) {
    return this->set((const char *)val, (size_t)strlen(val));
}

int _http_string::set(char *val) {
    return this->set((const char *)val, (size_t)strlen(val));
}

int _http_string::set_lower(const char *val, size_t len) {
    int i = 0;
    this->clear();
    if (this->concat(val, len)) {
        for(; i < this->len; i++) {
            this->ptr[i] = HTTP_LOWER(this->ptr[i]);
        }
        return 1;
    }
    return 0;
}

int _http_string::set_lower(char *val, size_t len) {
    return this->set_lower((const char *)val, (size_t)len);
}

int _http_string::set_lower(const char *val) {
    return this->set_lower((const char *)val, (size_t)strlen(val));
}

int _http_string::set_lower(char *val) {
    return this->set_lower((const char *)val, (size_t)strlen(val));
}

int _http_string::equals(const char *e, size_t len) {
    int i = 0;
    if (len != this->len) return 0;
    for (; i < len; i++) {
        if (HTTP_LOWER(e[i]) != this->ptr[i]) return 0;
    }
    return 1;
}

int _http_string::equals(const char *e) {
    return this->equals(e, strlen(e));
}

int _http_string::equals(char *e, size_t len) {
    return this->equals((const char *)e, len);
}

int _http_string::equals(char *e) {
    return this->equals((const char *)e, strlen(e));    
}






/*********************************************************************************/



/** _http_header */

_http_header_list::_http_header_list() {
    int i = 0;
    this->end_headers = 0;
    this->header_list_size = 200;
    this->header_list_length = 0;
    this->http_parent = 0;
    this->header_list = (struct _http_hdrl_ * )malloc( sizeof(struct _http_hdrl_) * this->header_list_size );
    if (!this->header_list) {
        this->header_list_size = 0;
        return;
    }
    for (; i < this->header_list_size; i++) {
        this->header_list[i].name = new HTTP_STRING;
        this->header_list[i].value = new HTTP_STRING(1200);
    }
    
}

_http_header_list::~_http_header_list() {
    int i = 0;
    this->header_list_length = 0;
    this->req_buffer_size = 0;
    for (; i < this->header_list_size; i++){
        delete this->header_list[i].name;
        delete this->header_list[i].value;
    }
}

int _http_header_list::complete() {
    return this->end_headers;
}

void _http_header_list::complete( int is_complete ) {
    if (is_complete > 0) 
        this->end_headers = 1;
    else
        this->end_headers = 0;
}

int _http_header_list::add_header( char *name, size_t name_len, char *value, size_t value_len ) {
    struct _http_hdrl_ *swap = 0;
    PHTTP_HEADER phdr = 0;
    size_t swap_len = 0, new_header_size = 0;
    int i = 0;
    
    if (!name) return 0;
    
    /* Remove white-space from end of strings */
    for (;   ((name[name_len-1] == '\r' ||   name[name_len-1] == '\n' ||   name[name_len-1] == ' ') &&  name_len-1>=0);  name_len--);
    for (; ((value[value_len-1] == '\r' || value[value_len-1] == '\n' || value[value_len-1] == ' ') && value_len-1>=0); value_len--);

    if (name_len == 0 && value_len == 0) {
        this->end_headers = 1;
        return 0;
    }
    
    if ( (name_len > 0 && value_len == 0) ||
         (name_len == 0 && value_len > 0))
    {
        return 0;
    }

    
    phdr = this->get(name, name_len);
    if (phdr) { /* The header already exists, we'll concatenate this value to the existing to avoid duplicate headers */
        this->req_buffer_size += 2 + (value_len-(phdr->value->length()));
        phdr->value->concat("; ");
        phdr->value->concat(value, value_len);
        return 1;
    }
    
    if (this->header_list_size == this->header_list_length) {
        new_header_size = this->header_list_size + 100;
        swap = (struct _http_hdrl_ *)realloc(this->header_list, sizeof(struct _http_hdrl_) * new_header_size);
        if (!swap) {
            return 0;
        }
        for (i = this->header_list_length; i < new_header_size; i++) {
            swap[i].name = new HTTP_STRING;
            swap[i].value = new HTTP_STRING(1200);
        }
        this->header_list = swap;
        this->header_list_size = new_header_size;
    }
    phdr = &this->header_list[(this->header_list_length++)];
    phdr->name->set_lower(name, name_len);
    phdr->value->set(value, value_len);
    this->req_buffer_size+=(name_len + value_len + 4 /* ':', ' ', '\r\n' */ );
    if (this->header_list_length == 1) {
        this->req_buffer_size+=4; /* '\r\n\r\n' - For the end of headers delimiter */
    }
    
    if (phdr->name->equals("content-length")) {
        this->http_parent->content_length = strtoul(phdr->value->val(), 0, 10);
    } else if (phdr->name->equals("Access-Control-Allow-Origin")) {
        if (!phdr->value->equals("*")) {
            return this->add_header("Vary", "Origin");
        }
    }
    
    return 1;
}

int _http_header_list::add_header( char *name, char *value ) {
    return this->add_header(name, strlen(name), value, strlen(value));
}

int _http_header_list::add_header( const char *name, const char *value ) {
    return this->add_header((char *)name, strlen(name), (char *)value, strlen(value));
}

int _http_header_list::add_header( const char *name, size_t name_len, const char *value, size_t value_len ) {
    return this->add_header((char *)name, name_len, (char *)value, value_len);
}

int _http_header_list::add_header_line( const char *line, size_t length) {
    int i = 0, plus = 1;
    
    if (line == 0) return -1;
    
    /* Trim whitespace off the end */
    if (length == 0) {
        this->end_headers = 1;
        return 0;
    }
    
    for (;((line[length-1] == '\r' || line[length-1] == '\n' || line[length-1] == ' ') && length-1>=0); length--);
    
    for (i = 0; i < length; i++) {
        if (line[i] == ':') {
            if (line[i+1] == ' ') plus++;
            return this->add_header(line, i, &line[i+plus], length-(i+plus));
        }
    }
    return -1;
}
int _http_header_list::add_header_line( char *line, size_t length) {
    return this->add_header_line((const char *)line, length);
}
int _http_header_list::add_header_line( const char *line) {
    return this->add_header_line((const char *)line, strlen(line));
}
int _http_header_list::add_header_line( char *line) {
    return this->add_header_line((const char *)line, strlen(line));
}




PHTTP_HEADER _http_header_list::get( const char *header_name, size_t len ) {
    size_t i = 0;
    for (; i < this->header_list_length; i++) {
        if (this->header_list[i].name->equals(header_name, len)) {
            return &this->header_list[i];
        }
    }
    return 0;
}

PHTTP_HEADER _http_header_list::get( char *header_name, size_t len ) {
    size_t i = 0;
    for (; i < this->header_list_length; i++) {
        if (this->header_list[i].name->equals((const char *)header_name, len)) {
            return &this->header_list[i];
        }
    }
    return 0;
}

PHTTP_HEADER _http_header_list::get( char *header_name ) {
    return this->get((const char *)header_name, strlen(header_name));
}

PHTTP_HEADER _http_header_list::get( const char *header_name ) {
    return this->get(header_name, strlen(header_name));
}

size_t _http_header_list::get_header_list( char **output_buffer, size_t buffer_size) {
    char *bfr = 0;
    size_t bfr_size = 0;
    int i = 0, j = 0;
    PHTTP_HEADER phdr = 0;
    if (!output_buffer) return 0;
    bfr = *output_buffer;
    if (!bfr) { /* The did NOT provide us a buffer */
        bfr_size = (this->req_buffer_size + 50);
        bfr = (char *)malloc(bfr_size);
        *output_buffer = bfr;
    } else {
        /* They DID provide a buffer. */
        if (buffer_size < (this->req_buffer_size + 50)) {
            bfr = (char *)realloc(bfr, (this->req_buffer_size+50));
            if (!bfr) {
                return 0;
            }
            *output_buffer = bfr;
            buffer_size = this->req_buffer_size+50;
        }
        memset(bfr, 0, buffer_size);
    }
    for (; i < this->header_list_length; i++) {
        phdr = &this->header_list[i];
        if ( (j + phdr->name->length() + phdr->value->length() + 4) > bfr_size) {
            bfr = (char *)realloc(bfr, (bfr_size + 300));
            if (!bfr) {
                return 0;
            }
            *output_buffer = bfr;
            bfr_size+=300;
        }
        j+=phdr->name->get(&bfr[j]);
        bfr[j++] = ':';
        bfr[j++] = ' ';
        j+=phdr->value->get(&bfr[j]);
        bfr[j++] = '\r';
        bfr[j++] = '\n';
    }
    bfr[j++] = '\r';
    bfr[j++] = '\n';
    return j;
}


/******/

HTTP::HTTP( LISTENER *plisten ) {
    this->headers.http_parent = this;
    this->content_length = 0;
    this->status_code = 0;
    this->lines_parsed = 0;
    this->authenticated = 0;
    this->is_request = 0;

    memset(&this->service, 0, sizeof(HTTP_S_INTERFACE));
    this->service.connection_valid = 1;
    this->service.pmutex = http_new_mutex(0);
    this->plistener = plisten;
    if (!phttp_server) {
        HTTP_SERVER::START_SERVER();
    }
}

int HTTP::is_complete( void ) {
    PHTTP_HEADER cl = this->headers.get("content-length");
    if (cl) { /* There IS a content-length header that's been received */
        if (this->content_length == this->body.length()) {
            return 1;
        }
    } else {
        /* No Content-Length header yet */
        if (this->headers.complete()) {
            return 1;
        }
    }
    return 0;
}

/* This HTTP object is dying */
HTTP::~HTTP() {
    /* Free up stuff here */
    http_free_mutex(this->service.pmutex);
    if (this->service.presponse) delete this->service.presponse;
}    

int HTTP::abort_connection( void ) {
    int retval = 0;
    http_lock(this->service.pmutex);
    this->service.connection_valid = 0;
    if (this->service.request_processed) {
        retval = 1;
    }
    http_unlock(this->service.pmutex);
    return retval;
}

int HTTP::parse_line( const char *line, size_t length) {
    int i = 0, j = 0, k = 0,
            dot_found = 0;
    JSTRING::jsstring **split = 0;
    char *trimmed = 0, *trimmed_line;
    size_t trimmed_len = 0;
    
    
    if (!line || length == 0) return 0;
    
    trimmed_line = JSTRING::trim((char *)line, &length, &length);
    
    if ( ++this->lines_parsed == 1) {
        this->is_request = 1;
        /* This should be a REQUEST line */
        split = JSTRING::split((char *)line, ' ', length);
        if (split) {
            for (i = 0; split[i]; i++) {
                trimmed = JSTRING::trim(split[i]->ptr, split[i]->length, &trimmed_len);
                if (trimmed_len == 0) { 
                    break; /* If the text is empty! */
                }
                if (i == 0) { /* Get METHOD */
                    for (j = 0; j < HTTP_METHOD_COUNT; j++) {
                        if (!strncmp(trimmed, HTTP_METHODS[j], trimmed_len)) {
                            this->method.concat(trimmed, trimmed_len);
                            break;
                        }
                    }
                    if (j == HTTP_METHOD_COUNT) break;
                } else if (i == 1) { /* Get path, filename and query string */
                    dot_found = 0;
                    for (j = 0; j < trimmed_len; j++) {
                        if (trimmed[j] == '?') {
                            break;
                        }
                    }
                    k = j; /* Remember the offset of the last character of the path/filename */
                    for (; j >=0; j--) {
                        if (trimmed[j] == '/') {
                            if (dot_found) {
                                this->filename.concat(&trimmed[j+1], (k-(j+1)));
                            }
                            break;
                        } else if (trimmed[j] == '.') {
                            dot_found = 1;
                        }
                    }
                    if (j == -1) {
                        break;
                    }
                    this->path.concat(trimmed, (int)(j+1));
                    if (k+1 <= trimmed_len) {
                        this->query_string.concat(&trimmed[k+1], trimmed_len-(k+1));
                    }
                } else if (i == 2) { /* Validate HTTP version */
                    for (j = (HTTP_PROTOCOL_VERSION_COUNT-1); j>=0; j--) {
                        if (!strncmp(trimmed, PROTOCOL_VERSION[j].on_wire, trimmed_len)) {
                            this->ihttp_version = (PROTOCOL_ID)j;
                            this->http_version.concat(trimmed, trimmed_len);
                            break;
                        }
                    }
                    if (j == -1) {
                        return -1;
                    }
                } else {
                    return -1;
                }
            }
            JSTRING::freesplit(split);
            return 1;
        } else {
            return -1;
        }
    } else {
        /* Header Line */
        if (this->headers.add_header_line(line, length) == 0) {
            return 0;
        }
        return 1;
    }
    return -1;
}
int HTTP::parse_line(       char *line, size_t length) {
    return this->parse_line((const char *)line, length);
}
int HTTP::parse_line( const char *line ) {
    return this->parse_line((const char *)line, strlen(line));
}
int HTTP::parse_line(       char *line ) {
    return this->parse_line((const char *)line, strlen(line));
}


int HTTP::buffer_http( const char *buffer, size_t bytes) {
    size_t i = 0, line_start = 0,
            bytes_processed = 0;
    int content_bytes_left = 0;
    int lp_output = 0;
    if (!buffer || !bytes) return 0;
    
    if (this->headers.complete()) {
        /* Here, we're just buffering content */
        content_bytes_left = this->content_length - this->body.length();
        if (bytes >= content_bytes_left ) {
            this->body.concat(buffer, content_bytes_left);
            if (this->is_complete()) this->process_request();
            return content_bytes_left;
        } else {
            this->body.concat(buffer, bytes);
            if (this->is_complete()) this->process_request();
            return bytes;
        }
    }
    for (; i < bytes; i++) {
        if (buffer[i] == '\n') { /* It's a new line character */
            if (i > 0 && buffer[i-1] == '\r') {
                i++;
                bytes_processed = i;
                lp_output = this->parse_line(&buffer[line_start], (i-line_start));
                if (lp_output == -1) {
                    return -1;
                }
                if (lp_output == 0) { /* This occurs when all the headers have been read! */
                    return (i+this->buffer_http(&buffer[bytes_processed], (bytes-bytes_processed)));
                }
                line_start = i; /* The next line starts at the NEXT octet */
            } else {
                /* There was a '\n', but NO '\r' */
                return -1; /* PROTOCOL ERROR */
            }
        }
    }
    if (this->is_complete()) this->process_request();
    return bytes_processed;
}

int HTTP::process_request( void ) {
    int retval = 1;
//    printf("\n--> HTTP::process_request() - Called to process a request!\n\n");
    if (!this->plistener) {
        printf("\n\nCall to HTTP::process_request() when no LISTENER class has been registered.\n\n");
        return 0;
    }
    if (!phttp_server) return 0;
    if (!this->is_request) {
        printf("\n\nHTTP::process_request() - Cannot process an HTTP message that isn't a request!\n\n");
        return 0;
    }
    http_lock(this->service.pmutex);
    this->service.owner = pthread_self();
    retval = phttp_server->add_job(this, &this->service);
    http_unlock(this->service.pmutex);
//    printf("\n-> HTTP::process_request() - returning 0x%x\n\n", retval);
    return retval;
}

int HTTP::check_buffer( const char *buffer, size_t bytes) {
    int i = 0, j = 0;
    for (; i < bytes; i++) {
        /* Each iteration will be further on down the byte stream */
        for (j = 0; j < HTTP_METHOD_COUNT; j++) {
            if (!strcmp(&buffer[i], HTTP_METHODS[j])) {
                return i;
            }
        }
    }
    return 0;
}

HTTP *HTTP::response( void ) {
    HTTP *retval = 0;
    if (!this->is_request) return 0;
    
    http_lock(this->service.pmutex);
    if (this->service.request_processed ) {
        retval = this->service.presponse;
    }
    http_unlock(this->service.pmutex);
    return retval;
}


int HTTP::is_processing( void ) {
    int retval = 0;
    http_lock(this->service.pmutex);
    retval = this->service.request_processed;
    http_unlock(this->service.pmutex);
    return retval;
}

/*********************************************************************************************************/
/*                                        HTTP SERVER THREADS                                            */
/*********************************************************************************************************/

HTTP_SERVER::HTTP_SERVER() {
    int i = 0;
    this->pthreads = 0;
    this->thread_mutex = 0;
    this->thread_size = 0;
    this->thread_mutex = http_new_mutex(1);
    if (!this->thread_mutex) return;
    for (; i < HTTP_SERVER_THREADS; i++) {
        this->start_thread();
    }
    http_unlock(this->thread_mutex);
}

/* Not going to free() or "delete" anything here because we're shutting down anyways */
HTTP_SERVER::~HTTP_SERVER() {
    int i = 0;
    PHTTP_SERVER_THREAD t = 0;
    
    http_lock(this->thread_mutex);
    for (; i < this->thread_size; i++) {
        t = &this->pthreads[i];
        if (t->okay_to_run) {
            t->okay_to_run = 0;
            if (t->available) { /* It's idle */
                sem_post(&t->new_http_available);
                HTTP_WAIT(t->alive == 0, 500) {
                    printf("HTTP_SERVER::server() thread shutdown successfully.\n");
                } else {
                    printf("*** ERROR, It took TOO LONG for HTTP_SERVER::server() to shutdown.\n");
                }
            } else { /* The thread is working right now... */
                sem_post(&t->new_http_available);
                HTTP_WAIT(t->alive == 0, 2000) {
                    printf("HTTP_SERVER::server() thread shutdown successfully.\n");
                } else {
                    printf("*** ERROR, It took TOO LONG a BUSY HTTP_SERVER::server() too long to shutdown...  > 2 seconds.\n");
                }
            }
        }
    }
    this->thread_size = 0;
    
    
    printf("^^^^  NEED TO SHUT DOWN ALL \"CGI\" THREADS HERE  ^^^^^\n\n");
    
    http_unlock(this->thread_mutex);
}


HTTP_SERVER_THREAD *HTTP_SERVER::start_thread( void ) {
    PHTTP_SERVER_THREAD swap = 0;
    size_t new_thread_count = 0;
    PHTTP_SERVER_THREAD r = 0;
    static int threads_started = 0;
    
    /* In here, this->thread_mutex is already locked so we have exclusive access to this->pthread */
    
    
    if (threads_started == 0 && !this->pthreads) {
        this->pthreads = (PHTTP_SERVER_THREAD) malloc(sizeof(HTTP_SERVER_THREAD) * HTTP_SERVER_THREADS);
        if (!this->pthreads) {
            return 0;
        }
        this->thread_size = HTTP_SERVER_THREADS;
        memset(this->pthreads, 0, sizeof(HTTP_SERVER_THREAD));
    }
    
    if (threads_started < HTTP_SERVER_THREADS ) {
        r = &this->pthreads[threads_started];
        r->alive = 0;
        r->available = 0;
        r->fundamental = 1;
        r->okay_to_run = 1;
        if (sem_init(&r->new_http_available, 0, 0) == -1) {
            printf("**** HTTP_SERVER::start_thread() - Failed to create 'new_http_available' semaphore!.\n\n");
            return 0;
        }
        
        if (!pthread_create(&r->thread_id, 0, &HTTP_SERVER::server, (void *)r)) {
            HTTP_WAIT( r->available, 1000 ) {
                threads_started++;
            } else {
                sem_post(&r->new_http_available);
                printf("**** HTTP_SERVER::start_thread() - Waited ONE second for server() thread to let us know it was okay.  It didn't.\n\n");
                r->fundamental = 0;
                r->okay_to_run = 0;
            }
        } else {
            printf("**** HTTP_SERVER::start_thread() - Failed to start server() thread!\n\n");
            r->fundamental = 0;
            r->okay_to_run = 0;
        }
    } else { /* We're adding a new thread! */
        new_thread_count = this->thread_size + 20;
        swap = (PHTTP_SERVER_THREAD)realloc(this->pthreads, sizeof(HTTP_SERVER_THREAD) * new_thread_count);
        if (!swap) return 0;
        memset(&swap[this->thread_size], 0, new_thread_count - this->thread_size);
        this->pthreads = swap;
        this->thread_size = new_thread_count;
        HTTP_SERVER_THREADS = new_thread_count;
        return this->start_thread();
    }
    return r;
}

int HTTP_SERVER::add_job( HTTP *http_to_process, PHTTP_S_INTERFACE si ) {
    int retval = 0, i = 0;
    HTTP_SERVER_THREAD *at = 0;
//    printf("\n-> HTTP_SERVER::add_job() - Called to assign a job to an HTTP_SERVER service thread!\n\n");
    http_lock(phttp_server->thread_mutex);
    for (; i < phttp_server->thread_size; i++) {
        at = &phttp_server->pthreads[i];
        if (at->alive && at->available) {
            at->http_to_process = http_to_process;
            at->pservice_interface = si;
            sem_post(&at->new_http_available);
            retval = 1; /* Job was assigned */
            break;
        }
    }
    if (i == phttp_server->thread_size) { /* All worker threads were busy.  Spawn a new one. */
        
        at = this->start_thread();
        if (at) {
            at->http_to_process = http_to_process;
            at->pservice_interface = si;
            sem_post(&at->new_http_available);
            retval = 1; /* Job was assigned */
        }
    }
    http_unlock(phttp_server->thread_mutex);
    return retval;
}

void *HTTP_SERVER::server( void *p ) {
    HTTP_SERVER_THREAD *thread = (HTTP_SERVER_THREAD *)p;
    HTTP *job = 0, *response = 0;
    HTTP_S_INTERFACE *intf = 0;
    struct sigaction sigact;
    
    if (!p) return 0;
    
    memset(&sigact, 0, sizeof(struct sigaction));
    sigact.sa_handler = &http_server_thread_signal_handler;
    sigaction(SIGUSR1, &sigact, NULL);
    sigaction(SIGUSR2, &sigact, NULL);
    sigaction(SIGPIPE, &sigact, NULL);
    
    thread->http_to_process = 0;
    thread->alive = 1;
    while (thread->okay_to_run) {
        thread->available = 1;
        sem_wait(&thread->new_http_available);
        thread->available = 0;
        job = thread->http_to_process;
        thread->http_to_process = 0;
        if (job) {
            printf("\n-> HTTP_SERVER::server() - New request to process!\n\n");
            intf = thread->pservice_interface;
            if (intf) {
                thread->pservice_interface = 0;
                intf->pserver_thread  = thread; /* Let the HTTP object (and by proxy the underlying conneciton) know WHO is processing its request */
            
                /* Process HTTP here! */

                
                
                printf("\n-> HTTP_SERVER::server() - Creating a new HTTP object for the response.\n\n");
                response = new HTTP( job->plistener ); /* Create the response object */
                printf("\n-> HTTP_SERVER::server() - DONE creating a new HTTP object for the response.\n\n");
                
                
            }
            /* Gain exlusive lock on HTTP resources and either mark it as served, or free it up */
            http_lock(intf->pmutex);
            intf->presponse = response;
            if (!intf->connection_valid) { /* The underlying connection has been shut down. */
                printf("****** HTTP_SERVER::server() - Done processing HTTP request.  The underlying connection was invalid so we're freeing the HTTP object\n");
                http_free_mutex(intf->pmutex);
                delete job;
                job = 0;
            } else {
                printf("****** HTTP_SERVER::server() - Done processing HTTP request.  Posting SIGUSR2 signal to thread 0x%x\n", intf->owner);
                pthread_kill(intf->owner, SIGUSR2);
                intf->pserver_thread = 0;       /* Take the reference to this thread */
                intf->request_processed = 1;
                http_unlock(intf->pmutex);
            }
        }
        
        job = 0;
        intf = 0; /* Pointer to the HTTP object's service interface */
        response = 0;
        
        
        
        
        
    }
    thread->alive = 0;
    return 0;
}

void HTTP_SERVER::START_SERVER( void ) {
    if (phttp_server) return;
    phttp_server = new HTTP_SERVER();
}

void HTTP_SERVER::START_SERVER( int initial_server_threads ) {
    if (phttp_server) return;
    HTTP_SERVER_THREADS = initial_server_threads;
    phttp_server = new HTTP_SERVER();
}



















/***** HTTP MUTEX FUNCTIONS *********************************************************************************/

int http_retire_mutex( PHTTP_MUTEX m ) {
    int r = 0;
    if (!m) return HTTP_INVALID_ARG;

    r = http_lock(m);
    if (r != HTTP_SUCCESS && r != HTTP_MUTEX_ALREADY_OWNED) {
        return r;
    }
    
    m->mutex_valid = 0;
    http_unlock(m);
    
    if (!pthread_mutex_destroy(&m->mutex)) {
        return HTTP_SUCCESS;
    }
    return HTTP_ERROR_MUTEX_FAILED;
}

int http_free_mutex( PHTTP_MUTEX m ) {
    int r = 0;
    if (!m) return HTTP_INVALID_ARG;
    
    if (m->mutex_valid == 1) {
        r = http_retire_mutex(m);
        if (r!=HTTP_SUCCESS) {
            return r;
        }
    }
    free(m);
    return HTTP_SUCCESS;
}

PHTTP_MUTEX http_new_mutex( int lock_now ) {
    pthread_mutexattr_t mta;
    PHTTP_MUTEX mtx = (PHTTP_MUTEX)malloc(sizeof(HTTP_MUTEX));
    if (!mtx) return HTTP_INVALID_MUTEX;
    mtx->current_owner = 0;
    mtx->mutex_valid = 0;
    
    pthread_mutexattr_init(&mta);
    pthread_mutexattr_settype(&mta, PTHREAD_MUTEX_DEFAULT);
    
    if (!pthread_mutex_init(&mtx->mutex, 0)) {
        if (lock_now) {
            if (!pthread_mutex_lock(&mtx->mutex)) {
                mtx->current_owner = pthread_self();
                mtx->mutex_valid = 1;
                return mtx;
            }
        }
        mtx->mutex_valid = 1;
        return mtx;
    }
    free(mtx);
    return HTTP_INVALID_MUTEX;
}

int http_lock( PHTTP_MUTEX m ) {
    pthread_t this_thread = pthread_self();
    if (!m) return HTTP_INVALID_ARG;
    if (!m->mutex_valid) {
        return HTTP_ERROR_INVALID_MUTEX;
    }
    if (m->current_owner == this_thread) {
        m->lock_count++;
        return HTTP_MUTEX_ALREADY_OWNED;
    }
    if (!pthread_mutex_lock(&m->mutex)) {
        m->lock_count = 0;
        m->current_owner = this_thread;
        return HTTP_SUCCESS;
    }
    return HTTP_ERROR_MUTEX_FAILED;
}

int http_unlock( PHTTP_MUTEX m ) {
    pthread_t this_thread = pthread_self();
    if (!m) return HTTP_INVALID_ARG;
    if (m->current_owner != this_thread) {
        return HTTP_ERROR_NOT_OWNED;
    }
    
    /* If the current owner is trying to unlock it, and this is its last lock */
    if (m->current_owner == this_thread && m->lock_count == 0) {
        m->current_owner = 0;
    }
    
    if (m->lock_count > 0) {
        m->lock_count--;
        return HTTP_SUCCESS;
    }
    
    /* Here, we know the owning thread is trying to unlock the mutex */
    
    /* Go ahead and clear the owner before the OS unlocks the 
     * mutex to avoid race conditions.
     */
    if (!pthread_mutex_unlock(&m->mutex)) {
        return HTTP_SUCCESS;
    }
    /* We've fail to unlock the mutex, set its owner back */
    m->current_owner = this_thread;
    return HTTP_ERROR_MUTEX_FAILED;
}
