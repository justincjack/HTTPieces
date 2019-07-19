#include "nb_ssl_wrappers.h"
/* SSL Wrapper functions.  Maybe transfer to another file *********************************************************/

int ssl_accept( SSL *ssl ) {
    int r = 0;
    do {
        r = SSL_accept(ssl);
    }
    while ( (r < 0) && (SSL_get_error(ssl, r) == SSL_ERROR_WANT_ACCEPT) );
    return r;
}


/******************************************************************************************************************/
