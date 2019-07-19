#include "httpieces_version.h"

const char *version( void ) {
    static char v[100] = {0};
    if (v[0] == 0) {
        sprintf(v, "%d.%d.%d", VERSION.major, VERSION.minor, VERSION.patch);
    }
    return v;
}

const HTTPIECES_VERSION *get_version( void ) {
    return &VERSION;
}