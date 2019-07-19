#include "showbits.h"

int showbits( unsigned char c ) {
    int i = 0;
    unsigned char v = 128;
    for (i = 8; i > 0; i--) {
        if ((c&v)==v) printf("1"); else printf("0");
        v/=2;
    }
    return 0;
}


int show32bits( uint32_t c ) {
    int i = 0;
    uint32_t v = 0x80000000;
    for (i = 31; i >= 0; i--) {
        v=pow(2, i);
        if ((c&v)==v) printf("1"); else printf("0");
        if (i < 32 && i%8 == 0) printf(" ");
    }
    return 0;
}


int shownbits( unsigned char *c, int len ) {
    int i = 0, j = 0;
    unsigned char v;
    
    for (j = 0; j < len; j++) {
//        if (c[j] == 0) return 0;
        v = 128;
        for (i = 8; i > 0; i--) {
            if ((c[j]&v)==v) printf("1"); else printf("0");
            if (j == len) return 0;
            v/=2;
        }
        printf(" ");
    }
    return 0;
}

void showhex( uint8_t *in, int len) {
    int i = 0;
    for (; i < len; i++) {
        if (i > 0 && i%2==0) printf(" ");
        printf("%x", (uint8_t)in[i]);
    }
    printf("\n\n");
}