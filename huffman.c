#include "huffman.h"
#include <stdio.h>
void huffman_zero_mem( void *ptr, size_t length ) {
    int i = 0;
    
    union _hmzs_ {
        void *_void;
        uint8_t *_char;
        uint16_t *_short;
        uint32_t *_long;
        uint64_t *_ull;
    } zs = {
        ._void = ptr
    };
    
//    printf("\nZeroing %zu bytes\n", length);
    
    if ( length % 8 == 0 && huffman_bits == 64) {
//        printf("\n\n Writing 8 bytes %zu times\n\n", (length/8));
        for (; i < length/8; i++) zs._ull[i] = (uint64_t)0x0000000000000000;
    } else if (length % 4 == 0) {
//        printf("\n\n Writing 4 bytes %zu times\n\n", (length/4));
        for (; i < length/4; i++) zs._long[i] = (uint32_t)0x00000000;
    } else if (length % 2 == 0) {
//        printf("\n\n Writing 2 bytes %zu times\n\n", (length/2));
        for (; i < length/2; i++) zs._short[i] = (uint16_t)0x0000;
    } else {
//        printf("\n\n Writing 1 bytes %zu times\n\n", (length));
        for (; i < length; i++) zs._char[i] = (uint8_t)0x00;;
    }
    return;
}

int prep_hpack_compression( void ) {
    phpack_table_deocde_sorted = (struct _hpack_table *)malloc(HPACK_BYTES);
    if (!phpack_table_deocde_sorted) {
        return HUFFMAN_NO_MEMORY;
    }
    if (!memcpy((void *)phpack_table_deocde_sorted, (void *)hpack_table, HPACK_BYTES)) {
        free(phpack_table_deocde_sorted);
        return HUFFMAN_INIT_ERROR;
    }
    qsort(phpack_table_deocde_sorted, HPACK_SIZE, HPACK_LEN, &sort_hpack_by_freq );
    return HUFFMAN_SUCCESS;
}

inline int sort_hpack_by_freq( const void *a, const void *b) {
    return ((struct _hpack_table *)a)->bits - ((struct _hpack_table *)b)->bits;
}

uint8_t *compress(const uint8_t *input, int inlen, int *outlen) {
    int i = 0, block = 0;
    unsigned long long bits_set = 0, bits_left = 0, bits_this_pass = 0;
    uint8_t *swap = 0, *ob = 0, val_to_write = 0;
    size_t len = 0, rmd = 0;
    const struct _hpack_table *tbl = 0;
    if (!outlen) return 0;
    *outlen = 0;
    if (!input || inlen <= 0) return 0;
    len = (int)((double)inlen * (double)1.25); /* Allocate 25% more space as a guesstimate */
    
    rmd = len%4;
    if (rmd) len+=(4-rmd);
    ob = (uint8_t *)malloc( len );
    
    huffman_zero_mem(ob, len);
    
    for (i=0; i < inlen; i++) {
        tbl = &hpack_table[input[i]];
        bits_left = tbl->bits;
        do {
            block = (bits_set/8);
            if (block==len) {
                swap = (uint8_t *)realloc(ob, len+100);
                if (!swap) {
                    free(ob);
                    *outlen = 0;
                    return 0;
                }
                huffman_zero_mem(swap+len, 100);
                len+=100;
                ob=swap;
            }
            rmd = (bits_set % 8);
            bits_this_pass = ((bits_left <= (8-rmd))?bits_left:(8-rmd));
            val_to_write = (uint32_t)(tbl->value >> (bits_left-bits_this_pass));
            val_to_write<<=((8-bits_this_pass)-rmd);
            ob[block]|=val_to_write;
            bits_set+=bits_this_pass;
            bits_left = bits_left - bits_this_pass;
        } while (bits_left);
        if (i == inlen-1) {
            rmd = bits_set%8;
            if (rmd) {
                rmd = 8-rmd;
                ob[block]|=0xff >> (8-rmd);
            }
            *outlen = (block+1);
        }
    }
    return ob;
}


int decompress(const uint8_t *input, int inlen, char **output, size_t *out_len) {
    uint8_t  _char = 0;
    uint16_t _short = 0;
    uint32_t _long = 0;
    int i = 0;
    int charpos = 0;
    int bits_done = 0;
    int bit_offset = 0;
    int bits_left = 0;
    int bits_total = (inlen*8);
    size_t written = 0;
    char *ob = *output, *swap = 0;
    size_t outlen = 0;
    
    
    if (!out_len) return HUFFMAN_INIT_ERROR;
    
    outlen = *out_len;
    
    
    
    if (!phpack_table_deocde_sorted) {
        if (!prep_hpack_compression()) return HUFFMAN_INIT_ERROR;
    }
    
    if (!ob) {
        outlen = inlen*2;
        ob = (char *)malloc(inlen*2);
        *output = ob;
        if (!ob) {
            *out_len = 0;
            return HUFFMAN_NO_MEMORY;
        }
        *out_len = outlen;
    }
    
    while (bits_done < bits_total) {
        charpos = bits_done/8;
        bit_offset = bits_done%8;
        bits_left = bits_total - bits_done;
        for (i = 0; i < HPACK_SIZE; i++) {
            if (bits_left < phpack_table_deocde_sorted[i].bits) {      /* We have fewer bits left than 
                                                                        * from this point in the huffman 
                                                                        * array going forward.  No need 
                                                                        * in continuing since it's 
                                                                        * sorted lowest to highest. This
                                                                        * means we're done decoding.
                                                                        */
                ob[written] = 0;
                *out_len = outlen;
                return (int)written;
            }
            if (written > outlen) { /* Check that we have enough space to populate the output buffer */
                swap = (char *)realloc(ob, outlen+1000);
                if (!swap) {
                    ob[written-1] = 0;
                    *out_len = outlen;
                    return HUFFMAN_NO_MEMORY; /* Out of memory! */
                }
                outlen+=1000;
                if (ob) free(ob);
                ob = swap;
                *output = ob;
            }
            if (phpack_table_deocde_sorted[i].bits <= 8) {
                /* 8 - bits */
                _char = input[charpos];
                _char <<= bit_offset;
                if (charpos+1 <= inlen) {
                    _char|=input[charpos+1]>>(8-bit_offset);
                }
                if ( (_char >> (8-phpack_table_deocde_sorted[i].bits) == phpack_table_deocde_sorted[i].value)) {
                    ob[written++] = (char)phpack_table_deocde_sorted[i].charval;
                    bits_done+=phpack_table_deocde_sorted[i].bits;
                    break;
                }
            } else if (phpack_table_deocde_sorted[i].bits <= 16) {
                /* 16 bits */
                _short = ntohs(*(uint16_t *)&input[charpos]);
                _short <<= bit_offset;
                if (charpos+2 <= inlen) {
                    _short|=ntohs(*(uint16_t *)&input[charpos+2])>>(16-bit_offset);
                }
                if ( (_short >> (16-phpack_table_deocde_sorted[i].bits) == phpack_table_deocde_sorted[i].value)) {
                    ob[written++] = (char)phpack_table_deocde_sorted[i].charval;
                    bits_done+=phpack_table_deocde_sorted[i].bits;
                    break;
                }
                
            } else if (phpack_table_deocde_sorted[i].bits <= 32) {
                /* 32 bits */
                _long = ntohl(*(uint32_t *)&input[charpos]);
                _long <<= bit_offset;
                if (charpos+4 <= inlen) {
                    _long|=ntohl(*(uint32_t *)&input[charpos+4])>>(32-bit_offset);
                }
                if ( (_long >> (32-phpack_table_deocde_sorted[i].bits) == phpack_table_deocde_sorted[i].value)) {
                    ob[written++] = (char)phpack_table_deocde_sorted[i].charval;
                    bits_done+=phpack_table_deocde_sorted[i].bits;
                    break;
                }
            } else {
                *out_len = outlen;
                return HUFFMAN_INTERNAL_ERROR;
            }
        }
        if (i == HPACK_SIZE )  {
            ob[written] = 0;
            *out_len = outlen;
            return (int)written;
        }
    }
    ob[written] = 0;
    *out_len = outlen;
    return (int)written;
}

