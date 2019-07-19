// md5.h
#ifndef MD5_H
#define MD5_H

#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef struct {
    uint32_t lo, hi;
    uint32_t a, b, c, d;
    uint8_t buffer[64];
    uint32_t block[16];
} md5_CTX;


#define md5( ptr ) md5_gen((char *)ptr)

#ifdef __cplusplus
extern "C" {
#endif
    void md5_init(md5_CTX *ctx);
    void md5_update(md5_CTX *ctx, uint8_t *data, unsigned long size);
    void md5_final(uint8_t *result, md5_CTX *ctx);
    char *md5_gen(char *in );
    static inline void *md5_body(md5_CTX *ctx, uint8_t *data, unsigned long size);
#ifdef __cplusplus
}
#endif

#define F(x, y, z)            ((z) ^ ((x) & ((y) ^ (z))))
#define G(x, y, z)            ((y) ^ ((z) & ((x) ^ (y))))
#define H(x, y, z)            ((x) ^ (y) ^ (z))
#define I(x, y, z)            ((y) ^ ((x) | ~(z)))

#define STEP(f, a, b, c, d, x, t, s) \
(a) += f((b), (c), (d)) + (x) + (t); \
(a) = (((a) << (s)) | (((a) & 0xffffffff) >> (32 - (s)))); \
(a) += (b);

#if defined(__i386__) || defined(__x86_64__) || defined(__vax__)
#define SET(n) \
(*(uint32_t *)&ptr[(n) * 4])
#define GET(n) \
SET(n)
#else
#define SET(n) \
(ctx->block[(n)] = \
(md5_u32plus)ptr[(n) * 4] | \
((md5_u32plus)ptr[(n) * 4 + 1] << 8) | \
((md5_u32plus)ptr[(n) * 4 + 2] << 16) | \
((md5_u32plus)ptr[(n) * 4 + 3] << 24))
#define GET(n) \
(ctx->block[(n)])
#endif

#endif



