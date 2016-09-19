
#ifndef CHACHA_H
#define CHACHA_H

#include <stddef.h>
#include <stdint.h>

#if defined(__SSE2__) && defined(__GNUC__) && __GNUC__ >= 4
#define USE_VECTOR_MATH 1
#ifdef __clang__
typedef uint32_t VectorUInt32 __attribute__((ext_vector_type(4)));
#else
typedef uint32_t VectorUInt32 __attribute__((__vector_size__(16)));
#endif
#else
#undef USE_VECTOR_MATH
#endif

typedef struct
{
#ifdef USE_VECTOR_MATH
    VectorUInt32 input[4];
#else
    uint32_t input[16];
#endif

} chacha_ctx;

extern void chacha_keysetup(chacha_ctx *x,const uint8_t *k,uint32_t kbits);
extern void chacha_ivsetup(chacha_ctx *x,const uint8_t *iv,const uint8_t *counter);
extern void chacha_encrypt_bytes(chacha_ctx *x,const uint8_t *m,uint8_t *c,uint32_t bytes);

#endif
