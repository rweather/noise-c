
#ifndef CHACHA_H
#define CHACHA_H

#include <stddef.h>
#include <stdint.h>

typedef struct
{
    uint32_t input[16];

} chacha_ctx;

extern void chacha_keysetup(chacha_ctx *x,const uint8_t *k,uint32_t kbits);
extern void chacha_ivsetup(chacha_ctx *x,const uint8_t *iv,const uint8_t *counter);
extern void chacha_encrypt_bytes(chacha_ctx *x,const uint8_t *m,uint8_t *c,uint32_t bytes);

#endif
