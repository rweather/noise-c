/*
 * Copyright (C) 2016 Southern Storm Software, Pty Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#ifndef NOISE_INTERNAL_H
#define NOISE_INTERNAL_H

#include <noise/noise.h>

#ifdef __cplusplus
extern "C" {
#endif

struct NoiseCipherState_s
{
    size_t size;
    int cipher_id;
    int has_key;
    size_t key_len;
    size_t mac_len;
    uint64_t n;

    NoiseCipherState *(*create)(void);
    void (*init_key)(NoiseCipherState *state, const uint8_t *key);
    int (*encrypt)(NoiseCipherState *state, const uint8_t *ad, size_t ad_len,
                   uint8_t *data, size_t len);
    int (*decrypt)(NoiseCipherState *state, const uint8_t *ad, size_t ad_len,
                   uint8_t *data, size_t len);
};

struct NoiseHashState_s
{
    size_t size;
    int hash_id;
    size_t hash_len;
    size_t block_len;

    void (*reset)(NoiseHashState *state);
    void (*update)(NoiseHashState *state, const uint8_t *data, size_t len);
    void (*finalize)(NoiseHashState *state, uint8_t *hash);
    void (*clean)(NoiseHashState *state);
};

typedef struct
{
    int id;
    const char *name;
    size_t name_len;

} NoiseIdMapping;

#define noise_new(type) ((type *)noise_calloc(sizeof(type)))
void *noise_calloc(size_t size);
void noise_free(void *ptr, size_t size);

void noise_clean(void *data, size_t size);
int noise_secure_is_equal(const void *s1, const void *s2, size_t size);

void noise_rand_bytes(void *bytes, size_t size);

int noise_map_name(const char *name, size_t name_len,
                   const NoiseIdMapping *mappings);

NoiseCipherState *noise_chachapoly_new(void);
NoiseCipherState *noise_aesgcm_new(void);

NoiseHashState *noise_blake2s_new(void);
NoiseHashState *noise_blake2b_new(void);
NoiseHashState *noise_sha256_new(void);
NoiseHashState *noise_sha512_new(void);

#ifdef __cplusplus
};
#endif

#endif
