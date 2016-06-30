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

#ifndef NOISE_HASHSTATE_H
#define NOISE_HASHSTATE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct NoiseHashState_s NoiseHashState;

int noise_hashstate_new_by_id(NoiseHashState **state, int id);
int noise_hashstate_new_by_name(NoiseHashState **state, const char *name);
int noise_hashstate_free(NoiseHashState *state);
int noise_hashstate_get_hash_id(const NoiseHashState *state);
size_t noise_hashstate_get_hash_length(const NoiseHashState *state);
size_t noise_hashstate_get_block_length(const NoiseHashState *state);
int noise_hashstate_reset(NoiseHashState *state);
int noise_hashstate_update
    (NoiseHashState *state, const uint8_t *data, size_t data_len);
int noise_hashstate_finalize
    (NoiseHashState *state, uint8_t *hash, size_t hash_len);
int noise_hashstate_hash_one
    (NoiseHashState *state, const uint8_t *data, size_t data_len,
     uint8_t *hash, size_t hash_len);
int noise_hashstate_hash_two
    (NoiseHashState *state, const uint8_t *data1, size_t data1_len,
     const uint8_t *data2, size_t data2_len, uint8_t *hash, size_t hash_len);
int noise_hashstate_hkdf
    (NoiseHashState *state, const uint8_t *key, size_t key_len,
     const uint8_t *data, size_t data_len,
     uint8_t *output1, size_t output1_len,
     uint8_t *output2, size_t output2_len);
int noise_hashstate_pbkdf2
    (NoiseHashState *state, const uint8_t *passphrase, size_t passphrase_len,
     const uint8_t *salt, size_t salt_len, size_t iterations,
     uint8_t *output, size_t output_len);
int noise_hashstate_get_max_hash_length(void);
int noise_hashstate_get_max_block_length(void);

#ifdef __cplusplus
};
#endif

#endif
