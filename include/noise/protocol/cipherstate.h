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

#ifndef NOISE_CIPHERSTATE_H
#define NOISE_CIPHERSTATE_H

#include <noise/protocol/buffer.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct NoiseCipherState_s NoiseCipherState;

int noise_cipherstate_new_by_id(NoiseCipherState **state, int id);
int noise_cipherstate_new_by_name(NoiseCipherState **state, const char *name);
int noise_cipherstate_free(NoiseCipherState *state);
int noise_cipherstate_get_cipher_id(const NoiseCipherState *state);
size_t noise_cipherstate_get_key_length(const NoiseCipherState *state);
size_t noise_cipherstate_get_mac_length(const NoiseCipherState *state);
int noise_cipherstate_init_key
    (NoiseCipherState *state, const uint8_t *key, size_t key_len);
int noise_cipherstate_has_key(const NoiseCipherState *state);
int noise_cipherstate_encrypt_with_ad
    (NoiseCipherState *state, const uint8_t *ad, size_t ad_len,
     NoiseBuffer *buffer);
int noise_cipherstate_decrypt_with_ad
    (NoiseCipherState *state, const uint8_t *ad, size_t ad_len,
     NoiseBuffer *buffer);
int noise_cipherstate_encrypt(NoiseCipherState *state, NoiseBuffer *buffer);
int noise_cipherstate_decrypt(NoiseCipherState *state, NoiseBuffer *buffer);
int noise_cipherstate_set_nonce(NoiseCipherState *state, uint64_t nonce);
int noise_cipherstate_get_max_key_length(void);
int noise_cipherstate_get_max_mac_length(void);

#ifdef __cplusplus
};
#endif

#endif
