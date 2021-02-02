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

#include <string.h>

#include "internal.h"
#include "aes-gcm.h"
#include "malloc.h"

typedef struct
{
    struct NoiseCipherState_s parent;

  uint8_t k[32];
  size_t k_len;

  uint8_t iv[32];
  size_t iv_len;
} NoiseAESGCMState;

static void noise_aesgcm_init_key
    (NoiseCipherState *state, const uint8_t *key)
{

    NoiseAESGCMState *st = (NoiseAESGCMState *)state;

    memcpy(st->k, key, 32);
    st->k_len = 32;
}

#define PUT_UINT64_BE(buf, value) \
    do { \
        uint64_t _value = (value); \
        (buf)[0] = (uint8_t)(_value >> 56); \
        (buf)[1] = (uint8_t)(_value >> 48); \
        (buf)[2] = (uint8_t)(_value >> 40); \
        (buf)[3] = (uint8_t)(_value >> 32); \
        (buf)[4] = (uint8_t)(_value >> 24); \
        (buf)[5] = (uint8_t)(_value >> 16); \
        (buf)[6] = (uint8_t)(_value >> 8); \
        (buf)[7] = (uint8_t)_value; \
    } while (0)

/**
 * \brief Sets up the IV to start encrypting or decrypting a block.
 *
 * \param st The cipher state for AESGCM.
 */
static void noise_aesgcm_setup_iv(NoiseAESGCMState *st)
{
    /* The 96-bit nonce is formed by encoding 32 bits of zeros followed by big-endian encoding of n */
    memset(st->iv, 0, 4);
    PUT_UINT64_BE(st->iv + 4, st->parent.n);
    st->iv_len = 12;
}

static int noise_aesgcm_encrypt
    (NoiseCipherState *state, const uint8_t *ad, size_t ad_len,
     uint8_t *data, size_t len)
{
    NoiseAESGCMState *st = (NoiseAESGCMState *)state;
    uint8_t *tmp;

    tmp = malloc(len);
    if (!tmp) {
      return NOISE_ERROR_NO_MEMORY;
    }

    memcpy(tmp, data, len);
    noise_aesgcm_setup_iv(st);

    if (aes_gcm_ae(st->k, st->k_len, st->iv, st->iv_len, tmp, len, ad, ad_len,
    		   data /* cipher */, data + len /* tag */) < 0) {
      free(tmp);
      return NOISE_ERROR_MAC_FAILURE;
    }

    free(tmp);
    return NOISE_ERROR_NONE;
}

static int noise_aesgcm_decrypt
    (NoiseCipherState *state, const uint8_t *ad, size_t ad_len,
     uint8_t *data, size_t len)
{
    NoiseAESGCMState *st = (NoiseAESGCMState *)state;
    uint8_t *tmp;

    tmp = malloc(len);
    if (!tmp) {
      return NOISE_ERROR_NO_MEMORY;
    }
    memcpy(tmp, data, len);

    noise_aesgcm_setup_iv(st);
    if (aes_gcm_ad(st->k, st->k_len, st->iv, st->iv_len, tmp, len, ad, ad_len,
    		   data + len, data) < 0) {
      free(tmp);
      return NOISE_ERROR_MAC_FAILURE;
    }

    free(tmp);
    return NOISE_ERROR_NONE;
}

NoiseCipherState *noise_aesgcm_new_bolos(void)
{
    NoiseAESGCMState *state = noise_new(NoiseAESGCMState);
    if (!state)
        return 0;
    state->parent.cipher_id = NOISE_CIPHER_AESGCM;
    state->parent.key_len = 32;
    state->parent.mac_len = 16;
    state->parent.create = noise_aesgcm_new_bolos;
    state->parent.init_key = noise_aesgcm_init_key;
    state->parent.encrypt = noise_aesgcm_encrypt;
    state->parent.decrypt = noise_aesgcm_decrypt;
    return &(state->parent);
}
