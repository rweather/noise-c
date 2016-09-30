/*
 * Copyright (C) 2016 Southern Storm Software, Pty Ltd.
 * Copyright (C) 2016 Topology LP.
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

#include "internal.h"
#include <sodium.h>
#include <string.h>

typedef struct
{
    struct NoiseCipherState_s parent;
    crypto_aead_aes256gcm_state context;
    uint8_t nonce[crypto_aead_aes256gcm_NPUBBYTES];
    uint8_t key[crypto_aead_aes256gcm_KEYBYTES];
} NoiseAESGCMState;

static void noise_aesgcm_init_key
    (NoiseCipherState *state, const uint8_t *key)
{
    NoiseAESGCMState *st = (NoiseAESGCMState *)state;

    memcpy(st->key, key, crypto_aead_aes256gcm_KEYBYTES);
    crypto_aead_aes256gcm_beforenm(&st->context, key);
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
    memset(st->nonce, 0, 4);
    PUT_UINT64_BE(st->nonce + 4, st->parent.n);
}

static int noise_aesgcm_encrypt
    (NoiseCipherState *state, const uint8_t *ad, size_t ad_len,
     uint8_t *data, size_t len)
{
    NoiseAESGCMState *st = (NoiseAESGCMState *)state;
    noise_aesgcm_setup_iv(st);
    crypto_aead_aes256gcm_encrypt_afternm(data, NULL, data, len, ad, ad_len, NULL, st->nonce, &st->context);
    return NOISE_ERROR_NONE;
}

static int noise_aesgcm_decrypt
    (NoiseCipherState *state, const uint8_t *ad, size_t ad_len,
     uint8_t *data, size_t len)
{
    NoiseAESGCMState *st = (NoiseAESGCMState *)state;
    noise_aesgcm_setup_iv(st);
    if (crypto_aead_aes256gcm_decrypt_afternm(data, NULL, NULL, data, len + crypto_aead_aes256gcm_ABYTES, ad, ad_len, st->nonce, &st->context) < 0)
        return NOISE_ERROR_MAC_FAILURE;
    return NOISE_ERROR_NONE;
}

NoiseCipherState *noise_aesgcm_new_sodium(void)
{
    NoiseAESGCMState *state = noise_new(NoiseAESGCMState);
    if (!state)
        return 0;
    state->parent.cipher_id = NOISE_CIPHER_AESGCM;
    state->parent.key_len = crypto_aead_aes256gcm_KEYBYTES;
    state->parent.mac_len = crypto_aead_aes256gcm_ABYTES;
    state->parent.create = noise_aesgcm_new_sodium;
    state->parent.init_key = noise_aesgcm_init_key;
    state->parent.encrypt = noise_aesgcm_encrypt;
    state->parent.decrypt = noise_aesgcm_decrypt;
    return &(state->parent);
}
