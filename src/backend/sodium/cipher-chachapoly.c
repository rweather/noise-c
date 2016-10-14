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
    uint8_t chacha_k[crypto_stream_chacha20_KEYBYTES];
    uint8_t chacha_n[crypto_stream_chacha20_IETF_NONCEBYTES];
    crypto_onetimeauth_poly1305_state poly1305;
    uint8_t block[64];

} NoiseChaChaPolyState;

static void noise_chachapoly_init_key
    (NoiseCipherState *state, const uint8_t *key)
{
    NoiseChaChaPolyState *st = (NoiseChaChaPolyState *)state;
    memcpy(st->chacha_k, key, crypto_stream_chacha20_KEYBYTES);
}

#define PUT_UINT64_LE(buf, value) \
    do { \
        (buf)[0] = (uint8_t)(value); \
        (buf)[1] = (uint8_t)((value) >> 8); \
        (buf)[2] = (uint8_t)((value) >> 16); \
        (buf)[3] = (uint8_t)((value) >> 24); \
        (buf)[4] = (uint8_t)((value) >> 32); \
        (buf)[5] = (uint8_t)((value) >> 40); \
        (buf)[6] = (uint8_t)((value) >> 48); \
        (buf)[7] = (uint8_t)((value) >> 56); \
    } while (0)

/**
 * \brief Sets up a ChaChaPoly context to encrypt/decrypt a block.
 *
 * \param st The encryption state for ChaChaPoly.
 * \param n The nonce for this block.
 */
static void noise_chachapoly_setup(NoiseChaChaPolyState *st, uint64_t n)
{
    /* The 96-bit nonce is formed by encoding 32 bits of zeros followed by little-endian encoding of n */
    memset(st->chacha_n, 0, 4);
    PUT_UINT64_LE(st->chacha_n + 4, n);

    /* Encrypt an initial block to create the Poly1305 key */
    memset(st->block, 0, 64);
    crypto_stream_chacha20_ietf_xor(st->block, st->block, 64, st->chacha_n, st->chacha_k);
    crypto_onetimeauth_poly1305_init(&(st->poly1305), st->block);
    noise_clean(st->block, sizeof(st->block));
}

/**
 * \brief Pads the Poly1305 input to a multiple of 16 bytes.
 *
 * \param st The encryption state for ChaChaPoly.
 * \param len The length of the input that needs to be padded.
 */
static void noise_chachapoly_pad_auth(NoiseChaChaPolyState *st, size_t len)
{
    len %= 16;
    if (len) {
        static uint8_t const padding[16] = {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        };
        crypto_onetimeauth_poly1305_update(&(st->poly1305), padding, 16 - len);
    }
}

/**
 * \brief Finalize the Poly1305 hash by adding the lengths.
 *
 * \param st The encryption state for ChaChaPoly.
 * \param ad_len The length of the associated data.
 * \param data_len The length of the ciphertext.
 */
static void noise_chachapoly_auth_lengths
    (NoiseChaChaPolyState *st, uint64_t ad_len, uint64_t data_len)
{
    PUT_UINT64_LE(st->block, ad_len);
    PUT_UINT64_LE(st->block + 8, data_len);
    crypto_onetimeauth_poly1305_update(&(st->poly1305), st->block, 16);
}

static int noise_chachapoly_encrypt
    (NoiseCipherState *state, const uint8_t *ad, size_t ad_len,
     uint8_t *data, size_t len)
{
    NoiseChaChaPolyState *st = (NoiseChaChaPolyState *)state;
    noise_chachapoly_setup(st, state->n);
    if (ad_len) {
        crypto_onetimeauth_poly1305_update(&(st->poly1305), ad, ad_len);
        noise_chachapoly_pad_auth(st, ad_len);
    }
    crypto_stream_chacha20_ietf_xor_ic(data, data, len, st->chacha_n, 1U, st->chacha_k);
    crypto_onetimeauth_poly1305_update(&(st->poly1305), data, len);
    noise_chachapoly_pad_auth(st, len);
    noise_chachapoly_auth_lengths(st, ad_len, len);
    crypto_onetimeauth_poly1305_final(&(st->poly1305), data + len);
    return NOISE_ERROR_NONE;
}

static int noise_chachapoly_decrypt
    (NoiseCipherState *state, const uint8_t *ad, size_t ad_len,
     uint8_t *data, size_t len)
{
    NoiseChaChaPolyState *st = (NoiseChaChaPolyState *)state;
    noise_chachapoly_setup(st, state->n);
    if (ad_len) {
        crypto_onetimeauth_poly1305_update(&(st->poly1305), ad, ad_len);
        noise_chachapoly_pad_auth(st, ad_len);
    }
    crypto_onetimeauth_poly1305_update(&(st->poly1305), data, len);
    noise_chachapoly_pad_auth(st, len);
    noise_chachapoly_auth_lengths(st, ad_len, len);
    crypto_onetimeauth_poly1305_final(&(st->poly1305), st->block);
    if (!noise_is_equal(st->block, data + len, 16))
        return NOISE_ERROR_MAC_FAILURE;
    crypto_stream_chacha20_ietf_xor_ic(data, data, len, st->chacha_n, 1U, st->chacha_k);
    return NOISE_ERROR_NONE;
}

NoiseCipherState *noise_chachapoly_new(void)
{
    NoiseChaChaPolyState *state = noise_new(NoiseChaChaPolyState);
    if (!state)
        return 0;
    state->parent.cipher_id = NOISE_CIPHER_CHACHAPOLY;
    state->parent.key_len = crypto_stream_chacha20_KEYBYTES;
    state->parent.mac_len = crypto_onetimeauth_poly1305_BYTES;
    state->parent.create = noise_chachapoly_new;
    state->parent.init_key = noise_chachapoly_init_key;
    state->parent.encrypt = noise_chachapoly_encrypt;
    state->parent.decrypt = noise_chachapoly_decrypt;
    return &(state->parent);
}
