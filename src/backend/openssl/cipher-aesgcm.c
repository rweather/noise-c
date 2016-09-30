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
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

typedef struct
{
    struct NoiseCipherState_s parent;
    EVP_CIPHER_CTX *ctx;

	uint8_t iv[12];
    uint8_t key[32];
} NoiseAESGCMState;

static void noise_aesgcm_init_key
    (NoiseCipherState *state, const uint8_t *key)
{
    NoiseAESGCMState *st = (NoiseAESGCMState *)state;

    memcpy(st->key, key, 32);
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
}

static int noise_aesgcm_encrypt(NoiseCipherState *state, const uint8_t *ad, size_t ad_len, uint8_t *data, size_t data_len)
{
    NoiseAESGCMState *st = (NoiseAESGCMState *)state;

    if (EVP_CIPHER_CTX_cleanup(st->ctx) <= 0) {
        ERR_clear_error();
        return NOISE_ERROR_SYSTEM;
    }

    noise_aesgcm_setup_iv(st);

    if (EVP_EncryptInit_ex(st->ctx, EVP_aes_256_gcm(), NULL, st->key, st->iv) != 1) {
        ERR_clear_error();
        return NOISE_ERROR_SYSTEM;
    }

    /* Provide any AAD data. This can be called zero or more times as
     * required
     */
    int len;
    if (ad_len > 0) {
        if (EVP_EncryptUpdate(st->ctx, NULL, &len, ad, ad_len) != 1) {
            ERR_clear_error();
            return NOISE_ERROR_SYSTEM;
        }
    }

    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    uint8_t out[data_len];
    if (EVP_EncryptUpdate(st->ctx, out, &len, data, data_len) != 1) {
        ERR_clear_error();
        return NOISE_ERROR_SYSTEM;
    }
    int ciphertext_len = len;

    /* Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if (EVP_EncryptFinal_ex(st->ctx, out + len, &len) != 1) {
        ERR_clear_error();
        return NOISE_ERROR_SYSTEM;
    }
    ciphertext_len += len;

    /* Get the tag */
    if (EVP_CIPHER_CTX_ctrl(st->ctx, EVP_CTRL_GCM_GET_TAG, 16, data + ciphertext_len) != 1) {
        ERR_clear_error();
        return NOISE_ERROR_SYSTEM;
    }

    memcpy(data, out, ciphertext_len);

    return NOISE_ERROR_NONE;
}

static int noise_aesgcm_decrypt(NoiseCipherState *state, const uint8_t *ad, size_t ad_len, uint8_t *data, size_t data_len)
{
    NoiseAESGCMState *st = (NoiseAESGCMState *)state;

    if (EVP_CIPHER_CTX_cleanup(st->ctx) <= 0) {
        ERR_clear_error();
        return NOISE_ERROR_SYSTEM;
    }

    noise_aesgcm_setup_iv(st);

    if (EVP_DecryptInit_ex(st->ctx, EVP_aes_256_gcm(), NULL, st->key, st->iv) != 1) {
        ERR_clear_error();
        return NOISE_ERROR_SYSTEM;
    }

    /* Provide any AAD data. This can be called zero or more times as
     * required
     */
    int len;
    if (ad_len > 0) {
        if (!EVP_DecryptUpdate(st->ctx, NULL, &len, ad, ad_len)) {
            ERR_clear_error();
            return NOISE_ERROR_SYSTEM;
        }
    }

    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if (!EVP_DecryptUpdate(st->ctx, data, &len, data, data_len)) {
        ERR_clear_error();
        return NOISE_ERROR_SYSTEM;
    }

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if (!EVP_CIPHER_CTX_ctrl(st->ctx, EVP_CTRL_GCM_SET_TAG, 16, data + len)) {
        ERR_clear_error();
        return NOISE_ERROR_SYSTEM;
    }

    /* Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    if (EVP_DecryptFinal_ex(st->ctx, data + len, &len) <= 0) {
        ERR_clear_error();
        return NOISE_ERROR_MAC_FAILURE;
    }

    return NOISE_ERROR_NONE;
}

void noise_aesgcm_free(NoiseCipherState *state)
{
    NoiseAESGCMState *st = (NoiseAESGCMState *)state;

    EVP_CIPHER_CTX_free(st->ctx);
}

NoiseCipherState *noise_aesgcm_new_openssl(void)
{
    NoiseAESGCMState *state = noise_new(NoiseAESGCMState);
    if (!state)
        return 0;
    if (!(state->ctx = EVP_CIPHER_CTX_new()))
        return 0;
    state->parent.cipher_id = NOISE_CIPHER_AESGCM;
    state->parent.key_len = 32;
    state->parent.mac_len = 16;
    state->parent.create = noise_aesgcm_new_openssl;
    state->parent.destroy = noise_aesgcm_free;
    state->parent.init_key = noise_aesgcm_init_key;
    state->parent.encrypt = noise_aesgcm_encrypt;
    state->parent.decrypt = noise_aesgcm_decrypt;
    return &(state->parent);
}
