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

#include "simple-cipherstate.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void CipherState_new(CipherState *cipher, int id)
{
    int err;
    cipher->state = 0;
    err = noise_cipherstate_new_by_id(&(cipher->state), id);
    if (err != NOISE_ERROR_NONE) {
        noise_perror("CipherState_new", err);
        exit(1);
    }
}

void CipherState_free(CipherState *cipher)
{
    noise_cipherstate_free(cipher->state);
    cipher->state = 0;
}

void InitializeKey(CipherState *cipher, const uint8_t *key, size_t key_len)
{
    if (key_len != 0) {
        int err = noise_cipherstate_init_key(cipher->state, key, key_len);
        if (err != NOISE_ERROR_NONE) {
            noise_perror("InitializeKey", err);
            exit(1);
        }
    }
}

int HasKey(const CipherState *cipher)
{
    return noise_cipherstate_has_key(cipher->state);
}

Buffer EncryptWithAd(CipherState *cipher, const Buffer ad, const Buffer plaintext)
{
    Buffer result;
    NoiseBuffer buf;
    int err;
    memcpy(result.data, plaintext.data, plaintext.size);
    result.size = plaintext.size;
    noise_buffer_set_inout(buf, result.data, result.size, sizeof(result.data));
    err = noise_cipherstate_encrypt_with_ad
        (cipher->state, ad.data, ad.size, &buf);
    if (err != NOISE_ERROR_NONE) {
        noise_perror("EncryptWithAd", err);
        exit(1);
    }
    result.size = buf.size;
    return result;
}

int DecryptWithAd(CipherState *cipher, const Buffer ad, const Buffer ciphertext, Buffer *result)
{
    NoiseBuffer buf;
    int err;
    memcpy(result->data, ciphertext.data, ciphertext.size);
    result->size = ciphertext.size;
    noise_buffer_set_inout(buf, result->data, result->size, sizeof(result->data));
    err = noise_cipherstate_decrypt_with_ad
        (cipher->state, ad.data, ad.size, &buf);
    if (err == NOISE_ERROR_MAC_FAILURE) {
        result->size = 0;
        return 0;
    } else if (err != NOISE_ERROR_NONE) {
        noise_perror("DecryptWithAd", err);
        exit(1);
    } else {
        result->size = buf.size;
    }
    return 1;
}
