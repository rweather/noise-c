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

#include "simple-symmetricstate.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void SymmetricState_new(SymmetricState *symmetric)
{
    memset(symmetric, 0, sizeof(SymmetricState));
}

void SymmetricState_free(SymmetricState *symmetric)
{
    CipherState_free(&(symmetric->cipher));
    noise_hashstate_free(symmetric->hash);
}

void InitializeSymmetric(SymmetricState *symmetric, const char *protocol_name)
{
    NoiseProtocolId id;
    size_t name_len = strlen(protocol_name);
    int err;
    err = noise_protocol_name_to_id(&id, protocol_name, name_len);
    if (err != NOISE_ERROR_NONE) {
        noise_perror("InitializeSymmetric", err);
        exit(1);
    }
    CipherState_new(&(symmetric->cipher), id.cipher_id);
    err = noise_hashstate_new_by_id(&(symmetric->hash), id.hash_id);
    if (err != NOISE_ERROR_NONE) {
        noise_perror("CreateHash", err);
        exit(1);
    }
    symmetric->hash_len = noise_hashstate_get_hash_length(symmetric->hash);
    if (name_len <= symmetric->hash_len) {
        memcpy(symmetric->h, protocol_name, name_len);
        memset(symmetric->h + name_len, 0, symmetric->hash_len - name_len);
    } else {
        noise_hashstate_hash_one
            (symmetric->hash, (const uint8_t *)protocol_name, name_len,
             symmetric->h, symmetric->hash_len);
    }
    memcpy(symmetric->ck, symmetric->h, MAX_HASHLEN);
    InitializeKey(&(symmetric->cipher), 0, 0);
}

void MixKey(SymmetricState *symmetric, const uint8_t *data, size_t len)
{
    uint8_t key[32];
    noise_hashstate_hkdf(symmetric->hash, symmetric->ck, symmetric->hash_len,
                         data, len, symmetric->ck, symmetric->hash_len,
                         key, sizeof(key));
    InitializeKey(&(symmetric->cipher), key, sizeof(key));
}

void MixHash(SymmetricState *symmetric, const uint8_t *data, size_t len)
{
    noise_hashstate_hash_two(symmetric->hash, symmetric->h, symmetric->hash_len,
                             data, len, symmetric->h, symmetric->hash_len);
}

Buffer EncryptAndHash(SymmetricState *symmetric, const Buffer plaintext)
{
    Buffer result;
    Buffer ad;
    memcpy(ad.data, symmetric->h, symmetric->hash_len);
    ad.size = symmetric->hash_len;
    result = EncryptWithAd(&(symmetric->cipher), ad, plaintext);
    MixHash(symmetric, result.data, result.size);
    return result;
}

int DecryptAndHash(SymmetricState *symmetric, const Buffer ciphertext, Buffer *result)
{
    Buffer ad;
    memcpy(ad.data, symmetric->h, symmetric->hash_len);
    ad.size = symmetric->hash_len;
    MixHash(symmetric, ciphertext.data, ciphertext.size);
    return DecryptWithAd(&(symmetric->cipher), ad, ciphertext, result);
}

void Split(SymmetricState *symmetric, const Buffer ssk, CipherState *c1, CipherState *c2)
{
    uint8_t temp_k1[32];
    uint8_t temp_k2[32];
    int id = noise_cipherstate_get_cipher_id(symmetric->cipher.state);
    noise_hashstate_hkdf(symmetric->hash, symmetric->ck, symmetric->hash_len,
                         ssk.data, ssk.size, temp_k1, sizeof(temp_k1),
                         temp_k2, sizeof(temp_k2));
    CipherState_new(c1, id);
    CipherState_new(c2, id);
    InitializeKey(c1, temp_k1, sizeof(temp_k1));
    InitializeKey(c2, temp_k2, sizeof(temp_k2));
}
