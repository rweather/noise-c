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

#ifndef __SIMPLE_SYMMETRICSTATE_H__
#define __SIMPLE_SYMMETRICSTATE_H__

#include "simple-cipherstate.h"

#define MAX_HASHLEN 64

typedef struct
{
    CipherState cipher;
    NoiseHashState *hash;
    uint8_t ck[MAX_HASHLEN];
    uint8_t h[MAX_HASHLEN];
    size_t hash_len;

} SymmetricState;

void SymmetricState_new(SymmetricState *symmetric);
void SymmetricState_free(SymmetricState *symmetric);
void InitializeSymmetric(SymmetricState *symmetric, const char *protocol_name);
void MixKey(SymmetricState *symmetric, const uint8_t *data, size_t len);
void MixHash(SymmetricState *symmetric, const uint8_t *data, size_t len);
Buffer EncryptAndHash(SymmetricState *symmetric, const Buffer plaintext);
int DecryptAndHash(SymmetricState *symmetric, const Buffer ciphertext, Buffer *result);
void Split(SymmetricState *symmetric, const Buffer ssk, CipherState *c1, CipherState *c2);

#endif
