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

#ifndef __SIMPLE_CIPHERSTATE_H__
#define __SIMPLE_CIPHERSTATE_H__

#include <noise/protocol.h>

#define MAX_BUFLEN 4096

typedef struct
{
    uint8_t data[MAX_BUFLEN];
    size_t size;

} Buffer;

typedef struct
{
    NoiseCipherState *state;

} CipherState;

void CipherState_new(CipherState *cipher, int id);
void CipherState_free(CipherState *cipher);
void InitializeKey(CipherState *cipher, const uint8_t *key, size_t key_len);
int  HasKey(const CipherState *cipher);
Buffer EncryptWithAd(CipherState *cipher, const Buffer ad, const Buffer plaintext);
int DecryptWithAd(CipherState *cipher, const Buffer ad, const Buffer ciphertext, Buffer *result);

#endif
