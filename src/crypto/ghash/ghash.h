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

#ifndef CRYPTO_GHASH_h
#define CRYPTO_GHASH_h

#include <stdint.h>
#include <stddef.h>

#if __WORDSIZE == 64 && !defined(GHASH_WORD64)
#define GHASH_WORD64 1
#endif

#if defined(GHASH_WORD64)

typedef struct {
    uint64_t H[2];
    uint64_t Y[2];
    uint8_t posn;
} ghash_state;

#else

typedef struct {
    uint32_t H[4];
    uint32_t Y[4];
    uint8_t posn;
} ghash_state;

#endif

void ghash_reset(ghash_state *state, const void *key);
void ghash_update(ghash_state *state, const void *data, size_t len);
void ghash_finalize(ghash_state *state, void *token, size_t len);
void ghash_pad(ghash_state *state);

#endif
