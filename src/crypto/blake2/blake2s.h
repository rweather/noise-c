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

#ifndef BLAKE2s_H
#define BLAKE2s_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__SSE2__) && defined(__GNUC__) && __GNUC__ >= 4
#define BLAKE2S_USE_VECTOR_MATH 1
#ifdef __clang__
typedef uint32_t BlakeVectorUInt32 __attribute__((ext_vector_type(4)));
#else
typedef uint32_t BlakeVectorUInt32 __attribute__((__vector_size__(16)));
#endif
#else
#undef BLAKE2S_USE_VECTOR_MATH
#endif

typedef struct
{
#if BLAKE2S_USE_VECTOR_MATH
    BlakeVectorUInt32 h[2];
#else
    uint32_t h[8];
#endif
    uint8_t  m[64];
    uint64_t length;
    uint8_t  posn;

} BLAKE2s_context_t;

void BLAKE2s_reset(BLAKE2s_context_t *context);
void BLAKE2s_update(BLAKE2s_context_t *context, const void *data, size_t size);
void BLAKE2s_finish(BLAKE2s_context_t *context, uint8_t *hash);

#ifdef __cplusplus
};
#endif

#endif
