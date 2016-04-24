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

/*
    Cut-down BLAKE2s implementation, starting with the version from arduinolibs
    and then making modifications for desktop systems, including SSE2 support.

    https://github.com/rweather/arduinolibs
*/

#include "blake2s.h"
#include "blake2-endian.h"
#include <string.h>

/* Initialization vectors for BLAKE2s */
#define BLAKE2s_IV0 0x6A09E667
#define BLAKE2s_IV1 0xBB67AE85
#define BLAKE2s_IV2 0x3C6EF372
#define BLAKE2s_IV3 0xA54FF53A
#define BLAKE2s_IV4 0x510E527F
#define BLAKE2s_IV5 0x9B05688C
#define BLAKE2s_IV6 0x1F83D9AB
#define BLAKE2s_IV7 0x5BE0CD19

void BLAKE2s_reset(BLAKE2s_context_t *context)
{
#if BLAKE2S_USE_VECTOR_MATH
    context->h[0] = (BlakeVectorUInt32){BLAKE2s_IV0 ^ 0x01010020,
                                        BLAKE2s_IV1, BLAKE2s_IV2, BLAKE2s_IV3};
    context->h[1] = (BlakeVectorUInt32){BLAKE2s_IV4, BLAKE2s_IV5,
                                        BLAKE2s_IV6, BLAKE2s_IV7};
#else
    context->h[0] = BLAKE2s_IV0 ^ 0x01010020; /* Default output length of 32 */
    context->h[1] = BLAKE2s_IV1;
    context->h[2] = BLAKE2s_IV2;
    context->h[3] = BLAKE2s_IV3;
    context->h[4] = BLAKE2s_IV4;
    context->h[5] = BLAKE2s_IV5;
    context->h[6] = BLAKE2s_IV6;
    context->h[7] = BLAKE2s_IV7;
#endif
    context->length = 0;
    context->posn = 0;
}

/* Permutation on the message input state for BLAKE2s */
static const uint8_t sigma[10][16] = {
    { 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15},
    {14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3},
    {11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4},
    { 7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8},
    { 9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13},
    { 2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9},
    {12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11},
    {13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10},
    { 6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5},
    {10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0}
};

/* Rotate right by a certain number of bits */
#define rightRotate(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

/* Perform a BLAKE2s quarter round operation */
#define quarterRound(a, b, c, d, i) \
    do { \
        (a) += (b) + m[sigma_row[2 * (i)]]; \
        (d) = rightRotate((d) ^ (a), 16); \
        (c) += (d); \
        (b) = rightRotate((b) ^ (c), 12); \
        (a) += (b) + m[sigma_row[2 * (i) + 1]]; \
        (d) = rightRotate((d) ^ (a), 8); \
        (c) += (d); \
        (b) = rightRotate((b) ^ (c), 7); \
    } while (0)

#if BLAKE2S_USE_VECTOR_MATH

#define shuffleLeft1(x) (BlakeVectorUInt32){(x)[1], (x)[2], (x)[3], (x)[0]}
#define shuffleLeft2(x) (BlakeVectorUInt32){(x)[2], (x)[3], (x)[0], (x)[1]}
#define shuffleLeft3(x) (BlakeVectorUInt32){(x)[3], (x)[0], (x)[1], (x)[2]}

/* Perform a BLAKE2s quarter round operation with vector math */
#define quarterRoundVec(a, b, c, d, mv0, mv1) \
    do { \
        (a) += (b) + (mv0); \
        (d) = rightRotate((d) ^ (a), 16); \
        (c) += (d); \
        (b) = rightRotate((b) ^ (c), 12); \
        (a) += (b) + (mv1); \
        (d) = rightRotate((d) ^ (a), 8); \
        (c) += (d); \
        (b) = rightRotate((b) ^ (c), 7); \
    } while (0)

#endif

static void blake2s_transform
    (BLAKE2s_context_t *context, const uint8_t *data, uint32_t f0)
{
#if BLAKE2S_USE_VECTOR_MATH
    /* Assumption: CPU is little-endian and supports unaligned 32-bit loads */
    uint8_t index;
    const uint32_t *m = (const uint32_t *)data;
    BlakeVectorUInt32 v0, v1, v2, v3, mv0, mv1;
    const uint8_t *sigma_row;

    /* Format the block to be hashed */
    v0 = context->h[0];
    v1 = context->h[1];
    v2 = (BlakeVectorUInt32){BLAKE2s_IV0, BLAKE2s_IV1,
                             BLAKE2s_IV2, BLAKE2s_IV3};
    v3 = (BlakeVectorUInt32){BLAKE2s_IV4 ^ (uint32_t)(context->length),
                             BLAKE2s_IV5 ^ (uint32_t)(context->length >> 32),
                             BLAKE2s_IV6 ^ f0, BLAKE2s_IV7};

    /* Perform the 10 BLAKE2s rounds */
    sigma_row = sigma[0];
    for (index = 0; index < 10; ++index, sigma_row += 16) {
        /* Column round */
        mv0 = (BlakeVectorUInt32){m[sigma_row[0]], m[sigma_row[2]],
                                  m[sigma_row[4]], m[sigma_row[6]]};
        mv1 = (BlakeVectorUInt32){m[sigma_row[1]], m[sigma_row[3]],
                                  m[sigma_row[5]], m[sigma_row[7]]};
        quarterRoundVec(v0, v1, v2, v3, mv0, mv1);
        v1 = shuffleLeft1(v1);
        v2 = shuffleLeft2(v2);
        v3 = shuffleLeft3(v3);

        /* Diagonal round */
        mv0 = (BlakeVectorUInt32){m[sigma_row[8]],  m[sigma_row[10]],
                                  m[sigma_row[12]], m[sigma_row[14]]};
        mv1 = (BlakeVectorUInt32){m[sigma_row[9]],  m[sigma_row[11]],
                                  m[sigma_row[13]], m[sigma_row[15]]};
        quarterRoundVec(v0, v1, v2, v3, mv0, mv1);
        v1 = shuffleLeft3(v1);
        v2 = shuffleLeft2(v2);
        v3 = shuffleLeft1(v3);
    }

    /* Combine the new and old hash values */
    context->h[0] ^= v0 ^ v2;
    context->h[1] ^= v1 ^ v3;
#else /* !BLAKE2S_USE_VECTOR_MATH */
    uint8_t index;
    uint32_t m[16];
    uint32_t v[16];
    const uint8_t *sigma_row;

    /* Unpack the input data from little-endian */
#if BLAKE2_LITTLE_ENDIAN
    memcpy(m, data, sizeof(m));
#else
    for (index = 0; index < 16; ++index, data += 4) {
        m[index] = ((uint32_t)(data[0])) |
                  (((uint32_t)(data[1])) <<  8) |
                  (((uint32_t)(data[2])) << 16) |
                  (((uint32_t)(data[3])) << 24);
    }
#endif

    /* Format the block to be hashed */
    memcpy(v, context->h, sizeof(context->h));
    v[8]  = BLAKE2s_IV0;
    v[9]  = BLAKE2s_IV1;
    v[10] = BLAKE2s_IV2;
    v[11] = BLAKE2s_IV3;
    v[12] = BLAKE2s_IV4 ^ (uint32_t)(context->length);
    v[13] = BLAKE2s_IV5 ^ (uint32_t)(context->length >> 32);
    v[14] = BLAKE2s_IV6 ^ f0;
    v[15] = BLAKE2s_IV7;

    /* Perform the 10 BLAKE2s rounds */
    sigma_row = sigma[0];
    for (index = 0; index < 10; ++index, sigma_row += 16) {
        /* Column round */
        quarterRound(v[0], v[4], v[8],  v[12], 0);
        quarterRound(v[1], v[5], v[9],  v[13], 1);
        quarterRound(v[2], v[6], v[10], v[14], 2);
        quarterRound(v[3], v[7], v[11], v[15], 3);

        /* Diagonal round */
        quarterRound(v[0], v[5], v[10], v[15], 4);
        quarterRound(v[1], v[6], v[11], v[12], 5);
        quarterRound(v[2], v[7], v[8],  v[13], 6);
        quarterRound(v[3], v[4], v[9],  v[14], 7);
    }

    /* Combine the new and old hash values */
    for (index = 0; index < 8; ++index)
        context->h[index] ^= (v[index] ^ v[index + 8]);
#endif /* !BLAKE2S_USE_VECTOR_MATH */
}

void BLAKE2s_update(BLAKE2s_context_t *context, const void *data, size_t size)
{
    /* Break the input up into 512-bit chunks and process each in turn */
    const uint8_t *d = (const uint8_t *)data;
    uint8_t len;
    while (size > 0) {
        if (context->posn == 64) {
            /* Previous chunk was full and we know that it wasn't the
               last chunk, so we can process it now with f0 set to zero. */
            blake2s_transform(context, context->m, 0);
            context->posn = 0;
        }
        if (size > 64 && context->posn == 0) {
            /* This chunk can be processed directly from the input buffer */
            context->length += 64;
            blake2s_transform(context, d, 0);
            d += 64;
            size -= 64;
        } else {
            /* Buffer the block for later */
            len = 64 - context->posn;
            if (len > size)
                len = size;
            memcpy(context->m + context->posn, d, len);
            context->posn += len;
            context->length += len;
            size -= len;
            d += len;
        }
    }
}

void BLAKE2s_finish(BLAKE2s_context_t *context, uint8_t *hash)
{
    /* Pad the last chunk and hash it with f0 set to all-ones */
    memset(context->m + context->posn, 0, 64 - context->posn);
    blake2s_transform(context, context->m, 0xFFFFFFFF);

    /* Copy the hash to the caller's return buffer in little-endian */
#if BLAKE2_LITTLE_ENDIAN
    memcpy(hash, context->h, sizeof(context->h));
#else
    {
        unsigned posn;
        for (posn = 0; posn < 8; ++posn, hash += 4) {
            uint32_t h = context->h[posn];
            hash[0] = (uint8_t)h;
            hash[1] = (uint8_t)(h >> 8);
            hash[2] = (uint8_t)(h >> 16);
            hash[3] = (uint8_t)(h >> 24);
        }
    }
#endif
}
