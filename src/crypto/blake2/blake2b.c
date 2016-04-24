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
    Cut-down BLAKE2b implementation, starting with the version from arduinolibs:

    https://github.com/rweather/arduinolibs
*/

#include "blake2b.h"
#include "blake2-endian.h"
#include <string.h>

/* Initialization vectors for BLAKE2b */
#define BLAKE2b_IV0 0x6a09e667f3bcc908ULL
#define BLAKE2b_IV1 0xbb67ae8584caa73bULL
#define BLAKE2b_IV2 0x3c6ef372fe94f82bULL
#define BLAKE2b_IV3 0xa54ff53a5f1d36f1ULL
#define BLAKE2b_IV4 0x510e527fade682d1ULL
#define BLAKE2b_IV5 0x9b05688c2b3e6c1fULL
#define BLAKE2b_IV6 0x1f83d9abfb41bd6bULL
#define BLAKE2b_IV7 0x5be0cd19137e2179ULL

void BLAKE2b_reset(BLAKE2b_context_t *context)
{
    context->h[0] = BLAKE2b_IV0 ^ 0x01010040; /* Default output length of 64 */
    context->h[1] = BLAKE2b_IV1;
    context->h[2] = BLAKE2b_IV2;
    context->h[3] = BLAKE2b_IV3;
    context->h[4] = BLAKE2b_IV4;
    context->h[5] = BLAKE2b_IV5;
    context->h[6] = BLAKE2b_IV6;
    context->h[7] = BLAKE2b_IV7;
    context->length = 0;
    context->posn = 0;
}

/* Permutation on the message input state for BLAKE2b */
static const uint8_t sigma[12][16] = {
    { 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15},
    {14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3},
    {11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4},
    { 7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8},
    { 9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13},
    { 2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9},
    {12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11},
    {13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10},
    { 6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5},
    {10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0},
    { 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15},
    {14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3},
};

/* Rotate right by a certain number of bits */
#define rightRotate(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

/* Perform a BLAKE2b quarter round operation */
#define quarterRound(a, b, c, d, i) \
    do { \
        (a) += (b) + m[sigma_row[2 * (i)]]; \
        (d) = rightRotate((d) ^ (a), 32); \
        (c) += (d); \
        (b) = rightRotate((b) ^ (c), 24); \
        (a) += (b) + m[sigma_row[2 * (i) + 1]]; \
        (d) = rightRotate((d) ^ (a), 16); \
        (c) += (d); \
        (b) = rightRotate((b) ^ (c), 63); \
    } while (0)

static void blake2b_transform
    (BLAKE2b_context_t *context, const uint8_t *data, uint64_t f0)
{
    uint8_t index;
    uint64_t m[16];
    uint64_t v[16];
    const uint8_t *sigma_row;

    /* Unpack the input data from little-endian */
#if BLAKE2_LITTLE_ENDIAN
    memcpy(m, data, sizeof(m));
#else
    for (index = 0; index < 16; ++index, data += 4) {
        m[index] = ((uint64_t)(data[0])) |
                  (((uint64_t)(data[1])) <<  8) |
                  (((uint64_t)(data[2])) << 16) |
                  (((uint64_t)(data[3])) << 24) |
                  (((uint64_t)(data[4])) << 32) |
                  (((uint64_t)(data[5])) << 40) |
                  (((uint64_t)(data[6])) << 48) |
                  (((uint64_t)(data[7])) << 56);
    }
#endif

    /* Format the block to be hashed */
    memcpy(v, context->h, sizeof(context->h));
    v[8]  = BLAKE2b_IV0;
    v[9]  = BLAKE2b_IV1;
    v[10] = BLAKE2b_IV2;
    v[11] = BLAKE2b_IV3;
    v[12] = BLAKE2b_IV4 ^ context->length;
    v[13] = BLAKE2b_IV5;
    v[14] = BLAKE2b_IV6 ^ f0;
    v[15] = BLAKE2b_IV7;

    /* Perform the 12 BLAKE2b rounds */
    sigma_row = sigma[0];
    for (index = 0; index < 12; ++index, sigma_row += 16) {
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
}

void BLAKE2b_update(BLAKE2b_context_t *context, const void *data, size_t size)
{
    /* Break the input up into 512-bit chunks and process each in turn */
    const uint8_t *d = (const uint8_t *)data;
    uint8_t len;
    while (size > 0) {
        if (context->posn == 128) {
            /* Previous chunk was full and we know that it wasn't the
               last chunk, so we can process it now with f0 set to zero. */
            blake2b_transform(context, context->m, 0);
            context->posn = 0;
        }
        if (size > 128 && context->posn == 0) {
            /* This chunk can be processed directly from the input buffer */
            context->length += 128;
            blake2b_transform(context, d, 0);
            d += 128;
            size -= 128;
        } else {
            /* Buffer the block for later */
            len = 128 - context->posn;
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

void BLAKE2b_finish(BLAKE2b_context_t *context, uint8_t *hash)
{
    /* Pad the last chunk and hash it with f0 set to all-ones */
    memset(context->m + context->posn, 0, 128 - context->posn);
    blake2b_transform(context, context->m, 0xFFFFFFFFFFFFFFFF);

    /* Copy the hash to the caller's return buffer in little-endian */
#if BLAKE2_LITTLE_ENDIAN
    memcpy(hash, context->h, sizeof(context->h));
#else
    {
        unsigned posn;
        for (posn = 0; posn < 8; ++posn, hash += 4) {
            uint64_t h = context->h[posn];
            hash[0] = (uint8_t)h;
            hash[1] = (uint8_t)(h >> 8);
            hash[2] = (uint8_t)(h >> 16);
            hash[3] = (uint8_t)(h >> 24);
            hash[4] = (uint8_t)(h >> 32);
            hash[5] = (uint8_t)(h >> 40);
            hash[6] = (uint8_t)(h >> 48);
            hash[7] = (uint8_t)(h >> 56);
        }
    }
#endif
}
