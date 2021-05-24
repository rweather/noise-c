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

#include "sha256.h"
#include <string.h>

void sha256_reset(sha256_context_t *context)
{
    context->h[0] = 0x6a09e667;
    context->h[1] = 0xbb67ae85;
    context->h[2] = 0x3c6ef372;
    context->h[3] = 0xa54ff53a;
    context->h[4] = 0x510e527f;
    context->h[5] = 0x9b05688c;
    context->h[6] = 0x1f83d9ab;
    context->h[7] = 0x5be0cd19;
    context->length = 0;
    context->posn = 0;
}

#define rightRotate(v, n) (((v) >> (n)) | ((v) << (32 - (n))))

static void sha256_transform(sha256_context_t *context, const uint8_t *m)
{
    static uint32_t const k[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };
    unsigned index;
    uint32_t temp1, temp2;
    uint32_t w[64];

    /* Initialize working variables to the current hash value */
    uint32_t a = context->h[0];
    uint32_t b = context->h[1];
    uint32_t c = context->h[2];
    uint32_t d = context->h[3];
    uint32_t e = context->h[4];
    uint32_t f = context->h[5];
    uint32_t g = context->h[6];
    uint32_t h = context->h[7];

    /* Convert the 16 message words from big endian to host byte order */
    for (index = 0; index < 16; ++index) {
        w[index] = (((uint32_t)(m[0])) << 24) |
                   (((uint32_t)(m[1])) << 16) |
                   (((uint32_t)(m[2])) << 8) |
                    ((uint32_t)(m[3]));
        m += 4;
    }

    /* Extend the first 16 words to 64 */
    for (index = 16; index < 64; ++index) {
        w[index] = w[index - 16] + w[index - 7] +
            (rightRotate(w[index - 15], 7) ^
             rightRotate(w[index - 15], 18) ^
             (w[index - 15] >> 3)) +
            (rightRotate(w[index - 2], 17) ^
             rightRotate(w[index - 2], 19) ^
             (w[index - 2] >> 10));
    }

    /* Round function */
#define SHA256_ROUND(a, b, c, d, e, f, g, h, n) \
    (temp1 = (h) + k[index + (n)] + w[index + (n)] + \
        (rightRotate((e), 6) ^ rightRotate((e), 11) ^ rightRotate((e), 25)) + \
        (((e) & (f)) ^ ((~(e)) & (g))), \
     temp2 = (rightRotate((a), 2) ^ rightRotate((a), 13) ^ rightRotate((a), 22)) + \
        (((a) & (b)) ^ ((a) & (c)) ^ ((b) & (c))), \
     (d) += temp1, \
     (h) = temp1 + temp2)

    /* Compression function main loop */
    for (index = 0; index < 64; index += 8) {
        SHA256_ROUND(a, b, c, d, e, f, g, h, 0);
        SHA256_ROUND(h, a, b, c, d, e, f, g, 1);
        SHA256_ROUND(g, h, a, b, c, d, e, f, 2);
        SHA256_ROUND(f, g, h, a, b, c, d, e, 3);
        SHA256_ROUND(e, f, g, h, a, b, c, d, 4);
        SHA256_ROUND(d, e, f, g, h, a, b, c, 5);
        SHA256_ROUND(c, d, e, f, g, h, a, b, 6);
        SHA256_ROUND(b, c, d, e, f, g, h, a, 7);
    }

    /* Add the compressed chunk to the current hash value */
    context->h[0] += a;
    context->h[1] += b;
    context->h[2] += c;
    context->h[3] += d;
    context->h[4] += e;
    context->h[5] += f;
    context->h[6] += g;
    context->h[7] += h;
}

void sha256_update(sha256_context_t *context, const void *data, size_t size)
{
    const uint8_t *d = (const uint8_t *)data;
    while (size > 0) {
        if (context->posn == 0 && size >= 64) {
            sha256_transform(context, d);
            d += 64;
            size -= 64;
            context->length += 64 * 8;
        } else {
            size_t temp = 64 - context->posn;
            if (temp > size)
                temp = size;
            memcpy(context->m + context->posn, d, temp);
            context->posn += temp;
            if (context->posn >= 64) {
                sha256_transform(context, context->m);
                context->posn = 0;
            }
            d += temp;
            size -= temp;
            context->length += temp * 8;
        }
    }
}

static void write_be32(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

void sha256_finish(sha256_context_t *context, uint8_t *hash)
{
    uint8_t posn = context->posn;
    if (posn <= (64 - 9)) {
        context->m[posn] = 0x80;
        memset(context->m + posn + 1, 0, 64 - 8 - (posn + 1));
    } else {
        context->m[posn] = 0x80;
        memset(context->m + posn + 1, 0, 64 - (posn + 1));
        sha256_transform(context, context->m);
        memset(context->m, 0, 64 - 8);
    }
    write_be32(context->m + 64 - 8, (uint32_t)(context->length >> 32));
    write_be32(context->m + 64 - 4, (uint32_t)context->length);
    sha256_transform(context, context->m);
    context->posn = 0;
    for (posn = 0; posn < 8; ++posn)
        write_be32(hash + posn * 4, context->h[posn]);
}
