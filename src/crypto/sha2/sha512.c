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

#include "sha512.h"
#include <string.h>

void sha512_reset(sha512_context_t *context)
{
    static uint64_t const hash_start[8] = {
        0x6A09E667F3BCC908ULL, 0xBB67AE8584CAA73BULL, 0x3C6EF372FE94F82BULL,
        0xA54FF53A5F1D36F1ULL, 0x510E527FADE682D1ULL, 0x9B05688C2B3E6C1FULL,
        0x1F83D9ABFB41BD6BULL, 0x5BE0CD19137E2179ULL
    };
    memcpy(context->h, hash_start, sizeof(hash_start));
    context->length = 0;
    context->posn = 0;
}

#define rightRotate(v, n) (((v) >> (n)) | ((v) << (64 - (n))))

static void sha512_transform(sha512_context_t *context, const uint8_t *m)
{
    static uint64_t const k[80] = {
        0x428A2F98D728AE22ULL, 0x7137449123EF65CDULL, 0xB5C0FBCFEC4D3B2FULL,
        0xE9B5DBA58189DBBCULL, 0x3956C25BF348B538ULL, 0x59F111F1B605D019ULL,
        0x923F82A4AF194F9BULL, 0xAB1C5ED5DA6D8118ULL, 0xD807AA98A3030242ULL,
        0x12835B0145706FBEULL, 0x243185BE4EE4B28CULL, 0x550C7DC3D5FFB4E2ULL,
        0x72BE5D74F27B896FULL, 0x80DEB1FE3B1696B1ULL, 0x9BDC06A725C71235ULL,
        0xC19BF174CF692694ULL, 0xE49B69C19EF14AD2ULL, 0xEFBE4786384F25E3ULL,
        0x0FC19DC68B8CD5B5ULL, 0x240CA1CC77AC9C65ULL, 0x2DE92C6F592B0275ULL,
        0x4A7484AA6EA6E483ULL, 0x5CB0A9DCBD41FBD4ULL, 0x76F988DA831153B5ULL,
        0x983E5152EE66DFABULL, 0xA831C66D2DB43210ULL, 0xB00327C898FB213FULL,
        0xBF597FC7BEEF0EE4ULL, 0xC6E00BF33DA88FC2ULL, 0xD5A79147930AA725ULL,
        0x06CA6351E003826FULL, 0x142929670A0E6E70ULL, 0x27B70A8546D22FFCULL,
        0x2E1B21385C26C926ULL, 0x4D2C6DFC5AC42AEDULL, 0x53380D139D95B3DFULL,
        0x650A73548BAF63DEULL, 0x766A0ABB3C77B2A8ULL, 0x81C2C92E47EDAEE6ULL,
        0x92722C851482353BULL, 0xA2BFE8A14CF10364ULL, 0xA81A664BBC423001ULL,
        0xC24B8B70D0F89791ULL, 0xC76C51A30654BE30ULL, 0xD192E819D6EF5218ULL,
        0xD69906245565A910ULL, 0xF40E35855771202AULL, 0x106AA07032BBD1B8ULL,
        0x19A4C116B8D2D0C8ULL, 0x1E376C085141AB53ULL, 0x2748774CDF8EEB99ULL,
        0x34B0BCB5E19B48A8ULL, 0x391C0CB3C5C95A63ULL, 0x4ED8AA4AE3418ACBULL,
        0x5B9CCA4F7763E373ULL, 0x682E6FF3D6B2B8A3ULL, 0x748F82EE5DEFB2FCULL,
        0x78A5636F43172F60ULL, 0x84C87814A1F0AB72ULL, 0x8CC702081A6439ECULL,
        0x90BEFFFA23631E28ULL, 0xA4506CEBDE82BDE9ULL, 0xBEF9A3F7B2C67915ULL,
        0xC67178F2E372532BULL, 0xCA273ECEEA26619CULL, 0xD186B8C721C0C207ULL,
        0xEADA7DD6CDE0EB1EULL, 0xF57D4F7FEE6ED178ULL, 0x06F067AA72176FBAULL,
        0x0A637DC5A2C898A6ULL, 0x113F9804BEF90DAEULL, 0x1B710B35131C471BULL,
        0x28DB77F523047D84ULL, 0x32CAAB7B40C72493ULL, 0x3C9EBE0A15C9BEBCULL,
        0x431D67C49C100D4CULL, 0x4CC5D4BECB3E42B6ULL, 0x597F299CFC657E2AULL,
        0x5FCB6FAB3AD6FAECULL, 0x6C44198C4A475817ULL
    };
    unsigned index;
    uint64_t temp1, temp2;
    uint64_t w[80];

    /* Initialise working variables to the current hash value */
    uint64_t a = context->h[0];
    uint64_t b = context->h[1];
    uint64_t c = context->h[2];
    uint64_t d = context->h[3];
    uint64_t e = context->h[4];
    uint64_t f = context->h[5];
    uint64_t g = context->h[6];
    uint64_t h = context->h[7];

    /* Convert the 16 message words from big endian to host byte order */
    for (index = 0; index < 16; ++index) {
        w[index] = (((uint64_t)(m[0])) << 56) |
                   (((uint64_t)(m[1])) << 48) |
                   (((uint64_t)(m[2])) << 40) |
                   (((uint64_t)(m[3])) << 32) |
                   (((uint64_t)(m[4])) << 24) |
                   (((uint64_t)(m[5])) << 16) |
                   (((uint64_t)(m[6])) << 8) |
                    ((uint64_t)(m[7]));
        m += 8;
    }

    /* Extend the first 16 words to 80 */
    for (index = 16; index < 80; ++index) {
        w[index] = w[index - 16] + w[index - 7] +
            (rightRotate(w[index - 15], 1) ^
             rightRotate(w[index - 15], 8) ^
             (w[index - 15] >> 7)) +
            (rightRotate(w[index - 2], 19) ^
             rightRotate(w[index - 2], 61) ^
             (w[index - 2] >> 6));
    }

    // Round function.
#define SHA512_ROUND(a, b, c, d, e, f, g, h, n) \
    (temp1 = (h) + k[index + (n)] + w[index + (n)] + \
        (rightRotate((e), 14) ^ rightRotate((e), 18) ^ rightRotate((e), 41)) + \
        (((e) & (f)) ^ ((~(e)) & (g))), \
     temp2 = (rightRotate((a), 28) ^ rightRotate((a), 34) ^ rightRotate((a), 39)) + \
        (((a) & (b)) ^ ((a) & (c)) ^ ((b) & (c))), \
     (d) += temp1, \
     (h) = temp1 + temp2)

    /* Compression function main loop */
    for (index = 0; index < 80; index += 8) {
        SHA512_ROUND(a, b, c, d, e, f, g, h, 0);
        SHA512_ROUND(h, a, b, c, d, e, f, g, 1);
        SHA512_ROUND(g, h, a, b, c, d, e, f, 2);
        SHA512_ROUND(f, g, h, a, b, c, d, e, 3);
        SHA512_ROUND(e, f, g, h, a, b, c, d, 4);
        SHA512_ROUND(d, e, f, g, h, a, b, c, 5);
        SHA512_ROUND(c, d, e, f, g, h, a, b, 6);
        SHA512_ROUND(b, c, d, e, f, g, h, a, 7);
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

void sha512_update(sha512_context_t *context, const void *data, size_t size)
{
    const uint8_t *d = (const uint8_t *)data;
    while (size > 0) {
        if (context->posn == 0 && size >= 128) {
            sha512_transform(context, d);
            d += 128;
            size -= 128;
            context->length += 128 * 8;
        } else {
            size_t temp = 128 - context->posn;
            if (temp > size)
                temp = size;
            memcpy(context->m + context->posn, d, temp);
            context->posn += temp;
            if (context->posn >= 128) {
                sha512_transform(context, context->m);
                context->posn = 0;
            }
            d += temp;
            size -= temp;
            context->length += temp * 8;
        }
    }
}

static void write_be64(uint8_t *out, uint64_t value)
{
    out[0] = (uint8_t)(value >> 56);
    out[1] = (uint8_t)(value >> 48);
    out[2] = (uint8_t)(value >> 40);
    out[3] = (uint8_t)(value >> 32);
    out[4] = (uint8_t)(value >> 24);
    out[5] = (uint8_t)(value >> 16);
    out[6] = (uint8_t)(value >> 8);
    out[7] = (uint8_t)value;
}

void sha512_finish(sha512_context_t *context, uint8_t *hash)
{
    uint8_t posn = context->posn;
    if (posn <= (128 - 17)) {
        context->m[posn] = 0x80;
        memset(context->m + posn + 1, 0, 128 - 16 - (posn + 1));
    } else {
        context->m[posn] = 0x80;
        memset(context->m + posn + 1, 0, 128 - (posn + 1));
        sha512_transform(context, context->m);
        memset(context->m, 0, 128 - 16);
    }
    write_be64(context->m + 128 - 16, 0);
    write_be64(context->m + 128 - 8, context->length);
    sha512_transform(context, context->m);
    context->posn = 0;
    for (posn = 0; posn < 8; ++posn)
        write_be64(hash + posn * 8, context->h[posn]);
}

void sha512_hash(uint8_t *hash, const void *data, size_t size)
{
    sha512_context_t context;
    sha512_reset(&context);
    sha512_update(&context, data, size);
    sha512_finish(&context, hash);
}
