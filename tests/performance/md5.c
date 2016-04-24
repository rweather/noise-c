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

#include "md5.h"
#include <string.h>

void md5_reset(md5_context_t *context)
{
    context->h[0] = 0x67452301;
    context->h[1] = 0xEFCDAB89;
    context->h[2] = 0x98BADCFE;
    context->h[3] = 0x10325476,
    context->length = 0;
    context->posn = 0;
}

/* Constants in the T table from the MD5 specification */
#define T_1 0xd76aa478
#define T_2 0xe8c7b756
#define T_3 0x242070db
#define T_4 0xc1bdceee
#define T_5 0xf57c0faf
#define T_6 0x4787c62a
#define T_7 0xa8304613
#define T_8 0xfd469501
#define T_9 0x698098d8
#define T_10 0x8b44f7af
#define T_11 0xffff5bb1
#define T_12 0x895cd7be
#define T_13 0x6b901122
#define T_14 0xfd987193
#define T_15 0xa679438e
#define T_16 0x49b40821
#define T_17 0xf61e2562
#define T_18 0xc040b340
#define T_19 0x265e5a51
#define T_20 0xe9b6c7aa
#define T_21 0xd62f105d
#define T_22 0x2441453
#define T_23 0xd8a1e681
#define T_24 0xe7d3fbc8
#define T_25 0x21e1cde6
#define T_26 0xc33707d6
#define T_27 0xf4d50d87
#define T_28 0x455a14ed
#define T_29 0xa9e3e905
#define T_30 0xfcefa3f8
#define T_31 0x676f02d9
#define T_32 0x8d2a4c8a
#define T_33 0xfffa3942
#define T_34 0x8771f681
#define T_35 0x6d9d6122
#define T_36 0xfde5380c
#define T_37 0xa4beea44
#define T_38 0x4bdecfa9
#define T_39 0xf6bb4b60
#define T_40 0xbebfbc70
#define T_41 0x289b7ec6
#define T_42 0xeaa127fa
#define T_43 0xd4ef3085
#define T_44 0x4881d05
#define T_45 0xd9d4d039
#define T_46 0xe6db99e5
#define T_47 0x1fa27cf8
#define T_48 0xc4ac5665
#define T_49 0xf4292244
#define T_50 0x432aff97
#define T_51 0xab9423a7
#define T_52 0xfc93a039
#define T_53 0x655b59c3
#define T_54 0x8f0ccc92
#define T_55 0xffeff47d
#define T_56 0x85845dd1
#define T_57 0x6fa87e4f
#define T_58 0xfe2ce6e0
#define T_59 0xa3014314
#define T_60 0x4e0811a1
#define T_61 0xf7537e82
#define T_62 0xbd3af235
#define T_63 0x2ad7d2bb
#define T_64 0xeb86d391

#define leftRotate(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

static void md5_transform(md5_context_t *context, const uint8_t *m)
{
    uint32_t X[16];
    unsigned index;

    /* Convert the input block from little endian to host byte order */
    for (index = 0; index < 16; ++index, m += 4) {
        X[index] = ((uint32_t)(m[0])) |
                  (((uint32_t)(m[1])) << 8) |
                  (((uint32_t)(m[2])) << 16) |
                  (((uint32_t)(m[3])) << 24);
    }

    /* Initialize the hash value for this chunk */
    uint32_t A = context->h[0];
    uint32_t B = context->h[1];
    uint32_t C = context->h[2];
    uint32_t D = context->h[3];

    /* Round 1 */
    #define F(x, y, z) (((x) & (y)) | (~(x) & (z)))
    #define FF(a, b, c, d, k, s, i) \
        (a = b + leftRotate(a + F(b, c, d) + X[k] + T_##i, s))
    FF(A, B, C, D,  0,  7,  1);
    FF(D, A, B, C,  1, 12,  2);
    FF(C, D, A, B,  2, 17,  3);
    FF(B, C, D, A,  3, 22,  4);
    FF(A, B, C, D,  4,  7,  5);
    FF(D, A, B, C,  5, 12,  6);
    FF(C, D, A, B,  6, 17,  7);
    FF(B, C, D, A,  7, 22,  8);
    FF(A, B, C, D,  8,  7,  9);
    FF(D, A, B, C,  9, 12, 10);
    FF(C, D, A, B, 10, 17, 11);
    FF(B, C, D, A, 11, 22, 12);
    FF(A, B, C, D, 12,  7, 13);
    FF(D, A, B, C, 13, 12, 14);
    FF(C, D, A, B, 14, 17, 15);
    FF(B, C, D, A, 15, 22, 16);

    /* Round 2 */
    #define G(x, y, z) (((x) & (z)) | ((y) & ~(z)))
    #define GG(a, b, c, d, k, s, i) \
        (a = b + leftRotate(a + G(b, c, d) + X[k] + T_##i, s))
    GG(A, B, C, D,  1,  5, 17);
    GG(D, A, B, C,  6,  9, 18);
    GG(C, D, A, B, 11, 14, 19);
    GG(B, C, D, A,  0, 20, 20);
    GG(A, B, C, D,  5,  5, 21);
    GG(D, A, B, C, 10,  9, 22);
    GG(C, D, A, B, 15, 14, 23);
    GG(B, C, D, A,  4, 20, 24);
    GG(A, B, C, D,  9,  5, 25);
    GG(D, A, B, C, 14,  9, 26);
    GG(C, D, A, B,  3, 14, 27);
    GG(B, C, D, A,  8, 20, 28);
    GG(A, B, C, D, 13,  5, 29);
    GG(D, A, B, C,  2,  9, 30);
    GG(C, D, A, B,  7, 14, 31);
    GG(B, C, D, A, 12, 20, 32);

    /* Round 3 */
    #define H(x, y, z) ((x) ^ (y) ^ (z))
    #define HH(a, b, c, d, k, s, i) \
        (a = b + leftRotate(a + H(b, c, d) + X[k] + T_##i, s))
    HH(A, B, C, D,  5,  4, 33);
    HH(D, A, B, C,  8, 11, 34);
    HH(C, D, A, B, 11, 16, 35);
    HH(B, C, D, A, 14, 23, 36);
    HH(A, B, C, D,  1,  4, 37);
    HH(D, A, B, C,  4, 11, 38);
    HH(C, D, A, B,  7, 16, 39);
    HH(B, C, D, A, 10, 23, 40);
    HH(A, B, C, D, 13,  4, 41);
    HH(D, A, B, C,  0, 11, 42);
    HH(C, D, A, B,  3, 16, 43);
    HH(B, C, D, A,  6, 23, 44);
    HH(A, B, C, D,  9,  4, 45);
    HH(D, A, B, C, 12, 11, 46);
    HH(C, D, A, B, 15, 16, 47);
    HH(B, C, D, A,  2, 23, 48);

    /* Round 4 */
    #define I(x, y, z) ((y) ^ ((x) | ~(z)))
    #define II(a, b, c, d, k, s, i) \
        (a = b + leftRotate(a + I(b, c, d) + X[k] + T_##i, s))
    II(A, B, C, D,  0,  6, 49);
    II(D, A, B, C,  7, 10, 50);
    II(C, D, A, B, 14, 15, 51);
    II(B, C, D, A,  5, 21, 52);
    II(A, B, C, D, 12,  6, 53);
    II(D, A, B, C,  3, 10, 54);
    II(C, D, A, B, 10, 15, 55);
    II(B, C, D, A,  1, 21, 56);
    II(A, B, C, D,  8,  6, 57);
    II(D, A, B, C, 15, 10, 58);
    II(C, D, A, B,  6, 15, 59);
    II(B, C, D, A, 13, 21, 60);
    II(A, B, C, D,  4,  6, 61);
    II(D, A, B, C, 11, 10, 62);
    II(C, D, A, B,  2, 15, 63);
    II(B, C, D, A,  9, 21, 64);

    /* Add this chunk's hash to the result so far */
    context->h[0] += A;
    context->h[1] += B;
    context->h[2] += C;
    context->h[3] += D;
}

void md5_update(md5_context_t *context, const void *data, size_t size)
{
    const uint8_t *d = (const uint8_t *)data;
    while (size > 0) {
        if (context->posn == 0 && size >= 64) {
            md5_transform(context, d);
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
                md5_transform(context, context->m);
                context->posn = 0;
            }
            d += temp;
            size -= temp;
            context->length += temp * 8;
        }
    }
}

static void write_le32(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)value;
    out[1] = (uint8_t)(value >> 8);
    out[2] = (uint8_t)(value >> 16);
    out[3] = (uint8_t)(value >> 24);
}

void md5_finish(md5_context_t *context, uint8_t *hash)
{
    uint8_t posn = context->posn;
    if (posn <= (64 - 9)) {
        context->m[posn] = 0x80;
        memset(context->m + posn + 1, 0, 64 - 8 - (posn + 1));
    } else {
        context->m[posn] = 0x80;
        memset(context->m + posn + 1, 0, 64 - (posn + 1));
        md5_transform(context, context->m);
        memset(context->m, 0, 64 - 8);
    }
    write_le32(context->m + 64 - 8, (uint32_t)(context->length >> 32));
    write_le32(context->m + 64 - 4, (uint32_t)context->length);
    md5_transform(context, context->m);
    context->posn = 0;
    for (posn = 0; posn < 4; ++posn)
        write_le32(hash + posn * 4, context->h[posn]);
}
