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

#include "chacha.h"
#include <string.h>

/* Essentially the same as D. J. Bernstein's reference implementation
   but with an option to use SIMD instructions for 4-way parallelism. */

#define fromLittle(ptr)   \
    (((uint32_t)((ptr)[0])) | \
    (((uint32_t)((ptr)[1])) << 8) | \
    (((uint32_t)((ptr)[2])) << 16) | \
    (((uint32_t)((ptr)[3])) << 24))

#define toLittle(ptr, v) \
    ((ptr)[0] = (uint8_t)(v), \
     (ptr)[1] = (uint8_t)((v) >> 8), \
     (ptr)[2] = (uint8_t)((v) >> 16), \
     (ptr)[3] = (uint8_t)((v) >> 24))

#ifdef USE_VECTOR_MATH

/* Assumption: CPU is little-endian and can perform unaligned
   32-bit loads and stores */
#define fromLittleVec(ptr)  \
    (VectorUInt32){((const uint32_t *)(ptr))[0], \
                   ((const uint32_t *)(ptr))[1], \
                   ((const uint32_t *)(ptr))[2], \
                   ((const uint32_t *)(ptr))[3]}
#define toLittleVec(ptr, v) \
    (((uint32_t *)(ptr))[0] = (v)[0], \
     ((uint32_t *)(ptr))[1] = (v)[1], \
     ((uint32_t *)(ptr))[2] = (v)[2], \
     ((uint32_t *)(ptr))[3] = (v)[3])

#endif

/* Rotate left by a certain number of bits */
#define leftRotate(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/* Perform a ChaCha quarter round operation */
#define quarterRound(a, b, c, d)    \
    do { \
        (a) += (b); \
        (d) = leftRotate((d) ^ (a), 16); \
        (c) += (d); \
        (b) = leftRotate((b) ^ (c), 12); \
        (a) += (b); \
        (d) = leftRotate((d) ^ (a), 8); \
        (c) += (d); \
        (b) = leftRotate((b) ^ (c), 7); \
    } while (0)

void chacha_keysetup(chacha_ctx *x, const uint8_t *k, uint32_t kbits)
{
    static const char tag128[] = "expand 16-byte k";
    static const char tag256[] = "expand 32-byte k";
    if (kbits == 256) {
        memcpy(x->input, tag256, 16);
#ifdef USE_VECTOR_MATH
        x->input[1] = fromLittleVec(k);
        x->input[2] = fromLittleVec(k + 16);
#else
        x->input[4]  = fromLittle(k);
        x->input[5]  = fromLittle(k + 4);
        x->input[6]  = fromLittle(k + 8);
        x->input[7]  = fromLittle(k + 12);
        x->input[8]  = fromLittle(k + 16);
        x->input[9]  = fromLittle(k + 20);
        x->input[10] = fromLittle(k + 24);
        x->input[11] = fromLittle(k + 28);
#endif
    } else {
        memcpy(x->input, tag128, 16);
#ifdef USE_VECTOR_MATH
        x->input[2] = x->input[1] = fromLittleVec(k);
#else
        x->input[8]  = x->input[4] = fromLittle(k);
        x->input[9]  = x->input[5] = fromLittle(k + 4);
        x->input[10] = x->input[6] = fromLittle(k + 8);
        x->input[11] = x->input[7] = fromLittle(k + 12);
#endif
    }
#ifdef USE_VECTOR_MATH
    x->input[3] = (VectorUInt32){0, 0, 0, 0};
#else
    memset(x->input + 12, 0, 16);
#endif
}

void chacha_ivsetup(chacha_ctx *x, const uint8_t *iv, const uint8_t *counter)
{
#ifdef USE_VECTOR_MATH
    if (counter) {
        x->input[3] = (VectorUInt32){fromLittle(counter),
                                     fromLittle(counter + 4),
                                     fromLittle(iv),
                                     fromLittle(iv + 4)};
    } else {
        x->input[3] = (VectorUInt32){0, 0, fromLittle(iv), fromLittle(iv + 4)};
    }
#else
    if (counter) {
        x->input[12] = fromLittle(counter);
        x->input[13] = fromLittle(counter + 4);
    } else {
        x->input[12] = 0;
        x->input[13] = 0;
    }
    x->input[14] = fromLittle(iv);
    x->input[15] = fromLittle(iv + 4);
#endif
}

#ifdef USE_VECTOR_MATH

#define shuffleLeft1(x) (VectorUInt32){(x)[1], (x)[2], (x)[3], (x)[0]}
#define shuffleLeft2(x) (VectorUInt32){(x)[2], (x)[3], (x)[0], (x)[1]}
#define shuffleLeft3(x) (VectorUInt32){(x)[3], (x)[0], (x)[1], (x)[2]}

void chacha_encrypt_bytes(chacha_ctx *x, const uint8_t *m, uint8_t *c, uint32_t bytes)
{
    VectorUInt32 out0, out1, out2, out3;
    uint32_t index;
    uint8_t temp[64];
    uint8_t *t;

    /* Encrypt all input blocks */
    while (bytes > 0) {
        /* Copy the "in" block to "out" */
        out0 = x->input[0];
        out1 = x->input[1];
        out2 = x->input[2];
        out3 = x->input[3];

        /* Perform the 20 rounds of the hash core */
        for (index = 20; index >= 2; index -= 2) {
            /* Column round */
            quarterRound(out0, out1, out2, out3);
            out1 = shuffleLeft1(out1);
            out2 = shuffleLeft2(out2);
            out3 = shuffleLeft3(out3);

            /* Diagonal round */
            quarterRound(out0, out1, out2, out3);
            out1 = shuffleLeft3(out1);
            out2 = shuffleLeft2(out2);
            out3 = shuffleLeft1(out3);
        }

        /* Add the input to the output */
        out0 += x->input[0];
        out1 += x->input[1];
        out2 += x->input[2];
        out3 += x->input[3];

        /* Increment the counter in the input block */
        if (++(x->input[3][0]) == 0)
            ++(x->input[3][1]);

        /* XOR the plaintext with the output to create the ciphertext */
        if (bytes >= 64) {
            t = c;
        } else {
            memcpy(temp, m, bytes);
            m = temp;
            t = temp;
        }
        out0 ^= fromLittleVec(m);
        out1 ^= fromLittleVec(m + 16);
        out2 ^= fromLittleVec(m + 32);
        out3 ^= fromLittleVec(m + 48);
        toLittleVec(t, out0);
        toLittleVec(t + 16, out1);
        toLittleVec(t + 32, out2);
        toLittleVec(t + 48, out3);
        if (bytes < 64) {
            memcpy(c, t, bytes);
            break;
        }
        m += 64;
        c += 64;
        bytes -= 64;
    }
}

#else /* !USE_VECTOR_MATH */

void chacha_encrypt_bytes(chacha_ctx *x, const uint8_t *m, uint8_t *c, uint32_t bytes)
{
    uint32_t in0, in1, in2, in3, in4, in5, in6, in7;
    uint32_t in8, in9, in10, in11, in12, in13, in14, in15;
    uint32_t out0, out1, out2, out3, out4, out5, out6, out7;
    uint32_t out8, out9, out10, out11, out12, out13, out14, out15;
    uint32_t index;
    uint8_t temp[64];
    uint8_t *t;

    /* Load the context into local variables */
    in0 = x->input[0]; in1 = x->input[1]; in2 = x->input[2]; in3 = x->input[3];
    in4 = x->input[4]; in5 = x->input[5]; in6 = x->input[6]; in7 = x->input[7];
    in8 = x->input[8]; in9 = x->input[9]; in10 = x->input[10]; in11 = x->input[11];
    in12 = x->input[12]; in13 = x->input[13]; in14 = x->input[14]; in15 = x->input[15];

    /* Encrypt all input blocks */
    while (bytes > 0) {
        /* Copy the "in" block to "out" */
        out0 = in0; out1 = in1; out2 = in2; out3 = in3;
        out4 = in4; out5 = in5; out6 = in6; out7 = in7;
        out8 = in8; out9 = in9; out10 = in10; out11 = in11;
        out12 = in12; out13 = in13; out14 = in14; out15 = in15;

        /* Perform the 20 rounds of the hash core */
        for (index = 20; index >= 2; index -= 2) {
            /* Column round */
            quarterRound(out0, out4, out8,  out12);
            quarterRound(out1, out5, out9,  out13);
            quarterRound(out2, out6, out10, out14);
            quarterRound(out3, out7, out11, out15);

            /* Diagonal round */
            quarterRound(out0, out5, out10, out15);
            quarterRound(out1, out6, out11, out12);
            quarterRound(out2, out7, out8,  out13);
            quarterRound(out3, out4, out9,  out14);
        }

        /* Add the input to the output */
        out0 += in0; out1 += in1; out2 += in2; out3 += in3;
        out4 += in4; out5 += in5; out6 += in6; out7 += in7;
        out8 += in8; out9 += in9; out10 += in10; out11 += in11;
        out12 += in12; out13 += in13; out14 += in14; out15 += in15;

        /* Increment the counter in the input block */
        if ((++in12) == 0)
            ++in13;

        /* XOR the plaintext with the output to create the ciphertext */
        if (bytes >= 64) {
            t = c;
        } else {
            memcpy(temp, m, bytes);
            m = temp;
            t = temp;
        }
        out0 ^= fromLittle(m);
        out1 ^= fromLittle(m + 4);
        out2 ^= fromLittle(m + 8);
        out3 ^= fromLittle(m + 12);
        out4 ^= fromLittle(m + 16);
        out5 ^= fromLittle(m + 20);
        out6 ^= fromLittle(m + 24);
        out7 ^= fromLittle(m + 28);
        out8 ^= fromLittle(m + 32);
        out9 ^= fromLittle(m + 36);
        out10 ^= fromLittle(m + 40);
        out11 ^= fromLittle(m + 44);
        out12 ^= fromLittle(m + 48);
        out13 ^= fromLittle(m + 52);
        out14 ^= fromLittle(m + 56);
        out15 ^= fromLittle(m + 60);
        toLittle(t, out0);
        toLittle(t + 4, out1);
        toLittle(t + 8, out2);
        toLittle(t + 12, out3);
        toLittle(t + 16, out4);
        toLittle(t + 20, out5);
        toLittle(t + 24, out6);
        toLittle(t + 28, out7);
        toLittle(t + 32, out8);
        toLittle(t + 36, out9);
        toLittle(t + 40, out10);
        toLittle(t + 44, out11);
        toLittle(t + 48, out12);
        toLittle(t + 52, out13);
        toLittle(t + 56, out14);
        toLittle(t + 60, out15);
        if (bytes < 64) {
            memcpy(c, t, bytes);
            break;
        }
        m += 64;
        c += 64;
        bytes -= 64;
    }

    /* Copy the counter back into the context */
    x->input[12] = in12;
    x->input[13] = in13;
}

#endif /* !USE_VECTOR_MATH */
