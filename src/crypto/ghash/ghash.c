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

#include "ghash.h"
#include <string.h>
#if defined(__WIN32__) || defined(WIN32)
#ifndef __BIG_ENDIAN
#define __BIG_ENDIAN 4321
#endif
#ifndef __LITTLE_ENDIAN
#define __LITTLE_ENDIAN 1234
#endif
#ifndef __BYTE_ORDER
#define __BYTE_ORDER __LITTLE_ENDIAN
#endif
#elif defined(__APPLE__)
#include <machine/endian.h>
#if !defined( __BYTE_ORDER) && defined(__DARWIN_BYTE_ORDER)
#define __BYTE_ORDER __DARWIN_BYTE_ORDER
#endif
#if !defined( __BIG_ENDIAN) && defined(__DARWIN_BIG_ENDIAN)
#define __BIG_ENDIAN __DARWIN_BIG_ENDIAN
#endif
#if !defined( __LITTLE_ENDIAN) && defined(__DARWIN_LITTLE_ENDIAN)
#define __LITTLE_ENDIAN __DARWIN_LITTLE_ENDIAN
#endif
#else
#include <endian.h>
#endif

#if defined(GHASH_WORD64)

/* 64-bit version of GHASH */

static uint64_t swapEndian(uint64_t x)
{
#if __BYTE_ORDER == __BIG_ENDIAN
    return x;
#else
    return ((x >> 56) & 0x00000000000000FF) |
           ((x >> 40) & 0x000000000000FF00) |
           ((x >> 24) & 0x0000000000FF0000) |
           ((x >>  8) & 0x00000000FF000000) |
           ((x <<  8) & 0x000000FF00000000) |
           ((x << 24) & 0x0000FF0000000000) |
           ((x << 40) & 0x00FF000000000000) |
           ((x << 56) & 0xFF00000000000000);
#endif
}

static void GF128_mulInit(uint64_t H[2], const void *key)
{
    /* Copy the key into H and convert from big endian to host order */
    memcpy(H, key, 16);
    H[0] = swapEndian(H[0]);
    H[1] = swapEndian(H[1]);
}

static void GF128_mul(uint64_t Y[2], const uint64_t H[2])
{
    uint64_t Z0 = 0;        /* Z = 0 */
    uint64_t Z1 = 0;
    uint64_t V0 = H[0];     /* V = H */
    uint64_t V1 = H[1];

    /* Multiply Z by V for the set bits in Y, starting at the top.
       This is a very simple bit by bit version that may not be very
       fast but it should be resistant to cache timing attacks. */
    for (uint8_t posn = 0; posn < 16; ++posn) {
        uint8_t value = ((const uint8_t *)Y)[posn];
        for (uint8_t bit = 0; bit < 8; ++bit, value <<= 1) {
            /* Extract the high bit of "value" and turn it into a mask */
            uint64_t mask = (~((uint64_t)(value >> 7))) + 1;

            /* XOR V with Z if the bit is 1 */
            Z0 ^= (V0 & mask);
            Z1 ^= (V1 & mask);

            /* Rotate V right by 1 bit */
            mask = ((~(V1 & 0x01)) + 1) & 0xE100000000000000ULL;
            V1 = (V1 >> 1) | (V0 << 63);
            V0 = (V0 >> 1) ^ mask;
        }
    }

    /* We have finished the block so copy Z into Y and byte-swap */
    Y[0] = swapEndian(Z0);
    Y[1] = swapEndian(Z1);
}

#else /* GHASH_WORD32 */

/* Default 32-bit version of GHASH */

static uint32_t swapEndian(uint32_t x)
{
#if __BYTE_ORDER == __BIG_ENDIAN
    return x;
#else
    return ((x >> 24) & 0x000000FF) |
           ((x >>  8) & 0x0000FF00) |
           ((x <<  8) & 0x00FF0000) |
           ((x << 24) & 0xFF000000);
#endif
}

static void GF128_mulInit(uint32_t H[4], const void *key)
{
    /* Copy the key into H and convert from big endian to host order */
    memcpy(H, key, 16);
    H[0] = swapEndian(H[0]);
    H[1] = swapEndian(H[1]);
    H[2] = swapEndian(H[2]);
    H[3] = swapEndian(H[3]);
}

static void GF128_mul(uint32_t Y[4], const uint32_t H[4])
{
    uint32_t Z0 = 0;        /* Z = 0 */
    uint32_t Z1 = 0;
    uint32_t Z2 = 0;
    uint32_t Z3 = 0;
    uint32_t V0 = H[0];     /* V = H */
    uint32_t V1 = H[1];
    uint32_t V2 = H[2];
    uint32_t V3 = H[3];

    /* Multiply Z by V for the set bits in Y, starting at the top.
       This is a very simple bit by bit version that may not be very
       fast but it should be resistant to cache timing attacks. */
    for (uint8_t posn = 0; posn < 16; ++posn) {
        uint8_t value = ((const uint8_t *)Y)[posn];
        for (uint8_t bit = 0; bit < 8; ++bit, value <<= 1) {
            /* Extract the high bit of "value" and turn it into a mask */
            uint32_t mask = (~((uint32_t)(value >> 7))) + 1;

            /* XOR V with Z if the bit is 1 */
            Z0 ^= (V0 & mask);
            Z1 ^= (V1 & mask);
            Z2 ^= (V2 & mask);
            Z3 ^= (V3 & mask);

            /* Rotate V right by 1 bit */
            mask = ((~(V3 & 0x01)) + 1) & 0xE1000000;
            V3 = (V3 >> 1) | (V2 << 31);
            V2 = (V2 >> 1) | (V1 << 31);
            V1 = (V1 >> 1) | (V0 << 31);
            V0 = (V0 >> 1) ^ mask;
        }
    }

    /* We have finished the block so copy Z into Y and byte-swap */
    Y[0] = swapEndian(Z0);
    Y[1] = swapEndian(Z1);
    Y[2] = swapEndian(Z2);
    Y[3] = swapEndian(Z3);
}

#endif /* GHASH_WORD32 */

void ghash_reset(ghash_state *state, const void *key)
{
    if (key)
        GF128_mulInit(state->H, (const void *)key);
    memset(state->Y, 0, sizeof(state->Y));
    state->posn = 0;
}

void ghash_update(ghash_state *state, const void *data, size_t len)
{
    const uint8_t *d = (const uint8_t *)data;
    while (len > 0) {
        uint8_t size = 16 - state->posn;
        if (size > len)
            size = len;
        uint8_t *y = ((uint8_t *)state->Y) + state->posn;
        for (uint8_t i = 0; i < size; ++i)
            y[i] ^= d[i];
        state->posn += size;
        len -= size;
        d += size;
        if (state->posn == 16) {
            GF128_mul(state->Y, state->H);
            state->posn = 0;
        }
    }
}

void ghash_finalize(ghash_state *state, void *token, size_t len)
{
    ghash_pad(state);
    if (len > 16)
        len = 16;
    memcpy(token, state->Y, len);
}

void ghash_pad(ghash_state *state)
{
    if (state->posn != 0) {
        /* Padding involves XOR'ing the rest of state->Y with zeroes,
           which does nothing.  Immediately process the next chunk */
        GF128_mul(state->Y, state->H);
        state->posn = 0;
    }
}
