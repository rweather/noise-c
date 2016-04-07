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

#ifndef NOISE_IDENTIFIERS_H
#define NOISE_IDENTIFIERS_H

#ifdef __cplusplus
extern "C" {
#endif

#define NOISE_ID(ch,num)    ((((int)(ch)) << 8) | ((int)(num)))

/* AEAD cipher algorithms */
#define NOISE_CIPHER_NONE               0
#define NOISE_CIPHER_CHACHAPOLY         NOISE_ID('C', 1)
#define NOISE_CIPHER_AESGCM             NOISE_ID('C', 2)

/* Hash algorithms */
#define NOISE_HASH_NONE                 0
#define NOISE_HASH_BLAKE2s              NOISE_ID('H', 1)
#define NOISE_HASH_BLAKE2b              NOISE_ID('H', 2)
#define NOISE_HASH_SHA256               NOISE_ID('H', 3)
#define NOISE_HASH_SHA512               NOISE_ID('H', 4)

/* Diffie-Hellman algorithms */
#define NOISE_DH_NONE                   0
#define NOISE_DH_CURVE25519             NOISE_ID('D', 1)
#define NOISE_DH_CURVE448               NOISE_ID('D', 2)

/* Error codes */
#define NOISE_ERROR_NONE                0
#define NOISE_ERROR_NO_MEMORY           NOISE_ID('E', 1)
#define NOISE_ERROR_UNKNOWN_ID          NOISE_ID('E', 2)
#define NOISE_ERROR_UNKNOWN_NAME        NOISE_ID('E', 3)
#define NOISE_ERROR_INVALID_LENGTH      NOISE_ID('E', 4)
#define NOISE_ERROR_INVALID_PARAM       NOISE_ID('E', 5)
#define NOISE_ERROR_INVALID_STATE       NOISE_ID('E', 6)
#define NOISE_ERROR_NONCE_OVERFLOW      NOISE_ID('E', 7)
#define NOISE_ERROR_MAC_FAILURE         NOISE_ID('E', 8)

#ifdef __cplusplus
};
#endif

#endif
