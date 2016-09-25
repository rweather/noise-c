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

#ifndef NOISE_NAMES_H
#define NOISE_NAMES_H

#include <noise/protocol/constants.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    int prefix_id;      /**< Protocol name prefix */
    int pattern_id;     /**< Handshake pattern */
    int dh_id;          /**< Diffie-Hellman algorithm identifier */
    int cipher_id;      /**< Cipher algorithm identifier */
    int hash_id;        /**< Hash algorithm identifier */
    int hybrid_id;      /**< Hybrid forward secrecy algorithm identifier */
    int reserved[4];    /**< Reserved for future use; should be zero */

} NoiseProtocolId;

int noise_name_to_id(int category, const char *name, size_t name_len);
const char *noise_id_to_name(int category, int id);

int noise_protocol_name_to_id
    (NoiseProtocolId *id, const char *name, size_t name_len);
int noise_protocol_id_to_name
    (char *name, size_t name_len, const NoiseProtocolId *id);

#ifdef __cplusplus
};
#endif

#endif
