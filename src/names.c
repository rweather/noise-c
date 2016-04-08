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

#include "internal.h"
#include <string.h>

/* List of all known algorithm names and the corresponding identifiers */
typedef struct
{
    int id;
    const char *name;
    size_t name_len;

} NoiseIdMapping;
static NoiseIdMapping const algorithm_names[] = {
    /* Cipher algorithsm */
    {NOISE_CIPHER_CHACHAPOLY,   "ChaChaPoly",   10},
    {NOISE_CIPHER_AESGCM,       "AESGCM",        6},

    /* Hash algorithms */
    {NOISE_HASH_BLAKE2s,        "BLAKE2s",       7},
    {NOISE_HASH_BLAKE2b,        "BLAKE2b",       7},
    {NOISE_HASH_SHA256,         "SHA256",        6},
    {NOISE_HASH_SHA512,         "SHA512",        6},

    /* Diffie-Hellman algorithms */
    {NOISE_DH_CURVE25519,       "25519",         5},
    {NOISE_DH_CURVE448,         "448",           3},

    /* Terminator for the list */
    {0,                         0,               0}
};

/**
 * \brief Maps an algorithm name to the corresponding identifier.
 *
 * \param category The category of identifier to look for; one of
 * NOISE_CIPHER_CATEGORY, NOISE_HASH_CATEGORY, NOISE_DH_CATEGORY, or zero.
 * Zero indicates "any category".
 * \param name Points to the name to map.
 * \param name_len Length of the \a name in bytes.
 *
 * \return The algorithm identifier, or zero if the name is unknown
 * in the specified \a category.
 *
 * The \a category parameter can be used to restrict the search to
 * algorithms of a certain type.  If the \a name is valid for some other
 * category, that mapping will be ignored.
 *
 * \sa noise_id_to_name()
 */
int noise_name_to_id(int category, const char *name, size_t name_len)
{
    const NoiseIdMapping *mapping = algorithm_names;
    int mask = category ? NOISE_ID(0xFF, 0) : 0;
    if (!name)
        return 0;
    while (mapping->name_len) {
        if ((mapping->id & mask) == category) {
            if (mapping->name_len == name_len &&
                    !memcmp(mapping->name, name, name_len)) {
                return mapping->id;
            }
        }
        ++mapping;
    }
    return 0;
}

/**
 * \brief Maps an algorithm identifier to the corresponding name.
 *
 * \param category The category of identifier to look for; one of
 * NOISE_CIPHER_CATEGORY, NOISE_HASH_CATEGORY, NOISE_DH_CATEGORY, or zero.
 * Zero indicates "any category".
 * \param id The algorithm identifier to map.
 *
 * \return The NUL-terminated name of the algorithm, or NULL if the
 * \a id is unknown in the specified \a category.
 *
 * The \a category parameter can be used to restrict the search to
 * algorithms of a certain type.  If the \a id is valid for some other
 * category, that mapping will be ignored.
 *
 * \sa noise_name_to_id()
 */
const char *noise_id_to_name(int category, int id)
{
    const NoiseIdMapping *mapping = algorithm_names;
    int mask = category ? NOISE_ID(0xFF, 0) : 0;
    if (id <= 0)
        return 0;
    while (mapping->name_len) {
        if ((mapping->id & mask) == category) {
            if (mapping->id == id)
                return mapping->name;
        }
        ++mapping;
    }
    return 0;
}
