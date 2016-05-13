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

/**
 * \file names.h
 * \brief Mapping algorithm names to/from identifiers
 */

/**
 * \file names.c
 * \brief Implementation of algorithm name mapping
 */

/**
 * \defgroup names Algorithm name lookup API
 */
/**@{*/

/**
 * \struct NoiseProtocolId
 * \brief Noise protocol name broken out into separate identifier fields.
 */

/** @cond */

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

    /* Handshake patterns */
    {NOISE_PATTERN_N,           "N",             1},
    {NOISE_PATTERN_X,           "X",             1},
    {NOISE_PATTERN_K,           "K",             1},
    {NOISE_PATTERN_NN,          "NN",            2},
    {NOISE_PATTERN_NK,          "NK",            2},
    {NOISE_PATTERN_NX,          "NX",            2},
    {NOISE_PATTERN_XN,          "XN",            2},
    {NOISE_PATTERN_XK,          "XK",            2},
    {NOISE_PATTERN_XX,          "XX",            2},
    {NOISE_PATTERN_KN,          "KN",            2},
    {NOISE_PATTERN_KK,          "KK",            2},
    {NOISE_PATTERN_KX,          "KX",            2},
    {NOISE_PATTERN_IN,          "IN",            2},
    {NOISE_PATTERN_IK,          "IK",            2},
    {NOISE_PATTERN_IX,          "IX",            2},
    {NOISE_PATTERN_XX_FALLBACK, "XXfallback",   10},

    /* Protocol name prefixes */
    {NOISE_PREFIX_STANDARD,     "Noise",         5},
    {NOISE_PREFIX_PSK,          "NoisePSK",      8},

    /* Signature algorithms */
    {NOISE_SIGN_ED25519,        "Ed25519",       7},

    /* Terminator for the list */
    {0,                         0,               0}
};

/** @endcond */

/**
 * \brief Maps an algorithm name to the corresponding identifier.
 *
 * \param category The category of identifier to look for; one of
 * NOISE_CIPHER_CATEGORY, NOISE_HASH_CATEGORY, NOISE_DH_CATEGORY,
 * NOISE_PATTERN_CATEGORY, NOISE_PREFIX_CATEGORY, NOISE_SIGN_CATEGORY,
 * or zero.  Zero indicates "any category".
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
 * NOISE_CIPHER_CATEGORY, NOISE_HASH_CATEGORY, NOISE_DH_CATEGORY,
 * NOISE_PATTERN_CATEGORY, NOISE_PREFIX_CATEGORY, NOISE_SIGN_CATEGORY,
 * or zero.  Zero indicates "any category".
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

/**
 * \brief Parses a field from a protocol name string.
 *
 * \param category The category of identifier that we expect in this field.
 * \param name Points to the start of the protocol name string.
 * \param len The total length of the protocol name string.
 * \param posn The current position in the string, updated once the next
 * field has been parsed.
 * \param is_last Non-zero if this is the last expected field, or zero
 * if we expect further fields to follow.
 * \param ok Initialized to non-zero by the caller.  Will be set to zero
 * if a parse error was encountered.
 *
 * \return The algorithm identifier for the current field, or zero
 * if the field's contents are not a recognized name for this field.
 */
static int noise_protocol_parse_field
    (int category, const char *name, size_t len, size_t *posn,
     int is_last, int *ok)
{
    size_t start, field_len;
    int id;

    /* If the parse already failed, then nothing further to do */
    if (!(*ok))
        return 0;

    /* Find the start and end of the current field */
    start = *posn;
    while (*posn < len && name[*posn] != '_')
        ++(*posn);
    field_len = *posn - start;

    /* If this is the last field, we should be at the end
       of the string.  Otherwise there should be a '_' here */
    if (is_last) {
        if (*posn < len) {
            *ok = 0;
            return 0;
        }
    } else {
        if (*posn >= len) {
            *ok = 0;
            return 0;
        }
        ++(*posn);  /* Skip the '_' */
    }

    /* Look up the name in the current category */
    id = noise_name_to_id(category, name + start, field_len);
    if (!id)
        *ok = 0;
    return id;
}

/**
 * \brief Parses a protocol name into a set of identifiers for the
 * algorithms that are indicated by the name.
 *
 * \param id The resulting structure to populate with identifiers.
 * \param name Points to the start of the protocol name.
 * \param name_len The length of the protocol name in bytes.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if either \a id or \a name is NULL.
 * \return NOISE_ERROR_UNKNOWN_NAME if the protocol name could not be parsed.
 *
 * \sa noise_protocol_id_to_name()
 */
int noise_protocol_name_to_id
    (NoiseProtocolId *id, const char *name, size_t name_len)
{
    size_t posn;
    int ok;

    /* Bail out if the parameters are incorrect */
    if (!id || !name)
        return NOISE_ERROR_INVALID_PARAM;

    /* Parse underscore-separated fields from the name */
    posn = 0;
    ok = 1;
    id->prefix_id = noise_protocol_parse_field
        (NOISE_PREFIX_CATEGORY, name, name_len, &posn, 0, &ok);
    id->pattern_id = noise_protocol_parse_field
        (NOISE_PATTERN_CATEGORY, name, name_len, &posn, 0, &ok);
    id->dh_id = noise_protocol_parse_field
        (NOISE_DH_CATEGORY, name, name_len, &posn, 0, &ok);
    id->cipher_id = noise_protocol_parse_field
        (NOISE_CIPHER_CATEGORY, name, name_len, &posn, 0, &ok);
    id->hash_id = noise_protocol_parse_field
        (NOISE_HASH_CATEGORY, name, name_len, &posn, 1, &ok);
    id->reserved_id = 0;

    /* If there was a parse error, then clear everything */
    if (!ok) {
        id->prefix_id = NOISE_PREFIX_NONE;
        id->pattern_id = NOISE_PATTERN_NONE;
        id->dh_id = NOISE_DH_NONE;
        id->cipher_id = NOISE_CIPHER_NONE;
        id->hash_id = NOISE_HASH_NONE;
        id->reserved_id = 0;
        return NOISE_ERROR_UNKNOWN_NAME;
    }

    /* The name has been parsed */
    return NOISE_ERROR_NONE;
}

/**
 * \brief Formats a field within a protocol name.
 *
 * \param category The category of algorithm identifier in this field.
 * \param id The identifier to format.
 * \param name The name buffer to format the field into.
 * \param len The length of the \a name buffer in bytes.
 * \param posn The current format position within the \a name buffer.
 * \param is_last Non-zero if this is the last field in the name,
 * or zero if this field is not the last.
 * \param err Points to an error code.  Initialized to NOISE_ERROR_NONE
 * by the caller and updated by this function if there is an error.
 */
static void noise_protocol_format_field
    (int category, int id, char *name, size_t len, size_t *posn,
     int is_last, int *err)
{
    const char *alg_name;
    size_t alg_len;

    /* If the formatting already failed, then bail out now */
    if (*err != NOISE_ERROR_NONE)
        return;

    /* Look up the name for the algorithm identifier */
    alg_name = noise_id_to_name(category, id);
    if (!alg_name) {
        *err = NOISE_ERROR_UNKNOWN_ID;
        return;
    }
    alg_len = strlen(alg_name);

    /* Will the name fit into the buffer, followed by either '_' or '\0'? */
    if (alg_len >= (len - *posn)) {
        *err = NOISE_ERROR_INVALID_LENGTH;
        return;
    }
    memcpy(name + *posn, alg_name, alg_len);
    *posn += alg_len;

    /* Add either a separator or a terminator */
    if (!is_last)
        name[(*posn)++] = '_';
    else
        name[*posn] = '\0';
}

/**
 * \brief Formats a protocol name from a set of identifiers for
 * the algorithms that make up the name.
 *
 * \param name The buffer to write the protocol name to.
 * \param name_len The number of bytes of space in the \a name buffer.
 * \param id The set of identifiers to format.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if either \a name or \a id is NULL.
 * \return NOISE_ERROR_INVALID_LENGTH if the \a name buffer is not large
 * enough to contain the full name.
 * \return NOISE_ERROR_UNKNOWN_ID if one of the identifiers in \a id does
 * not have a known mapping to a name.
 *
 * This function guarantees to NUL-terminate the \a name if
 * the function succeeds.
 *
 * It is recommended that \a name_len be at least NOISE_MAX_PROTOCOL_NAME
 * bytes in length.
 *
 * \sa noise_protocol_name_to_id()
 */
int noise_protocol_id_to_name
    (char *name, size_t name_len, const NoiseProtocolId *id)
{
    size_t posn;
    int err;

    /* Bail out if the parameters are incorrect */
    if (!id) {
        if (name && name_len)
            *name = '\0';   /* Just to be safe */
        return NOISE_ERROR_INVALID_PARAM;
    }
    if (!name)
        return NOISE_ERROR_INVALID_PARAM;
    if (!name_len)
        return NOISE_ERROR_INVALID_LENGTH;

    /* Format the fields into the return buffer */
    posn = 0;
    err = NOISE_ERROR_NONE;
    noise_protocol_format_field
        (NOISE_PREFIX_CATEGORY, id->prefix_id, name, name_len, &posn, 0, &err);
    noise_protocol_format_field
        (NOISE_PATTERN_CATEGORY, id->pattern_id, name, name_len, &posn, 0, &err);
    noise_protocol_format_field
        (NOISE_DH_CATEGORY, id->dh_id, name, name_len, &posn, 0, &err);
    noise_protocol_format_field
        (NOISE_CIPHER_CATEGORY, id->cipher_id, name, name_len, &posn, 0, &err);
    noise_protocol_format_field
        (NOISE_HASH_CATEGORY, id->hash_id, name, name_len, &posn, 1, &err);

    /* The reserved identifier must be zero.  We don't know how to
       format reserved identifiers other than zero */
    if (id->reserved_id != 0 && err == NOISE_ERROR_NONE)
        err = NOISE_ERROR_UNKNOWN_ID;

    /* If an error occurred, then clear the buffer just to be safe */
    if (err != NOISE_ERROR_NONE)
        *name = '\0';

    /* Done */
    return err;
}

/**@}*/
