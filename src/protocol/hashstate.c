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
 * \file hashstate.h
 * \brief HashState interface
 */

/**
 * \file hashstate.c
 * \brief HashState implementation
 */

/**
 * \defgroup hashstate HashState API
 *
 * The HashState API provides access to the hash algorithms within the
 * library.  Normally applications won't need to use these functions
 * directly because \ref symmetricstate "SymmetricState" takes care
 * of hashing operations for the Noise protocol internally.
 *
 * These functions are provided mainly for testing purposes.  However,
 * applications can use them if they need to hash values for some
 * higher-level protocol purpose.  This may be preferable to the
 * application having to source its own hash implementations
 * for that purpose.
 */
/**@{*/

/**
 * \typedef NoiseHashState
 * \brief Opaque object that represents a HashState.
 */

/**
 * \brief Creates a new HashState object by its algorithm identifier.
 *
 * \param state Points to the variable where to store the pointer to
 * the new HashState object.
 * \param id The algorithm identifier; NOISE_HASH_BLAKE2s,
 * NOISE_HASH_SHA256, etc.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state is NULL.
 * \return NOISE_ERROR_UNKNOWN_ID if \a id is unknown.
 * \return NOISE_ERROR_NO_MEMORY if there is insufficient memory to
 * allocate the new HashState object.
 *
 * \sa noise_hashstate_free(), noise_hashstate_new_by_name()
 */
int noise_hashstate_new_by_id(NoiseHashState **state, int id)
{
    /* The "state" argument must be non-NULL */
    if (!state)
        return NOISE_ERROR_INVALID_PARAM;

    /* Create the HashState object for the "id" */
    *state = 0;
    switch (id) {
    case NOISE_HASH_BLAKE2s:
        *state = noise_blake2s_new();
        break;

    case NOISE_HASH_BLAKE2b:
        *state = noise_blake2b_new();
        break;

    case NOISE_HASH_SHA256:
        *state = noise_sha256_new();
        break;

    case NOISE_HASH_SHA512:
        *state = noise_sha512_new();
        break;

    default:
        return NOISE_ERROR_UNKNOWN_ID;
    }

    /* Bail out if insufficient memory */
    if (!(*state))
        return NOISE_ERROR_NO_MEMORY;

    /* Ready to go */
    return NOISE_ERROR_NONE;
}

/**
 * \brief Creates a new HashState object by its algorithm name.
 *
 * \param state Points to the variable where to store the pointer to
 * the new HashState object.
 * \param name The name of the cipher algorithm; e.g. "BLAKE2s", "SHA256", etc.
 * This string must be NUL-terminated.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state or \a name is NULL.
 * \return NOISE_ERROR_UNKNOWN_NAME if \a name is unknown.
 * \return NOISE_ERROR_NO_MEMORY if there is insufficient memory to
 * allocate the new HashState object.
 *
 * \sa noise_hashstate_free(), noise_hashstate_new_by_id()
 */
int noise_hashstate_new_by_name(NoiseHashState **state, const char *name)
{
    int id;

    /* The "state" and "name" arguments must be non-NULL */
    if (!state)
        return NOISE_ERROR_INVALID_PARAM;
    *state = 0;
    if (!name)
        return NOISE_ERROR_INVALID_PARAM;

    /* Map the name and create the corresponding object */
    id = noise_name_to_id(NOISE_HASH_CATEGORY, name, strlen(name));
    if (id)
        return noise_hashstate_new_by_id(state, id);

    /* We don't know what this is */
    return NOISE_ERROR_UNKNOWN_NAME;
}

/**
 * \brief Frees a HashState object after destroying all sensitive material.
 *
 * \param state The HashState object to free.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state is NULL.
 *
 * \sa noise_hashstate_new_by_id(), noise_hashstate_new_by_name()
 */
int noise_hashstate_free(NoiseHashState *state)
{
    /* Bail out if no hash state */
    if (!state)
        return NOISE_ERROR_INVALID_PARAM;

    /* Call the backend-specific destroy function if necessary */
    if (state->destroy)
        (*(state->destroy))(state);

    /* Clean and free the memory */
    noise_free(state, state->size);
    return NOISE_ERROR_NONE;
}

/**
 * \brief Gets the algorithm identifier for a HashState object.
 *
 * \param state The HashState object.
 *
 * \return The algorithm identifier, or NOISE_HASH_NONE if \a state is NULL.
 */
int noise_hashstate_get_hash_id(const NoiseHashState *state)
{
    return state ? state->hash_id : NOISE_HASH_NONE;
}

/**
 * \brief Gets the length of the hash output for a HashState object.
 *
 * \param state The HashState object.
 *
 * \return The size of the hash in bytes, or 0 if \a state is NULL.
 *
 * \sa noise_hashstate_get_block_length()
 */
size_t noise_hashstate_get_hash_length(const NoiseHashState *state)
{
    return state ? state->hash_len : 0;
}

/**
 * \brief Gets the length of the block for a HashState object.
 *
 * \param state The HashState object.
 *
 * \return The size of the block in bytes, or 0 if \a state is NULL.
 *
 * \sa noise_hashstate_get_hash_length()
 */
size_t noise_hashstate_get_block_length(const NoiseHashState *state)
{
    return state ? state->block_len : 0;
}

/**
 * \brief Resets the hash state.
 *
 * \param state The HashState object.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state is NULL.
 *
 * \sa noise_hashstate_update(), noise_hashstate_finalize()
 */
int noise_hashstate_reset(NoiseHashState *state)
{
    /* Validate the parameter */
    if (!state)
        return NOISE_ERROR_INVALID_PARAM;

    /* Reset the hash state */
    (*(state->reset))(state);
    return NOISE_ERROR_NONE;
}

/**
 * \brief Updates the hash state with more data.
 *
 * \param state The HashState object.
 * \param data The new data to incorporate into the hash state.
 * \param data_len The length of the \a data in bytes.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state or \a data is NULL.
 *
 * \sa noise_hashstate_reset(), noise_hashstate_finalize()
 */
int noise_hashstate_update
    (NoiseHashState *state, const uint8_t *data, size_t data_len)
{
    /* Validate the parameters */
    if (!state || !data)
        return NOISE_ERROR_INVALID_PARAM;

    /* Update the hash state */
    (*(state->update))(state, data, data_len);
    return NOISE_ERROR_NONE;
}

/**
 * \brief Finalizes the hash state and returns the hash value.
 *
 * \param state The HashState object.
 * \param hash The return buffer for the hash value.
 * \param hash_len The length of the \a hash buffer in bytes.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state or \a hash is NULL.
 * \return NOISE_ERROR_INVALID_LENGTH if \a hash_len is not the same
 * as the hash length for the algorithm.
 *
 * \sa noise_hashstate_reset(), noise_hashstate_update(),
 * noise_hashstate_get_hash_length()
 */
int noise_hashstate_finalize
    (NoiseHashState *state, uint8_t *hash, size_t hash_len)
{
    /* Validate the parameters */
    if (!state || !hash)
        return NOISE_ERROR_INVALID_PARAM;
    if (hash_len != state->hash_len)
        return NOISE_ERROR_INVALID_LENGTH;

    /* Finalize the hash state */
    (*(state->finalize))(state, hash);
    return NOISE_ERROR_NONE;
}

/**
 * \brief Hashes a single data buffer and returns the hash value.
 *
 * \param state The HashState object.
 * \param data Points to the data to be hashed.
 * \param data_len The length of the data in bytes.
 * \param hash The return buffer for the hash value.
 * \param hash_len The length of the \a hash buffer in bytes.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if one of \a state, \a data,
 * or \a hash is NULL.
 * \return NOISE_ERROR_INVALID_LENGTH if \a hash_len is not the same
 * as the hash length for the algorithm.
 *
 * The \a data and \a hash buffers are allowed to overlap.
 *
 * This is a convenience function that combines the effect of
 * noise_hashstate_reset(), nose_hashstate_update(), and
 * noise_hashstate_finalize().
 *
 * \sa noise_hashstate_hash_two(), noise_hashstate_get_hash_length()
 */
int noise_hashstate_hash_one
    (NoiseHashState *state, const uint8_t *data, size_t data_len,
     uint8_t *hash, size_t hash_len)
{
    /* Validate the parameters */
    if (!state || !data || !hash)
        return NOISE_ERROR_INVALID_PARAM;
    if (hash_len != state->hash_len)
        return NOISE_ERROR_INVALID_LENGTH;

    /* Hash the data */
    (*(state->reset))(state);
    (*(state->update))(state, data, data_len);
    (*(state->finalize))(state, hash);
    return NOISE_ERROR_NONE;
}

/**
 * \brief Hashes the concatenation of two data buffers and returns
 * the combined hash value.
 *
 * \param state The HashState object.
 * \param data1 Points to the first data buffer to be hashed.
 * \param data1_len The length of the first data buffer in bytes.
 * \param data2 Points to the second data buffer to be hashed.
 * \param data2_len The length of the second data buffer in bytes.
 * \param hash The return buffer for the hash value.
 * \param hash_len The length of the \a hash buffer in bytes.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if one of \a state, \a data1,
 * \a data2, or \a hash is NULL.
 * \return NOISE_ERROR_INVALID_LENGTH if \a hash_len is not the same
 * as the hash length for the algorithm.
 *
 * The \a data1, \a data2, and \a hash buffers are allowed to overlap.
 *
 * This is a convenience function that combines the effect of
 * noise_hashstate_reset(), nose_hashstate_update(), and
 * noise_hashstate_finalize().
 *
 * \sa noise_hashstate_hash_one(), noise_hashstate_get_hash_length()
 */
int noise_hashstate_hash_two
    (NoiseHashState *state, const uint8_t *data1, size_t data1_len,
     const uint8_t *data2, size_t data2_len, uint8_t *hash, size_t hash_len)
{
    /* Validate the parameters */
    if (!state || !data1 || !data2 || !hash)
        return NOISE_ERROR_INVALID_PARAM;
    if (hash_len != state->hash_len)
        return NOISE_ERROR_INVALID_LENGTH;

    /* Hash the data */
    (*(state->reset))(state);
    (*(state->update))(state, data1, data1_len);
    (*(state->update))(state, data2, data2_len);
    (*(state->finalize))(state, hash);
    return NOISE_ERROR_NONE;
}

/** @cond */
#define HMAC_IPAD   0x36    /**< Padding value for the inner HMAC context */
#define HMAC_OPAD   0x5C    /**< Padding value for the outer HMAC context */
/** @endcond */

/**
 * \brief XOR's a HMAC key value with a byte value.
 *
 * \param key Points to the key.
 * \param key_len The length of the key in bytes.
 * \param value The byte value to XOR into the \a key.
 */
static void noise_hashstate_xor_key(uint8_t *key, size_t key_len, uint8_t value)
{
    while (key_len > 0) {
        *key++ ^= value;
        --key_len;
    }
}

/**
 * \brief Computes a HMAC value from key and data.
 *
 * \param state The HashState object.
 * \param key Points to the key.
 * \param key_len The length of the key in bytes.
 * \param data1 Points to the first data block.
 * \param data1_len The length of the first data block in bytes.
 * \param data2 Points to the second data block (may be NULL).
 * \param data2_len The length of the second data block in bytes.
 * \param hash The final output HMAC hash value.
 *
 * The \a data and \a hash buffers are allowed to overlap, but neither
 * must overlap with \a key.
 *
 * Reference: <a href="http://tools.ietf.org/html/rfc2104">RFC 2104</a>
 */
static void noise_hashstate_hmac
    (NoiseHashState *state, const uint8_t *key, size_t key_len,
     const uint8_t *data1, size_t data1_len,
     const uint8_t *data2, size_t data2_len, uint8_t *hash)
{
    size_t hash_len = state->hash_len;
    size_t block_len = state->block_len;
    uint8_t *key_block;

    /* Allocate temporary stack space for the key block */
    key_block = alloca(block_len);

    /* Format the key for the inner hashing context */
    if (key_len <= block_len) {
        memcpy(key_block, key, key_len);
        memset(key_block + key_len, 0, block_len - key_len);
    } else {
        (*(state->reset))(state);
        (*(state->update))(state, key, key_len);
        (*(state->finalize))(state, key_block);
        memset(key_block + hash_len, 0, block_len - hash_len);
    }
    noise_hashstate_xor_key(key_block, block_len, HMAC_IPAD);

    /* Calculate the inner hash */
    (*(state->reset))(state);
    (*(state->update))(state, key_block, block_len);
    (*(state->update))(state, data1, data1_len);
    if (data2)
        (*(state->update))(state, data2, data2_len);
    (*(state->finalize))(state, hash);

    /* Format the key for the outer hashing context */
    noise_hashstate_xor_key(key_block, block_len, HMAC_IPAD ^ HMAC_OPAD);

    /* Calculate the outer hash */
    (*(state->reset))(state);
    (*(state->update))(state, key_block, block_len);
    (*(state->update))(state, hash, hash_len);
    (*(state->finalize))(state, hash);

    /* Clean up and exit */
    noise_clean(key_block, state->block_len);
}

/**
 * \brief Hashes input data with a key to generate two output values.
 *
 * \param state The HashState object.
 * \param key Points to the key.
 * \param key_len The length of the \a key in bytes.
 * \param data Points to the data.
 * \param data_len The length of the \a data in bytes.
 * \param output1 The first output buffer to fill.
 * \param output1_len The length of the first output buffer, which may
 * be shorter than the hash length of the HashState object.
 * \param output2 The second output buffer to fill.
 * \param output2_len The length of the second output buffer, which may
 * be shorter than the hash length of the HashState object.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if one of \a state, \a key, \a data,
 * \a output1, or \a output2 is NULL.
 * \return NOISE_ERROR_INVALID_LENGTH if \a output1_len or \a output2_len is
 * greater than the hash length for the HashState object.
 *
 * Reference: <a href="http://tools.ietf.org/html/rfc5869">RFC 5868</a>
 *
 * \sa noise_hashstate_hash_one()
 */
int noise_hashstate_hkdf
    (NoiseHashState *state, const uint8_t *key, size_t key_len,
     const uint8_t *data, size_t data_len,
     uint8_t *output1, size_t output1_len,
     uint8_t *output2, size_t output2_len)
{
    size_t hash_len;
    uint8_t *temp_key;
    uint8_t *temp_hash;

    /* Validate the parameters */
    if (!state || !key || !data || !output1 || !output2)
        return NOISE_ERROR_INVALID_PARAM;
    hash_len = state->hash_len;
    if (output1_len > hash_len || output2_len > hash_len)
        return NOISE_ERROR_INVALID_LENGTH;

    /* Allocate local stack space for the temporary hash values */
    temp_key = alloca(hash_len);
    temp_hash = alloca(hash_len + 1);

    /* Generate the temporary hashing key */
    noise_hashstate_hmac(state, key, key_len, data, data_len, 0, 0, temp_key);

    /* Generate the first output */
    temp_hash[0] = 0x01;
    noise_hashstate_hmac
        (state, temp_key, hash_len, temp_hash, 1, 0, 0, temp_hash);
    memcpy(output1, temp_hash, output1_len);

    /* Generate the second output */
    temp_hash[hash_len] = 0x02;
    noise_hashstate_hmac
        (state, temp_key, hash_len, temp_hash, hash_len + 1, 0, 0, temp_hash);
    memcpy(output2, temp_hash, output2_len);

    /* Clean up and exit */
    noise_clean(temp_key, hash_len);
    noise_clean(temp_hash, hash_len + 1);
    return NOISE_ERROR_NONE;
}

/**
 * \brief Hashes a passphrase and salt using the PBKDF2 key derivation function.
 *
 * \param state The HashState object.
 * \param passphrase Points to the passphrase.
 * \param passphrase_len The length of the passphrase in bytes.
 * \param salt Points to the salt.
 * \param salt_len The length of the salt in bytes.
 * \param iterations The number of hash iterations to use.
 * \param output The output buffer to put the final hash into.
 * \param output_len The length of the output in bytes.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if one of \a state, \a passphrase,
 * \a salt, or \a output is NULL.
 * \return NOISE_ERROR_INVALID_LENGTH if the \a output_len is too large
 * for valid PBKDF2 output.
 *
 * This function is intended as a utility for applications that need to hash a
 * passphrase to encrypt private keys and other sensitive information.
 *
 * Reference: <a href="https://www.ietf.org/rfc/rfc2898.txt">RFC 2898</a>
 */
int noise_hashstate_pbkdf2
    (NoiseHashState *state, const uint8_t *passphrase, size_t passphrase_len,
     const uint8_t *salt, size_t salt_len, size_t iterations,
     uint8_t *output, size_t output_len)
{
    size_t hash_len;
    uint64_t max_size;
    uint8_t T[NOISE_MAX_HASHLEN];
    uint8_t U[NOISE_MAX_HASHLEN];
    uint8_t ibuf[4];
    size_t i, index, index2;

    /* Validate the parameters */
    if (!state || !passphrase || !salt || !output)
        return NOISE_ERROR_INVALID_PARAM;
    hash_len = state->hash_len;
    max_size = ((uint64_t)0xFFFFFFFFU) * hash_len;
    if (output_len > max_size)
        return NOISE_ERROR_INVALID_LENGTH;

    /* Generate the required output blocks */
    i = 1;
    while (output_len > 0) {
        /* Generate the next block of output */
        ibuf[0] = (uint8_t)(i >> 24);
        ibuf[1] = (uint8_t)(i >> 16);
        ibuf[2] = (uint8_t)(i >> 8);
        ibuf[3] = (uint8_t)i;
        ++i;
        noise_hashstate_hmac
            (state, passphrase, passphrase_len, salt, salt_len,
             ibuf, sizeof(ibuf), T);
        memcpy(U, T, hash_len);
        for (index = 1; index < iterations; ++index) {
            noise_hashstate_hmac
                (state, passphrase, passphrase_len, U, hash_len, 0, 0, U);
            for (index2 = 0; index2 < hash_len; ++index2)
                T[index2] ^= U[index2];
        }

        /* Copy the generated data into the output buffer */
        if (output_len >= hash_len) {
            memcpy(output, T, hash_len);
            output += hash_len;
            output_len -= hash_len;
        } else {
            memcpy(output, T, output_len);
            output_len = 0;
        }
    }

    /* Clean up and exit */
    noise_clean(T, sizeof(T));
    noise_clean(U, sizeof(U));
    return NOISE_ERROR_NONE;
}

/**
 * \brief Gets the maximum hash length for the supported algorithms.
 *
 * \sa noise_hashstate_get_max_block_length()
 */
int noise_hashstate_get_max_hash_length(void)
{
    return NOISE_MAX_HASHLEN;
}

/**
 * \brief Gets the maximum block length for the supported algorithms.
 *
 * \sa noise_hashstate_get_max_hash_length()
 */
int noise_hashstate_get_max_block_length(void)
{
    return 128;
}

/**@}*/
