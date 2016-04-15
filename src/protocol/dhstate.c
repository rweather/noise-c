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
 * \file dhstate.h
 * \brief DHState interface
 */

/**
 * \file dhstate.c
 * \brief DHState implementation
 */

/**
 * \defgroup dhstate DHState API
 *
 * DHState objects are used to generate key pairs and perform
 * Diffie-Hellman calculations.
 */
/**@{*/

/**
 * \typedef NoiseDHState
 * \brief Opaque object that represents a DHState.
 */

/**
 * \brief Creates a new DHState object by its algorithm identifier.
 *
 * \param state Points to the variable where to store the pointer to
 * the new DHState object.
 * \param id The algorithm identifier; NOISE_DH_CURVE25519,
 * NOISE_DH_CURVE448, etc.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state is NULL.
 * \return NOISE_ERROR_UNKNOWN_ID if \a id is unknown.
 * \return NOISE_ERROR_NO_MEMORY if there is insufficient memory to
 * allocate the new DHState object.
 *
 * \sa noise_dhstate_free(), noise_dhstate_new_by_name()
 */
int noise_dhstate_new_by_id(NoiseDHState **state, int id)
{
    /* The "state" argument must be non-NULL */
    if (!state)
        return NOISE_ERROR_INVALID_PARAM;

    /* Create the DHState object for the "id" */
    *state = 0;
    switch (id) {
    case NOISE_DH_CURVE25519:
        *state = noise_curve25519_new();
        break;

    case NOISE_DH_CURVE448:
        *state = noise_curve448_new();
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
 * \brief Creates a new DHState object by its algorithm name.
 *
 * \param state Points to the variable where to store the pointer to
 * the new DHState object.
 * \param name The name of the Diffie-Hellman algorithm; e.g. "25519".
 * This string must be NUL-terminated.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state or \a name is NULL.
 * \return NOISE_ERROR_UNKNOWN_NAME if \a name is unknown.
 * \return NOISE_ERROR_NO_MEMORY if there is insufficient memory to
 * allocate the new DHState object.
 *
 * \sa noise_dhstate_free(), noise_dhstate_new_by_id()
 */
int noise_dhstate_new_by_name(NoiseDHState **state, const char *name)
{
    int id;

    /* The "state" and "name" arguments must be non-NULL */
    if (!state)
        return NOISE_ERROR_INVALID_PARAM;
    *state = 0;
    if (!name)
        return NOISE_ERROR_INVALID_PARAM;

    /* Map the name and create the corresponding object */
    id = noise_name_to_id(NOISE_DH_CATEGORY, name, strlen(name));
    if (id)
        return noise_dhstate_new_by_id(state, id);

    /* We don't know what this is */
    return NOISE_ERROR_UNKNOWN_NAME;
}

/**
 * \brief Frees a DHState object after destroying all sensitive material.
 *
 * \param state The DHState object to free.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state is NULL.
 *
 * \sa noise_dhstate_new_by_id(), noise_dhstate_new_by_name()
 */
int noise_dhstate_free(NoiseDHState *state)
{
    /* Bail out if no DH state */
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
 * \brief Gets the algorithm identifier for a DHState object.
 *
 * \param state The DHState object.
 *
 * \return The algorithm identifier, or NOISE_DH_NONE if \a state is NULL.
 */
int noise_dhstate_get_dh_id(const NoiseDHState *state)
{
    return state ? state->dh_id : NOISE_DH_NONE;
}

/**
 * \brief Gets the length of the public key for a DHState object.
 *
 * \param state The DHState object.
 *
 * \return The size of the public key in bytes, or 0 if \a state is NULL.
 *
 * \sa noise_dhstate_get_private_key_length(),
 * noise_dhstate_get_shared_key_length()
 */
size_t noise_dhstate_get_public_key_length(const NoiseDHState *state)
{
    return state ? state->public_key_len : 0;
}

/**
 * \brief Gets the length of the private key for a DHState object.
 *
 * \param state The DHState object.
 *
 * \return The size of the private key in bytes, or 0 if \a state is NULL.
 *
 * \sa noise_dhstate_get_public_key_length(),
 * noise_dhstate_get_shared_key_length()
 */
size_t noise_dhstate_get_private_key_length(const NoiseDHState *state)
{
    return state ? state->private_key_len : 0;
}

/**
 * \brief Gets the length of the shared key for a DHState object.
 *
 * \param state The DHState object.
 *
 * \return The size of the shared key in bytes, or 0 if \a state is NULL.
 *
 * \sa noise_dhstate_get_public_key_length(),
 * noise_dhstate_get_private_key_length()
 */
size_t noise_dhstate_get_shared_key_length(const NoiseDHState *state)
{
    return state ? state->shared_key_len : 0;
}

/**
 * \brief Gets the null public key value for this Diffie-Hellman algorithm.
 *
 * \param state The DHState object.
 * \param key The buffer to fill with the null public key value.
 * \param len The length of the \a key buffer in bytes.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state or \a key is NULL.
 * \return NOISE_ERROR_INVALID_LENGTH if \a len is not a valid public key
 * length for the algorithm.
 *
 * \sa noise_dhstate_get_null_public_key(), noise_dhstate_get_public_key_length()
 */
int noise_dhstate_get_null_public_key
    (const NoiseDHState *state, uint8_t *key, size_t len)
{
    /* Validate the parameters */
    if (!state || !key)
        return NOISE_ERROR_INVALID_PARAM;

    /* Check the key length.  We allow both the public and shared
       key lengths because we also need to check the output of
       noise_dhstate_calculate() for null values */
    if (len != state->public_key_len && len != state->shared_key_len)
        return NOISE_ERROR_INVALID_LENGTH;

    /* For now we assume that all DH algorithms use all-zeroes
       as their null value.  If this changes in the future, then
       we will add a new back end function to NoiseDHState_s */
    memset(key, 0, len);
    return NOISE_ERROR_NONE;
}

/**
 * \brief Determine if a public key has the special null value.
 *
 * \param state The DHState object.
 * \param key Points to the public key value.
 * \param len The length of the public \a key in bytes.
 *
 * \return Returns non-zero if \a key is the null value or zero if
 * \a key is not the null value.
 *
 * \sa noise_dhstate_get_null_public_key()
 */
int noise_dhstate_is_null_public_key
    (const NoiseDHState *state, const uint8_t *key, size_t len)
{
    /* Validate the parameters */
    if (!state || !key)
        return 0;

    /* Check the key length.  We allow both the public and shared
       key lengths because we also need to check the output of
       noise_dhstate_calculate() for null values */
    if (len != state->public_key_len && len != state->shared_key_len)
        return 0;

    /* Determine if all bytes of the key are zero in constant time */
    return noise_is_zero(key, len);
}

/**
 * \brief Generates a key pair for a Diffie-Hellman algorithm.
 *
 * \param state The DHState object.
 * \param private_key Points to the private key on exit.
 * \param private_key_len The length of the \a private_key buffer in bytes.
 * \param public_key Points to the public key on exit.
 * \param public_key_len The length of the \a public_key buffer in bytes.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state, \a private_key or
 * \a public_key is NULL.
 * \return NOISE_ERROR_INVALID_LENGTH if \a private_key_len or
 * \a public_key_len is incorrect.
 *
 * \note This function needs to generate random key material for the
 * \a private_key, so the system random number generator must be properly
 * seeded before calling this function.
 *
 * \sa noise_dhstate_calculate(), noise_dhstate_get_private_key_length(),
 * noise_dhstate_get_public_key_length()
 */
int noise_dhstate_generate_keypair
    (const NoiseDHState *state, uint8_t *private_key, size_t private_key_len,
     uint8_t *public_key, size_t public_key_len)
{
    /* Validate the parameters */
    if (!state || !private_key || !public_key)
        return NOISE_ERROR_INVALID_PARAM;
    if (private_key_len != state->private_key_len)
        return NOISE_ERROR_INVALID_LENGTH;
    if (public_key_len != state->public_key_len)
        return NOISE_ERROR_INVALID_LENGTH;

    /* Generate the keypair */
    return (*(state->generate_keypair))(state, private_key, public_key);
}

/**
 * \brief Performs a Diffie-Hellman calculation.
 *
 * \param state Points to the DHState.
 * \param shared_key Points to the shared key on exit.
 * \param shared_key_len The length of the \a shared_key buffer in bytes.
 * \param private_key Points to the private key.
 * \param private_key_len The length of the \a private_key in bytes.
 * \param public_key Points to the public key.
 * \param public_key_len The length of the \a public_key in bytes.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state, \a shared_key,
 * \a private_key or \a public_key is NULL.
 * \return NOISE_ERROR_INVALID_DH_KEY if either \a public_key or \a private_key
 * are invalid for the algorithm.
 *
 * If the input \a public_key is the special null value, then the output
 * \a shared_key will also be the null value.
 *
 * \sa noise_dhstate_generate_keypair()
 */
int noise_dhstate_calculate
    (const NoiseDHState *state, uint8_t *shared_key, size_t shared_key_len,
     const uint8_t *private_key, size_t private_key_len,
     const uint8_t *public_key, size_t public_key_len)
{
    int is_null, err;

    /* Validate the parameters */
    if (!state || !shared_key || !private_key || !public_key)
        return NOISE_ERROR_INVALID_PARAM;
    if (shared_key_len != state->shared_key_len)
        return NOISE_ERROR_INVALID_LENGTH;
    if (private_key_len != state->private_key_len)
        return NOISE_ERROR_INVALID_LENGTH;
    if (public_key_len != state->public_key_len)
        return NOISE_ERROR_INVALID_LENGTH;

    /* If the public key is null, then the output must be null too.
       We check for null now, but still perform the normal evaluation.
       At the end we will null out the result in constant time */
    is_null = noise_is_zero(public_key, public_key_len);

    /* Perform the calculation */
    err = (*(state->calculate))(state, shared_key, private_key, public_key);

    /* If the public key was null, then we need to set the shared key
       to null and replace any error we got from the back end with "none" */
    noise_cmove_zero(shared_key, shared_key_len, is_null);
    err &= (is_null - 1);
    return err;
}

/**
 * \brief Validates a Diffie-Hellman keypair.
 *
 * \param state Points to the DHState.
 * \param private_key Points to the private key for the keypair.
 * \param private_key_len The length of the \a private_key in bytes.
 * \param public_key Points to the public key for the keypair.
 * \param public_key_len The length of the \a public_key in bytes.
 *
 * \return NOISE_ERROR_NONE if the keypair is valid.
 * \return NOISE_ERROR_INVALID_PARAM if one of \a state, \a private_key,
 * or \a public_key is NULL.
 * \return NOISE_ERROR_INVALID_LENGTH if either \a private_key_len or
 * \a public_key_len is invalid for the algorithm.
 * \return NOISE_ERROR_INVALID_DH_KEY if the \a public_key does not
 * match the \a private_key, or the values are otherwise invalid for
 * the algorithm.
 */
int noise_dhstate_validate_keypair
    (const NoiseDHState *state, const uint8_t *private_key,
     size_t private_key_len, const uint8_t *public_key, size_t public_key_len)
{
    /* Validate the parameters */
    if (!state || !private_key || !public_key)
        return NOISE_ERROR_INVALID_PARAM;
    if (private_key_len != state->private_key_len)
        return NOISE_ERROR_INVALID_LENGTH;
    if (public_key_len != state->public_key_len)
        return NOISE_ERROR_INVALID_LENGTH;

    /* If the public key is NULL, then the keypair is invalid */
    if (noise_dhstate_is_null_public_key(state, public_key, public_key_len))
        return NOISE_ERROR_INVALID_DH_KEY;

    /* TODO: Use the backend to perform algorithm-specific validation */

    /* The keypair is OK */
    return NOISE_ERROR_NONE;
}

/**@}*/
