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
 * DHState objects are used to store the keypairs for the local party or
 * the public keys for remote parties.  Once the keys have been set,
 * noise_dhstate_calculate() can be used to perform a Diffie-Hellman
 * operation with two DHState objects.
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
 * \brief Determine if a DHState object contains a keypair.
 *
 * \param state The DHState object.
 *
 * \return Returns 1 if \a state contains both a private key and a
 * public key.  Returns 0 if \a state is NULL or it only contains a
 * public key.
 *
 * \sa noise_dhstate_set_keypair(), noise_dhstate_has_public_key(),
 * noise_dhstate_clear_key()
 */
int noise_dhstate_has_keypair(const NoiseDHState *state)
{
    if (state)
        return state->key_type == NOISE_KEY_TYPE_KEYPAIR;
    else
        return 0;
}

/**
 * \brief Determine if a DHState object contains a public key.
 *
 * \param state The DHState object.
 *
 * \return Returns 1 if \a state contains a public key (and optionally a
 * private key).  Returns 0 if \a state is NULL or it does not contain a
 * public key.
 *
 * \sa noise_dhstate_set_keypair(), noise_dhstate_has_public_key(),
 * noise_dhstate_clear_key()
 */
int noise_dhstate_has_public_key(const NoiseDHState *state)
{
    if (state)
        return state->key_type != NOISE_KEY_TYPE_NO_KEY;
    else
        return 0;
}

/**
 * \brief Generates a new key pair within a DHState object.
 *
 * \param state The DHState object.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state is NULL.
 *
 * \note This function needs to generate random key material for the
 * private key, so the system random number generator must be properly
 * seeded before calling this function.
 *
 * \sa noise_dhstate_calculate(), noise_dhstate_set_keypair()
 */
int noise_dhstate_generate_keypair(NoiseDHState *state)
{
    /* Validate the parameter */
    if (!state)
        return NOISE_ERROR_INVALID_PARAM;

    /* Generate the new keypair */
    (*(state->generate_keypair))(state);
    state->key_type = NOISE_KEY_TYPE_KEYPAIR;
    return NOISE_ERROR_NONE;
}

/**
 * \brief Sets the keypair within a DHState object.
 *
 * \param state The DHState object.
 * \param private_key Points to the private key.
 * \param private_key_len The private key length in bytes.
 * \param public_key Points to the public key.
 * \param public_key_len The public key length in bytes.
 *
 * \return NOISE_ERROR on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state, \a private_key, or
 * \a public_key is NULL.
 * \return NOISE_ERROR_INVALID_LENGTH if either \a private_key_len or
 * \a public_key_len is incorrect for the algorithm.
 * \return NOISE_ERROR_INVALID_PRIVATE_KEY if \a private_key is not valid.
 * \return NOISE_ERROR_INVALID_PUBLIC_KEY if \a public_key is not valid.
 *
 * The algorithm may decide to defer NOISE_ERROR_INVALID_PRIVATE_KEY or
 * NOISE_ERROR_INVALID_PUBLIC_KEY to later when the keypair is actually
 * used during noise_dhstate_calculate().
 *
 * \sa noise_dhstate_get_keypair(), noise_dhstate_set_public_key(),
 * noise_dhstate_set_keypair_private()
 */
int noise_dhstate_set_keypair
    (NoiseDHState *state, const uint8_t *private_key, size_t private_key_len,
     const uint8_t *public_key, size_t public_key_len)
{
    int err;

    /* Validate the parameters */
    if (!state || !private_key || !public_key)
        return NOISE_ERROR_INVALID_PARAM;
    if (private_key_len != state->private_key_len)
        return NOISE_ERROR_INVALID_LENGTH;
    if (public_key_len != state->public_key_len)
        return NOISE_ERROR_INVALID_LENGTH;

    /* Validate the keypair */
    err = (*(state->validate_keypair))(state, private_key, public_key);
    if (err != NOISE_ERROR_NONE)
        return err;

    /* Copy the key into place */
    memcpy(state->private_key, private_key, state->private_key_len);
    memcpy(state->public_key, public_key, state->public_key_len);
    state->key_type = NOISE_KEY_TYPE_KEYPAIR;
    return NOISE_ERROR_NONE;
}

/**
 * \brief Sets the keypair within a DHState object based on a private key only.
 *
 * \param state The DHState object.
 * \param private_key Points to the private key.
 * \param private_key_len The private key length in bytes.
 *
 * \return NOISE_ERROR on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state or \a private_key is NULL.
 * \return NOISE_ERROR_INVALID_LENGTH if either \a private_key_len is
 * incorrect for the algorithm.
 * \return NOISE_ERROR_INVALID_PRIVATE_KEY if \a private_key is not valid.
 * \return NOISE_ERROR_INVALID_PUBLIC_KEY if \a public_key that is derived
 * from the \a private_key is not valid.
 *
 * The algorithm may decide to defer NOISE_ERROR_INVALID_PRIVATE_KEY or
 * NOISE_ERROR_INVALID_PUBLIC_KEY to later when the keypair is actually
 * used during noise_dhstate_calculate().
 *
 * This function only takes the private key as an argument.  The public
 * key in the keypair is derived from the private key.
 *
 * \sa noise_dhstate_get_keypair(), noise_dhstate_set_public_key(),
 * noise_dhstate_set_keypair()
 */
int noise_dhstate_set_keypair_private
    (NoiseDHState *state, const uint8_t *private_key, size_t private_key_len)
{
    int err;

    /* Validate the parameters */
    if (!state || !private_key)
        return NOISE_ERROR_INVALID_PARAM;
    if (private_key_len != state->private_key_len)
        return NOISE_ERROR_INVALID_LENGTH;

    /* Derive the public key from the private key */
    err = (*(state->derive_public_key))
        (state, private_key, state->public_key);
    if (err != NOISE_ERROR_NONE) {
        noise_dhstate_clear_key(state);
        return err;
    }

    /* Copy the private key into place */
    memcpy(state->private_key, private_key, state->private_key_len);
    state->key_type = NOISE_KEY_TYPE_KEYPAIR;
    return NOISE_ERROR_NONE;
}

/**
 * \brief Gets the keypair from within a DHState object.
 *
 * \param state The DHState object.
 * \param private_key Points to the buffer to receive the private key.
 * \param private_key_len The private key buffer length in bytes.
 * \param public_key Points to the buffer to receive the public key.
 * \param public_key_len The public key buffer length in bytes.
 *
 * \return NOISE_ERROR on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state, \a private_key, or
 * \a public_key is NULL.
 * \return NOISE_ERROR_INVALID_LENGTH if either \a private_key_len or
 * \a public_key_len is incorrect for the algorithm.
 * \return NOISE_ERROR_INVALID_STATE if \a state does not contain a keypair.
 *
 * \sa noise_dhstate_set_keypair(), noise_dhstate_get_public_key()
 */
int noise_dhstate_get_keypair
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

    /* Is this actually a keypair? */
    if (state->key_type != NOISE_KEY_TYPE_KEYPAIR) {
        memset(private_key, 0, private_key_len);
        memset(public_key, 0, public_key_len);
        return NOISE_ERROR_INVALID_STATE;
    }

    /* Copy the keypair out */
    memcpy(private_key, state->private_key, private_key_len);
    memcpy(public_key, state->public_key, public_key_len);
    return NOISE_ERROR_NONE;
}

/**
 * \brief Sets the public key in a DHState object.
 *
 * \param state The DHState object.
 * \param public_key Points to the public key.
 * \param public_key_len The public key length in bytes.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state or \a public_key is NULL.
 * \return NOISE_ERROR_INVALID_LENGTH if \a public_key_len is incorrect
 * for the algorithm.
 * \return NOISE_ERROR_INVALID_PUBLIC_KEY if \a public_key is not valid
 * and it is not the special null value.
 *
 * After this function succeeds, the DHState will only contain a public key.
 * Any existing private key will be cleared.  Thus, this function is useful
 * to set the public key of a remote party.  Use noise_dhstate_set_keypair()
 * to set both the public and private key for the local party.
 *
 * The algorithm may decide to defer NOISE_ERROR_INVALID_PUBLIC_KEY to
 * later when the public key is actually used during noise_dhstate_calculate().
 *
 * \sa noise_dhstate_get_public_key(), noise_dhstate_set_keypair()
 */
int noise_dhstate_set_public_key
    (NoiseDHState *state, const uint8_t *public_key, size_t public_key_len)
{
    int is_null, err;

    /* Validate the parameters */
    if (!state || !public_key)
        return NOISE_ERROR_INVALID_PARAM;
    if (public_key_len != state->public_key_len)
        return NOISE_ERROR_INVALID_LENGTH;

    /* Validate the public key with the back end and then ignore the
       result if the public key is the special null value */
    is_null = noise_is_zero(public_key, public_key_len);
    err = (*(state->validate_public_key))(state, public_key);
    err &= (is_null - 1);
    if (err != NOISE_ERROR_NONE)
        return err;

    /* Copy the public key into place and clear the private key */
    memcpy(state->public_key, public_key, public_key_len);
    memset(state->private_key, 0, state->private_key_len);
    state->key_type = NOISE_KEY_TYPE_PUBLIC;
    return NOISE_ERROR_NONE;
}

/**
 * \brief Gets the public key value from a DHState object.
 *
 * \param state The DHState object.
 * \param public_key The buffer to receive the public key value.
 * \param public_key_len The public key length in bytes.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state or \a public_key is NULL.
 * \return NOISE_ERROR_INVALID_LENGTH if \a public_key_len is incorrect
 * for this algorithm.
 *
 * \sa noise_dhstate_set_public_key(), noise_dhstate_get_public_key_length()
 */
int noise_dhstate_get_public_key
    (const NoiseDHState *state, uint8_t *public_key, size_t public_key_len)
{
    /* Validate the parameters */
    if (!state || !public_key)
        return NOISE_ERROR_INVALID_PARAM;
    if (public_key_len != state->public_key_len)
        return NOISE_ERROR_INVALID_LENGTH;

    /* Copy the public key out */
    memcpy(public_key, state->public_key, public_key_len);
    return NOISE_ERROR_NONE;
}

/**
 * \brief Sets the public key in a DHState object to the special null value.
 *
 * \param state The DHState object.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state is NULL.
 *
 * \sa noise_dhstate_is_null_public_key()
 */
int noise_dhstate_set_null_public_key(NoiseDHState *state)
{
    /* Validate the parameter */
    if (!state)
        return NOISE_ERROR_INVALID_PARAM;

    /* Clear the key to all-zeroes */
    memset(state->public_key, 0, state->public_key_len);
    memset(state->private_key, 0, state->private_key_len);

    /* We have a public key but no private key */
    state->key_type = NOISE_KEY_TYPE_PUBLIC;
    return NOISE_ERROR_NONE;
}

/**
 * \brief Determine if the public key in a DHState object has the
 * special null value.
 *
 * \param state The DHState object.
 *
 * \return Returns non-zero if the public key within \a state is the
 * special null value; zero otherwise.
 *
 * \sa noise_dhstate_set_null_public_key()
 */
int noise_dhstate_is_null_public_key(const NoiseDHState *state)
{
    if (state && state->key_type != NOISE_KEY_TYPE_NO_KEY)
        return noise_is_zero(state->public_key, state->public_key_len);
    else
        return 0;
}

/**
 * \brief Clears the key in a DHState object.
 *
 * \param state The DHState object.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state is NULL.
 *
 * \sa noise_dhstate_has_keypair(), noise_dhstate_has_public_key()
 */
int noise_dhstate_clear_key(NoiseDHState *state)
{
    /* Validate the parameter */
    if (!state)
        return NOISE_ERROR_INVALID_PARAM;

    /* Clear the key to all-zeroes */
    memset(state->public_key, 0, state->public_key_len);
    memset(state->private_key, 0, state->private_key_len);

    /* There is no key in the object now */
    state->key_type = NOISE_KEY_TYPE_NO_KEY;
    return NOISE_ERROR_NONE;
}

/**
 * \brief Conditional move of zero into a buffer in constant time.
 *
 * \param data The data buffer to fill with zeroes if the condition is true.
 * \param len The length of the \a data buffer in bytes.
 * \param condition Condition that is 1 to move zero into \a data, or
 * zero to leave the contents of \a data as-is.
 */
static void noise_cmove_zero(uint8_t *data, size_t len, int condition)
{
    /* Turn the condition into an all-zeroes or all-ones mask.
       If the condition is set, then we want all-zeroes in the mask.
       If the condition is not set, then we want all-ones in the mask. */
    uint8_t mask = ~((uint8_t)(-condition));

    /* AND the contents of the data buffer with the mask */
    while (len > 0) {
        *data++ &= mask;
        --len;
    }
}

/**
 * \brief Performs a Diffie-Hellman calculation.
 *
 * \param private_key_state Points to the DHState containing the private key.
 * \param public_key_state Points to the DHState containing the public key.
 * \param shared_key Points to the shared key on exit.
 * \param shared_key_len The length of the \a shared_key buffer in bytes.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a private_key_state,
 * \a public_key_state, or \a shared_key is NULL.
 * \return NOISE_ERROR_INVALID_PARAM if \a private_key_state and
 * \a public_key_state do not have the same algorithm identifier.
 * \return NOISE_ERROR_INVALID_LENGTH if \a shared_key_len is not
 * correct for the algorithm.
 * \return NOISE_ERROR_INVALID_PRIVATE_KEY if \a private_key_state does not
 * contain a private key or the private key is invalid.
 * \return NOISE_ERROR_INVALID_PUBLIC_KEY if the public key in
 * \a public_key_state is invalid.
 *
 * If the input public key is the special null value, then the output
 * \a shared_key will also be the null value and NOISE_ERROR_NONE
 * will be returned.
 *
 * \sa noise_dhstate_generate_keypair()
 */
int noise_dhstate_calculate
    (const NoiseDHState *private_key_state,
     const NoiseDHState *public_key_state,
     uint8_t *shared_key, size_t shared_key_len)
{
    int is_null, err;

    /* Validate the parameters */
    if (!private_key_state || !public_key_state || !shared_key)
        return NOISE_ERROR_INVALID_PARAM;
    if (private_key_state->dh_id != public_key_state->dh_id)
        return NOISE_ERROR_INVALID_PARAM;
    if (shared_key_len != private_key_state->shared_key_len)
        return NOISE_ERROR_INVALID_LENGTH;
    if (private_key_state->key_type != NOISE_KEY_TYPE_KEYPAIR)
        return NOISE_ERROR_INVALID_PRIVATE_KEY;

    /* If the public key is null, then the output must be null too.
       We check for null now, but still perform the normal evaluation.
       At the end we will null out the result in constant time */
    is_null = noise_is_zero
        (public_key_state->public_key, public_key_state->public_key_len);

    /* Perform the calculation */
    err = (*(private_key_state->calculate))
        (private_key_state, public_key_state, shared_key);

    /* If the public key was null, then we need to set the shared key
       to null and replace any error we got from the back end with "none" */
    noise_cmove_zero(shared_key, shared_key_len, is_null);
    err &= (is_null - 1);
    return err;
}

/**
 * \brief Copies the keys from one DHState object to another.
 *
 * \param state The DHState to copy into.
 * \param from The DHState to copy from.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state or \a from is NULL.
 * \return NOISE_ERROR_NOT_APPLICABLE if \a from does not have the same
 * key type identifier as \a state.
 */
int noise_dhstate_copy(NoiseDHState *state, const NoiseDHState *from)
{
    /* Validate the parameters */
    if (!state || !from)
        return NOISE_ERROR_INVALID_PARAM;
    if (state->dh_id != from->dh_id)
        return NOISE_ERROR_NOT_APPLICABLE;

    /* Copy the key information across */
    if (state != from) {
        state->key_type = from->key_type;
        memcpy(state->private_key, from->private_key, from->private_key_len);
        memcpy(state->public_key, from->public_key, from->public_key_len);
    }
    return NOISE_ERROR_NONE;
}

/**
 * \brief Formats the public key fingerprint for the key within a DHState.
 *
 * \param state The DHState object.
 * \param fingerprint_type The type of fingerprint to format,
 * NOISE_FINGERPRINT_BASIC or NOISE_FINGERPRINT_FULL.
 * \param buffer The buffer to write the fingerprint string to, including a
 * terminating NUL.
 * \param len The length of \a buffer in bytes.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state or \a buffer is NULL.
 * \return NOISE_ERROR_INVALID_PARAM if \a fingerprint_type is not a
 * supported fingerprint type.
 * \return NOISE_ERROR_INVALID_LENGTH if \a len is not large enough to
 * hold the entire fingerprint string.
 * \return NOISE_ERROR_INVALID_STATE if a public key has not been set
 * on \a state yet.
 *
 * Fingerprints are created by hashing the public key with SHA256 and
 * then formatting the value in hexadecimal with bytes separated by colons.
 * If the \a fingerprint_type is NOISE_FINGERPRINT_BASIC, then the SHA256
 * hash value is truncated to the first 16 bytes.  If the type is
 * NOISE_FINGERPRINT_FULL, then the entire 32 byte hash value is formatted.
 */
int noise_dhstate_format_fingerprint
    (const NoiseDHState *state, int fingerprint_type, char *buffer, size_t len)
{
    /* Validate the parameters */
    if (!buffer)
        return NOISE_ERROR_INVALID_PARAM;
    if (!len)
        return NOISE_ERROR_INVALID_LENGTH;
    *buffer = '\0'; /* In case we bail out with an error later */
    if (!state)
        return NOISE_ERROR_INVALID_PARAM;
    if (state->key_type == NOISE_KEY_TYPE_NO_KEY)
        return NOISE_ERROR_INVALID_STATE;

    /* Format the fingerprint */
    return noise_format_fingerprint
        (fingerprint_type, buffer, len,
         state->public_key, state->public_key_len);
}

/**
 * \brief Gets the maximum length of DH keys for the supported algorithms.
 */
int noise_dhstate_get_max_key_length(void)
{
    return 56;
}

/**@}*/
