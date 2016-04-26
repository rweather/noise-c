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
 * \file signstate.h
 * \brief SignState interface
 */

/**
 * \file signstate.c
 * \brief SignState implementation
 */

/**
 * \defgroup signstate SignState API
 *
 * SignState objects are used to store the keypairs for the local party or
 * the public keys for remote parties.  Once the keys have been set,
 * noise_signstate_sign() can be used to create a digital signature with a
 * keypair, or noise_signstate_verify() can be used to verify a digital
 * signature with a public key.
 */
/**@{*/

/**
 * \typedef NoiseSignState
 * \brief Opaque object that represents a SignState.
 */

/**
 * \brief Creates a new SignState object by its algorithm identifier.
 *
 * \param state Points to the variable where to store the pointer to
 * the new SignState object.
 * \param id The algorithm identifier; e.g. NOISE_SIGN_ED5519.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state is NULL.
 * \return NOISE_ERROR_UNKNOWN_ID if \a id is unknown.
 * \return NOISE_ERROR_NO_MEMORY if there is insufficient memory to
 * allocate the new SignState object.
 *
 * \sa noise_signstate_free(), noise_signstate_new_by_name()
 */
int noise_signstate_new_by_id(NoiseSignState **state, int id)
{
    /* The "state" argument must be non-NULL */
    if (!state)
        return NOISE_ERROR_INVALID_PARAM;

    /* Create the SignState object for the "id" */
    *state = 0;
    switch (id) {
    case NOISE_SIGN_ED25519:
        *state = noise_ed25519_new();
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
 * \brief Creates a new SignState object by its algorithm name.
 *
 * \param state Points to the variable where to store the pointer to
 * the new SignState object.
 * \param name The name of the digital signature algorithm; e.g. "Ed25519".
 * This string must be NUL-terminated.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state or \a name is NULL.
 * \return NOISE_ERROR_UNKNOWN_NAME if \a name is unknown.
 * \return NOISE_ERROR_NO_MEMORY if there is insufficient memory to
 * allocate the new SignState object.
 *
 * \sa noise_signstate_free(), noise_signstate_new_by_id()
 */
int noise_signstate_new_by_name(NoiseSignState **state, const char *name)
{
    int id;

    /* The "state" and "name" arguments must be non-NULL */
    if (!state)
        return NOISE_ERROR_INVALID_PARAM;
    *state = 0;
    if (!name)
        return NOISE_ERROR_INVALID_PARAM;

    /* Map the name and create the corresponding object */
    id = noise_name_to_id(NOISE_SIGN_CATEGORY, name, strlen(name));
    if (id)
        return noise_signstate_new_by_id(state, id);

    /* We don't know what this is */
    return NOISE_ERROR_UNKNOWN_NAME;
}

/**
 * \brief Frees a SignState object after destroying all sensitive material.
 *
 * \param state The SignState object to free.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state is NULL.
 *
 * \sa noise_signstate_new_by_id(), noise_signstate_new_by_name()
 */
int noise_signstate_free(NoiseSignState *state)
{
    /* Bail out if no sign state */
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
 * \brief Gets the algorithm identifier for a SignState object.
 *
 * \param state The SignState object.
 *
 * \return The algorithm identifier, or NOISE_SIGN_NONE if \a state is NULL.
 */
int noise_signstate_get_sign_id(const NoiseSignState *state)
{
    return state ? state->sign_id : NOISE_SIGN_NONE;
}

/**
 * \brief Gets the length of the public key for a SignState object.
 *
 * \param state The SignState object.
 *
 * \return The size of the public key in bytes, or 0 if \a state is NULL.
 *
 * \sa noise_signstate_get_private_key_length(),
 * noise_signstate_get_signature_length()
 */
size_t noise_signstate_get_public_key_length(const NoiseSignState *state)
{
    return state ? state->public_key_len : 0;
}

/**
 * \brief Gets the length of the private key for a SignState object.
 *
 * \param state The SignState object.
 *
 * \return The size of the private key in bytes, or 0 if \a state is NULL.
 *
 * \sa noise_signstate_get_public_key_length(),
 * noise_signstate_get_signature_length()
 */
size_t noise_signstate_get_private_key_length(const NoiseSignState *state)
{
    return state ? state->private_key_len : 0;
}

/**
 * \brief Gets the length of the signature for a SignState object.
 *
 * \param state The SignState object.
 *
 * \return The size of the signature in bytes, or 0 if \a state is NULL.
 *
 * \sa noise_signstate_get_public_key_length(),
 * noise_signstate_get_private_key_length()
 */
size_t noise_signstate_get_signature_length(const NoiseSignState *state)
{
    return state ? state->signature_len : 0;
}

/**
 * \brief Determine if a SignState object contains a keypair.
 *
 * \param state The SignState object.
 *
 * \return Returns 1 if \a state contains both a private key and a
 * public key.  Returns 0 if \a state is NULL or it only contains a
 * public key.
 *
 * \sa noise_signstate_set_keypair(), noise_signstate_has_public_key(),
 * noise_signstate_clear_key()
 */
int noise_signstate_has_keypair(const NoiseSignState *state)
{
    if (state)
        return state->key_type == NOISE_KEY_TYPE_KEYPAIR;
    else
        return 0;
}

/**
 * \brief Determine if a SignState object contains a public key.
 *
 * \param state The SignState object.
 *
 * \return Returns 1 if \a state contains a public key (and optionally a
 * private key).  Returns 0 if \a state is NULL or it does not contain a
 * public key.
 *
 * \sa noise_signstate_set_keypair(), noise_signstate_has_public_key(),
 * noise_signstate_clear_key()
 */
int noise_signstate_has_public_key(const NoiseSignState *state)
{
    if (state)
        return state->key_type != NOISE_KEY_TYPE_NO_KEY;
    else
        return 0;
}

/**
 * \brief Generates a new key pair within a SignState object.
 *
 * \param state The SignState object.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state is NULL.
 *
 * \note This function needs to generate random key material for the
 * private key, so the system random number generator must be properly
 * seeded before calling this function.
 *
 * \sa noise_signstate_sign(), noise_signstate_set_keypair()
 */
int noise_signstate_generate_keypair(NoiseSignState *state)
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
 * \brief Sets the keypair within a SignState object.
 *
 * \param state The SignState object.
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
 * used during noise_signstate_sign().
 *
 * \sa noise_signstate_get_keypair(), noise_signstate_set_public_key(),
 * noise_signstate_set_keypair_private()
 */
int noise_signstate_set_keypair
    (NoiseSignState *state, const uint8_t *private_key, size_t private_key_len,
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
 * \brief Sets the keypair within a SignState object based on a private key only.
 *
 * \param state The SignState object.
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
 * used during noise_signstate_sign().
 *
 * This function only takes the private key as an argument.  The public
 * key in the keypair is derived from the private key.
 *
 * \sa noise_signstate_get_keypair(), noise_signstate_set_public_key(),
 * noise_signstate_set_keypair()
 */
int noise_signstate_set_keypair_private
    (NoiseSignState *state, const uint8_t *private_key, size_t private_key_len)
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
        noise_signstate_clear_key(state);
        return err;
    }

    /* Copy the private key into place */
    memcpy(state->private_key, private_key, state->private_key_len);
    state->key_type = NOISE_KEY_TYPE_KEYPAIR;
    return NOISE_ERROR_NONE;
}

/**
 * \brief Gets the keypair from within a SignState object.
 *
 * \param state The SignState object.
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
 * \sa noise_signstate_set_keypair(), noise_signstate_get_public_key()
 */
int noise_signstate_get_keypair
    (const NoiseSignState *state, uint8_t *private_key, size_t private_key_len,
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
 * \brief Sets the public key in a SignState object.
 *
 * \param state The SignState object.
 * \param public_key Points to the public key.
 * \param public_key_len The public key length in bytes.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state or \a public_key is NULL.
 * \return NOISE_ERROR_INVALID_LENGTH if \a public_key_len is incorrect
 * for the algorithm.
 * \return NOISE_ERROR_INVALID_PUBLIC_KEY if \a public_key is not valid.
 *
 * After this function succeeds, the SignState will only contain a public key.
 * Any existing private key will be cleared.  Thus, this function is useful
 * to set the public key of a remote party.  Use noise_signstate_set_keypair()
 * to set both the public and private key for the local party.
 *
 * The algorithm may decide to defer NOISE_ERROR_INVALID_PUBLIC_KEY to
 * later when the public key is actually used during noise_signstate_verify().
 *
 * \sa noise_signstate_get_public_key(), noise_signstate_set_keypair()
 */
int noise_signstate_set_public_key
    (NoiseSignState *state, const uint8_t *public_key, size_t public_key_len)
{
    int err;

    /* Validate the parameters */
    if (!state || !public_key)
        return NOISE_ERROR_INVALID_PARAM;
    if (public_key_len != state->public_key_len)
        return NOISE_ERROR_INVALID_LENGTH;

    /* Validate the public key with the back end */
    err = (*(state->validate_public_key))(state, public_key);
    if (err != NOISE_ERROR_NONE)
        return err;

    /* Copy the public key into place and clear the private key */
    memcpy(state->public_key, public_key, public_key_len);
    memset(state->private_key, 0, state->private_key_len);
    state->key_type = NOISE_KEY_TYPE_PUBLIC;
    return NOISE_ERROR_NONE;
}

/**
 * \brief Gets the public key value from a SignState object.
 *
 * \param state The SignState object.
 * \param public_key The buffer to receive the public key value.
 * \param public_key_len The public key length in bytes.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state or \a public_key is NULL.
 * \return NOISE_ERROR_INVALID_LENGTH if \a public_key_len is incorrect
 * for this algorithm.
 * \return NOISE_ERROR_INVALID_STATE if the public key has not been
 * set on the SignState object yet.
 *
 * \sa noise_signstate_set_public_key(), noise_signstate_get_public_key_length()
 */
int noise_signstate_get_public_key
    (const NoiseSignState *state, uint8_t *public_key, size_t public_key_len)
{
    /* Validate the parameters */
    if (!state || !public_key)
        return NOISE_ERROR_INVALID_PARAM;
    if (public_key_len != state->public_key_len)
        return NOISE_ERROR_INVALID_LENGTH;
    if (state->key_type == NOISE_KEY_TYPE_NO_KEY)
        return NOISE_ERROR_INVALID_STATE;

    /* Copy the public key out */
    memcpy(public_key, state->public_key, public_key_len);
    return NOISE_ERROR_NONE;
}

/**
 * \brief Clears the key in a SignState object.
 *
 * \param state The SignState object.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state is NULL.
 *
 * \sa noise_signstate_has_keypair(), noise_signstate_has_public_key()
 */
int noise_signstate_clear_key(NoiseSignState *state)
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
 * \brief Signs a message to create a digital signature.
 *
 * \param state The SignState object containing the private key.
 * \param message Points to the message to be signed, which is usually a
 * short hash value.
 * \param message_len The length of the \a message to be signed.
 * \param signature Points to the signature on exit.
 * \param signature_len The length of the \a signature buffer in bytes.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state, \a message,
 * or \a signature is NULL.
 * \return NOISE_ERROR_INVALID_LENGTH if \a signature_len is not
 * correct for the algorithm.
 * \return NOISE_ERROR_INVALID_PRIVATE_KEY if \a state does not
 * contain a private key or the private key is invalid.
 * \return NOISE_ERROR_INVALID_PUBLIC_KEY if the public key in
 * \a state is invalid.
 *
 * \sa noise_signstate_generate_keypair(), noise_signstate_verify()
 */
int noise_signstate_sign
    (const NoiseSignState *state, const uint8_t *message, size_t message_len,
     uint8_t *signature, size_t signature_len)
{
    /* Validate the parameters */
    if (!state || !message || !signature)
        return NOISE_ERROR_INVALID_PARAM;
    if (signature_len != state->signature_len)
        return NOISE_ERROR_INVALID_LENGTH;
    if (state->key_type != NOISE_KEY_TYPE_KEYPAIR)
        return NOISE_ERROR_INVALID_PRIVATE_KEY;

    /* Create the digial signature */
    return (*(state->sign))(state, message, message_len, signature);
}

/**
 * \brief Verifies a digital signature on a message.
 *
 * \param state The SignState object containing the private key.
 * \param message Points to the message whose signature should
 * be verified, which is usually a short hash value.
 * \param message_len The length of the \a message to be verified.
 * \param signature Points to the signature to be verified.
 * \param signature_len The length of the \a signature in bytes.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state, \a message,
 * or \a signature is NULL.
 * \return NOISE_ERROR_INVALID_LENGTH if \a signature_len is not
 * correct for the algorithm.
 * \return NOISE_ERROR_INVALID_PUBLIC_KEY if \a state does not
 * contain a public key or the public key is invalid.
 * \return NOISE_ERROR_INVALID_SIGNATURE if the \a signature is not
 * valid for the \a message using this public key.
 *
 * \sa noise_signstate_set_public_key(), noise_signstate_sign()
 */
int noise_signstate_verify
    (const NoiseSignState *state, const uint8_t *message, size_t message_len,
     const uint8_t *signature, size_t signature_len)
{
    /* Validate the parameters */
    if (!state || !message || !signature)
        return NOISE_ERROR_INVALID_PARAM;
    if (signature_len != state->signature_len)
        return NOISE_ERROR_INVALID_LENGTH;
    if (state->key_type == NOISE_KEY_TYPE_NO_KEY)
        return NOISE_ERROR_INVALID_PUBLIC_KEY;

    /* Verify the digial signature */
    return (*(state->verify))(state, message, message_len, signature);
}

/**
 * \brief Copies the keys from one SignState object to another.
 *
 * \param state The SignState to copy into.
 * \param from The SignState to copy from.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state or \a from is NULL.
 * \return NOISE_ERROR_NOT_APPLICABLE if \a from does not have the same
 * key type identifier as \a state.
 */
int noise_signstate_copy(NoiseSignState *state, const NoiseSignState *from)
{
    /* Validate the parameters */
    if (!state || !from)
        return NOISE_ERROR_INVALID_PARAM;
    if (state->sign_id != from->sign_id)
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
 * \brief Formats the public key fingerprint for the key within a SignState.
 *
 * \param state The SignState object.
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
int noise_signstate_format_fingerprint
    (const NoiseSignState *state, int fingerprint_type,
     char *buffer, size_t len)
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
 * \brief Gets the maximum length of signing keys for the supported algorithms.
 *
 * \sa noise_signstate_get_max_signature_length()
 */
int noise_signstate_get_max_key_length(void)
{
    return 32;
}

/**
 * \brief Gets the maximum length of signatures for the supported algorithms.
 *
 * \sa noise_signstate_get_max_key_length()
 */
int noise_signstate_get_max_signature_length(void)
{
    return 64;
}

/**@}*/
