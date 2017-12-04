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
 * \file cipherstate.h
 * \brief CipherState interface
 */

/**
 * \file cipherstate.c
 * \brief CipherState implementation
 */

/**
 * \defgroup cipherstate CipherState API
 *
 * CipherState objects are used to encrypt or decrypt data during a
 * session.  Once the handshake has completed, noise_symmetricstate_split()
 * will create two CipherState objects for encrypting packets sent to
 * the other party, and decrypting packets received from the other party.
 */
/**@{*/

/**
 * \typedef NoiseCipherState
 * \brief Opaque object that represents a CipherState.
 */

/** @cond */

/** Maximum length of an encryption key across all back ends */
#define NOISE_MAX_KEY_LEN   32

/** Maximum length of a MAC value across all back ends */
#define NOISE_MAX_MAC_LEN   16

/** @endcond */

/**
 * \brief Creates a new CipherState object by its algorithm identifier.
 *
 * \param state Points to the variable where to store the pointer to
 * the new CipherState object.
 * \param id The algorithm identifier; NOISE_CIPHER_CHACHAPOLY,
 * NOISE_CIPHER_AESGCM, etc.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state is NULL.
 * \return NOISE_ERROR_UNKNOWN_ID if \a id is unknown.
 * \return or NOISE_ERROR_NO_MEMORY if there is insufficient memory to
 * allocate the new CipherState object.
 *
 * \sa noise_cipherstate_free(), noise_cipherstate_new_by_name()
 */
int noise_cipherstate_new_by_id(NoiseCipherState **state, int id)
{
    /* The "state" argument must be non-NULL */
    if (!state)
        return NOISE_ERROR_INVALID_PARAM;

    /* Create the CipherState object for the "id" */
    *state = 0;
    switch (id) {
    case NOISE_CIPHER_CHACHAPOLY:
        *state = noise_chachapoly_new();
        break;

    case NOISE_CIPHER_AESGCM:
        *state = noise_aesgcm_new();
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
 * \brief Creates a new CipherState object by its algorithm name.
 *
 * \param state Points to the variable where to store the pointer to
 * the new CipherState object.
 * \param name The name of the cipher algorithm; e.g. "ChaChaPoly".
 * This string must be NUL-terminated.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state or \a name is NULL.
 * \return NOISE_ERROR_UNKNOWN_NAME if \a name is unknown.
 * \return NOISE_ERROR_NO_MEMORY if there is insufficient memory to
 * allocate the new CipherState object.
 *
 * \sa noise_cipherstate_free(), noise_cipherstate_new_by_id()
 */
int noise_cipherstate_new_by_name(NoiseCipherState **state, const char *name)
{
    int id;

    /* The "state" and "name" arguments must be non-NULL */
    if (!state)
        return NOISE_ERROR_INVALID_PARAM;
    *state = 0;
    if (!name)
        return NOISE_ERROR_INVALID_PARAM;

    /* Map the name and create the corresponding object */
    id = noise_name_to_id(NOISE_CIPHER_CATEGORY, name, strlen(name));
    if (id)
        return noise_cipherstate_new_by_id(state, id);

    /* We don't know what this is */
    return NOISE_ERROR_UNKNOWN_NAME;
}

/**
 * \brief Frees a CipherState object after destroying all sensitive material.
 *
 * \param state The CipherState object to free.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state is NULL.
 *
 * \sa noise_cipherstate_new_by_id(), noise_cipherstate_new_by_name()
 */
int noise_cipherstate_free(NoiseCipherState *state)
{
    /* Bail out if no cipher state */
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
 * \brief Gets the algorithm identifier for a CipherState object.
 *
 * \param state The CipherState object.
 *
 * \return The algorithm identifier, or NOISE_CIPHER_NONE if \a state is NULL.
 */
int noise_cipherstate_get_cipher_id(const NoiseCipherState *state)
{
    return state ? state->cipher_id : NOISE_CIPHER_NONE;
}

/**
 * \brief Gets the length of the encryption key for a CipherState object.
 *
 * \param state The CipherState object.
 *
 * \return The size of the key in bytes, or 0 if \a state is NULL.
 *
 * \sa noise_cipherstate_get_mac_length()
 */
size_t noise_cipherstate_get_key_length(const NoiseCipherState *state)
{
    return state ? state->key_len : 0;
}

/**
 * \brief Gets the length of packet MAC values for a CipherState object.
 *
 * \param state The CipherState object.
 *
 * \return The size of the MAC in bytes, or 0 if \a state is NULL.
 *
 * \sa noise_cipherstate_get_key_length()
 */
size_t noise_cipherstate_get_mac_length(const NoiseCipherState *state)
{
    return state ? state->mac_len : 0;
}

/**
 * \brief Initializes the key on a CipherState object.
 *
 * \param state The CipherState object.
 * \param key Points to the key.
 * \param key_len The length of the key in bytes.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state or \a key is NULL.
 * \return NOISE_ERROR_INVALID_LENGTH if \a key_len is the wrong length
 * for this cipher.
 *
 * \sa noise_cipherstate_get_key_length(), noise_cipherstate_has_key()
 */
int noise_cipherstate_init_key
    (NoiseCipherState *state, const uint8_t *key, size_t key_len)
{
    /* Validate the parameters */
    if (!state || !key)
        return NOISE_ERROR_INVALID_PARAM;
    if (key_len != state->key_len)
        return NOISE_ERROR_INVALID_LENGTH;

    /* Set the key */
    (*(state->init_key))(state, key);
    state->has_key = 1;
    state->n = 0;
    return NOISE_ERROR_NONE;
}

/**
 * \brief Determine if the key has been set on a CipherState object.
 *
 * \param state The CipherState object.
 *
 * \return Returns 1 if the key has been set, or 0 if the key has
 * not been set (or \a state is NULL).
 *
 * \sa noise_cipherstate_init_key()
 */
int noise_cipherstate_has_key(const NoiseCipherState *state)
{
    return state ? state->has_key : 0;
}

/**
 * \brief Encrypts a block of data with this CipherState object.
 *
 * \param state The CipherState object.
 * \param ad Points to the associated data, which can be NULL only if
 * \a ad_len is zero.
 * \param ad_len The length of the associated data in bytes.
 * \param buffer The buffer containing the plaintext on entry and the
 * ciphertext plus MAC on exit.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state or \a buffer is NULL.
 * \return NOISE_ERROR_INVALID_PARAM if \a ad is NULL and \a ad_len
 * is not zero.
 * \return NOISE_ERROR_INVALID_NONCE if the nonce previously overflowed.
 * \return NOISE_ERROR_INVALID_LENGTH if the ciphertext plus MAC is
 * too large to fit within the maximum size of \a buffer and to also
 * remain within 65535 bytes.
 *
 * The plaintext is encrypted in-place with the ciphertext also written
 * to \a buffer.  There must be enough room on the end of \a buffer to hold
 * the extra MAC value that will be appended.  In other words, it is
 * assumed that the plaintext is in an output buffer ready to be
 * transmitted once the data has been encrypted and the final packet
 * length has been determined.
 *
 * The following example demonstrates how to initialize a buffer for
 * use with this function.  The <tt>message</tt> is a byte array containing
 * <tt>plaintext_size</tt> bytes of plaintext on entry.  On exit,
 * <tt>buffer.size</tt> will contain the number of bytes of ciphertext
 * plus MAC to be transmitted:
 *
 * \code
 * NoiseBuffer buffer;
 * noise_buffer_set_inout(buffer, message, plaintext_size, sizeof(message));
 * noise_cipherstate_encrypt_with_ad(state, ad, ad_len, &buffer);
 * // Transmit the buffer.size bytes starting at buffer.data
 * \endcode
 *
 * \sa noise_cipherstate_decrypt_with_ad(), noise_cipherstate_get_mac_length()
 */
int noise_cipherstate_encrypt_with_ad
    (NoiseCipherState *state, const uint8_t *ad, size_t ad_len,
     NoiseBuffer *buffer)
{
    int err;

    /* Validate the parameters */
    if (!state || (!ad && ad_len) || !buffer || !(buffer->data))
        return NOISE_ERROR_INVALID_PARAM;
    if (buffer->size > buffer->max_size)
        return NOISE_ERROR_INVALID_LENGTH;

    /* If the key hasn't been set yet, return the plaintext as-is */
    if (!state->has_key) {
        if (buffer->size > NOISE_MAX_PAYLOAD_LEN)
            return NOISE_ERROR_INVALID_LENGTH;
        return NOISE_ERROR_NONE;
    }

    /* Make sure that there is room for the MAC */
    if (buffer->size > (size_t)(NOISE_MAX_PAYLOAD_LEN - state->mac_len))
        return NOISE_ERROR_INVALID_LENGTH;
    if ((buffer->max_size - buffer->size) < state->mac_len)
        return NOISE_ERROR_INVALID_LENGTH;

    /* If the nonce has overflowed, then further encryption is impossible.
       The value 2^64 - 1 is reserved (Noise specification revision 30),
       so if the nonce has reached that value then overflow has occurred. */
    if (state->n == 0xFFFFFFFFFFFFFFFFULL)
        return NOISE_ERROR_INVALID_NONCE;

    /* Encrypt the plaintext and authenticate it */
    err = (*(state->encrypt))(state, ad, ad_len, buffer->data, buffer->size);
    ++(state->n);
    if (err != NOISE_ERROR_NONE)
        return err;

    /* Adjust the output length for the MAC and return */
    buffer->size += state->mac_len;
    return NOISE_ERROR_NONE;
}

/**
 * \brief Decrypts a block of data with this CipherState object.
 *
 * \param state The CipherState object.
 * \param ad Points to the associated data, which can be NULL only if
 * \a ad_len is zero.
 * \param ad_len The length of the associated data in bytes.
 * \param buffer The buffer containing the ciphertext plus MAC on entry
 * and the plaintext on exit.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state or \a buffer is NULL.
 * \return NOISE_ERROR_INVALID_PARAM if \a ad is NULL and \a ad_len
 * is not zero.
 * \return NOISE_ERROR_MAC_FAILURE if the MAC check failed.
 * \return NOISE_ERROR_INVALID_NONCE if the nonce previously overflowed.
 * \return NOISE_ERROR_INVALID_LENGTH if the size of \a buffer is larger
  than 65535 bytes or is too small to contain the MAC value.
 *
 * The ciphertext is decrypted in-place with the plaintext also written
 * to \a buffer.  In other words, it is assumed that the ciphertext plus
 * MAC is in an input buffer ready to be processed once the MAC has
 * been checked and the ciphertext has been decrypted.
 *
 * The following example demonstrates how to initialize a buffer for
 * use with this function.  The <tt>message</tt> is a byte array containing
 * <tt>ciphertext_size</tt> bytes of ciphertext plus MAC on entry.  On exit,
 * <tt>buffer.size</tt> will contain the number of bytes of plaintext:
 *
 * \code
 * NoiseBuffer buffer;
 * noise_buffer_set_inout(buffer, message, ciphertext_size, sizeof(message));
 * noise_cipherstate_decrypt_with_ad(state, ad, ad_len, &buffer);
 * // The plaintext is the buffer.size bytes starting at buffer.data
 * \endcode
 *
 * \sa noise_cipherstate_encrypt_with_ad(), noise_cipherstate_get_mac_length()
 */
int noise_cipherstate_decrypt_with_ad
    (NoiseCipherState *state, const uint8_t *ad, size_t ad_len,
     NoiseBuffer *buffer)
{
    int err;

    /* Validate the parameters */
    if (!state || (!ad && ad_len) || !buffer || !(buffer->data))
        return NOISE_ERROR_INVALID_PARAM;
    if (buffer->size > buffer->max_size || buffer->size > NOISE_MAX_PAYLOAD_LEN)
        return NOISE_ERROR_INVALID_LENGTH;

    /* If the key hasn't been set yet, return the ciphertext as-is */
    if (!state->has_key)
        return NOISE_ERROR_NONE;

    /* Make sure there are enough bytes for the MAC */
    if (buffer->size < state->mac_len)
        return NOISE_ERROR_INVALID_LENGTH;

    /* If the nonce has overflowed, then further decryption is impossible.
       The value 2^64 - 1 is reserved (Noise specification revision 30),
       so if the nonce has reached that value then overflow has occurred. */
    if (state->n == 0xFFFFFFFFFFFFFFFFULL)
        return NOISE_ERROR_INVALID_NONCE;

    /* Decrypt the ciphertext and check the MAC */
    err = (*(state->decrypt))
        (state, ad, ad_len, buffer->data, buffer->size - state->mac_len);
    if (err != NOISE_ERROR_NONE)
        return err;

    ++(state->n);

    /* Adjust the output length for the MAC and return */
    buffer->size -= state->mac_len;
    return NOISE_ERROR_NONE;
}

/**
 * \brief Encrypts a block of data with this CipherState object.
 *
 * \param state The CipherState object.
 * \param buffer The buffer containing the plaintext on entry and the
 * ciphertext plus MAC on exit.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state or \a buffer is NULL.
 * \return NOISE_ERROR_INVALID_NONCE if the nonce previously overflowed.
 * \return NOISE_ERROR_INVALID_LENGTH if the ciphertext plus MAC is
 * too large to fit within the maximum size of \a buffer and to also
 * remain within 65535 bytes.
 *
 * This is a convenience function which encrypts the contents of a buffer
 * without any associated data.  It is otherwise identical to
 * noise_cipherstate_encrypt_with_ad().
 *
 * The plaintext is encrypted in-place with the ciphertext also written
 * to \a buffer.  There must be enough room on the end of \a buffer to hold
 * the extra MAC value that will be appended.  In other words, it is
 * assumed that the plaintext is in an output buffer ready to be
 * transmitted once the data has been encrypted and the final packet
 * length has been determined.
 *
 * The following example demonstrates how to initialize a buffer for
 * use with this function.  The <tt>message</tt> is a byte array containing
 * <tt>plaintext_size</tt> bytes of plaintext on entry.  On exit,
 * <tt>buffer.size</tt> will contain the number of bytes of ciphertext
 * plus MAC to be transmitted:
 *
 * \code
 * NoiseBuffer buffer;
 * noise_buffer_set_inout(buffer, message, plaintext_size, sizeof(message));
 * noise_cipherstate_encrypt(state, &buffer);
 * // Transmit the buffer.size bytes starting at buffer.data
 * \endcode
 *
 * \sa noise_cipherstate_encrypt_with_ad()
 */
int noise_cipherstate_encrypt(NoiseCipherState *state, NoiseBuffer *buffer)
{
    return noise_cipherstate_encrypt_with_ad(state, NULL, 0, buffer);
}

/**
 * \brief Decrypts a block of data with this CipherState object.
 *
 * \param state The CipherState object.
 * \param buffer The buffer containing the ciphertext plus MAC on entry
 * and the plaintext on exit.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state or \a buffer is NULL.
 * \return NOISE_ERROR_MAC_FAILURE if the MAC check failed.
 * \return NOISE_ERROR_INVALID_NONCE if the nonce previously overflowed.
 * \return NOISE_ERROR_INVALID_LENGTH if the size of \a buffer is larger
  than 65535 bytes or is too small to contain the MAC value.
 *
 * This is a convenience function which decrypts the contents of a buffer
 * without any associated data.  It is otherwise identical to
 * noise_cipherstate_decrypt_with_ad().
 *
 * The ciphertext is decrypted in-place with the plaintext also written
 * to \a buffer.  In other words, it is assumed that the ciphertext plus
 * MAC is in an input buffer ready to be processed once the MAC has
 * been checked and the ciphertext has been decrypted.
 *
 * The following example demonstrates how to initialize a buffer for
 * use with this function.  The <tt>message</tt> is a byte array containing
 * <tt>ciphertext_size</tt> bytes of ciphertext plus MAC on entry.  On exit,
 * <tt>buffer.size</tt> will contain the number of bytes of plaintext:
 *
 * \code
 * NoiseBuffer buffer;
 * noise_buffer_set_inout(buffer, message, ciphertext_size, sizeof(message));
 * noise_cipherstate_decrypt(state, &buffer);
 * // The plaintext is the buffer.size bytes starting at buffer.data
 * \endcode
 *
 * \sa noise_cipherstate_decrypt_with_ad()
 */
int noise_cipherstate_decrypt(NoiseCipherState *state, NoiseBuffer *buffer)
{
    return noise_cipherstate_decrypt_with_ad(state, NULL, 0, buffer);
}

/**
 * \brief Sets the nonce value for this cipherstate object.
 *
 * \param state The CipherState object.
 * \param nonce The new nonce value to set.  This must be greater than
 * or equal to the current nonce value in the state.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state is NULL.
 * \return NOISE_ERROR_INVALID_STATE if the key has not been set yet.
 * \return NOISE_ERROR_INVALID_NONCE if \a nonce is smaller than
 * the current value.
 *
 * \warning This function is intended for testing purposes only.  It is
 * dangerous to set the nonce back to a previously-used value so this
 * function will actively prevent that from happening.
 *
 * \sa noise_cipherstate_init_key()
 */
int noise_cipherstate_set_nonce(NoiseCipherState *state, uint64_t nonce)
{
    /* Bail out if the state is NULL */
    if (!state)
        return NOISE_ERROR_INVALID_PARAM;

    /* If the key hasn't been set yet, we cannot do this */
    if (!state->has_key)
        return NOISE_ERROR_INVALID_STATE;

    /* Reject the value if the nonce would go backwards */
    if (state->n > nonce)
        return NOISE_ERROR_INVALID_NONCE;

    /* Set the nonce and return */
    state->n = nonce;
    return NOISE_ERROR_NONE;
}

/**
 * \brief Gets the maximum key length for the supported algorithms.
 *
 * \sa noise_cipherstate_get_max_mac_length()
 */
int noise_cipherstate_get_max_key_length(void)
{
    return NOISE_MAX_KEY_LEN;
}

/**
 * \brief Gets the maximum MAC length for the supported algorithms.
 *
 * \sa noise_cipherstate_get_max_key_length()
 */
int noise_cipherstate_get_max_mac_length(void)
{
    return NOISE_MAX_MAC_LEN;
}

/**@}*/
