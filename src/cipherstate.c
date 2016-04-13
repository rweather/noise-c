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

    /* Destroy the random number generator, if one is in use */
    if (state->rand) {
        noise_free(state->rand, state->rand->size);
        state->rand = 0;
    }

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
    state->nonce_overflow = 0;
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
 * \param data On entry, contains the plaintext.  On exit, contains the
 * ciphertext plus the MAC.
 * \param in_data_len The number of bytes of plaintext in \a data.
 * \param out_data_len Set to the number of bytes of ciphertext plus MAC
 * in \a data on exit.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if the parameters are invalid.
 * \return NOISE_ERROR_INVALID_NONCE if the nonce previously overflowed.
 * \return or NOISE_ERROR_INVALID_LENGTH if \a in_data_len is too large to
 * contain the ciphertext plus MAC and still remain within 65535 bytes.
 *
 * The plaintext is encrypted in-place with the ciphertext also written
 * to \a data.  There must be enough room on the end of \a data to hold
 * the extra MAC value that will be appended.  In other words, it is
 * assumed that the plaintext is in an output buffer ready to be
 * transmitted once the data has been encrypted and the final packet
 * length (\a out_data_len) has been determined.
 *
 * \sa noise_cipherstate_decrypt_with_ad(), noise_cipherstate_get_mac_length()
 */
int noise_cipherstate_encrypt_with_ad
    (NoiseCipherState *state, const uint8_t *ad, size_t ad_len,
     uint8_t *data, size_t in_data_len, size_t *out_data_len)
{
    int err;

    /* Set the output length to zero in case of error */
    if (!out_data_len)
        return NOISE_ERROR_INVALID_PARAM;
    *out_data_len = 0;

    /* Validate the parameters */
    if (!state || (!ad && ad_len) || !data)
        return NOISE_ERROR_INVALID_PARAM;

    /* If the key hasn't been set yet, return the plaintext as-is */
    if (!state->has_key) {
        if (in_data_len > NOISE_MAX_PAYLOAD_LEN)
            return NOISE_ERROR_INVALID_LENGTH;
        *out_data_len = in_data_len;
        return NOISE_ERROR_NONE;
    }

    /* Make sure that there is room for the MAC */
    if (in_data_len > (size_t)(NOISE_MAX_PAYLOAD_LEN - state->mac_len))
        return NOISE_ERROR_INVALID_LENGTH;

    /* If the nonce has overflowed, then further encryption is impossible */
    if (state->nonce_overflow)
        return NOISE_ERROR_INVALID_NONCE;

    /* Encrypt the plaintext */
    err = (*(state->encrypt))(state, ad, ad_len, data, in_data_len);
    if (state->n == 0xFFFFFFFFFFFFFFFFULL)
        state->nonce_overflow = 1;
    ++(state->n);
    if (err != NOISE_ERROR_NONE)
        return err;

    /* Adjust the output length for the MAC and return */
    *out_data_len = in_data_len + state->mac_len;
    return NOISE_ERROR_NONE;
}

/**
 * \brief Decrypts a block of data with this CipherState object.
 *
 * \param state The CipherState object.
 * \param ad Points to the associated data, which can be NULL only if
 * \a ad_len is zero.
 * \param ad_len The length of the associated data in bytes.
 * \param data On entry, contains the ciphertext plus MAC.  On exit,
 * contains the plaintext.
 * \param in_data_len The number of bytes in \a data, including both
 * the ciphertext and the MAC.
 * \param out_data_len Set to the number of plaintext bytes in \a data on exit.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if the parameters are invalid.
 * \return NOISE_ERROR_MAC_FAILURE if the MAC check failed.
 * \return NOISE_ERROR_INVALID_NONCE if the nonce previously overflowed.
 * \return NOISE_ERROR_INVALID_LENGTH if \a in_data_len is larger than
 * 65535 bytes or too small to contain the MAC value.
 *
 * The ciphertext is decrypted in-place with the plaintext also written
 * to \a data.  In other words, it is assumed that the ciphertext plus
 * MAC is in an input buffer ready to be processed once the MAC has
 * been checked and the ciphertext has been decrypted.
 *
 * \sa noise_cipherstate_encrypt_with_ad(), noise_cipherstate_get_mac_length()
 */
int noise_cipherstate_decrypt_with_ad
    (NoiseCipherState *state, const uint8_t *ad, size_t ad_len,
     uint8_t *data, size_t in_data_len, size_t *out_data_len)
{
    int err;

    /* Set the output length to zero in case of error */
    if (!out_data_len)
        return NOISE_ERROR_INVALID_PARAM;
    *out_data_len = 0;

    /* Validate the parameters */
    if (!state || (!ad && ad_len) || !data)
        return NOISE_ERROR_INVALID_PARAM;
    if (in_data_len > NOISE_MAX_PAYLOAD_LEN)
        return NOISE_ERROR_INVALID_LENGTH;

    /* If the key hasn't been set yet, return the ciphertext as-is */
    if (!state->has_key) {
        *out_data_len = in_data_len;
        return NOISE_ERROR_NONE;
    }

    /* Make sure there are enough bytes for the MAC */
    if (in_data_len < state->mac_len)
        return NOISE_ERROR_INVALID_LENGTH;

    /* If the nonce has overflowed, then further encryption is impossible */
    if (state->nonce_overflow)
        return NOISE_ERROR_INVALID_NONCE;

    /* Decrypt the ciphertext and check the MAC */
    err = (*(state->decrypt))
        (state, ad, ad_len, data, in_data_len - state->mac_len);
    if (state->n == 0xFFFFFFFFFFFFFFFFULL)
        state->nonce_overflow = 1;
    ++(state->n);
    if (err != NOISE_ERROR_NONE)
        return err;

    /* Adjust the output length for the MAC and return */
    *out_data_len = in_data_len - state->mac_len;
    return NOISE_ERROR_NONE;
}

/**
 * \brief Splits a new CipherState object out of an existing object.
 *
 * \param state The existing CipherState object.
 * \param key Points to the key to set on the new CipherState object.
 * \param key_len The length of the key in bytes.
 * \param new_state Points to a variable that should be set to a pointer
 * to the new CipherState object.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if one of \a state, \a key,
 * or \a new_state is NULL.
 * \return NOISE_ERROR_INVALID_LENGTH if \a key_len is incorrect for
 * the cipher.
 * \return or NOISE_ERROR_NO_MEMORY if the system is out of memory.
 *
 * This function is intended to help implement noise_symmetricstate_split().
 * It clones the existing object, creating a new object with the same
 * algorithm identifier but a new key.
 *
 * \sa noise_symmetricstate_split()
 */
int noise_cipherstate_split
    (const NoiseCipherState *state, const uint8_t *key, size_t key_len,
     NoiseCipherState **new_state)
{
    /* Set the return object to NULL in case of error */
    if (!new_state)
        return NOISE_ERROR_INVALID_PARAM;
    *new_state = 0;

    /* Validate the parameters */
    if (!state || !key)
        return NOISE_ERROR_INVALID_PARAM;
    if (key_len != state->key_len)
        return NOISE_ERROR_INVALID_LENGTH;

    /* Create a new CipherState object of the same type */
    *new_state = (*(state->create))();
    if (!(*new_state))
        return NOISE_ERROR_NO_MEMORY;

    /* Initialize the key in the new state object */
    noise_cipherstate_init_key(*new_state, key, key_len);
    return NOISE_ERROR_NONE;
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

/* The random number generator here is inspired by the
 * ChaCha20 version of arc4random() from OpenBSD. */

/** @cond */

/** Number of bytes to generate before forcing a reseed */
#define NOISE_RAND_RESEED_COUNT 1600000

/** Force a rekey after this many blocks */
#define NOISE_RAND_REKEY_COUNT  16

/** @endcond */

/**
 * \brief Reseeds the random number generator from operating system entropy.
 *
 * \param rand The state of the random number generator.
 */
static void noise_cipherstate_rand_reseed(NoiseRandomState *rand)
{
    /* Get new random data from the operating system, encrypt it
       with the previous key/IV, and then replace the key/IV */
    uint8_t data[40];
    noise_rand_bytes(data, sizeof(data));
    chacha_encrypt_bytes(&(rand->chacha), data, data, sizeof(data));
    chacha_keysetup(&(rand->chacha), data, 256);
    chacha_ivsetup(&(rand->chacha), data + 32, 0);
    noise_clean(data, sizeof(data));
    rand->left = NOISE_RAND_RESEED_COUNT;
}

/**
 * \brief Forces a rekey on the random number generator.
 *
 * \param rand The state of the random number generator.
 */
static void noise_cipherstate_rand_rekey(NoiseRandomState *rand)
{
    uint8_t data[40];
    memset(data, 0, sizeof(data));
    chacha_encrypt_bytes(&(rand->chacha), data, data, sizeof(data));
    chacha_keysetup(&(rand->chacha), data, 256);
    chacha_ivsetup(&(rand->chacha), data + 32, 0);
    noise_clean(data, sizeof(data));
}

/**
 * \brief Generates random bytes for use by the application.
 *
 * \param state The CipherState object.
 * \param buffer The buffer to fill with random bytes.
 * \param len The number of random bytes to generate.
 * \param force_reseed Non-zero to force the random number generator
 * to reseed entropy from the operating system, zero to let this function
 * decide itself when to reseed (zero is recommended).
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state or \a buffer is NULL.
 * \return NOISE_ERROR_NO_MEMORY if this is the first time this function
 * has been called and there is insufficient memory to allocate the
 * state for the random number generator.
 *
 * This function is provided as a convenience for applications that
 * need to generate extra random data during the course of a
 * higher-level protocol that runs over the Noise protocol.
 *
 * If the application wishes to pad message payloads with random data,
 * then the noise_cipherstate_pad() function may be a better option.
 *
 * \sa noise_cipherstate_pad()
 */
int noise_cipherstate_rand_bytes
    (NoiseCipherState *state, uint8_t *buffer, size_t len, int force_reseed)
{
    /* Starting key for the random state before the first reseed.
       This is the SHA256 initialization vector, to introduce a
       little chaos into the starting state. */
    static uint8_t const starting_key[32] = {
          0x6A, 0x09, 0xE6, 0x67, 0xBB, 0x67, 0xAE, 0x85,
          0x3C, 0x6E, 0xF3, 0x72, 0xA5, 0x4F, 0xF5, 0x3A,
          0x51, 0x0E, 0x52, 0x7F, 0x9B, 0x05, 0x68, 0x8C,
          0x1F, 0x83, 0xD9, 0xAB, 0x5B, 0xE0, 0xCD, 0x19
    };
    size_t blocks;

    /* Validate the parameters */
    if (!state || !buffer)
        return NOISE_ERROR_INVALID_PARAM;

    /* Create the random state for the first time if necessary */
    if (!state->rand) {
        state->rand = noise_new(NoiseRandomState);
        if (!state->rand) {
            /* Out of memory.  Set the output to something just in case
               the caller forgets to check the return value.  We don't want
               to accidentally leak the previous contents in the buffer. */
            memset(buffer, 0xAA, len);
            return NOISE_ERROR_NO_MEMORY;
        }
        chacha_keysetup(&(state->rand->chacha), starting_key, 256);
        force_reseed = 1;
    }

    /* Force a reseed if necessary */
    if (force_reseed || state->rand->left < len)
        noise_cipherstate_rand_reseed(state->rand);

    /* Generate the random data in ChaCha20 block-sized chunks */
    memset(buffer, 0, len);
    blocks = 0;
    while (len > 0) {
        size_t temp_len = len;
        if (temp_len > 64)
            temp_len = 64;
        if (state->rand->left >= 64) {
            /* One less block before we need to force a reseed */
            state->rand->left -= 64;
        } else {
            /* Too much random data generated.  Force a reseed now */
            noise_cipherstate_rand_reseed(state->rand);
            blocks = 0;
        }
        if (blocks++ >= NOISE_RAND_REKEY_COUNT) {
            /* Too many blocks in the current request.  Force a rekey now */
            noise_cipherstate_rand_rekey(state->rand);
            blocks = 0;
        }
        chacha_encrypt_bytes(&(state->rand->chacha), buffer, buffer, temp_len);
        buffer += temp_len;
        len -= temp_len;
    }

    /* Force a rekey after every request to destroy the input that
       was used to generate the random data for this request.
       This prevents the state from being rolled backwards. */
    noise_cipherstate_rand_rekey(state->rand);
    return NOISE_ERROR_NONE;
}

/**
 * \brief Adds padding bytes to the end of a message payload.
 *
 * \param state The CipherState object.
 * \param payload Points to the original message payload to be padded,
 * which must be large enough to hold the maximum of \a orig_len
 * or \a padded_len.
 * \param orig_len The original length of the payload before padding.
 * \param padded_len The new length of the payload, including the
 * original data and padding.
 * \param padding_mode The padding mode to use, NOISE_PADDING_ZERO or
 * NOISE_PADDING_RANDOM.  If the padding mode is unknown, then
 * NOISE_PADDING_RANDOM will be used instead.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state or \a payload is NULL.
 * \return NOISE_ERROR_NO_MEMORY if this is the first time this function
 * has been used to generate random padding and there is insufficient memory
 * to allocate the state for the random number generator.  Will not occur
 * if the \a padding_mode is NOISE_PADDING_ZERO.
 *
 * This function is intended for padding message payloads prior to them
 * being encrypted with noise_handshakestate_write_message().  If the
 * \a padding_mode is NOISE_PADDING_RANDOM, then the random bytes are
 * generated using noise_cipherstate_rand_bytes().
 *
 * The number of padding bytes added will be \a padded_len - \a orig_len.
 * If \a padded_len is less than or equal to \a orig_len, then no padding
 * bytes will be added.  Essentially, this function pads the payload to a
 * minimum length.  Larger payloads are transmitted as-is.
 *
 * \sa noise_cipherstate_rand_bytes()
 */
int noise_cipherstate_pad
    (NoiseCipherState *state, uint8_t *payload, size_t orig_len,
     size_t padded_len, int padding_mode)
{
    /* Validate the parameters */
    if (!state || !payload)
        return NOISE_ERROR_INVALID_PARAM;

    /* Nothing to do if the padded length is shorter than the original */
    if (padded_len <= orig_len)
        return NOISE_ERROR_NONE;

    /* Pad the payload as requested */
    if (padding_mode == NOISE_PADDING_ZERO) {
        memset(payload + orig_len, 0, padded_len - orig_len);
        return NOISE_ERROR_NONE;
    } else {
        return noise_cipherstate_rand_bytes
            (state, payload + orig_len, padded_len - orig_len, 0);
    }
}

/**@}*/
