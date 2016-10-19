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
 * \file symmetricstate.h
 * \brief SymmetricState interface
 */

/**
 * \file symmetricstate.c
 * \brief SymmetricState implementation
 */

/**
 * \defgroup symmetricstate SymmetricState API
 */
/**@{*/

/**
 * \typedef NoiseSymmetricState
 * \brief Opaque object that represents a SymmetricState.
 */

/**
 * \brief Creates a new SymmetricState object.
 *
 * \param state Points to the variable where to store the pointer to
 * the new SymmetricState object.
 * \param name The name of the Noise protocol to use.  This string
 * must be NUL-terminated.
 * \param id The protocol identifier as a set of algorithm identifiers.
 *
 * This is the internal implementation of noise_symmetricstate_new_by_id()
 * and noise_symmetricstate_new_by_name().
 */
static int noise_symmetricstate_new
    (NoiseSymmetricState **state, const char *name, const NoiseProtocolId *id)
{
    NoiseSymmetricState *new_state;
    size_t name_len;
    size_t hash_len;
    int err;

    /* Construct a state object and initialize it */
    new_state = noise_new(NoiseSymmetricState);
    if (!new_state)
        return NOISE_ERROR_NO_MEMORY;
    new_state->id = *id;
    err = noise_cipherstate_new_by_id(&(new_state->cipher), id->cipher_id);
    if (err != NOISE_ERROR_NONE) {
        noise_symmetricstate_free(new_state);
        return err;
    }
    err = noise_hashstate_new_by_id(&(new_state->hash), id->hash_id);
    if (err != NOISE_ERROR_NONE) {
        noise_symmetricstate_free(new_state);
        return err;
    }

    /* Check the hash length against the maximum, just in case someone
       adds a new hash algorithm in the future with longer output.
       If this happens, modify NOISE_MAX_HASHLEN in internal.h accordingly */
    hash_len = noise_hashstate_get_hash_length(new_state->hash);
    if (hash_len > NOISE_MAX_HASHLEN) {
        noise_symmetricstate_free(new_state);
        return NOISE_ERROR_NOT_APPLICABLE;
    }

    /* The key length must also be less than or equal to the hash length */
    if (noise_cipherstate_get_key_length(new_state->cipher) > hash_len) {
        noise_symmetricstate_free(new_state);
        return NOISE_ERROR_NOT_APPLICABLE;
    }

    /* Initialize the chaining key "ck" and the handshake hash "h" from
       the protocol name.  If the name is too long, hash it down first */
    name_len = strlen(name);
    if (name_len <= hash_len) {
        memcpy(new_state->h, name, name_len);
        memset(new_state->h + name_len, 0, hash_len - name_len);
    } else {
        noise_hashstate_hash_one
            (new_state->hash, (const uint8_t *)name, name_len,
             new_state->h, hash_len);
    }
    memcpy(new_state->ck, new_state->h, hash_len);

    /* Ready to go */
    *state = new_state;
    return NOISE_ERROR_NONE;
}

/**
 * \brief Creates a new SymmetricState object from a protocol identifier.
 *
 * \param state Points to the variable where to store the pointer to
 * the new SymmetricState object.
 * \param id The protocol identifier as a set of algorithm identifiers.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state or \a id is NULL.
 * \return NOISE_ERROR_UNKNOWN_ID if the protocol \a id is unknown.
 * \return NOISE_ERROR_INVALID_LENGTH if the full name corresponding
 * to \a id is too long.
 * \return NOISE_ERROR_NOT_APPLICABLE if the lengths of the hash output
 * or the cipher key are incompatible.
 * \return NOISE_ERROR_NO_MEMORY if there is insufficient memory to
 * allocate the new SymmetricState object.
 *
 * \sa noise_symmetricstate_free(), noise_symmetricstate_new_by_name()
 */
int noise_symmetricstate_new_by_id
    (NoiseSymmetricState **state, const NoiseProtocolId *id)
{
    char name[NOISE_MAX_PROTOCOL_NAME];
    int err;

    /* Validate the parameters */
    if (!state)
        return NOISE_ERROR_INVALID_PARAM;
    *state = 0;
    if (!id)
        return NOISE_ERROR_INVALID_PARAM;

    /* Format the full protocol name from the identifiers.  We need the
       full name because the handshake hash is initialized from the name */
    err = noise_protocol_id_to_name(name, sizeof(name), id);
    if (err != NOISE_ERROR_NONE)
        return err;

    /* Create the SymmetricState object */
    return noise_symmetricstate_new(state, name, id);
}

/**
 * \brief Creates a new SymmetricState object from a protocol name.
 *
 * \param state Points to the variable where to store the pointer to
 * the new SymmetricState object.
 * \param name The name of the Noise protocol to use.  This string
 * must be NUL-terminated.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state or \a name is NULL.
 * \return NOISE_ERROR_UNKNOWN_NAME if the protocol \a name is unknown.
 * \return NOISE_ERROR_NOT_APPLICABLE if the lengths of the hash output
 * or the cipher key are incompatible.
 * \return NOISE_ERROR_NO_MEMORY if there is insufficient memory to
 * allocate the new SymmetricState object.
 *
 * \sa noise_symmetricstate_free(), noise_symmetricstate_new_by_id()
 */
int noise_symmetricstate_new_by_name
    (NoiseSymmetricState **state, const char *name)
{
    NoiseProtocolId id;
    size_t name_len;
    int err;

    /* Validate the parameters */
    if (!state)
        return NOISE_ERROR_INVALID_PARAM;
    *state = 0;
    if (!name)
        return NOISE_ERROR_INVALID_PARAM;

    /* Parse the protocol identifier and validate the names */
    name_len = strlen(name);
    err = noise_protocol_name_to_id(&id, name, name_len);
    if (err != NOISE_ERROR_NONE)
        return err;

    /* Create the SymmetricState object */
    return noise_symmetricstate_new(state, name, &id);
}

/**
 * \brief Frees a SymmetricState object after destroying all sensitive material.
 *
 * \param state The SymmetricState object to free.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state is NULL.
 *
 * \sa noise_symmetricstate_new_by_id(), noise_symmetricstate_new_by_name()
 */
int noise_symmetricstate_free(NoiseSymmetricState *state)
{
    /* Bail out if no symmetric state */
    if (!state)
        return NOISE_ERROR_INVALID_PARAM;

    /* Free the sub objects that are hanging off the symmetricstate */
    if (state->cipher)
        noise_cipherstate_free(state->cipher);
    if (state->hash)
        noise_hashstate_free(state->hash);

    /* Clean and free the memory for "state" */
    noise_free(state, state->size);
    return NOISE_ERROR_NONE;
}

/**
 * \brief Gets the protocol identifier associated with a SymmetricState object.
 *
 * \param state The SymmetricState object.
 * \param id Return buffer for the protocol identifier, which consists of
 * fields that identify the cipher algorithm, hash algorith, handshake
 * pattern, etc.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state or \a id is NULL.
 */
int noise_symmetricstate_get_protocol_id
    (const NoiseSymmetricState *state, NoiseProtocolId *id)
{
    /* Validate the parameters */
    if (!state || !id)
        return NOISE_ERROR_INVALID_PARAM;

    /* Copy the internal id block to the parameter */
    *id = state->id;
    return NOISE_ERROR_NONE;
}

/**
 * \brief Mixes new input data into the chaining key.
 *
 * \param state The SymmetricState object.
 * \param input Points to the input data to mix in.
 * \param size The size of the \a input data in bytes.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state or \a input is NULL.
 * \return NOISE_ERROR_INVALID_STATE if the \a state has already been split.
 *
 * \sa noise_symmetricstate_mix_hash(), noise_symmetricstate_split()
 */
int noise_symmetricstate_mix_key
    (NoiseSymmetricState *state, const uint8_t *input, size_t size)
{
    uint8_t temp_k[NOISE_MAX_HASHLEN];
    size_t hash_len;
    size_t key_len;

    /* Validate the parameters */
    if (!state || !input)
        return NOISE_ERROR_INVALID_PARAM;

    /* If the state has been split, then we cannot do this */
    if (!state->cipher)
        return NOISE_ERROR_INVALID_STATE;

    /* Mix the input data in using HKDF */
    hash_len = noise_hashstate_get_hash_length(state->hash);
    key_len = noise_cipherstate_get_key_length(state->cipher);
    noise_hashstate_hkdf
        (state->hash, state->ck, hash_len, input, size,
         state->ck, hash_len, temp_k, key_len);

    /* Change the cipher key, or set it for the first time */
    noise_cipherstate_init_key(state->cipher, temp_k, key_len);
    noise_clean(temp_k, sizeof(temp_k));
    return NOISE_ERROR_NONE;
}

/**
 * \brief Mixes new input data into the handshake hash.
 *
 * \param state The SymmetricState object.
 * \param input Points to the input data to mix in.
 * \param size The size of the \a input data in bytes.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state or \a input is NULL.
 * \return NOISE_ERROR_INVALID_STATE if the \a state has already been split.
 *
 * \sa noise_symmetricstate_mix_key(), noise_symmetricstate_split()
 */
int noise_symmetricstate_mix_hash
    (NoiseSymmetricState *state, const uint8_t *input, size_t size)
{
    size_t hash_len;

    /* Validate the parameters */
    if (!state || !input)
        return NOISE_ERROR_INVALID_PARAM;

    /* If the state has been split, then we cannot do this */
    if (!state->cipher)
        return NOISE_ERROR_INVALID_STATE;

    /* Mix the input data into "h" */
    hash_len = noise_hashstate_get_hash_length(state->hash);
    noise_hashstate_hash_two
        (state->hash, state->h, hash_len, input, size, state->h, hash_len);
    return NOISE_ERROR_NONE;
}

/**
 * \brief Encrypts a block of data with this SymmetricState object
 * and adds the ciphertext to the handshake hash.
 *
 * \param state The SymmetricState object.
 * \param buffer The buffer containing the plaintext on entry and the
 * ciphertext plus MAC on exit.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state or \a buffer is NULL.
 * \return NOISE_ERROR_INVALID_NONCE if the nonce previously overflowed
 * \return NOISE_ERROR_INVALID_LENGTH if the ciphertext plus MAC is
 * too large to fit within the maximum size of \a buffer and to also
 * remain within 65535 bytes.
 *
 * The plaintext is encrypted in-place with the ciphertext also written
 * to \a buffer.  There must be enough room on the end of \a buffer
 * to hold the extra MAC value that will be appended.  In other words,
 * it is assumed that the plaintext is in an output buffer ready to be
 * transmitted once the data has been encrypted and the final packet
 * length has been determined.
 *
 * The noise_symmetricstate_get_mac_length() function can be used to
 * determine the size of the MAC value that will be added, which may
 * be zero if the encryption key has not been set up yet.
 *
 * \sa noise_symmetricstate_decrypt_and_hash(),
 * noise_symmetricstate_get_mac_length()
 */
int noise_symmetricstate_encrypt_and_hash
    (NoiseSymmetricState *state, NoiseBuffer *buffer)
{
    size_t hash_len;
    int err;

    /* Validate the parameters */
    if (!state || !buffer || !(buffer->data))
        return NOISE_ERROR_INVALID_PARAM;

    /* If the state has been split, then we cannot do this */
    if (!state->cipher)
        return NOISE_ERROR_INVALID_STATE;

    /* Encrypt the plaintext using the underlying cipher */
    hash_len = noise_hashstate_get_hash_length(state->hash);
    err = noise_cipherstate_encrypt_with_ad
        (state->cipher, state->h, hash_len, buffer);
    if (err != NOISE_ERROR_NONE)
        return err;

    /* Feed the ciphertext into the handshake hash */
    noise_symmetricstate_mix_hash(state, buffer->data, buffer->size);
    return NOISE_ERROR_NONE;
}

/**
 * \brief Decrypts a block of data with this SymmetricState object
 * and adds the ciphertext to the handshake hash.
 *
 * \param state The SymmetricState object.
 * \param buffer The buffer containing the ciphertext plus MAC on entry
 * and the plaintext on exit.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state or \a buffer is NULL.
 * \return NOISE_ERROR_MAC_FAILURE if the MAC check failed.
 * \return NOISE_ERROR_INVALID_STATE if this SymmetricState has
 * already been split.
 * \return NOISE_ERROR_INVALID_NONCE if the nonce previously overflowed.
 * \return NOISE_ERROR_INVALID_LENGTH if the data in \a buffer is
 * larger than 65535 bytes or too small to contain the MAC value.
 *
 * The ciphertext is decrypted in-place with the plaintext also written
 * to \a buffer.  In other words, it is assumed that the ciphertext plus
 * MAC is in an input buffer ready to be processed once the MAC has
 * been checked and the ciphertext has been decrypted.
 *
 * \sa noise_symmetricstate_encrypt_and_hash()
 */
int noise_symmetricstate_decrypt_and_hash
    (NoiseSymmetricState *state, NoiseBuffer *buffer)
{
    uint8_t temp[NOISE_MAX_HASHLEN];
    size_t hash_len;
    int err;

    /* Validate the parameters */
    if (!state || !buffer || !(buffer->data))
        return NOISE_ERROR_INVALID_PARAM;

    /* If the state has been split, then we cannot do this */
    if (!state->cipher)
        return NOISE_ERROR_INVALID_STATE;

    /* Validate the input data length before we hash the data */
    if (buffer->size > NOISE_MAX_PAYLOAD_LEN)
        return NOISE_ERROR_INVALID_LENGTH;
    if (noise_cipherstate_has_key(state->cipher)) {
        if (buffer->size < noise_cipherstate_get_mac_length(state->cipher))
            return NOISE_ERROR_INVALID_LENGTH;
    }

    /* Feed the ciphertext into the handshake hash first.  We make a
       temporary copy of the hash.  If the decryption fails below,
       then we don't update the handshake hash with the bogus data */
    hash_len = noise_hashstate_get_hash_length(state->hash);
    noise_hashstate_hash_two
        (state->hash, state->h, hash_len,
         buffer->data, buffer->size, temp, hash_len);

    /* Decrypt the ciphertext using the underlying cipher */
    err = noise_cipherstate_decrypt_with_ad
        (state->cipher, state->h, hash_len, buffer);
    if (err != NOISE_ERROR_NONE) {
        noise_clean(temp, sizeof(temp));
        return err;
    }

    /* Update the handshake hash */
    memcpy(state->h, temp, hash_len);
    noise_clean(temp, sizeof(temp));
    return NOISE_ERROR_NONE;
}

/**
 * \brief Gets the current length of packet MAC values for a
 * SymmetricState object.
 *
 * \param state The SymmetricState object.
 *
 * \return The size of the MAC in bytes. Returns zero if \a state is NULL,
 * the encryption key has not been set yet, or the SymmetricState has
 * been split.
 *
 * This function can be used to determine the size of the MAC value that
 * will be added to the next packet that will be encrypted with
 * noise_symmetricstate_encrypt_and_hash().  Early in the handshake when
 * packets are still being exchanged in plaintext, the size will be zero.
 *
 * \sa noise_symmetricstate_encrypt_and_hash()
 */
size_t noise_symmetricstate_get_mac_length(const NoiseSymmetricState *state)
{
    /* Validate the parameter */
    if (!state)
        return 0;

    /* If the state has been split or the key has not been set, then zero */
    if (!state->cipher)
        return 0;
    if (!noise_cipherstate_has_key(state->cipher))
        return 0;

    /* Return the MAC length for the cipher */
    return noise_cipherstate_get_mac_length(state->cipher);
}

/**
 * \brief Splits the transport encryption CipherState objects out of
 * this SymmetricState object.
 *
 * \param state The SymmetricState object.
 * \param c1 Points to the variable where to place the pointer to the
 * first CipherState object.  This can be NULL if the application is
 * using a one-way handshake pattern.
 * \param c2 Points to the variable where to place the pointer to the
 * second CipherState object.  This can be NULL if the application is
 * using a one-way handshake pattern.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state is NULL.
 * \return NOISE_ERROR_INVALID_PARAM if both \a c1 and \a c2 are NULL.
 * \return NOISE_ERROR_INVALID_STATE if the \a state has already been split.
 * \return NOISE_ERROR_NO_MEMORY if there is insufficient memory to create
 * the new CipherState objects.
 *
 * Once a SymmetricState has been split, it is effectively finished and
 * cannot be used for future encryption or hashing operations.
 * If those operations are invoked, the relevant functions will return
 * NOISE_ERROR_INVALID_STATE.
 *
 * The \a c1 object should be used to protect messages from the initiator to
 * the responder, and the \a c2 object should be used to protect messages
 * from the responder to the initiator.
 *
 * If the handshake pattern is one-way, then the application should call
 * noise_cipherstate_free() on the object that is not needed.  Alternatively,
 * the application can pass NULL to noise_symmetricstate_split() as the
 * \a c1 or \a c2 argument and the second CipherState will not be created
 * at all.
 */
int noise_symmetricstate_split
    (NoiseSymmetricState *state, NoiseCipherState **c1, NoiseCipherState **c2)
{
    uint8_t temp_k1[NOISE_MAX_HASHLEN];
    uint8_t temp_k2[NOISE_MAX_HASHLEN];
    size_t hash_len;
    size_t key_len;

    /* Validate the parameters */
    if (!state)
        return NOISE_ERROR_INVALID_PARAM;
    if (!c1 && !c2)
        return NOISE_ERROR_INVALID_PARAM;
    if (c1)
        *c1 = 0;
    if (c2)
        *c2 = 0;

    /* If the state has already been split, then we cannot split again */
    if (!state->cipher)
        return NOISE_ERROR_INVALID_STATE;

    /* Generate the two encryption keys with HKDF */
    hash_len = noise_hashstate_get_hash_length(state->hash);
    key_len = noise_cipherstate_get_key_length(state->cipher);
    noise_hashstate_hkdf
        (state->hash, state->ck, hash_len, state->ck, 0,
         temp_k1, key_len, temp_k2, key_len);

    /* If we only need c2, then re-initialize the key in the internal
       cipher and copy it to c2 */
    if (!c1 && c2) {
        noise_cipherstate_init_key(state->cipher, temp_k2, key_len);
        *c2 = state->cipher;
        state->cipher = 0;
        noise_clean(temp_k1, sizeof(temp_k1));
        noise_clean(temp_k2, sizeof(temp_k2));
        return NOISE_ERROR_NONE;
    }

    /* Split a copy out of the cipher and give it the second key.
       We don't need to do this if the second CipherSuite is not required */
    if (c2) {
        *c2 = (*(state->cipher->create))();
        if (!(*c2)) {
            noise_clean(temp_k1, sizeof(temp_k1));
            noise_clean(temp_k2, sizeof(temp_k2));
            return NOISE_ERROR_NO_MEMORY;
        }
        noise_cipherstate_init_key(*c2, temp_k2, key_len);
    }

    /* Re-initialize the key in the internal cipher and copy it to c1 */
    noise_cipherstate_init_key(state->cipher, temp_k1, key_len);
    *c1 = state->cipher;
    state->cipher = 0;
    noise_clean(temp_k1, sizeof(temp_k1));
    noise_clean(temp_k2, sizeof(temp_k2));
    return NOISE_ERROR_NONE;
}

/**@}*/
