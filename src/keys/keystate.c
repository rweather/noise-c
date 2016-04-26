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

#include "keyinternal.h"
#include <noise/protocol/util.h>
#include <noise/protocol/names.h>
#include <noise/protocol/hashstate.h>
#include <string.h>
#include <errno.h>
#if defined(__WIN32__) || defined(WIN32)
#include <malloc.h>
#else
#include <alloca.h>
#endif

/**
 * \file keystate.h
 * \brief KeyState interface
 */

/**
 * \file keystate.c
 * \brief KeyState implementation
 */

/**
 * \file keys.h
 * \brief Main header file to include the Noise key library definitions.
 */

/**
 * \file keyconstants.h
 * \brief Constants for the Noise key library.
 */

/**
 * \defgroup keystate KeyState API for key management
 *
 * KeyState objects are used to store public and private keys that have
 * been loaded from secondary storage, to generate new keys, and to
 * save them to secondary storage.
 *
 * KeyState objects may contain multiple keys, each for different
 * Diffie-Hellman or signature algorithms.  The appropriate type is
 * chosen when the key is set on a DHState, SignState, or HandshakeState.
 */
/**@{*/

/**
 * \typedef NoiseKeyState
 * \brief Opaque object that represents a KeyState.
 */

/**
 * \def NOISE_KEYREP_BINARY_PRIVATE
 * \brief Binary representation of a bare private key.
 */

/**
 * \def NOISE_KEYREP_BINARY_PUBLIC
 * \brief Binary representation of a bare public key.
 */

/**
 * \def NOISE_KEYREP_BASE64_PRIVATE
 * \brief Base64 representation of a bare private key.
 */

/**
 * \def NOISE_KEYREP_BASE64_PUBLIC
 * \brief Base64 representation of a bare public key.
 */

/** @cond */

#define NOISE_KEYREP_FIRST      NOISE_KEYREP_BINARY_PRIVATE
#define NOISE_KEYREP_LAST       NOISE_KEYREP_BASE64_PUBLIC

/**
 * \brief Information about a single public or private key.
 */
typedef struct NoiseKey_s
{
    /** \brief Size of this structure, including the key data on the end */
    size_t size;

    /** \brief Next key in the list of keys */
    struct NoiseKey_s *next;

    /** \brief Type of key: NOISE_DH_CURVE25519, NOISE_SIGN_ED25519, etc */
    int type;

    /** \brief DHState object if this is a Diffie-Hellman key */
    NoiseDHState *dh;

    /** \brief SignState object if this is a signing key */
    NoiseSignState *sign;

} NoiseKey;

struct NoiseKeyState_s
{
    /** \brief Size of this structure */
    size_t size;

    /** \brief Number of keys that are stored in this object */
    int count;

    /** \brief Points to the first key stored in this object */
    NoiseKey *first;

    /** \brief Points to the last key stored in this object */
    NoiseKey *last;
};

/** @endcond */

/**
 * \brief Creates a new KeyState object, initially with no keys.
 *
 * \param state Points to the variable where to store the pointer to
 * the new KeyState object.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state is NULL.
 * \return NOISE_ERROR_NO_MEMORY if there is insufficient memory to
 * create the new KeyState.
 *
 * \sa noise_keystate_free(), noise_keystate_load_from_file(),
 * noise_keystate_generate_key()
 */
int noise_keystate_new(NoiseKeyState **state)
{
    /* Validate the parameter */
    if (!state)
        return NOISE_ERROR_INVALID_PARAM;

    /* Allocate the KeyState object */
    *state = noise_new(NoiseKeyState);
    if (!(*state))
        return NOISE_ERROR_NO_MEMORY;

    /* Ready to go */
    return NOISE_ERROR_NONE;
}

/**
 * \brief Frees a KeyState object after destroying all sensitive material.
 *
 * \param state The KeyState object to free.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state is NULL.
 *
 * \sa noise_keystate_new()
 */
int noise_keystate_free(NoiseKeyState *state)
{
    NoiseKey *current, *next;

    /* Validate the parameter */
    if (!state)
        return NOISE_ERROR_INVALID_PARAM;

    /* Destroy all keys that are attached to this object */
    current = state->first;
    while (current != 0) {
        next = current->next;
        if (current->dh)
            noise_dhstate_free(current->dh);
        if (current->sign)
            noise_signstate_free(current->sign);
        noise_free(current, current->size);
        current = next;
    }

    /* Destroy the KeyState object itself */
    noise_free(state, state->size);
    return NOISE_ERROR_NONE;
}

/**
 * \brief Adds a DHState object to the end of a KeyState.
 *
 * \param state The KeyState object.
 * \param dh The DHState object to add.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_NO_MEMORY if there is insufficient memory to
 * add the key to \a state.
 *
 * Ownership of the \a dh object transfers to the \a state.
 */
static int noise_keystate_add_dhstate(NoiseKeyState *state, NoiseDHState *dh)
{
    NoiseKey *key;

    /* Create the NoiseKey object and populate it */
    key = noise_new(NoiseKey);
    if (!key) {
        noise_dhstate_free(dh);
        return NOISE_ERROR_NO_MEMORY;
    }
    key->type = noise_dhstate_get_dh_id(dh);
    key->dh = dh;

    /* Add the key to the end of the list in the KeyState */
    key->next = 0;
    if (state->last)
        state->last->next = key;
    else
        state->first = key;
    state->last = key;
    ++(state->count);
    return NOISE_ERROR_NONE;
}

/**
 * \brief Adds a SignState object to the end of a KeyState.
 *
 * \param state The KeyState object.
 * \param sign The SignState object containing the key to add.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_NO_MEMORY if there is insufficient memory to
 * add the key to \a state.
 *
 * Ownership of the \a sign object transfers to the \a state.
 */
static int noise_keystate_add_signstate
    (NoiseKeyState *state, NoiseSignState *sign)
{
    NoiseKey *key;

    /* Create the NoiseKey object and populate it */
    key = noise_new(NoiseKey);
    if (!key) {
        noise_signstate_free(sign);
        return NOISE_ERROR_NO_MEMORY;
    }
    key->type = noise_signstate_get_sign_id(sign);
    key->sign = sign;

    /* Add the key to the end of the list in the KeyState */
    key->next = 0;
    if (state->last)
        state->last->next = key;
    else
        state->first = key;
    state->last = key;
    ++(state->count);
    return NOISE_ERROR_NONE;
}

/**
 * \brief Internal implementation of key loading.
 *
 * \param state The KeyState object to load the keys into.
 * \param stream The input stream to load the keys from.
 * \param rep The representation of the keys in the file.
 * \param type The type of key to load, or zero to automatically
 * detect the type of key (if possible).
 *
 * \return NOISE_ERROR_NONE on success or an error code otherwise.
 */
static int noise_keystate_load
    (NoiseKeyState *state, NoiseKeyStream *stream, int rep, int type)
{
    int is_private = 0;
    size_t key_len = 0;
    int err;

    /* Determine how to load the key data from the representation */
    switch (rep) {
    case NOISE_KEYREP_BINARY_PRIVATE:
        is_private = 1;
        /* Fall through to the next case */
    case NOISE_KEYREP_BINARY_PUBLIC:
        key_len = noise_key_stream_read_binary
            (stream, stream->key, sizeof(stream->key));
        if (!noise_key_stream_expect_eof(stream))
            return NOISE_ERROR_INVALID_FORMAT;
        break;

    case NOISE_KEYREP_BASE64_PRIVATE:
        is_private = 1;
        /* Fall through to the next case */
    case NOISE_KEYREP_BASE64_PUBLIC:
        key_len = noise_key_stream_read_base64
            (stream, stream->key, sizeof(stream->key), 0);
        if (!noise_key_stream_expect_white_eof(stream))
            return NOISE_ERROR_INVALID_FORMAT;
        break;

    default:
        return NOISE_ERROR_INVALID_PARAM;
    }

    /* Auto-detect the algorithm from the key length if necessary */
    if (!type || type == NOISE_DH_CATEGORY) {
        if (key_len == 32)
            type = NOISE_DH_CURVE25519;
        else if (key_len == 56)
            type = NOISE_DH_CURVE448;
        else
            return NOISE_ERROR_UNKNOWN_ID;
    } else if (type == NOISE_SIGN_CATEGORY) {
        if (key_len == 32)
            type = NOISE_SIGN_ED25519;
        else
            return NOISE_ERROR_UNKNOWN_ID;
    }

    /* Create the DHState or SignState for the algorithm */
    err = noise_dhstate_new_by_id(&(stream->dh), type);
    if (err == NOISE_ERROR_NONE) {
        /* Load a Diffie-Hellman key from the stream */
        err = NOISE_ERROR_INVALID_FORMAT;
        if (is_private) {
            if (key_len == noise_dhstate_get_private_key_length(stream->dh)) {
                err = noise_dhstate_set_keypair_private
                    (stream->dh, stream->key, key_len);
            }
        } else {
            if (key_len == noise_dhstate_get_public_key_length(stream->dh)) {
                err = noise_dhstate_set_public_key
                    (stream->dh, stream->key, key_len);
            }
        }
        if (err == NOISE_ERROR_NONE) {
            err = noise_keystate_add_dhstate(state, stream->dh);
            if (err == NOISE_ERROR_NONE)
                stream->dh = 0;
        }
    } else if ((err = noise_signstate_new_by_id(&(stream->sign), type))
                    != NOISE_ERROR_NONE) {
        /* Load a signing key from the stream */
        err = NOISE_ERROR_INVALID_FORMAT;
        if (is_private) {
            if (key_len == noise_signstate_get_private_key_length(stream->sign)) {
                err = noise_signstate_set_keypair_private
                    (stream->sign, stream->key, key_len);
            }
        } else {
            if (key_len == noise_signstate_get_public_key_length(stream->sign)) {
                err = noise_signstate_set_public_key
                    (stream->sign, stream->key, key_len);
            }
        }
        if (err == NOISE_ERROR_NONE) {
            err = noise_keystate_add_signstate(state, stream->sign);
            if (err == NOISE_ERROR_NONE)
                stream->sign = 0;
        }
    }
    return err;
}

/**
 * \brief Loads a set of keys from a file into a KeyState object.
 *
 * \param state The KeyState object to load the keys into.
 * \param filename The name of the file to load.
 * \param rep The representation of the keys in the file, such as
 * NOISE_KEYREP_BINARY_PRIVATE, NOISE_KEYREP_BASE64_PUBLIC, etc.
 * \param type The type of key to load, or one of zero, NOISE_DH_CATEGORY,
 * or NOISE_SIGN_CATEGORY to auto-detect the algorithm (if possible).
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state or \a filename is NULL.
 * \return NOISE_ERROR_INVALID_PARAM if \a rep is not a supported
 * representation.
 * \return NOISE_ERROR_UNKNOWN_ID if \a type is not a recognized key type
 * and the key type cannot be auto-detected.
 * \return NOISE_ERROR_SYSTEM if \a filename cannot be opened, with further
 * information in the system errno variable.
 * \return NOISE_ERROR_INVALID_FORMAT if the contents of \a filename are
 * incorrect for \a rep and \a type.
 * \return NOISE_ERROR_NO_MEMORY if there is insufficient memory to load
 * the key information.
 *
 * \sa noise_keystate_load_from_buffer(), noise_keystate_save_to_file()
 */
int noise_keystate_load_from_file
    (NoiseKeyState *state, const char *filename, int rep, int type)
{
    NoiseKeyStream stream;
    int err;

    /* Validate the parameters */
    if (!state || !filename)
        return NOISE_ERROR_INVALID_PARAM;
    if (rep < NOISE_KEYREP_FIRST || rep > NOISE_KEYREP_LAST)
        return NOISE_ERROR_INVALID_PARAM;

    /* Open the file and initialize the input stream */
    memset(&stream, 0, sizeof(stream));
    stream.file = fopen(filename, "rb");
    if (!stream.file)
        return NOISE_ERROR_SYSTEM;

    /* Load the contents of the file */
    err = noise_keystate_load(state, &stream, rep, type);
    noise_key_stream_close(&stream);
    return err;
}

/**
 * \brief Loads a set of keys from a memory buffer into a KeyState object.
 *
 * \param state The KeyState object to load the keys into.
 * \param buffer The buffer containing the key information to load.
 * \param rep The representation of the keys in the \a buffer, such as
 * NOISE_KEYREP_BINARY_PRIVATE, NOISE_KEYREP_BASE64_PUBLIC, etc.
 * \param type The type of key to load, or one of zero, NOISE_DH_CATEGORY,
 * or NOISE_SIGN_CATEGORY to auto-detect the algorithm (if possible).
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state or \a buffer is NULL.
 * \return NOISE_ERROR_INVALID_PARAM if \a rep is not a supported
 * representation.
 * \return NOISE_ERROR_UNKNOWN_ID if \a type is not a recognized key type
 * and the key type cannot be auto-detected.
 * \return NOISE_ERROR_INVALID_FORMAT if the contents of \a buffer are
 * incorrect for \a rep and \a type.
 * \return NOISE_ERROR_NO_MEMORY if there is insufficient memory to load
 * the key information.
 *
 * The following example loads a static binary key for Curve25519 into a
 * KeyState object:
 *
 * \code
 * static uint8_t const client_key_25519[32] = { ... };
 * NoiseBuffer buf;
 * noise_buffer_set_input(buf, client_key_25519, sizeof(client_key_25519));
 * err = noise_keystate_load_from_buffer
 *          (state, &buf, NOISE_KEYREP_BINARY_PRIVATE, NOISE_DH_CURVE25519);
 * \endcode
 *
 * \sa noise_keystate_load_from_file(), noise_keystate_save_to_file()
 */
int noise_keystate_load_from_buffer
    (NoiseKeyState *state, const NoiseBuffer *buffer, int rep, int type)
{
    NoiseKeyStream stream;
    int err;

    /* Validate the parameters */
    if (!state || !buffer || !(buffer->data))
        return NOISE_ERROR_INVALID_PARAM;
    if (rep < NOISE_KEYREP_FIRST || rep > NOISE_KEYREP_LAST)
        return NOISE_ERROR_INVALID_PARAM;

    /* Initialize the input stream from the buffer */
    memset(&stream, 0, sizeof(stream));
    stream.buffer = (NoiseBuffer *)buffer;

    /* Load the contents of the stream */
    err = noise_keystate_load(state, &stream, rep, type);
    noise_key_stream_close(&stream);
    return err;
}

/**
 * \brief Saves a key to a stream.
 *
 * \param stream The stream to save to.
 * \param rep The key representation to save in.
 * \param key The key to be saved.
 *
 * \return NOISE_ERROR_NONE on success, or an error code.
 */
static int noise_keystate_save
    (NoiseKeyStream *stream, int rep, const NoiseKey *key)
{
    uint8_t *private_key = 0;
    uint8_t *public_key = 0;
    size_t private_key_len = 0;
    size_t public_key_len = 0;
    int err = NOISE_ERROR_NONE;

    /* Fetch the key value that we need to encode */
    if (key->dh) {
        private_key_len = noise_dhstate_get_private_key_length(key->dh);
        public_key_len = noise_dhstate_get_public_key_length(key->dh);
        if (noise_dhstate_has_keypair(key->dh)) {
            private_key = alloca(private_key_len);
            public_key = alloca(public_key_len);
            err = noise_dhstate_get_keypair
                (key->dh, private_key, private_key_len,
                 public_key, public_key_len);
        } else {
            public_key = alloca(public_key_len);
            err = noise_dhstate_get_public_key
                (key->dh, public_key, public_key_len);
        }
    } else {
        private_key_len = noise_signstate_get_private_key_length(key->sign);
        public_key_len = noise_signstate_get_public_key_length(key->sign);
        if (noise_signstate_has_keypair(key->sign)) {
            private_key = alloca(private_key_len);
            public_key = alloca(public_key_len);
            err = noise_signstate_get_keypair
                (key->sign, private_key, private_key_len,
                 public_key, public_key_len);
        } else {
            public_key = alloca(public_key_len);
            err = noise_signstate_get_public_key
                (key->sign, public_key, public_key_len);
        }
    }

    /* Write the key to the stream */
    if (err == NOISE_ERROR_NONE) {
        switch (rep) {
        case NOISE_KEYREP_BINARY_PRIVATE:
            /* Binary private key */
            if (private_key) {
                if (!noise_key_stream_write_binary
                        (stream, private_key, private_key_len)) {
                    err = NOISE_ERROR_INVALID_LENGTH;
                }
            } else {
                err = NOISE_ERROR_INVALID_PRIVATE_KEY;
            }
            break;

        case NOISE_KEYREP_BINARY_PUBLIC:
            /* Binary public key */
            if (!noise_key_stream_write_binary
                    (stream, public_key, public_key_len)) {
                err = NOISE_ERROR_INVALID_LENGTH;
            }
            break;

        case NOISE_KEYREP_BASE64_PRIVATE:
            /* Base64 private key */
            if (private_key) {
                if (!noise_key_stream_write_base64
                        (stream, private_key, private_key_len, 0)) {
                    err = NOISE_ERROR_INVALID_LENGTH;
                }
            } else {
                err = NOISE_ERROR_INVALID_PRIVATE_KEY;
            }
            break;

        case NOISE_KEYREP_BASE64_PUBLIC:
            /* Base64 public key */
            if (!noise_key_stream_write_base64
                    (stream, private_key, private_key_len, 0)) {
                err = NOISE_ERROR_INVALID_LENGTH;
            }
            break;

        default:
            err = NOISE_ERROR_INVALID_PARAM;
            break;
        }
    }

    /* Clean up and exit */
    if (private_key)
        noise_clean(private_key, private_key_len);
    if (public_key)
        noise_clean(public_key, public_key_len);
    return err;
}

/**
 * \brief Saves the contents of a KeyState object to a file.
 *
 * \param state The KeyState object to save the keys from.
 * \param filename The name of the file to save.
 * \param rep The representation of the keys in the file, such as
 * NOISE_KEYREP_BINARY_PRIVATE, NOISE_KEYREP_BASE64_PUBLIC, etc.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state or \a filename is NULL.
 * \return NOISE_ERROR_INVALID_PARAM if \a rep is not a supported
 * representation.
 * \return NOISE_ERROR_SYSTEM if \a filename cannot be opened, with further
 * information in the system errno variable.
 * \return NOISE_ERROR_INVALID_STATE if \a state does not contain any keys.
 * \return NOISE_ERROR_INVALID_PRIVATE_KEY if \a rep refers to a private key
 * but the key to be saved is not a keypair.
 *
 * Some representations can only handle a single key.  For those
 * representations only the first key in the KeyState is written
 * to the file.
 *
 * \sa noise_keystate_save_to_buffer(), noise_keystate_load_from_file()
 */
int noise_keystate_save_to_file
    (NoiseKeyState *state, const char *filename, int rep)
{
    NoiseKeyStream stream;
    int err;

    /* Validate the parameters */
    if (!state || !filename)
        return NOISE_ERROR_INVALID_PARAM;
    if (rep < NOISE_KEYREP_FIRST || rep > NOISE_KEYREP_LAST)
        return NOISE_ERROR_INVALID_PARAM;
    if (!state->count)
        return NOISE_ERROR_INVALID_STATE;

    /* Open the file and initialize the output stream */
    memset(&stream, 0, sizeof(stream));
    stream.file = fopen(filename, "wb");
    if (!stream.file)
        return NOISE_ERROR_SYSTEM;

    /* Save the first key in the KeyState to the file */
    err = noise_keystate_save(&stream, rep, state->first);
    if (err == NOISE_ERROR_INVALID_LENGTH) {
        int saved_errno = errno;
        noise_key_stream_close(&stream);
        errno = saved_errno;
        err = NOISE_ERROR_SYSTEM;
    } else {
        noise_key_stream_close(&stream);
    }
    return err;
}

/**
 * \brief Saves the contents of a KeyState object to a memory buffer.
 *
 * \param state The KeyState object to save the keys from.
 * \param buffer The buffer to save the keys to.
 * \param rep The representation of the keys in the buffer, such as
 * NOISE_KEYREP_BINARY_PRIVATE, NOISE_KEYREP_BASE64_PUBLIC, etc.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state or \a buffer is NULL.
 * \return NOISE_ERROR_INVALID_PARAM if \a rep is not a supported
 * representation.
 *
 * Some representations can only handle a single key.  For those
 * representations only the first key in the KeyState is written
 * to the buffer.
 *
 * The following example saves a static public key for Curve25519
 * into a data buffer in base64 format:
 *
 * \code
 * uint8_t data[128];
 * NoiseBuffer buf;
 * noise_buffer_set_output(buf, data, sizeof(data));
 * err = noise_keystate_save_to_buffer(state, &buf, NOISE_KEYREP_BASE64_PUBLIC);
 * \endcode
 *
 * \sa noise_keystate_save_to_file(), noise_keystate_load_from_buffer()
 */
int noise_keystate_save_to_buffer
    (NoiseKeyState *state, NoiseBuffer *buffer, int rep)
{
    NoiseKeyStream stream;
    int err;

    /* Validate the parameters */
    if (!state || !buffer || !(buffer->data))
        return NOISE_ERROR_INVALID_PARAM;
    if (rep < NOISE_KEYREP_FIRST || rep > NOISE_KEYREP_LAST)
        return NOISE_ERROR_INVALID_PARAM;
    if (!state->count)
        return NOISE_ERROR_INVALID_STATE;

    /* Initialize the input stream from the buffer */
    memset(&stream, 0, sizeof(stream));
    stream.buffer = (NoiseBuffer *)buffer;
    buffer->size = 0;

    /* Save the first key in the KeyState to the buffer */
    err = noise_keystate_save(&stream, rep, state->first);
    noise_key_stream_close(&stream);
    return err;
}

/**
 * \brief Gets the number of keys that are stored in a KeyState.
 *
 * \param state The KeyState object.
 *
 * \return The number of keys in \a state, or zero if \a state is NULL.
 *
 * \sa noise_keystate_get_key_type()
 */
int noise_keystate_get_key_count(const NoiseKeyState *state)
{
    return state ? state->count : 0;
}

/**
 * \brief Gets a specific key information block given its index.
 *
 * \param state The KeyState to inspect.
 * \param index The key index to look for.
 *
 * \return The key information block, or NULL if \a state or \a index
 * are invalid.
 */
static const NoiseKey *noise_keystate_get_by_index
    (const NoiseKeyState *state, int index)
{
    const NoiseKey *key;
    if (!state || index < 0)
        return 0;
    key = state->first;
    while (key != 0 && index > 0) {
        key = key->next;
        --index;
    }
    return key;
}

/**
 * \brief Gets a specific key information block given the key type.
 *
 * \param state The KeyState to inspect.
 * \param type The key type to look for.
 *
 * \return The key information block, or NULL if \a state or \a type
 * are invalid.
 */
static const NoiseKey *noise_keystate_get_by_type
    (const NoiseKeyState *state, int type)
{
    const NoiseKey *key;
    if (!state)
        return 0;
    key = state->first;
    while (key != 0) {
        if (key->type == type)
            return key;
        key = key->next;
    }
    return 0;
}

/**
 * \brief Gets the type of a specific key within a KeyState.
 *
 * \param state The KeyState object.
 * \param index The index of the key, between zero and
 * noise_keystate_get_key_count() - 1.
 *
 * \return The type of key, typically one of NOISE_DH_CURVE25519,
 * NOISE_DH_CURVE448, or NOISE_DH_ED25519.
 * \return Zero if \a state is NULL or \a index is out of range.
 *
 * \sa noise_keystate_get_key_count(), noise_keystate_find_key_type()
 */
int noise_keystate_get_key_type(const NoiseKeyState *state, int index)
{
    const NoiseKey *key = noise_keystate_get_by_index(state, index);
    return key ? key->type : 0;
}

/**
 * \brief Finds the index of the first key within a KeyState with a
 * specific key type.
 *
 * \param state The KeyState object.
 * \param type The type of key, typically one of NOISE_DH_CURVE25519,
 * NOISE_DH_CURVE448, or NOISE_DH_ED25519.
 *
 * \return The index of the key within \a state, or -1 if there is
 * no key within \a state with the specified \a type.
 *
 * \sa noise_keystate_get_key_type()
 */
int noise_keystate_find_key_type(const NoiseKeyState *state, int type)
{
    const NoiseKey *key;
    int index;
    if (!state)
        return -1;
    key = state->first;
    index = 0;
    while (key != 0) {
        if (key->type == type)
            return index;
        key = key->next;
        ++index;
    }
    return -1;
}

/**
 * \brief Determine if a specific key within a KeyState has a private
 * key component.
 *
 * \param state The KeyState object.
 * \param index The index of the key, between zero and
 * noise_keystate_get_key_count() - 1.
 *
 * \return Non-zero if the key at \a index within \a state has a private key.
 * \return Zero if \a state is NULL, \a index is out of range, or
 * the key at \a index only has a public key.
 */
int noise_keystate_has_private_key(const NoiseKeyState *state, int index)
{
    const NoiseKey *key = noise_keystate_get_by_index(state, index);
    if (!key)
        return 0;
    if (key->dh)
        return noise_dhstate_has_keypair(key->dh);
    else
        return noise_signstate_has_keypair(key->sign);
}

/**
 * \brief Copies a specific key within a KeyState to a DHState.
 *
 * \param state The KeyState object.
 * \param index The index of the key, between zero and
 * noise_keystate_get_key_count() - 1, or -1 to let this function
 * select the first key with a type that matches \a dh.
 * \param dh The DHState object to set the key on.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state or \a dh is NULL.
 * \return NOISE_ERROR_INVALID_PARAM if \a index is out of range and not -1.
 * \return NOISE_ERROR_NOT_APPLICABLE if the key at \a index is not
 * applicable to \a dh.
 * \return NOISE_ERROR_NOT_APPLICABLE if \a index is -1 and there is no
 * key in \a state that is applicable to \a dh.
 *
 * \sa noise_keystate_copy_to_handshake_local(),
 * noise_keystate_copy_to_signstate()
 */
int noise_keystate_copy_to_dhstate
    (const NoiseKeyState *state, int index, NoiseDHState *dh)
{
    const NoiseKey *key;
    int type;

    /* Validate the parameters */
    if (!state || !dh)
        return NOISE_ERROR_INVALID_PARAM;

    /* Look up the key */
    type = noise_dhstate_get_dh_id(dh);
    if (index != -1) {
        key = noise_keystate_get_by_index(state, index);
        if (!key)
            return NOISE_ERROR_INVALID_PARAM;
        if (key->type != type)
            return NOISE_ERROR_NOT_APPLICABLE;
    } else {
        key = noise_keystate_get_by_type(state, type);
        if (!key)
            return NOISE_ERROR_NOT_APPLICABLE;
    }

    /* Copy the key across */
    return noise_dhstate_copy(dh, key->dh);
}

/**
 * \brief Copies a specific key within a KeyState to a SignState.
 *
 * \param state The KeyState object.
 * \param index The index of the key, between zero and
 * noise_keystate_get_key_count() - 1, or -1 to let this function
 * select the first key with a type that matches \a dh.
 * \param sign The SignState object to set the key on.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state or \a sign is NULL.
 * \return NOISE_ERROR_INVALID_PARAM if \a index is out of range and not -1.
 * \return NOISE_ERROR_NOT_APPLICABLE if the key at \a index is not
 * applicable to \a sign.
 * \return NOISE_ERROR_NOT_APPLICABLE if \a index is -1 and there is no
 * key in \a state that is applicable to \a sign.
 *
 * \sa noise_keystate_copy_to_dhstate()
 */
int noise_keystate_copy_to_signstate
    (const NoiseKeyState *state, int index, NoiseSignState *sign)
{
    const NoiseKey *key;
    int type;

    /* Validate the parameters */
    if (!state || !sign)
        return NOISE_ERROR_INVALID_PARAM;

    /* Look up the key */
    type = noise_signstate_get_sign_id(sign);
    if (index != -1) {
        key = noise_keystate_get_by_index(state, index);
        if (!key)
            return NOISE_ERROR_INVALID_PARAM;
        if (key->type != type)
            return NOISE_ERROR_NOT_APPLICABLE;
    } else {
        key = noise_keystate_get_by_type(state, type);
        if (!key)
            return NOISE_ERROR_NOT_APPLICABLE;
    }

    /* Copy the key across */
    return noise_signstate_copy(sign, key->sign);
}

/**
 * \brief Copies a specific key within a KeyState to the local static
 * key for a HandshakeState.
 *
 * \param state The KeyState object.
 * \param index The index of the key, between zero and
 * noise_keystate_get_key_count() - 1, or -1 to let this function
 * select the first key with a type that matches the local static
 * key type of \a handshake.
 * \param handshake The HandshakeState object to set the key on.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state or \a handshake is NULL.
 * \return NOISE_ERROR_INVALID_PARAM if \a index is out of range and not -1.
 * \return NOISE_ERROR_NOT_APPLICABLE if the key at \a index is not
 * applicable to \a handshake.
 * \return NOISE_ERROR_NOT_APPLICABLE if \a index is -1 and there is no
 * key in \a state that is applicable to \a handshake.
 * \return NOISE_ERROR_NOT_APPLICABLE if \a handshake does not require a
 * local static key.
 * \return NOISE_ERROR_INVALID_PRIVATE_KEY if the key at \a index does
 * not contain a private key component.
 *
 * \sa noise_keystate_copy_to_handshake_remote(),
 * noise_keystate_copy_to_dhstate()
 */
int noise_keystate_copy_to_handshake_local
    (const NoiseKeyState *state, int index, NoiseHandshakeState *handshake)
{
    NoiseDHState *dh;
    const NoiseKey *key;
    int type;

    /* Validate the parameters */
    if (!state || !handshake)
        return NOISE_ERROR_INVALID_PARAM;
    dh = noise_handshakestate_get_local_keypair_dh(handshake);
    if (!dh)
        return NOISE_ERROR_NOT_APPLICABLE;

    /* Look up the key */
    type = noise_dhstate_get_dh_id(dh);
    if (index != -1) {
        key = noise_keystate_get_by_index(state, index);
        if (!key)
            return NOISE_ERROR_INVALID_PARAM;
        if (key->type != type)
            return NOISE_ERROR_NOT_APPLICABLE;
    } else {
        key = noise_keystate_get_by_type(state, type);
        if (!key)
            return NOISE_ERROR_NOT_APPLICABLE;
    }

    /* If the key doesn't have a private component then it is not
       suitable for use as a local static key */
    if (!noise_dhstate_has_keypair(key->dh))
        return NOISE_ERROR_INVALID_PRIVATE_KEY;

    /* Copy the key across */
    return noise_dhstate_copy(dh, key->dh);
}

/**
 * \brief Copies a specific key within a KeyState to the remote public
 * key for a HandshakeState.
 *
 * \param state The KeyState object.
 * \param index The index of the key, between zero and
 * noise_keystate_get_key_count() - 1, or -1 to let this function
 * select the first key with a type that matches the remote public
 * key type of \a handshake.
 * \param handshake The HandshakeState object to set the key on.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state or \a handshake is NULL.
 * \return NOISE_ERROR_INVALID_PARAM if \a index is out of range and not -1.
 * \return NOISE_ERROR_NOT_APPLICABLE if the key at \a index is not
 * applicable to \a handshake.
 * \return NOISE_ERROR_NOT_APPLICABLE if \a index is -1 and there is no
 * key in \a state that is applicable to \a handshake.
 * \return NOISE_ERROR_NOT_APPLICABLE if \a handshake does not require a
 * remote public key.
 *
 * \sa noise_keystate_copy_to_handshake_local(),
 * noise_keystate_copy_to_dhstate()
 */
int noise_keystate_copy_to_handshake_remote
    (const NoiseKeyState *state, int index, NoiseHandshakeState *handshake)
{
    NoiseDHState *dh;

    /* Validate the parameters */
    if (!state || !handshake)
        return NOISE_ERROR_INVALID_PARAM;
    dh = noise_handshakestate_get_remote_public_key_dh(handshake);
    if (!dh)
        return NOISE_ERROR_NOT_APPLICABLE;

    /* Copy the key across */
    return noise_keystate_copy_to_dhstate(state, index, dh);
}

/**
 * \brief Adds the key in a DHState to the end of a KeyState.
 *
 * \param state The KeyState object.
 * \param dh The DHState object containing the key to add.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM is \a state or \a dh is NULL.
 * \return NOISE_ERROR_INVALID_STATE if \a dh does not contain a key yet.
 * \return NOISE_ERROR_NO_MEMORY if there is insufficient memory to
 * add the key to \a state.
 *
 * \sa noise_keystate_add_from_signstate(), noise_keystate_generate_key()
 */
int noise_keystate_add_from_dhstate
    (NoiseKeyState *state, const NoiseDHState *dh)
{
    NoiseDHState *dh_copy;
    int err;

    /* Validate the parameters */
    if (!state || !dh)
        return NOISE_ERROR_INVALID_PARAM;

    /* Make a copy of the incoming key */
    err = noise_dhstate_new_by_id(&dh_copy, noise_dhstate_get_dh_id(dh));
    if (err != NOISE_ERROR_NONE)
        return err;
    noise_dhstate_copy(dh_copy, dh);

    /* Add the new key to the end of the KeyState */
    return noise_keystate_add_dhstate(state, dh_copy);
}

/**
 * \brief Adds the key in a SignState to the end of a KeyState.
 *
 * \param state The KeyState object.
 * \param sign The SignState object containing the key to add.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM is \a state or \a sign is NULL.
 * \return NOISE_ERROR_INVALID_STATE if \a sign does not contain a key yet.
 * \return NOISE_ERROR_NO_MEMORY if there is insufficient memory to
 * add the key to \a state.
 *
 * \sa noise_keystate_add_from_dhstate(), noise_keystate_generate_key()
 */
int noise_keystate_add_from_signstate
    (NoiseKeyState *state, const NoiseSignState *sign)
{
    NoiseSignState *sign_copy;
    int err;

    /* Validate the parameters */
    if (!state || !sign)
        return NOISE_ERROR_INVALID_PARAM;

    /* Make a copy of the incoming key */
    err = noise_signstate_new_by_id
        (&sign_copy, noise_signstate_get_sign_id(sign));
    if (err != NOISE_ERROR_NONE)
        return err;
    noise_signstate_copy(sign_copy, sign);

    /* Add the new key to the end of the KeyState */
    return noise_keystate_add_signstate(state, sign_copy);
}

/**
 * \brief Removes a key from a KeyState object.
 *
 * \param state The KeyState object.
 * \param index The index of the key to remove, between zero and
 * noise_keystate_get_key_count() - 1.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state is NULL or \a index is
 * out of range.
 */
int noise_keystate_remove_key(NoiseKeyState *state, int index)
{
    NoiseKey *current, *prev, *next;

    /* Validate the parameters */
    if (!state || index < 0)
        return NOISE_ERROR_INVALID_PARAM;

    /* Find the key value to remove */
    prev = 0;
    current = state->first;
    while (current != 0) {
        if (!index) {
            /* This is the object we're interested in.  Remove it */
            next = current->next;
            if (prev)
                prev->next = next;
            else
                state->first = next;
            if (!next)
                state->last = prev;
            if (current->dh)
                noise_dhstate_free(current->dh);
            if (current->sign)
                noise_signstate_free(current->sign);
            noise_free(current, current->size);
            --(state->count);
            return NOISE_ERROR_NONE;
        }
        --index;
        prev = current;
        current = current->next;
    }

    /* The index is out of range */
    return NOISE_ERROR_INVALID_PARAM;
}

/**
 * \brief Generates a new keypair and adds it to a KeyState object.
 *
 * \param state The KeyState object.
 * \param type The type of keypair to generate; one of NOISE_DH_CURVE25519,
 * NOISE_DH_CURVE448, or NOISE_SIGN_ED25519.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state is NULL.
 * \return NOISE_ERROR_UNKNOWN_ID if \a type is not one of the known
 * Diffie-Hellman or signature algorithm types.
 * \return NOISE_ERROR_NO_MEMORY if there is insufficient memory to
 * generate the new keypair.
 *
 * \sa noise_keystate_add_from_dhstate(), noise_keystate_add_from_signstate()
 */
int noise_keystate_generate_key(NoiseKeyState *state, int type)
{
    NoiseDHState *dh = 0;
    NoiseSignState *sign = 0;
    int err;

    /* Validate the state parameter */
    if (!state)
        return NOISE_ERROR_INVALID_PARAM;

    /* Generate a keypair using the appropriate type of object */
    err = noise_dhstate_new_by_id(&dh, type);
    if (err == NOISE_ERROR_NONE) {
        err = noise_dhstate_generate_keypair(dh);
    } else if (err == NOISE_ERROR_UNKNOWN_ID) {
        err = noise_signstate_new_by_id(&sign, type);
        if (err == NOISE_ERROR_NONE)
            err = noise_signstate_generate_keypair(sign);
    }
    if (err != NOISE_ERROR_NONE) {
        noise_dhstate_free(dh);
        noise_signstate_free(sign);
        return err;
    }

    /* Add the new key to the end of the KeyState */
    if (dh)
        return noise_keystate_add_dhstate(state, dh);
    else
        return noise_keystate_add_signstate(state, sign);
}

/**
 * \brief Formats the public key fingerprint for a specific key in a KeyState.
 *
 * \param state The KeyState object.
 * \param index The index of the key, between zero and
 * noise_keystate_get_key_count() - 1.
 * \param fingerprint_type The type of fingerprint to format,
 * NOISE_FINGERPRINT_BASIC or NOISE_FINGERPRINT_FULL.
 * \param buffer The buffer to write the fingerprint string to, including a
 * terminating NUL.
 * \param len The length of \a buffer in bytes.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state or \a buffer is NULL.
 * \return NOISE_ERROR_INVALID_PARAM if \a index is out of range.
 * \return NOISE_ERROR_INVALID_PARAM if \a fingerprint_type is not a
 * supported fingerprint type.
 * \return NOISE_ERROR_INVALID_LENGTH if \a len is not large enough to
 * hold the entire fingerprint string.
 *
 * Fingerprints are created by hashing the public key with SHA256 and
 * then formatting the value in hexadecimal with bytes separated by colons.
 * If the \a fingerprint_type is NOISE_FINGERPRINT_BASIC, then the SHA256
 * hash value is truncated to the first 16 bytes.  If the type is
 * NOISE_FINGERPRINT_FULL, then the entire 32 byte hash value is formatted.
 */
int noise_keystate_format_fingerprint
    (const NoiseKeyState *state, int index, int fingerprint_type,
     char *buffer, size_t len)
{
    const NoiseKey *key;

    /* Validate the parameters */
    if (!buffer)
        return NOISE_ERROR_INVALID_PARAM;
    if (!len)
        return NOISE_ERROR_INVALID_LENGTH;
    *buffer = '\0'; /* In case we bail out with an error later */
    if (!state)
        return NOISE_ERROR_INVALID_PARAM;

    /* Look up the key */
    key = noise_keystate_get_by_index(state, index);
    if (!key)
        return NOISE_ERROR_INVALID_PARAM;

    /* Format the fingerprint for the key */
    if (key->dh) {
        return noise_dhstate_format_fingerprint
            (key->dh, fingerprint_type, buffer, len);
    } else {
        return noise_signstate_format_fingerprint
            (key->sign, fingerprint_type, buffer, len);
    }
}

/**
 * \brief Convert the name of a key algorithm into the corresponding type.
 *
 * \param name The name of the key algorithm; e.g. "25519", "448",
 * "Ed25519", etc.  This string must be NUL-terminated.
 *
 * \return The identifier for the key algorithm's type, or zero if the
 * \a name is not recognized.
 *
 * This is a convenience function wrapped around noise_name_to_id()
 * which can resolve either Diffie-Hellman or signature algorithm names.
 */
int noise_keystate_name_to_type(const char *name)
{
    size_t name_len;
    int type;
    if (!name)
        return 0;
    name_len = strlen(name);
    type = noise_name_to_id(NOISE_DH_CATEGORY, name, name_len);
    if (!type)
        type = noise_name_to_id(NOISE_SIGN_CATEGORY, name, name_len);
    return type;
}

/**@}*/
