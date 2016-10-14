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
#if USE_LIBSODIUM
#include <sodium.h>
#else
#include "crypto/chacha/chacha.h"
#endif
#include <string.h>

/**
 * \file randstate.h
 * \brief RandState interface
 */

/**
 * \file randstate.c
 * \brief RandState implementation
 */

/**
 * \defgroup randstate RandState API
 *
 * The RandState API is provided as a convenience for applications that
 * need to generate extra random data during the course of a higher-level
 * protocol that runs over the Noise protocol.
 *
 * One use for random data is to pad message payloads to a uniform
 * length prior to encryption.  The noise_randstate_pad() function
 * provides a convenient method to do this.
 */
/**@{*/

/**
 * \typedef NoiseRandState
 * \brief Opaque object that represents a random number generator.
 */

/* The random number generator here is inspired by the
 * ChaCha20 version of arc4random() from OpenBSD. */

/** @cond */

/**
 * \brief State information for random number generators.
 */
struct NoiseRandState_s
{
    /** \brief Total size of the structure */
    size_t size;

    /** \brief Number of bytes left until the next reseed */
    size_t left;

    /** \brief ChaCha20 state for the random number generator */
#if USE_LIBSODIUM
    uint8_t chacha_k[crypto_stream_chacha20_KEYBYTES];
    uint8_t chacha_n[crypto_stream_chacha20_IETF_NONCEBYTES];
#else
    chacha_ctx chacha;
#endif
};

/** Number of bytes to generate before forcing a reseed */
#define NOISE_RAND_RESEED_COUNT 1600000

/** Force a rekey after this many blocks */
#define NOISE_RAND_REKEY_COUNT  16

/* Starting key for the random state before the first reseed.
   This is the SHA256 initialization vector, to introduce a
   little chaos into the starting state. */
static uint8_t const starting_key[32] = {
      0x6A, 0x09, 0xE6, 0x67, 0xBB, 0x67, 0xAE, 0x85,
      0x3C, 0x6E, 0xF3, 0x72, 0xA5, 0x4F, 0xF5, 0x3A,
      0x51, 0x0E, 0x52, 0x7F, 0x9B, 0x05, 0x68, 0x8C,
      0x1F, 0x83, 0xD9, 0xAB, 0x5B, 0xE0, 0xCD, 0x19
};

/** @endcond */

/**
 * \brief Creates a new random number generator.
 *
 * \param state Points to the variable where to store the pointer to
 * the new RandState object.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state is NULL.
 * \return NOISE_ERROR_NO_MEMORY if there is insufficient memory to
 * allocate the new RandState object.
 *
 * \sa noise_randstate_free(), noise_randstate_generate()
 */
int noise_randstate_new(NoiseRandState **state)
{
    /* Validate the parameter */
    if (!state)
        return NOISE_ERROR_INVALID_PARAM;

    /* Create the random number generator state */
    *state = noise_new(NoiseRandState);
    if (!(*state))
        return NOISE_ERROR_NO_MEMORY;

    /* Initialize the random number generator */
#if USE_LIBSODIUM
    memcpy((*state)->chacha_k, starting_key, crypto_stream_chacha20_KEYBYTES);
    memset((*state)->chacha_n, 0, crypto_stream_chacha20_IETF_NONCEBYTES);
#else
    chacha_keysetup(&((*state)->chacha), starting_key, 256);
#endif
    noise_randstate_reseed((*state));
    return NOISE_ERROR_NONE;
}

/**
 * \brief Frees a RandState object after destroying all sensitive material.
 *
 * \param state The RandState object to free.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state is NULL.
 *
 * \sa noise_randstate_new()
 */
int noise_randstate_free(NoiseRandState *state)
{
    /* Validate the parameter */
    if (!state)
        return NOISE_ERROR_INVALID_PARAM;

    /* Clean and free the memory */
    noise_free(state, state->size);
    return NOISE_ERROR_NONE;
}

/**
 * \brief Reseeds the random number generator from operating system entropy.
 *
 * \param state The RandState object.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state is NULL.
 *
 * This function forces the random number generator to fetch fresh entropy
 * from the operating system.  Normally this isn't necessary because
 * noise_randstate_generate() will reseed automatically when necessary.
 *
 * If the application needs to generate a highly critical value such as a
 * new keypair then it may want to force a reseed.  Even this isn't necessary
 * for \ref dhstate "DHState" and \ref signstate "SignState" which already
 * seek fresh operating system entropy when generating keypairs.
 *
 * \sa noise_randstate_generate()
 */
int noise_randstate_reseed(NoiseRandState *state)
{
#if USE_LIBSODIUM
    uint8_t data[crypto_stream_chacha20_KEYBYTES + crypto_stream_chacha20_IETF_NONCEBYTES];
#else
    uint8_t data[40];
#endif

    /* Validate the parameter */
    if (!state)
        return NOISE_ERROR_INVALID_PARAM;

    /* Get new random data from the operating system, encrypt it
       with the previous key/IV, and then replace the key/IV */
    noise_rand_bytes(data, sizeof(data));
#if USE_LIBSODIUM
    crypto_stream_chacha20_ietf_xor(data, data, sizeof(data), state->chacha_n, state->chacha_k);
    memcpy(state->chacha_k, data, crypto_stream_chacha20_KEYBYTES);
    memcpy(state->chacha_n, data + crypto_stream_chacha20_KEYBYTES, crypto_stream_chacha20_IETF_NONCEBYTES);
#else
    chacha_encrypt_bytes(&(state->chacha), data, data, sizeof(data));
    chacha_keysetup(&(state->chacha), data, 256);
    chacha_ivsetup(&(state->chacha), data + 32, 0);
#endif
    state->left = NOISE_RAND_RESEED_COUNT;

    /* And force a rekey as well for good measure */
    memset(data, 0, sizeof(data));
#if USE_LIBSODIUM
    crypto_stream_chacha20_ietf_xor(data, data, sizeof(data), state->chacha_n, state->chacha_k);
    memcpy(state->chacha_k, data, crypto_stream_chacha20_KEYBYTES);
    memcpy(state->chacha_n, data + crypto_stream_chacha20_KEYBYTES, crypto_stream_chacha20_IETF_NONCEBYTES);
#else
    chacha_encrypt_bytes(&(state->chacha), data, data, sizeof(data));
    chacha_keysetup(&(state->chacha), data, 256);
    chacha_ivsetup(&(state->chacha), data + 32, 0);
#endif
    noise_clean(data, sizeof(data));

    /* Ready to go */
    return NOISE_ERROR_NONE;
}

/**
 * \brief Forces a rekey on the random number generator.
 *
 * \param state The state of the random number generator.
 */
static void noise_randstate_rekey(NoiseRandState *state)
{
#if USE_LIBSODIUM
    uint8_t data[crypto_stream_chacha20_KEYBYTES + crypto_stream_chacha20_IETF_NONCEBYTES];
#else
    uint8_t data[40];
#endif
    memset(data, 0, sizeof(data));
#if USE_LIBSODIUM
    crypto_stream_chacha20_ietf_xor(data, data, sizeof(data), state->chacha_n, state->chacha_k);
    memcpy(state->chacha_k, data, crypto_stream_chacha20_KEYBYTES);
    memcpy(state->chacha_n, data + crypto_stream_chacha20_KEYBYTES, crypto_stream_chacha20_IETF_NONCEBYTES);
#else
    chacha_encrypt_bytes(&(state->chacha), data, data, sizeof(data));
    chacha_keysetup(&(state->chacha), data, 256);
    chacha_ivsetup(&(state->chacha), data + 32, 0);
#endif
    noise_clean(data, sizeof(data));
}

/**
 * \brief Generates random bytes for use by the application.
 *
 * \param state The RandState object.
 * \param buffer The buffer to fill with random bytes.
 * \param len The number of random bytes to generate.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state or \a buffer is NULL.
 *
 * This function will periodically reseed the random number generator
 * from operating system entropy.  The application can force a reseed
 * at any time by calling noise_randstate_reseed(), but it is usually
 * better to let the RandState API decide when to reseed on its own.
 *
 * \sa noise_randstate_pad(), noise_randstate_reseed(),
 * noise_randstate_generate_simple()
 */
int noise_randstate_generate
    (NoiseRandState *state, uint8_t *buffer, size_t len)
{
    size_t blocks;
    size_t temp_len;

    /* Validate the parameters.  We make sure to set the contents of
       the buffer to zero before proceeding just in case this function
       bails out before it can actually generate data.  We don't want
       to accidentally leak the previous contents in the buffer. */
    if (!buffer)
        return NOISE_ERROR_INVALID_PARAM;
    memset(buffer, 0, len);
    if (!state)
        return NOISE_ERROR_INVALID_PARAM;

    /* Force a reseed if necessary */
    if (state->left < len)
        noise_randstate_reseed(state);

    /* Generate the random data in ChaCha20 block-sized chunks */
    blocks = 0;
    while (len > 0) {
        temp_len = len;
        if (temp_len > 64)
            temp_len = 64;
        if (state->left >= 64) {
            /* One less block before we need to force a reseed */
            state->left -= 64;
        } else {
            /* Too much random data generated.  Force a reseed now */
            noise_randstate_reseed(state);
            blocks = 0;
        }
        if (blocks++ >= NOISE_RAND_REKEY_COUNT) {
            /* Too many blocks in the current request.  Force a rekey now */
            noise_randstate_rekey(state);
            blocks = 0;
        }
#if USE_LIBSODIUM
        crypto_stream_chacha20_ietf_xor_ic(buffer, buffer, temp_len, state->chacha_n, blocks + 1, state->chacha_k);
#else
        chacha_encrypt_bytes(&(state->chacha), buffer, buffer, temp_len);
#endif
        buffer += temp_len;
        len -= temp_len;
    }

    /* Force a rekey after every request to destroy the input that
       was used to generate the random data for this request.
       This prevents the state from being rolled backwards. */
    noise_randstate_rekey(state);
    return NOISE_ERROR_NONE;
}

/**
 * \brief Adds padding bytes to the end of a message payload.
 *
 * \param state The RandState object.
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
 *
 * This function is intended for padding message payloads prior to them
 * being encrypted with noise_handshakestate_write_message() or
 * noise_cipherstate_encrypt_with_ad().  If the \a padding_mode is
 * NOISE_PADDING_RANDOM, then the random bytes are generated using
 * noise_randstate_generate().
 *
 * The number of padding bytes added will be \a padded_len - \a orig_len.
 * If \a padded_len is less than or equal to \a orig_len, then no padding
 * bytes will be added.  Essentially, this function pads the payload to a
 * minimum length.  Larger payloads are transmitted as-is.
 *
 * \sa noise_cipherstate_rand_bytes()
 */
int noise_randstate_pad
    (NoiseRandState *state, uint8_t *payload, size_t orig_len,
     size_t padded_len, int padding_mode)
{
    /* Validate the parameters */
    if (!payload)
        return NOISE_ERROR_INVALID_PARAM;
    if (!state) {
        /* Zero the padding region just in case so that we don't accidentally
           leak the previous contents of the payload's padding region. */
        if (padded_len > orig_len)
            memset(payload + orig_len, 0, padded_len - orig_len);
        return NOISE_ERROR_INVALID_PARAM;
    }

    /* Nothing to do if the new length is shorter than the original */
    if (padded_len <= orig_len)
        return NOISE_ERROR_NONE;

    /* Pad the payload as requested */
    if (padding_mode == NOISE_PADDING_ZERO) {
        memset(payload + orig_len, 0, padded_len - orig_len);
        return NOISE_ERROR_NONE;
    } else {
        return noise_randstate_generate
            (state, payload + orig_len, padded_len - orig_len);
    }
}

/**
 * \brief Generates random data without first creating a RandState object.
 *
 * \param buffer The buffer to fill with random bytes.
 * \param len The number of random bytes to generate.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a buffer is NULL.
 *
 * This function is provided for the convenience of applications that only
 * need to generate a small amount of random data.
 *
 * \sa noise_randstate_generate()
 */
int noise_randstate_generate_simple(uint8_t *buffer, size_t len)
{
    NoiseRandState state;

    /* Validate the parameters */
    if (!buffer)
        return NOISE_ERROR_INVALID_PARAM;

    /* Initialize the random number generator on the stack */
    memset(&state, 0, sizeof(state));
#if USE_LIBSODIUM
    memcpy(state.chacha_k, starting_key, crypto_stream_chacha20_KEYBYTES);
    memset(state.chacha_n, 0, crypto_stream_chacha20_IETF_NONCEBYTES);
#else
    chacha_keysetup(&(state.chacha), starting_key, 256);
#endif
    noise_randstate_reseed(&state);

    /* Generate the required data */
    noise_randstate_generate(&state, buffer, len);

    /* Clean up the random number generator on the stack */
    noise_clean(&state, sizeof(state));
    return NOISE_ERROR_NONE;
}

/**@}*/
