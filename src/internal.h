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

#ifndef NOISE_INTERNAL_H
#define NOISE_INTERNAL_H

#include <noise/noise.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file internal.h
 * \brief Internal definitions for the library.
 *
 * \note This file and its definitions are not part of the public API.
 * The definitions are subject to change without notice.
 */

/**
 * \brief Maximum hash length over all supported hash algorithms.
 */
#define NOISE_MAX_HASHLEN 64

/**
 * \brief Internal structure of the NoiseCipherState type.
 */
struct NoiseCipherState_s
{
    /** \brief Total size of the structure including subclass state */
    size_t size;

    /** \brief Algorithm identifier for the cipher */
    int cipher_id;

    /** \brief Non-zero if the key has been set on this cipher */
    uint8_t has_key;

    /** \brief Non-zero if the nonce has overflowed */
    uint8_t nonce_overflow;

    /** \brief Length of the key for this cipher in bytes */
    uint8_t key_len;

    /** \brief Length of the MAC for this cipher in bytes */
    uint8_t mac_len;

    /** \brief The nonce value for the next packet */
    uint64_t n;

    /**
     * \brief Creates a new CipherState of the same type as this one.
     *
     * \return A new CipherState object, or NULL if there is insufficient
     * memory for the request.
     */
    NoiseCipherState *(*create)(void);

    /**
     * \brief Sets the key for this CipherState.
     *
     * \param state Points to the CipherState.
     * \param key Points to the key, which must be \ref key_len bytes in size.
     *
     * If the key has already been set before, then calling this function
     * again will set a new key.
     */
    void (*init_key)(NoiseCipherState *state, const uint8_t *key);

    /**
     * \brief Encrypts data with this CipherState.
     *
     * \param state Points to the CipherState.
     * \param ad Points to the associated data to include in the
     * MAC computation.
     * \param ad_len The length of the associated data; may be zero.
     * \param data Points to the plaintext on entry, and to the ciphertext
     * plus MAC on exit.
     * \param len The length of the plaintext.
     *
     * \return NOISE_ERROR_NONE on success.
     *
     * The \a data buffer must have enough room to append \ref mac_len extra
     * bytes for the MAC value.
     */
    int (*encrypt)(NoiseCipherState *state, const uint8_t *ad, size_t ad_len,
                   uint8_t *data, size_t len);

    /**
     * \brief Decrypts data with this CipherState.
     *
     * \param state Points to the CipherState.
     * \param ad Points to the associated data to include in the
     * MAC computation.
     * \param ad_len The length of the associated data; may be zero.
     * \param data Points to the ciphertext plus MAC on entry, and to
     * the plaintext on exit.
     * \param len The length of the ciphertext, excluding the MAC.
     *
     * \return NOISE_ERROR_NONE on success, NOISE_ERROR_MAC_FAILURE
     * if the MAC check failed.
     */
    int (*decrypt)(NoiseCipherState *state, const uint8_t *ad, size_t ad_len,
                   uint8_t *data, size_t len);

    /**
     * \brief Destroys this CipherState prior to the memory being freed.
     *
     * \param state Points to the CipherState.
     *
     * This function is called just before the memory for the CipherState
     * is deallocated.  It gives the back end an opportunity to clean up
     * linked objects.
     *
     * This pointer can be NULL if the back end does not need any special
     * clean up logic.
     */
    void (*destroy)(NoiseCipherState *state);
};

/**
 * \brief Internal structure of the NoiseHashState type.
 */
struct NoiseHashState_s
{
    /** \brief Total size of the structure including subclass state */
    size_t size;

    /** \brief Algorithm identifier for the hash */
    int hash_id;

    /** \brief Length of the output from this hash algorithm */
    uint16_t hash_len;

    /** \brief Length of the underlying block for this hash algorithm */
    uint16_t block_len;

    /**
     * \brief Resets the HashState for a new hashing session.
     *
     * \param state Points to the HashState.
     */
    void (*reset)(NoiseHashState *state);

    /**
     * \brief Updates the HashState with more input data.
     *
     * \param state Points to the HashState.
     * \param data Points to the input data.
     * \param len The length of the input \a data in bytes.
     */
    void (*update)(NoiseHashState *state, const uint8_t *data, size_t len);

    /**
     * \brief Finalizes the HashState and returns the hash value.
     *
     * \param state Points to the HashState.
     * \param hash Points to the buffer to receive the final hash value.
     * This must be at least \ref hash_len bytes in length.
     */
    void (*finalize)(NoiseHashState *state, uint8_t *hash);

    /**
     * \brief Cleans up sensitive data in the HashState.
     *
     * \param state Points to the HashState.
     */
    void (*clean)(NoiseHashState *state);

    /**
     * \brief Destroys this HashState prior to the memory being freed.
     *
     * \param state Points to the HashState.
     *
     * This function is called just before the memory for the HashState
     * is deallocated.  It gives the back end an opportunity to clean up
     * linked objects.
     *
     * This pointer can be NULL if the back end does not need any special
     * clean up logic.
     */
    void (*destroy)(NoiseHashState *state);
};

/**
 * \brief Internal structure of the NoiseDHState type.
 */
struct NoiseDHState_s
{
    /** \brief Total size of the structure including subclass state */
    size_t size;

    /** \brief Algorithm identifier for the Diffie-Hellman operation */
    int dh_id;

    /** \brief Length of the private key for this algorithm in bytes */
    uint16_t private_key_len;

    /** \brief Length of the public key for this algorithm in bytes */
    uint16_t public_key_len;

    /** \brief Length of the shared key for this algorithm in bytes */
    uint16_t shared_key_len;

    /**
     * \brief Generates a key pair for this Diffie-Hellman algorithm.
     *
     * \param state Points to the DHState.
     * \param private_key Points to the private key on exit.  Must be at
     * least \ref private_key_len bytes in length.
     * \param public_key Points to the public key on exit.  Must be at
     * least \ref public_key_len bytes in length.
     *
     * \return NOISE_ERROR_NONE on success.
     */
    int (*generate_keypair)
        (const NoiseDHState *state, uint8_t *private_key, uint8_t *public_key);

    /**
     * \brief Performs a Diffie-Hellman calculation.
     *
     * \param state Points to the DHState.
     * \param shared_key Points to the shared key on exit.  Must be at
     * least \ref shared_key_len bytes in length.
     * \param private_key Points to the private key.  Must be at least
     * \ref private_key_len bytes in length.
     * \param public_key Points to the public key.  Must be at least
     * \ref public_key_len bytes in length.
     *
     * \return NOISE_ERROR_NONE on success, or NOISE_ERROR_INVALID_DH_KEY if
     * either \a public_key or \a private_key are invalid for the algorithm.
     *
     * This function must always operate in the same amount of time, even
     * if the \a public_key or \a private_key is invalid.
     */
    int (*calculate)
        (const NoiseDHState *state, uint8_t *shared_key,
         const uint8_t *private_key, const uint8_t *public_key);

    /**
     * \brief Destroys this DHState prior to the memory being freed.
     *
     * \param state Points to the DHState.
     *
     * This function is called just before the memory for the DHState
     * is deallocated.  It gives the back end an opportunity to clean up
     * linked objects.
     *
     * This pointer can be NULL if the back end does not need any special
     * clean up logic.
     */
    void (*destroy)(NoiseDHState *state);
};

/**
 * \brief Internal structure of the NoiseSymmetricState type.
 */
struct NoiseSymmetricState_s
{
    /** \brief Total size of the structure including subclass state */
    size_t size;

    /** \brief Algorithm identifiers for the components of the protocol */
    NoiseProtocolId id;

    /**
     * \brief Points to the CipherState object for this SymmetricState.
     *
     * When the SymmetricState is split, this field will be set to NULL as
     * the CipherState will be handed off to the application with a new key.
     *
     * \sa noise_symmetricstate_split()
     */
    NoiseCipherState *cipher;

    /** \brief Points to the HashState object for this SymmetricState */
    NoiseHashState *hash;

    /** \brief Current value of the chaining key for the handshake */
    uint8_t ck[NOISE_MAX_HASHLEN];

    /** \brief Current value of the handshake hash */
    uint8_t h[NOISE_MAX_HASHLEN];
};

/* Handshake message pattern tokens (must be single-byte values) */
#define NOISE_TOKEN_END         0   /**< End of pattern, start data session */
#define NOISE_TOKEN_S           1   /**< "s" token */
#define NOISE_TOKEN_E           2   /**< "e" token */
#define NOISE_TOKEN_DHEE        3   /**< "dhee" token */
#define NOISE_TOKEN_DHES        4   /**< "dhes" token */
#define NOISE_TOKEN_DHSE        5   /**< "dhse" token */
#define NOISE_TOKEN_DHSS        6   /**< "dhss" token */
#define NOISE_TOKEN_REQ_IKEY    128 /**< Requires the initiator's static key */
#define NOISE_TOKEN_REQ_RKEY    129 /**< Requires the responder's static key */
#define NOISE_TOKEN_FALLBACK    254 /**< Continue with the fallback protocol */
#define NOISE_TOKEN_FLIP_DIR    255 /**< Flip the handshake direction */

#define noise_new(type) ((type *)noise_new_object(sizeof(type)))
void *noise_new_object(size_t size);
void noise_free(void *ptr, size_t size);

void noise_clean(void *data, size_t size);

int noise_is_equal(const void *s1, const void *s2, size_t size);
int noise_is_zero(const void *data, size_t size);

void noise_cmove_zero(uint8_t *data, size_t len, int condition);

void noise_rand_bytes(void *bytes, size_t size);

NoiseCipherState *noise_chachapoly_new(void);
NoiseCipherState *noise_aesgcm_new(void);

NoiseHashState *noise_blake2s_new(void);
NoiseHashState *noise_blake2b_new(void);
NoiseHashState *noise_sha256_new(void);
NoiseHashState *noise_sha512_new(void);

NoiseDHState *noise_curve25519_new(void);
NoiseDHState *noise_curve448_new(void);

const uint8_t *noise_lookup_pattern(int id);

#ifdef __cplusplus
};
#endif

#endif
