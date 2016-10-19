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

#include <noise/protocol.h>
#if defined(__WIN32__) || defined(WIN32)
#include <malloc.h>
#else
#include <alloca.h>
#endif

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
 * \brief Standard length for pre-shared keys.
 */
#define NOISE_PSK_LEN 32

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

/* States for public key algorithms, either DHState or SignState */
#define NOISE_KEY_TYPE_NO_KEY   0   /**< No key set yet */
#define NOISE_KEY_TYPE_KEYPAIR  1   /**< Set to a keypair */
#define NOISE_KEY_TYPE_PUBLIC   2   /**< Set to a public key only */

/**
 * \brief Internal structure of the NoiseDHState type.
 */
struct NoiseDHState_s
{
    /** \brief Total size of the structure including subclass state */
    size_t size;

    /** \brief Algorithm identifier for the Diffie-Hellman operation */
    short dh_id;

    /** \brief The role; either initiator or responder or zero */
    short role;

    /** \brief The type of key stored within this DHState object */
    uint8_t key_type;

    /** \brief Non-zero if this algorithm only supports ephemeral keys */
    uint8_t ephemeral_only : 1;

    /** \brief Non-zero if null public keys are allowed with this algorithm */
    uint8_t nulls_allowed : 1;

    /** \brief Length of the private key for this algorithm in bytes */
    uint16_t private_key_len;

    /** \brief Length of the public key for this algorithm in bytes */
    uint16_t public_key_len;

    /** \brief Length of the shared key for this algorithm in bytes */
    uint16_t shared_key_len;

    /** \brief Points to the private key in the subclass state */
    uint8_t *private_key;

    /** \brief Points to the public key in the subclass state */
    uint8_t *public_key;

    /**
     * \brief Generates a new key pair for this Diffie-Hellman algorithm.
     *
     * \param state Points to the DHState.
     * \param other Points to the other DHState for obtaining dependent
     * parameters.  May be NULL.
     *
     * \return NOISE_ERROR_NONE on success or an error code otherwise.
     */
    int (*generate_keypair)(NoiseDHState *state, const NoiseDHState *other);

    /**
     * \brief Sets a keypair.
     *
     * \param state Points to the DHState.
     * \param private_key Points to the private key for the keypair.
     * \param public_key Points to the public key for the keypair.
     *
     * \return NOISE_ERROR_NONE if the keypair is valid.
     * \return NOISE_ERROR_INVALID_PRIVATE_KEY if there is something wrong
     * with the private key.
     * \return NOISE_ERROR_INVALID_PUBLIC_KEY if there is something wrong
     * with the public key.
     */
    int (*set_keypair)
        (NoiseDHState *state, const uint8_t *private_key,
         const uint8_t *public_key);

    /**
     * \brief Sets a keypair using only the private key.
     *
     * \param state Points to the DHState.
     * \param private_key Points to the private key for the keypair.
     *
     * \return NOISE_ERROR_NONE if the keypair is valid.
     * \return NOISE_ERROR_INVALID_PRIVATE_KEY if there is something wrong
     * with the private key.
     */
    int (*set_keypair_private)
        (NoiseDHState *state, const uint8_t *private_key);

    /**
     * \brief Validates a public key.
     *
     * \param state Points to the DHState.
     * \param public_key Points to the public key.
     *
     * \return NOISE_ERROR_NONE if the keypair is valid.
     * \return NOISE_ERROR_INVALID_PUBLIC_KEY if there is something wrong
     * with the public key.
     */
    int (*validate_public_key)
        (const NoiseDHState *state, const uint8_t *public_key);

    /**
     * \brief Copies another key into this object.
     *
     * \param state Points to the DHState to copy into.
     * \param from Points to the DHState to copy from.
     * \param other Points to another DHState for obtaining dependent
     * parameters.  May be NULL.
     */
    int (*copy)(NoiseDHState *state, const NoiseDHState *from,
                const NoiseDHState *other);

    /**
     * \brief Performs a Diffie-Hellman calculation.
     *
     * \param private_key_state Points to the DHState for the private key.
     * \param public_key_state Points to the DHState for the public key.
     * \param shared_key Points to the shared key on exit.
     *
     * \return NOISE_ERROR_NONE on success.
     * \return NOISE_ERROR_INVALID_PRIVATE_KEY if the private key is
     * invalid for the algorithm.
     * \return NOISE_ERROR_INVALID_PUBLIC_KEY if the public key is
     * invalid for the algorithm.
     *
     * This function must always operate in the same amount of time, even
     * if the private or public key is invalid.
     */
    int (*calculate)
        (const NoiseDHState *private_key_state,
         const NoiseDHState *public_key_state,
         uint8_t *shared_key);

    /**
     * \brief Changes the role for this object.
     *
     * \param state Points to the DHState.
     *
     * This pointer can be NULL if the back end does not need any special
     * logic to change the role.
     */
    void (*change_role)(NoiseDHState *state);

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
 * \brief Internal structure of the NoiseSignState type.
 */
struct NoiseSignState_s
{
    /** \brief Total size of the structure including subclass state */
    size_t size;

    /** \brief Algorithm identifier for the digital signature operation */
    int sign_id;

    /** \brief The type of key stored within this SignState object */
    uint16_t key_type;

    /** \brief Length of the private key for this algorithm in bytes */
    uint16_t private_key_len;

    /** \brief Length of the public key for this algorithm in bytes */
    uint16_t public_key_len;

    /** \brief Length of the signature for this algorithm in bytes */
    uint16_t signature_len;

    /** \brief Points to the private key in the subclass state */
    uint8_t *private_key;

    /** \brief Points to the public key in the subclass state */
    uint8_t *public_key;

    /**
     * \brief Generates a new key pair for this digital signature algorithm.
     *
     * \param state Points to the SignState.
     */
    void (*generate_keypair)(NoiseSignState *state);

    /**
     * \brief Validates a keypair.
     *
     * \param state Points to the SignState.
     * \param private_key Points to the private key for the keypair.
     * \param public_key Points to the public key for the keypair.
     *
     * \return NOISE_ERROR_NONE if the keypair is valid.
     * \return NOISE_ERROR_INVALID_PRIVATE_KEY if there is something wrong
     * with the private key.
     * \return NOISE_ERROR_INVALID_PUBLIC_KEY if there is something wrong
     * with the public key.
     */
    int (*validate_keypair)
        (const NoiseSignState *state, const uint8_t *private_key,
         const uint8_t *public_key);

    /**
     * \brief Derives a public key from a private key.
     *
     * \param state Points to the SignState.
     * \param private_key Points to the private key for the keypair.
     * \param public_key Points to the public key for the keypair.
     *
     * \return NOISE_ERROR_NONE if the keypair is valid.
     * \return NOISE_ERROR_INVALID_PRIVATE_KEY if there is something wrong
     * with the private key.
     * \return NOISE_ERROR_INVALID_PUBLIC_KEY if there is something wrong
     * with the derived public key.
     */
    int (*derive_public_key)
        (const NoiseSignState *state, const uint8_t *private_key,
         uint8_t *public_key);

    /**
     * \brief Validates a public key.
     *
     * \param state Points to the SignState.
     * \param public_key Points to the public key.
     *
     * \return NOISE_ERROR_NONE if the keypair is valid.
     * \return NOISE_ERROR_INVALID_PUBLIC_KEY if there is something wrong
     * with the public key.
     */
    int (*validate_public_key)
        (const NoiseSignState *state, const uint8_t *public_key);

    /**
     * \brief Creates a signature.
     *
     * \param state Points to the SignState.
     * \param message Points to the message to be signed.
     * \param message_len The length of the \a message to be signed.
     * \param signature Points to the signature on exit.
     *
     * \return NOISE_ERROR_NONE on success.
     * \return NOISE_ERROR_INVALID_PRIVATE_KEY if the private key is
     * invalid for the algorithm.
     * \return NOISE_ERROR_INVALID_PUBLIC_KEY if the public key is
     * invalid for the algorithm.
     *
     * This function must always operate in the same amount of time, even
     * if the private or public key is invalid.
     */
    int (*sign)
        (const NoiseSignState *state, const uint8_t *message,
         size_t message_len, uint8_t *signature);

    /**
     * \brief Verifies a digital signature on a message.
     *
     * \param state Points to the SignState.
     * \param message Points to the message whose signature should
     * be verified, which is usually a short hash value.
     * \param message_len The length of the \a message to be verified.
     * \param signature Points to the signature to be verified.
     *
     * \return NOISE_ERROR_NONE on success.
     * \return NOISE_ERROR_INVALID_PUBLIC_KEY if \a state does not
     * contain a public key or the public key is invalid.
     * \return NOISE_ERROR_INVALID_SIGNATURE if the \a signature is not
     * valid for the \a message using this public key.
     */
    int (*verify)
        (const NoiseSignState *state, const uint8_t *message,
         size_t message_len, const uint8_t *signature);

    /**
     * \brief Destroys this SignState prior to the memory being freed.
     *
     * \param state Points to the SignState.
     *
     * This function is called just before the memory for the SignState
     * is deallocated.  It gives the back end an opportunity to clean up
     * linked objects.
     *
     * This pointer can be NULL if the back end does not need any special
     * clean up logic.
     */
    void (*destroy)(NoiseSignState *state);
};

/**
 * \brief Internal structure of the NoiseSymmetricState type.
 */
struct NoiseSymmetricState_s
{
    /** \brief Total size of the structure */
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

/**
 * \brief Internal structure of the NoiseHandshakeState type.
 */
struct NoiseHandshakeState_s
{
    /** \brief Total size of the structure, including DH key storage */
    size_t size;

    /** \brief The role of this object, initiator or responder */
    int role;

    /** \brief Requirements that are yet to be satisfied */
    int requirements;

    /** \brief Next action to be taken by the application */
    int action;

    /** \brief Points to the next message pattern tokens to be processed */
    const uint8_t *tokens;

    /** \brief Points to the SymmetricState object for this HandshakeState */
    NoiseSymmetricState *symmetric;

    /** \brief Points to the DHState object for local static key */
    NoiseDHState *dh_local_static;

    /** \brief Points to the DHState object for local ephemeral key */
    NoiseDHState *dh_local_ephemeral;

    /** \brief Points to the DHState object for local hybrid forward secrecy key */
    NoiseDHState *dh_local_hybrid;

    /** \brief Points to the DHState object for remote static key */
    NoiseDHState *dh_remote_static;

    /** \brief Points to the DHState object for remote ephemeral key */
    NoiseDHState *dh_remote_ephemeral;

    /** \brief Points to the DHState object for remote hybrid forward secrecy key */
    NoiseDHState *dh_remote_hybrid;

    /** \brief Points to the object for the fixed ephemeral test key */
    NoiseDHState *dh_fixed_ephemeral;

    /** \brief Points to the object for the fixed hybrid forward secrecy test key */
    NoiseDHState *dh_fixed_hybrid;

    /** \brief Pre-shared key value */
    uint8_t pre_shared_key[NOISE_PSK_LEN];

    /** \brief Length of the pre-shared key value: zero or NOISE_PSK_LEN only */
    size_t pre_shared_key_len;

    /** \brief Points to the prologue value */
    uint8_t *prologue;

    /** \brief Length of the prologue value in bytes */
    size_t prologue_len;
};

/* Handshake message pattern tokens (must be single-byte values) */
#define NOISE_TOKEN_END         0   /**< End of pattern, start data session */
#define NOISE_TOKEN_S           1   /**< "s" token */
#define NOISE_TOKEN_E           2   /**< "e" token */
#define NOISE_TOKEN_EE          3   /**< "ee" token */
#define NOISE_TOKEN_ES          4   /**< "es" token */
#define NOISE_TOKEN_SE          5   /**< "se" token */
#define NOISE_TOKEN_SS          6   /**< "ss" token */
#define NOISE_TOKEN_F           7   /**< "f" token (hybrid forward secrecy) */
#define NOISE_TOKEN_FF          8   /**< "ff" token (hybrid forward secrecy) */
#define NOISE_TOKEN_FLIP_DIR    255 /**< Flip the handshake direction */

/** Pattern requires a local static keypair */
#define NOISE_PAT_FLAG_LOCAL_STATIC     (1 << 0)
/** Pattern requires a local ephemeral keypair */
#define NOISE_PAT_FLAG_LOCAL_EPHEMERAL  (1 << 1)
/** Pattern requires that the local public key be provided
    ahead of time to start the protocol.  That is, it is not
    sent as part of the protocol but is assumed to already be
    known to the other party. */
#define NOISE_PAT_FLAG_LOCAL_REQUIRED   (1 << 2)
/** Pattern requires that the local ephemeral key be provided
    ahead of time to start the protocol (for XXfallback) */
#define NOISE_PAT_FLAG_LOCAL_EPHEM_REQ  (1 << 3)
/** Pattern requires a local hybrid keypair */
#define NOISE_PAT_FLAG_LOCAL_HYBRID     (1 << 4)
/** Pattern requires that the local hybrid key be provided
    ahead of time to start the protocol (for XXfallback) */
#define NOISE_PAT_FLAG_LOCAL_HYBRID_REQ (1 << 5)

/** Pattern requires a remote static public key */
#define NOISE_PAT_FLAG_REMOTE_STATIC    (1 << 8)
/** Pattern requires a remote ephemeral public key */
#define NOISE_PAT_FLAG_REMOTE_EPHEMERAL (1 << 9)
/** Pattern requires that the remote public key be provided
    ahead of time to start the protocol.  That is, it is not
    sent as part of the protocol but is assumed to already be
    known to the other party. */
#define NOISE_PAT_FLAG_REMOTE_REQUIRED  (1 << 10)
/** Pattern requires that the remote ephemeral key be provided
    ahead of time to start the protocol (for XXfallback) */
#define NOISE_PAT_FLAG_REMOTE_EPHEM_REQ (1 << 11) 
/** Pattern requires a remote hybrid public key */
#define NOISE_PAT_FLAG_REMOTE_HYBRID    (1 << 12)
/** Pattern requires that the remote hybrid key be provided
    ahead of time to start the protocol (for XXfallback) */
#define NOISE_PAT_FLAG_REMOTE_HYBRID_REQ (1 << 13)

/** Local static keypair is required for the handshake */
#define NOISE_REQ_LOCAL_REQUIRED        (1 << 0)
/** Remote public key is required for the handshake */
#define NOISE_REQ_REMOTE_REQUIRED       (1 << 1)
/** Pre-shared key has not been provided yet */
#define NOISE_REQ_PSK                   (1 << 2)
/** Emphemeral key for fallback pre-message has been provided */
#define NOISE_REQ_FALLBACK_PREMSG       (1 << 3)
/** Local public key is part of the pre-message */
#define NOISE_REQ_LOCAL_PREMSG          (1 << 4)
/** Remote public key is part of the pre-message */
#define NOISE_REQ_REMOTE_PREMSG         (1 << 5)
/** Fallback is possible from this pattern (two-way, ends in "K") */
#define NOISE_REQ_FALLBACK_POSSIBLE     (1 << 6)

void noise_rand_bytes(void *bytes, size_t size);

/** @cond */

NoiseCipherState *noise_chachapoly_new(void);
NoiseCipherState *noise_aesgcm_new(void);

NoiseHashState *noise_blake2s_new(void);
NoiseHashState *noise_blake2b_new(void);
NoiseHashState *noise_sha256_new(void);
NoiseHashState *noise_sha512_new(void);

NoiseDHState *noise_curve25519_new(void);
NoiseDHState *noise_curve448_new(void);
NoiseDHState *noise_newhope_new(void);

NoiseSignState *noise_ed25519_new(void);

typedef uint16_t NoisePatternFlags_t;

/** @endcond */

const uint8_t *noise_pattern_lookup(int id);
NoisePatternFlags_t noise_pattern_reverse_flags(NoisePatternFlags_t flags);

#ifdef __cplusplus
};
#endif

#endif
