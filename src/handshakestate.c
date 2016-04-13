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
 * \file handshakestate.h
 * \brief HandshakeState interface
 */

/**
 * \file handshakestate.c
 * \brief HandshakeState implementation
 */

/**
 * \defgroup handshakestate HandshakeState API
 *
 * \code
 * NoiseHandshakeState *state;
 * noise_handshakestate_new_by_name
 *      (&state, "NoisePSK_XX_25519_ChaChaPoly_BLAKE2s", NOISE_ROLE_INITIATOR);
 * noise_handshakestate_set_prologue(state, prologue, sizeof(prologue));
 * noise_handshakestate_set_psk(state, psk, sizeof(psk));
 * \endcode
 */
/**@{*/

/**
 * \typedef NoiseHandshakeState
 * \brief Opaque object that represents a HandshakeState.
 */

/**
 * \brief Creates a new HandshakeState object.
 *
 * \param state Points to the variable where to store the pointer to
 * the new HandshakeState object.
 * \param symmetric The pre-allocated SymmetricState, which contains
 * the protocol identifier.
 * \param role The role for the new object, either NOISE_ROLE_INITIATOR or
 * NOISE_ROLE_RESPONDER.
 *
 * \return NOISE_ERROR_NONE on success, or some other error code on failure.
 * The \a symmetric object must be destroyed by this function if it fails.
 *
 * This is the internal implementation of noise_handshakestate_new_by_id()
 * and noise_handshakestate_new_by_name().
 */
static int noise_handshakestate_new
    (NoiseHandshakeState **state, NoiseSymmetricState *symmetric, int role)
{
    const uint8_t *pattern;
    NoiseDHState *dh;
    int requirements;
    uint8_t flags;
    uint8_t *ptr;
    size_t size;
    int err;

    /* Locate the information for the current handshake pattern */
    pattern = noise_pattern_lookup(symmetric->id.pattern_id);
    if (!pattern) {
        noise_symmetricstate_free(symmetric);
        return NOISE_ERROR_UNKNOWN_ID;
    }
    flags = pattern[0];
    if (role == NOISE_ROLE_RESPONDER) {
        /* Reverse the pattern flags so that the responder is "local" */
        flags = noise_pattern_reverse_flags(flags);
    }

    /* Create the DHState object */
    err = noise_dhstate_new_by_id(&dh, symmetric->id.dh_id);
    if (err != NOISE_ERROR_NONE) {
        noise_symmetricstate_free(symmetric);
        return err;
    }

    /* Determine how much memory we need for the HandshakeState,
       plus all of the private/public key values we'll need later. */
    size = sizeof(NoiseHandshakeState);
    if (flags & NOISE_PAT_FLAG_LOCAL_STATIC)
        size += dh->private_key_len + dh->public_key_len;
    if (flags & NOISE_PAT_FLAG_LOCAL_EMPEMERAL)
        size += dh->private_key_len + dh->public_key_len;
    if (flags & NOISE_PAT_FLAG_REMOTE_STATIC)
        size += dh->public_key_len;
    if (flags & NOISE_PAT_FLAG_REMOTE_EMPEMERAL)
        size += dh->public_key_len;

    /* Allocate the HandshakeState */
    *state = noise_new_object(size);
    if (!(*state)) {
        noise_symmetricstate_free(symmetric);
        noise_dhstate_free(dh);
        return NOISE_ERROR_NO_MEMORY;
    }

    /* What keys do we require to be able to start the protocol? */
    requirements = 0;
    if (flags & (NOISE_PAT_FLAG_LOCAL_STATIC | NOISE_PAT_FLAG_LOCAL_REQUIRED))
        requirements |= NOISE_REQ_LOCAL_REQUIRED;
    if (flags & NOISE_PAT_FLAG_REMOTE_REQUIRED)
        requirements |= NOISE_REQ_REMOTE_REQUIRED;
    if (symmetric->id.prefix_id == NOISE_PREFIX_PSK)
        requirements |= NOISE_REQ_PSK;

    /* Initialize the HandshakeState */
    (*state)->requirements = requirements;
    (*state)->tokens = pattern + 1;
    (*state)->role = role;
    (*state)->symmetric = symmetric;
    (*state)->dh = dh;

    /* Set the pointers for all of the key values we'll need later */
    #define alloc_key(name, type)   \
        ((*state)->name##_##type = ptr, ptr += dh->type##_len)
    ptr = ((uint8_t *)(*state)) + sizeof(NoiseHandshakeState);
    if (flags & NOISE_PAT_FLAG_LOCAL_STATIC) {
        alloc_key(local_static, private_key);
        alloc_key(local_static, public_key);
    }
    if (flags & NOISE_PAT_FLAG_LOCAL_EMPEMERAL) {
        alloc_key(local_ephemeral, private_key);
        alloc_key(local_ephemeral, public_key);
    }
    if (flags & NOISE_PAT_FLAG_REMOTE_STATIC) {
        alloc_key(remote_static, public_key);
    }
    if (flags & NOISE_PAT_FLAG_REMOTE_EMPEMERAL) {
        alloc_key(remote_ephemeral, public_key);
    }

    /* Ready to go */
    return NOISE_ERROR_NONE;
}

/**
 * \brief Creates a new HandshakeState object by protocol identifier.
 *
 * \param state Points to the variable where to store the pointer to
 * the new HandshakeState object.
 * \param protocol_id The protocol identifier as a set of algorithm identifiers.
 * \param role The role for the new object, either NOISE_ROLE_INITIATOR or
 * NOISE_ROLE_RESPONDER.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if either \a state or \a protocol_id
 * is NULL, or \a role is not one of NOISE_ROLE_INITIATOR or
 * NOISE_ROLE_RESPONDER.
 * \return NOISE_ERROR_UNKNOWN_ID if the \a protocol_id is unknown.
 * \return NOISE_ERROR_INVALID_LENGTH if the full name corresponding to
 * \a protocol_id is too long.
 * \return NOISE_ERROR_INVALID_LENGTH if the lengths of the hash output
 * or the cipher key are incompatible.
 * \return NOISE_ERROR_NO_MEMORY if there is insufficient memory to
 * allocate the new HandshakeState object.
 *
 * \sa noise_handshakestate_free(), noise_handshakestate_new_by_name()
 */
int noise_handshakestate_new_by_id
    (NoiseHandshakeState **state, const NoiseProtocolId *protocol_id, int role)
{
    NoiseSymmetricState *symmetric;
    int err;

    /* Validate the parameters */
    if (!state)
        return NOISE_ERROR_INVALID_PARAM;
    *state = 0;
    if (!protocol_id)
        return NOISE_ERROR_INVALID_PARAM;
    if (role != NOISE_ROLE_INITIATOR && role != NOISE_ROLE_RESPONDER)
        return NOISE_ERROR_INVALID_PARAM;

    /* Create the SymmetricState object */
    err = noise_symmetricstate_new_by_id(&symmetric, protocol_id);
    if (err != NOISE_ERROR_NONE) {
        return err;
    }

    /* Create the HandshakeState object */
    return noise_handshakestate_new(state, symmetric, role);
}

/**
 * \brief Creates a new HandshakeState object by protocol name.
 *
 * \param state Points to the variable where to store the pointer to
 * the new HandshakeState object.
 * \param protocol_name The name of the Noise protocol to use.  This string
 * must be NUL-terminated.
 * \param role The role for the new object, either NOISE_ROLE_INITIATOR or
 * NOISE_ROLE_RESPONDER.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if either \a state or \a protocol_name
 * is NULL, or \a role is not one of NOISE_ROLE_INITIATOR or
 * NOISE_ROLE_RESPONDER.
 * \return NOISE_ERROR_UNKNOWN_NAME if the \a protocol_name is unknown.
 * \return NOISE_ERROR_INVALID_LENGTH if the lengths of the hash output
 * or the cipher key are incompatible.
 * \return NOISE_ERROR_NO_MEMORY if there is insufficient memory to
 * allocate the new HandshakeState object.
 *
 * \sa noise_handshakestate_free(), noise_handshakestate_new_by_id()
 */
int noise_handshakestate_new_by_name
    (NoiseHandshakeState **state, const char *protocol_name, int role)
{
    NoiseSymmetricState *symmetric;
    int err;

    /* Validate the parameters */
    if (!state)
        return NOISE_ERROR_INVALID_PARAM;
    *state = 0;
    if (!protocol_name)
        return NOISE_ERROR_INVALID_PARAM;
    if (role != NOISE_ROLE_INITIATOR && role != NOISE_ROLE_RESPONDER)
        return NOISE_ERROR_INVALID_PARAM;

    /* Create the SymmetricState object */
    err = noise_symmetricstate_new_by_name(&symmetric, protocol_name);
    if (err != NOISE_ERROR_NONE) {
        return err;
    }

    /* Create the HandshakeState object */
    return noise_handshakestate_new(state, symmetric, role);
}

/**
 * \brief Frees a HandshakeState object after destroying all sensitive material.
 *
 * \param state The HandshakeState object to free.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state is NULL.
 *
 * \sa noise_handshakestate_new_by_id(), noise_handshakestate_new_by_name()
 */
int noise_handshakestate_free(NoiseHandshakeState *state)
{
    /* Bail out if no handshake state */
    if (!state)
        return NOISE_ERROR_INVALID_PARAM;

    /* Free the sub objects that are hanging off the handshakestate */
    if (state->symmetric)
        noise_symmetricstate_free(state->symmetric);
    if (state->dh)
        noise_dhstate_free(state->dh);

    /* Clean and free the memory for "state" */
    noise_free(state, state->size);
    return NOISE_ERROR_NONE;
}

/**
 * \brief Gets the role that a HandshakeState object is playing.
 *
 * \param state The HandshakeState object.
 *
 * \return Returns one of NOISE_ROLE_INITIATOR or NOISE_ROLE_RESPONDER
 * if \a state is non-NULL, or zero if \a state is NULL.
 */
int noise_handshakestate_get_role(const NoiseHandshakeState *state)
{
    return state ? state->role : 0;
}

/**
 * \brief Gets the protocol identifier associated with a HandshakeState object.
 *
 * \param state The HandshakeState object.
 * \param id Return buffer for the protocol identifier, which consists of
 * fields that identify the cipher algorithm, hash algorith, handshake
 * pattern, etc.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state or \a id is NULL.
 *
 * \sa noise_handshakestate_get_dh_id()
 */
int noise_handshakestate_get_protocol_id
    (const NoiseHandshakeState *state, NoiseProtocolId *id)
{
    /* Validate the parameters */
    if (!state || !id)
        return NOISE_ERROR_INVALID_PARAM;

    /* Copy the protocol identifiers to the caller's buffer */
    *id = state->symmetric->id;
    return NOISE_ERROR_NONE;
}

/**
 * \brief Gets the Diffie-Hellman algorithm identifier for a
 * HandshakeState object.
 *
 * \param state The HandshakeState object.
 *
 * \return The DH algorithm identifier, or NOISE_DH_NONE if \a state is NULL.
 *
 * This is a convenience function, which is more efficient than calling
 * noise_handshakestate_get_protocol_id() to obtain the DH identifier.
 *
 * \sa noise_handshakestate_get_protocol_id()
 */
int noise_handshakestate_get_dh_id(const NoiseHandshakeState *state)
{
    return state ? state->dh->dh_id : NOISE_DH_NONE;
}

/**
 * \brief Gets the length of the Diffie-Hellman private keys for a
 * HandshakeObject object.
 *
 * \param state The HandshakeState object.
 *
 * \return The size of the private key in bytes, or 0 if \a state is NULL.
 *
 * \sa noise_handshakestate_get_public_key_length(),
 * noise_handshakestate_get_dh_id()
 */
int noise_handshakestate_get_private_key_length
    (const NoiseHandshakeState *state)
{
    return state ? state->dh->private_key_len : 0;
}

/**
 * \brief Gets the length of the Diffie-Hellman public keys for a
 * HandshakeObject object.
 *
 * \param state The HandshakeState object.
 *
 * \return The size of the public key in bytes, or 0 if \a state is NULL.
 *
 * \sa noise_handshakestate_get_private_key_length(),
 * noise_handshakestate_get_dh_id()
 */
int noise_handshakestate_get_public_key_length
    (const NoiseHandshakeState *state)
{
    return state ? state->dh->public_key_len : 0;
}

/**
 * \brief Sets the pre shared key for a HandshakeState.
 *
 * \param state The HandshakeState object.
 * \param key Points to the pre shared key.
 * \param key_len The length of the \a key in bytes.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state or \a key is NULL.
 * \return NOISE_ERROR_NOT_APPLICABLE if the protocol name does not
 * begin with "NoisePSK".
 * \return NOISE_ERROR_INVALID_STATE if this function is called afer
 * the protocol has already started.
 *
 * If the prologue has not been set yet, then calling this function will
 * implicitly set the prologue to the empty sequence and it will no longer
 * be possible to specify an explicit prologue.
 *
 * \sa noise_handshakestate_start(), noise_handshakestate_set_prologue()
 */
int noise_handshakestate_set_pre_shared_key
    (NoiseHandshakeState *state, const uint8_t *key, size_t key_len)
{
    // TODO
    return NOISE_ERROR_NONE;
}

/**
 * \brief Sets the prologue for a HandshakeState.
 *
 * \param state The HandshakeState object.
 * \param prologue Points to the prologue value.
 * \param prologue_len The length of the \a prologue value in bytes.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state or \a prologue is NULL.
 * \return NOISE_ERROR_INVALID_STATE if this function is called afer
 * noise_handshakestate_set_pre_shared_key() or after the protocol has
 * already started.
 *
 * This function must be called immediately after
 * noise_handshakestate_new_by_id() or noise_handshakestate_new_by_name()
 * if there is a prologue for the session.  If the function is not called,
 * then the prologue will be assumed to be empty when the protocol starts.
 *
 * \sa noise_handshakestate_start(), noise_handshakestate_set_pre_shared_key()
 */
int noise_handshakestate_set_prologue
    (NoiseHandshakeState *state, const void *prologue, size_t prologue_len)
{
    // TODO
    return NOISE_ERROR_NONE;
}

/**
 * \brief Determine if a HandshakeState still needs to be configured
 * with a local keypair.
 *
 * \param state The HandshakeState object.
 *
 * \return Returns 1 if the \a state has not yet been configured with a
 * local keypair, or 0 if the keypair has been provided or is not required
 * at all.  Also returns zero if \a state is NULL.
 *
 * \sa noise_handshakestate_has_local_keypair(),
 * noise_handshakestate_set_local_keypair()
 */
int noise_handshakestate_needs_local_keypair(const NoiseHandshakeState *state)
{
    // TODO
    return 0;
}

/**
 * \brief Determine if a HandshakeState has been configured with a
 * local keypair.
 *
 * \param state The HandshakeState object.
 *
 * \return Returns 1 if the \a state has already been configured with a
 * local keypair, or 0 if the keypair is yet to be provided.  Also returns
 * zero if \a state is NULL.
 *
 * \sa noise_handshakestate_needs_local_keypair(),
 * noise_handshakestate_set_local_keypair()
 */
int noise_handshakestate_has_local_keypair(const NoiseHandshakeState *state)
{
    // TODO
    return 0;
}

/**
 * \brief Sets the local keypair for a HandshakeState.
 *
 * \param state The HandshakeState object.
 * \param private_key Points to the private key for the local keypair.
 * \param private_key_len The length of the private key in bytes.
 * \param public_key Points to the public key for the local keypair.
 * \param public_key_len The length of the public key in bytes.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if one of \a state, \a private_key,
 * or \a public_key is NULL.
 * \return NOISE_ERROR_INVALID_LENGTH if \a private_key_len or
 * \a public_key_len is incorrect for the Diffie-Hellman algorithm in
 * the protocol name.
 * \return NOISE_ERROR_NOT_APPLICABLE if the protocol name does not
 * require a local keypair.
 * \return NOISE_ERROR_INVALID_STATE if the protocol has already started.
 *
 * If noise_handshakestate_needs_local_keypair() returns a non-zero value,
 * then this function must be called before noise_handshakestate_start()
 * to specify the local keypair for the session.
 *
 * \sa noise_handshakestate_needs_local_keypair()
 */
int noise_handshakestate_set_local_keypair
    (NoiseHandshakeState *state,
     const uint8_t *private_key, size_t private_key_len,
     const uint8_t *public_key, size_t public_key_len)
{
    // TODO
    return NOISE_ERROR_NONE;
}

/**
 * \brief Determine if a HandshakeState still needs to be configured
 * with a remote public key before the protocol can start.
 *
 * \param state The HandshakeState object.
 *
 * \return Returns 1 if the \a state has not yet been configured with a
 * required remote public key, or 0 if the key has been provided or is
 * not required at all.  Also returns zero if \a state is NULL.
 *
 * This function indicates that a remote public key must be supplied
 * before the protocol starts.  If it is possible for the remote public key
 * to be provided by the remote party during the session, then
 * noise_handshakestate_get_remote_public_key() can be called at the
 * end of the handshake to get the remotely-provided value.
 *
 * \sa noise_handshakestate_has_remote_public_key(),
 * noise_handshakestate_set_remote_public_key()
 */
int noise_handshakestate_needs_remote_public_key(const NoiseHandshakeState *state)
{
    // TODO
    return 0;
}

/**
 * \brief Determine if a HandshakeState has a remote public key.
 *
 * \param state The HandshakeState object.
 *
 * \return Returns 1 if the \a state has a remote public key, or 0 if the
 * key is yet to be seen.  Also returns zero if \a state is NULL.
 *
 * A remote public key may either be provided ahead of time by
 * noise_handshakestate_set_remote_public_key(), or it may be provided
 * by the remote party during the handshake.
 *
 * \sa noise_handshakestate_needs_remote_public_key(),
 * noise_handshakestate_set_remote_public_key()
 */
int noise_handshakestate_has_remote_public_key(const NoiseHandshakeState *state)
{
    // TODO
    return 0;
}

/**
 * \brief Gets the remote public key for a HandshakeState.
 *
 * \param state The HandshakeState object.
 * \param public_key Points to the buffer to fill with the public key.
 * \param public_key_len The length of the \a public_key buffer in bytes.
 *
 * \return NOISE_ERROR on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state or \a public_key is NULL.
 * \return NOISE_ERROR_INVALID_LENGTH if \a public_key_len is incorrect
 * for the Diffie-Hellman algorithm in the protocol name.
 * \return NOISE_ERROR_INVALID_STATE if the remote public key is not available.
 *
 * The remote public key may be provided by the local party with a call to
 * noise_handshakestate_set_remote_public_key(), or it may be provided by
 * the remote party itself during the handshake.
 *
 * \sa noise_handshakestate_set_remote_public_key(),
 * noise_handshakestate_has_remote_public_key()
 */
int noise_handshakestate_get_remote_public_key
    (NoiseHandshakeState *state, uint8_t *public_key, size_t public_key_len)
{
    // TODO
    return NOISE_ERROR_NONE;
}

/**
 * \brief Sets the remote public key for a HandshakeState.
 *
 * \param state The HandshakeState object.
 * \param public_key Points to the remote public key.
 * \param public_key_len The length of the \a public_key in bytes.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state or \a public_key is NULL.
 * \return NOISE_ERROR_INVALID_LENGTH if \a public_key_len is incorrect
 * for the Diffie-Hellman algorithm in the protocol name.
 * \return NOISE_ERROR_NOT_APPLICABLE if the protocol does not need a remote
 * public key, or the remote public key is expected to be provided by the
 * remote party during the handshake.
 * \return NOISE_ERROR_INVALID_STATE if the protocol has already started.
 *
 * \sa noise_handshakestate_get_remote_public_key(),
 * noise_handshakestate_needs_remote_public_key()
 */
int noise_handshakestate_set_remote_public_key
    (NoiseHandshakeState *state,
     const uint8_t *public_key, size_t public_key_len)
{
    // TODO
    return NOISE_ERROR_NONE;
}

/**
 * \brief Starts the handshake on a HandshakeState object.
 *
 * \param state The HandshakeState object.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state is NULL.
 * \return NOISE_ERROR_REMOTE_KEY_REQUIRED if a remote public key is required
 * to start the protocol but one has not been provided yet.
 * \return NOISE_ERROR_LOCAL_KEY_REQUIRED if a local keypair is required
 * to start the protocol but one has not been provided yet.
 * \return NOISE_ERROR_PSK_REQUIRED if a pre shared key is required
 * to start the protocol but one has not been provided yet.
 * \return NOISE_ERROR_INVALID_STATE if the protocol handshake
 * was already started.
 * \return NOISE_ERROR_NOT_APPLICABLE if an attempt was made to
 * start a "XXfallback" handshake pattern without first calling
 * noise_handshakestate_fallback() on a previous "IK" handshake.
 *
 * This function is called after all of the handshake parameters have been
 * provided to the HandshakeState object.  This function should be followed
 * by calls to noise_handshake_write_message() or noise_handshake_read_message()
 * to process the messages in the handshake.
 *
 * \sa noise_handshake_write_message(), noise_handshake_read_message(),
 * noise_handshakestate_fallback()
 */
int noise_handshakestate_start(NoiseHandshakeState *state)
{
    // TODO
    return NOISE_ERROR_NONE;
}

/**
 * \brief Falls back to the "XXfallback" handshake pattern.
 *
 * \param state The HandshakeState object.
 *
 * \return NOISE_ERROR_NONE on error.
 * \return NOISE_ERROR_INVALID_PARAM if \a state is NULL.
 * \return NOISE_ERROR_INVALID_STATE if the previous protocol has not
 * been started or has not reached the fallback position yet.
 * \return NOISE_ERROR_NOT_APPLICABLE if the handshake pattern in the
 * original protocol name was not "IK".
 *
 * This function is used to help implement the "Noise Pipes" protocol.
 * It resets a HandshakeState object with the handshake pattern "IK",
 * converting it into an object with the handshake pattern "XXfallback".
 * Information from the previous session such as the local keypair and
 * the initiator's ephemeral key are passed to the new session.
 *
 * This function also reverses the roles of the communicating parties.
 * The previous initiator becomes the responder and the previous responder
 * becomes the initiator.
 *
 * Once the fallback has been initiated, the application must call
 * noise_handshakestate_set_prologue() and
 * noise_handshakestate_set_pre_shared_key() again to re-establish the
 * early handshake details.  The application can then call
 * noise_handshakestate_start() to restart the handshake from where
 * it left off before the fallback.
 *
 * \sa noise_handshakestate_start(), noise_handshakestate_get_role()
 */
int noise_handshakestate_fallback(NoiseHandshakeState *state)
{
    // TODO
    return NOISE_ERROR_NONE;
}

/**
 * \brief Gets the next action the application should perform for
 * the handshake phase of the protocol.
 *
 * \param state The HandshakeState object.
 *
 * \return NOISE_ACTION_NONE if no action needs to be taken by the
 * application because the protocol hasn't started yet.
 * \return NOISE_ACTION_WRITE_MESSAGE if the application is expected
 * to write a new message payload for the next outgoing handshake message
 * using noise_handshakestate_write_message().
 * \return NOISE_ACTION_READ_MESSAGE if the application is expected
 * wait for an incoming handshake message from the remote party and then
 * pass the message to noise_handshakestate_read_message() to
 * extract the payload.
 * \return NOISE_ACTION_SPLIT if the handshake has finished successfully
 * and the application should call noise_handshakestate_split() to
 * obtain the CipherState objects for the data phase of the protocol.
 * \return NOISE_ACTION_FAILED if the handshake has failed with a MAC
 * error.  The application should destroy the HandshakeState by calling
 * noise_handshakestate_free() and terminate the connection.  If the
 * application is using Noise Pipes, then it may be able to continue by
 * calling noise_handshakestate_fallback() depending upon where in the
 * protocol the failure occurred.
 *
 * \sa noise_handshakestate_write_message(),
 * noise_handshakestate_read_message(), noise_handshakestate_split(),
 * noise_handshakestate_fallback()
 */
int noise_handshakestate_get_action(const NoiseHandshakeState *state)
{
    // TODO
    return 0;
}

/**
 * \brief Writes a message payload using a HandshakeState.
 *
 * \param state The HandshakeState object.
 * \param payload Points to the message payload to be sent, which can
 * be NULL if \a payload_size is zero.
 * \param payload_size The size of the message payload in bytes.
 * \param message Points to the message buffer to be populated with
 * handshake details and the message payload.
 * \param message_size On entry, set to the number of bytes of memory
 * that are available in \a message.  On exit, set to the number of
 * bytes that were actually written to \a message.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state, \a message, or
 * \a message_size is NULL.
 * \return NOISE_ERROR_INVALID_PARAM if \a payload is NULL and \a payload_size
 * is not zero.
 * \return NOISE_ERROR_INVALID_STATE if noise_handshakestate_get_action() is 
 * not NOISE_ACTION_WRITE_MESSAGE.
 * \return NOISE_ERROR_INVALID_LENGTH if the \a message_size is too small
 * to contain all of the bytes that need to be written to \a message.
 *
 * \sa noise_handshakestate_read_message(), noise_handshakestate_get_action()
 */
int noise_handshakestate_write_message
    (NoiseHandshakeState *state, const void *payload, size_t payload_size,
     uint8_t *message, size_t *message_size)
{
    // TODO
    return NOISE_ERROR_NONE;
}

/**
 * \brief Reads a message payload using a HandshakeState.
 *
 * \param state The HandshakeState object.
 * \param message Points to the incoming handshake message to be unpacked.
 * \param message_size The length of the incoming handshake message in bytes.
 * \param payload Points to the buffer to fill with the message payload.
 * This can be NULL if the application does not need the message payload.
 * \param payload_size On entry, set to the number of bytes of memory
 * that are available in \a payload.  On exit, set to the number of bytes
 * that were actually written to \a payload.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state, \a message, or
 * \a payload_size is NULL.
 * \return NOISE_ERROR_INVALID_PARAM if \a payload is NULL and \a payload_size
 * is not zero.
 * \return NOISE_ERROR_INVALID_STATE if noise_handshakestate_get_action() is 
 * not NOISE_ACTION_READ_MESSAGE.
 * \return NOISE_ERROR_INVALID_LENGTH if the \a payload_size is too small
 * to contain all of the bytes that need to be written to \a payload.
 * \return NOISE_ERROR_MAC_FAILURE if the \a message failed to authenticate,
 * which terminates the handshake.
 *
 * If \a payload is NULL, then the message payload will be authenticated
 * but then discarded.  If the application was expecting a zero-length
 * payload, then \a payload should be non-NULL and \a payload_size
 * should be zero.
 *
 * \sa noise_handshakestate_write_message(), noise_handshakestate_get_action()
 */
int noise_handshakestate_read_message
    (NoiseHandshakeState *state, const uint8_t *message, size_t message_size,
     void *payload, size_t *payload_size)
{
    // TODO
    return NOISE_ERROR_NONE;
}

/**
 * \brief Splits the transport encryption CipherState objects out of
 * this HandshakeState object.
 *
 * \param state The HandshakeState object.
 * \param c1 Points to the variable where to place the pointer to the
 * first CipherState object.  Must not be NULL.
 * \param c2 Points to the variable where to place the pointer to the
 * second CipherState object.  This can be NULL if the application is
 * using a one-way handshake pattern.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if one of \a state or \a c1 is NULL.
 * \return NOISE_ERROR_INVALID_STATE if the \a state has already been split
 * or the handshake protocol has not completed successfully yet.
 * \return NOISE_ERROR_NO_MEMORY if there is insufficient memory to create
 * the new CipherState objects.
 *
 * Once a HandshakeState has been split, it is effectively finished and
 * cannot be used for future handshake operations.  If those operations are
 * invoked, the relevant functions will return NOISE_ERROR_INVALID_STATE.
 *
 * The \a c1 object should be used to protect messages from the initiator to
 * the responder, and the \a c2 object should be used to protect messages
 * from the responder to the initiator.
 *
 * If the handshake pattern is one-way, then the application should call
 * noise_cipherstate_free() on \a c2 as it will not be needed.  Alternatively,
 * the application can pass NULL to noise_handshakestate_split() as the
 * \a c2 argument and the second CipherState will not be created at all.
 */
int noise_handshakestate_split
    (NoiseHandshakeState *state, NoiseCipherState **c1, NoiseCipherState **c2)
{
    // TODO
    return NOISE_ERROR_NONE;
}

/**@}*/
