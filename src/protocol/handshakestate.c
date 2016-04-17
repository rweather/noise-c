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
    int requirements;
    int dh_id;
    uint8_t flags;
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

    /* Create the HandshakeState object */
    *state = noise_new(NoiseHandshakeState);
    if (!(*state)) {
        noise_symmetricstate_free(symmetric);
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
    requirements |= NOISE_REQ_PROLOGUE;

    /* Initialize the HandshakeState */
    (*state)->requirements = requirements;
    (*state)->action = NOISE_ACTION_NONE;
    (*state)->tokens = pattern + 1;
    (*state)->role = role;
    (*state)->symmetric = symmetric;

    /* Create DHState objects for all of the keys we will need later */
    err = NOISE_ERROR_NONE;
    dh_id = symmetric->id.dh_id;
    if ((flags & NOISE_PAT_FLAG_LOCAL_STATIC) != 0)
        err = noise_dhstate_new_by_id(&((*state)->dh_local_static), dh_id);
    if ((flags & NOISE_PAT_FLAG_LOCAL_EMPEMERAL) != 0 && err == NOISE_ERROR_NONE)
        err = noise_dhstate_new_by_id(&((*state)->dh_local_ephemeral), dh_id);
    if ((flags & NOISE_PAT_FLAG_REMOTE_STATIC) != 0 && err == NOISE_ERROR_NONE)
        err = noise_dhstate_new_by_id(&((*state)->dh_remote_static), dh_id);
    if ((flags & NOISE_PAT_FLAG_REMOTE_EMPEMERAL) != 0 && err == NOISE_ERROR_NONE)
        err = noise_dhstate_new_by_id(&((*state)->dh_remote_ephemeral), dh_id);

    /* Bail out if we had an error trying to create the DHState objects */
    if (err != NOISE_ERROR_NONE) {
        noise_handshakestate_free(*state);
        return err;
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
    if (err != NOISE_ERROR_NONE)
        return err;

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
    if (err != NOISE_ERROR_NONE)
        return err;

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
    if (state->dh_local_static)
        noise_dhstate_free(state->dh_local_static);
    if (state->dh_local_ephemeral)
        noise_dhstate_free(state->dh_local_ephemeral);
    if (state->dh_remote_static)
        noise_dhstate_free(state->dh_remote_static);
    if (state->dh_remote_ephemeral)
        noise_dhstate_free(state->dh_remote_ephemeral);

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
 * \brief Gets the DHStatic object that contains the local static keypair.
 *
 * \param state The HandshakeState object.
 *
 * \return Returns a pointer to the DHState object for the local static
 * keypair, or NULL if the handshake does not require a local static keypair.
 *
 * The application uses the returned object to set the static keypair for
 * the local end of the handshake if one is required.
 *
 * \sa noise_handshakestate_get_remote_public_key_dh()
 */
NoiseDHState *noise_handshakestate_get_local_keypair_dh
    (const NoiseHandshakeState *state)
{
    return state ? state->dh_local_static : 0;
}

/**
 * \brief Gets the DHStatic object that contains the remote static public key.
 *
 * \param state The HandshakeState object.
 *
 * \return Returns a pointer to the DHState object for the remote static
 * public key, or NULL if the handshake does not require a remote public key.
 *
 * The application uses the returned object to set the public key for
 * the remote end of the handshake if the key must be provided prior to
 * the handshake.  The returned object can also be used to obtain the public
 * key value that was transmitted by the remote party during the handshake.
 *
 * \sa noise_handshakestate_get_local_keypair_dh()
 */
NoiseDHState *noise_handshakestate_get_remote_public_key_dh
    (const NoiseHandshakeState *state)
{
    return state ? state->dh_remote_static : 0;
}

/** @cond */

/* Not part of the public API.  Intended for fixed vector tests only. */

NoiseDHState *noise_handshakestate_get_local_ephemeral_dh_
    (const NoiseHandshakeState *state)
{
    return state ? state->dh_local_ephemeral : 0;
}

NoiseDHState *noise_handshakestate_get_remote_ephemeral_dh_
    (const NoiseHandshakeState *state)
{
    return state ? state->dh_remote_ephemeral : 0;
}

/** @endcond */

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
 * the protocol has already started, or the pre shared key was already set.
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
    uint8_t temp[NOISE_MAX_HASHLEN];
    NoiseHashState *hash;

    /* Validate the parameters and state */
    if (!state || !key)
        return NOISE_ERROR_INVALID_PARAM;
    if (state->symmetric->id.prefix_id != NOISE_PREFIX_PSK)
        return NOISE_ERROR_NOT_APPLICABLE;
    if (state->action != NOISE_ACTION_NONE)
        return NOISE_ERROR_INVALID_STATE;
    if (!(state->requirements & NOISE_REQ_PSK))
        return NOISE_ERROR_INVALID_STATE;

    /* If we haven't hashed the prologue yet, hash an empty one now */
    if (state->requirements & NOISE_REQ_PROLOGUE)
        noise_handshakestate_set_prologue(state, "", 0);

    /* Mix the pre shared key into the chaining key and handshake hash */
    hash = state->symmetric->hash;
    noise_hashstate_hkdf
        (hash, state->symmetric->ck, hash->hash_len, key, key_len,
         state->symmetric->ck, hash->hash_len, temp, hash->hash_len);
    noise_symmetricstate_mix_hash(state->symmetric, temp, hash->hash_len);
    noise_clean(temp, sizeof(temp));

    /* We have the pre shared key now */
    state->requirements &= ~NOISE_REQ_PSK;
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
    /* Validate the parameters */
    if (!state || !prologue)
        return NOISE_ERROR_INVALID_PARAM;
    if (state->action != NOISE_ACTION_NONE)
        return NOISE_ERROR_INVALID_STATE;
    if (!(state->requirements & NOISE_REQ_PROLOGUE))
        return NOISE_ERROR_INVALID_STATE;

    /* Mix the prologue into the handshake hash */
    noise_symmetricstate_mix_hash(state->symmetric, prologue, prologue_len);
    state->requirements &= ~NOISE_REQ_PROLOGUE;
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
 * The application configures the local keypair on the object returned by
 * noise_handshakestate_get_local_keypair_dh().
 *
 * \sa noise_handshakestate_has_local_keypair(),
 * noise_handshakestate_get_local_keypair_dh()
 */
int noise_handshakestate_needs_local_keypair(const NoiseHandshakeState *state)
{
    if (!state)
        return 0;
    if ((state->requirements & NOISE_REQ_LOCAL_REQUIRED) == 0)
        return 0;
    return !noise_dhstate_has_keypair(state->dh_local_static);
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
 * noise_handshakestate_get_local_keypair_dh()
 */
int noise_handshakestate_has_local_keypair(const NoiseHandshakeState *state)
{
    if (!state || !state->dh_local_static)
        return 0;
    return noise_dhstate_has_keypair(state->dh_local_static);
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
 * to be provided by the remote party during the session, then the
 * remote public key can be obtained at the end of the handshake using the
 * noise_handshakestate_get_remote_public_key_dh() object.
 *
 * \sa noise_handshakestate_has_remote_public_key(),
 * noise_handshakestate_get_remote_public_key_dh()
 */
int noise_handshakestate_needs_remote_public_key(const NoiseHandshakeState *state)
{
    if (!state)
        return 0;
    if ((state->requirements & NOISE_REQ_REMOTE_REQUIRED) == 0)
        return 0;
    return !noise_dhstate_has_keypair(state->dh_remote_static);
}

/**
 * \brief Determine if a HandshakeState has a remote public key.
 *
 * \param state The HandshakeState object.
 *
 * \return Returns 1 if the \a state has a remote public key, or 0 if the
 * key is yet to be seen.  Also returns zero if \a state is NULL.
 *
 * A remote public key may either be provided ahead of time on the
 * noise_handshakestate_get_remote_public_key_dh() object, or it may be
 * provided by the remote party during the handshake.
 *
 * \sa noise_handshakestate_needs_remote_public_key(),
 * noise_handshakestate_set_remote_public_key()
 */
int noise_handshakestate_has_remote_public_key(const NoiseHandshakeState *state)
{
    if (!state || !state->dh_remote_static)
        return 0;
    return noise_dhstate_has_public_key(state->dh_remote_static);
}

/**
 * \brief Mixes a public key value into the handshake hash.
 *
 * \param state The HandshakeState object.
 * \param dh The DHState for the key to mix in.  Can be NULL.
 */
static void noise_handshakestate_mix_public_key
    (NoiseHandshakeState *state, const NoiseDHState *dh)
{
    if (noise_dhstate_has_public_key(dh)) {
        noise_symmetricstate_mix_hash
            (state->symmetric, dh->public_key, dh->public_key_len);
    }
}

/**
 * \brief Starts the handshake on a HandshakeState object.
 *
 * \param state The HandshakeState object.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state is NULL.
 * \return NOISE_ERROR_LOCAL_KEY_REQUIRED if a local keypair is required
 * to start the protocol but one has not been provided yet.
 * \return NOISE_ERROR_REMOTE_KEY_REQUIRED if a remote public key is required
 * to start the protocol but one has not been provided yet.
 * \return NOISE_ERROR_PSK_REQUIRED if a pre shared key is required
 * to start the protocol but one has not been provided yet.
 * \return NOISE_ERROR_INVALID_STATE if the protocol handshake
 * has already started.
 * \return NOISE_ERROR_NOT_APPLICABLE if an attempt was made to
 * start a "XXfallback" handshake pattern without first calling
 * noise_handshakestate_fallback() on a previous "IK" handshake.
 *
 * This function is called after all of the handshake parameters have been
 * provided to the HandshakeState object.  This function should be followed
 * by calls to noise_handshake_write_message() or noise_handshake_read_message()
 * to process the handshake messages.  The noise_handshakestate_get_action()
 * function indicates the action to take next.
 *
 * \sa noise_handshake_write_message(), noise_handshake_read_message(),
 * noise_handshakestate_get_action(), noise_handshakestate_fallback()
 */
int noise_handshakestate_start(NoiseHandshakeState *state)
{
    /* Validate the parameter */
    if (!state)
        return NOISE_ERROR_INVALID_PARAM;
    if (state->action != NOISE_ACTION_NONE)
        return NOISE_ERROR_INVALID_STATE;
    if (state->symmetric->id.pattern_id == NOISE_PATTERN_XX_FALLBACK &&
            (state->requirements & NOISE_REQ_FALLBACK_EPHEM) == 0)
        return NOISE_ERROR_NOT_APPLICABLE;

    /* Check that we have satisfied all of the pattern requirements */
    if ((state->requirements & NOISE_REQ_LOCAL_REQUIRED) != 0 &&
            !noise_dhstate_has_keypair(state->dh_local_static))
        return NOISE_ERROR_LOCAL_KEY_REQUIRED;
    if ((state->requirements & NOISE_REQ_REMOTE_REQUIRED) != 0 &&
            !noise_dhstate_has_public_key(state->dh_remote_static))
        return NOISE_ERROR_REMOTE_KEY_REQUIRED;
    if ((state->requirements & NOISE_REQ_PSK) != 0)
        return NOISE_ERROR_PSK_REQUIRED;

    /* If the prologue has not been provided yet, hash an empty one */
    if (state->requirements & NOISE_REQ_PROLOGUE)
        noise_handshakestate_set_prologue(state, "", 0);

    /* Mix the pre-supplied public keys into the handshake hash */
    if (state->role == NOISE_ROLE_INITIATOR) {
        noise_handshakestate_mix_public_key(state, state->dh_local_static);
        noise_handshakestate_mix_public_key(state, state->dh_local_ephemeral);
        noise_handshakestate_mix_public_key(state, state->dh_remote_static);
        noise_handshakestate_mix_public_key(state, state->dh_remote_ephemeral);
    } else {
        noise_handshakestate_mix_public_key(state, state->dh_remote_static);
        noise_handshakestate_mix_public_key(state, state->dh_remote_ephemeral);
        noise_handshakestate_mix_public_key(state, state->dh_local_static);
        noise_handshakestate_mix_public_key(state, state->dh_local_ephemeral);
    }

    /* The handshake has now officially started */
    if (state->role == NOISE_ROLE_INITIATOR)
        state->action = NOISE_ACTION_WRITE_MESSAGE;
    else
        state->action = NOISE_ACTION_READ_MESSAGE;
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
 * \return NOISE_ERROR_INVALID_LENGTH if the new protocol name is too long.
 * \return NOISE_ERROR_NOT_APPLICABLE if the handshake pattern in the
 * original protocol name was not "IK".
 *
 * This function is used to help implement the "Noise Pipes" protocol.
 * It resets a HandshakeState object with the handshake pattern "IK",
 * converting it into an object with the handshake pattern "XXfallback".
 * Information from the previous session such as the local keypair and
 * the initiator's ephemeral key are passed to the new session.
 *
 * Once the fallback has been initiated, the application must call
 * noise_handshakestate_set_prologue() and
 * noise_handshakestate_set_pre_shared_key() again to re-establish the
 * early handshake details.  The application can then call
 * noise_handshakestate_start() to restart the handshake from where
 * it left off before the fallback.
 *
 * \note This function reverses the roles of initiator and responder,
 * which will also affect the ordering of the final CipherState objects
 * returned by noise_handshakestate_split().
 *
 * \sa noise_handshakestate_start(), noise_handshakestate_get_role()
 */
int noise_handshakestate_fallback(NoiseHandshakeState *state)
{
    char name[NOISE_MAX_PROTOCOL_NAME];
    size_t hash_len;
    size_t name_len;
    NoiseProtocolId id;
    int err;

    /* Validate the parameter */
    if (!state)
        return NOISE_ERROR_INVALID_PARAM;
    if (state->symmetric->id.pattern_id != NOISE_PATTERN_IK)
        return NOISE_ERROR_NOT_APPLICABLE;

    /* The initiator should be waiting for a return message from the
       responder, and the responder should have failed on the first
       handshake message from the initiator.  We also allow the
       responder to fallback after processing the first message
       successfully; it decides to always fall back anyway. */
    if (state->role == NOISE_ROLE_INITIATOR) {
        if (state->action != NOISE_ACTION_READ_MESSAGE)
            return NOISE_ERROR_INVALID_STATE;
        if (!noise_dhstate_has_public_key(state->dh_local_ephemeral))
            return NOISE_ERROR_INVALID_STATE;
    } else {
        if (state->action != NOISE_ACTION_FAILED &&
                state->action != NOISE_ACTION_WRITE_MESSAGE)
            return NOISE_ERROR_INVALID_STATE;
        if (!noise_dhstate_has_public_key(state->dh_remote_ephemeral))
            return NOISE_ERROR_INVALID_STATE;
    }

    /* Format a new protocol name for the "XXfallback" variant */
    id = state->symmetric->id;
    id.pattern_id = NOISE_PATTERN_XX_FALLBACK;
    err = noise_protocol_id_to_name(name, sizeof(name), &id);
    if (err != NOISE_ERROR_NONE)
        return err;

    /* Convert the HandshakeState to the "XXfallback" pattern */
    state->symmetric->id.pattern_id = NOISE_PATTERN_XX_FALLBACK;
    noise_dhstate_clear_key(state->dh_remote_static);
    if (state->role == NOISE_ROLE_INITIATOR) {
        noise_dhstate_clear_key(state->dh_remote_ephemeral);
        state->action = NOISE_ACTION_READ_MESSAGE;
        state->role = NOISE_ROLE_RESPONDER;
    } else {
        noise_dhstate_clear_key(state->dh_local_ephemeral);
        state->action = NOISE_ACTION_WRITE_MESSAGE;
        state->role = NOISE_ROLE_INITIATOR;
    }
    state->requirements |= NOISE_REQ_FALLBACK_EPHEM;

    /* Re-initialize the chaining key "ck" and the handshake hash "h" from
       the new protocol name.  If the name is too long, hash it down first */
    name_len = strlen(name);
    hash_len = noise_hashstate_get_hash_length(state->symmetric->hash);
    if (name_len <= hash_len) {
        memcpy(state->symmetric->h, name, name_len);
        memset(state->symmetric->h + name_len, 0, hash_len - name_len);
    } else {
        noise_hashstate_hash_one
            (state->symmetric->hash, (const uint8_t *)name, name_len,
             state->symmetric->h);
    }
    memcpy(state->symmetric->ck, state->symmetric->h, hash_len);

    /* Reset the encryption key within the symmetric state to empty */
    state->symmetric->cipher->has_key = 0;
    state->symmetric->cipher->n = 0;
    state->symmetric->cipher->nonce_overflow = 0;

    /* Ready to go */
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
 * \return NOISE_ACTION_FAILED if the handshake has failed with an
 * error.  The application should destroy the HandshakeState by calling
 * noise_handshakestate_free() and terminate the connection.  If the
 * application is using Noise Pipes, then it may be able to continue by
 * calling noise_handshakestate_fallback() depending upon where in the
 * protocol the failure occurred.
 * \return NOISE_ACTION_SPLIT if the handshake has finished successfully
 * and the application should call noise_handshakestate_split() to
 * obtain the CipherState objects for the data phase of the protocol.
 *
 * \sa noise_handshakestate_write_message(),
 * noise_handshakestate_read_message(), noise_handshakestate_split(),
 * noise_handshakestate_fallback()
 */
int noise_handshakestate_get_action(const NoiseHandshakeState *state)
{
    return state ? state->action : NOISE_ACTION_NONE;
}

/**
 * \brief Performs a Diffie-Hellman operation and mixes the result into
 * the chaining key.
 *
 * \param state The HandshakeState object.
 * \param private_key Points to the private key DHState object.
 * \param public_key Points to the public key DHState object.
 *
 * \return NOISE_ERROR_NONE on success, or an error code from
 * noise_dhstate_calculate() otherwise.
 */
static int noise_handshake_mix_dh
    (NoiseHandshakeState *state, const NoiseDHState *private_key,
     const NoiseDHState *public_key)
{
    size_t len = private_key->shared_key_len;
    uint8_t *shared = alloca(len);
    int err = noise_dhstate_calculate(private_key, public_key, shared, len);
    noise_symmetricstate_mix_key(state->symmetric, shared, len);
    noise_clean(shared, len);
    return err;
}

/**
 * \brief Internal implementation of noise_handshakestate_write_message().
 *
 * \param state The HandshakeState object.
 * \param payload Points to the message payload to be sent, which can
 * be NULL if \a payload_size is zero.
 * \param payload_size The size of the message payload in bytes.
 * \param message Points to the message buffer to be populated with
 * handshake details and the message payload.
 * \param message_size On exit, set to the number of bytes that were actually
 * written to \a message.
 * \param max_size The maximum size for the \a message buffer.
 *
 * \sa noise_handshakestate_write_message()
 */
static int noise_handshakestate_write
    (NoiseHandshakeState *state, const void *payload, size_t payload_size,
     uint8_t *message, size_t *message_size, size_t max_size)
{
    size_t size = 0;
    size_t len;
    size_t out_len;
    size_t mac_len;
    uint8_t token;
    int err;

    /* Process tokens until the direction changes or the pattern ends */
    for (;;) {
        token = *(state->tokens);
        if (token == NOISE_TOKEN_END) {
            /* The pattern has finished, so the next action is "split" */
            state->action = NOISE_ACTION_SPLIT;
            break;
        } else if (token == NOISE_TOKEN_FLIP_DIR) {
            /* Changing directions, so this message is complete and
               the next action is "read message". */
            ++(state->tokens);
            state->action = NOISE_ACTION_READ_MESSAGE;
            break;
        }
        err = NOISE_ERROR_NONE;
        switch (token) {
        case NOISE_TOKEN_E:
            /* Generate a local ephemeral keypair and add the public
               key to the message.  If we are running fixed vector tests,
               then the ephemeral key may have already been provided. */
            if (!state->dh_local_ephemeral)
                return NOISE_ERROR_INVALID_STATE;
            len = state->dh_local_ephemeral->public_key_len;
            if (!noise_dhstate_has_keypair(state->dh_local_ephemeral)) {
                err = noise_dhstate_generate_keypair(state->dh_local_ephemeral);
                if (err != NOISE_ERROR_NONE)
                    break;
            }
            if ((max_size - size) < len)
                return NOISE_ERROR_INVALID_LENGTH;
            memcpy(message + size, state->dh_local_ephemeral->public_key, len);
            noise_symmetricstate_mix_hash
                (state->symmetric, message + size, len);
            size += len;

            /* If the protocol is using pre-shared keys, then also mix
               the local ephemeral key into the chaining key */
            if (state->symmetric->id.prefix_id == NOISE_PREFIX_PSK) {
                err = noise_symmetricstate_mix_key
                    (state->symmetric,
                     state->dh_local_ephemeral->public_key, len);
            }
            break;
        case NOISE_TOKEN_S:
            /* Encrypt the local static public key and add it to the message */
            if (!state->dh_local_static)
                return NOISE_ERROR_INVALID_STATE;
            len = state->dh_local_static->public_key_len;
            mac_len = noise_symmetricstate_get_mac_length(state->symmetric);
            if ((max_size - size) < (len + mac_len))
                return NOISE_ERROR_INVALID_LENGTH;
            memcpy(message + size, state->dh_local_static->public_key, len);
            err = noise_symmetricstate_encrypt_and_hash
                (state->symmetric, message + size, len, &out_len);
            if (err != NOISE_ERROR_NONE)
                break;
            size += out_len;
            break;
        case NOISE_TOKEN_DHEE:
            /* DH operation with local and remote ephemeral keys */
            err = noise_handshake_mix_dh
                (state, state->dh_local_ephemeral, state->dh_remote_ephemeral);
            break;
        case NOISE_TOKEN_DHES:
            /* DH operation with local ephemeral and remote static keys */
            err = noise_handshake_mix_dh
                (state, state->dh_local_ephemeral, state->dh_remote_static);
            break;
        case NOISE_TOKEN_DHSE:
            /* DH operation with local static and remote ephemeral keys */
            err = noise_handshake_mix_dh
                (state, state->dh_local_static, state->dh_remote_ephemeral);
            break;
        case NOISE_TOKEN_DHSS:
            /* DH operation with local and remote static keys */
            err = noise_handshake_mix_dh
                (state, state->dh_local_static, state->dh_remote_static);
            break;
        default:
            /* Unknown token code in the pattern.  This shouldn't happen.
               If it does, then abort immediately. */
            err = NOISE_ERROR_INVALID_STATE;
            break;
        }
        if (err != NOISE_ERROR_NONE)
            return err;
        ++(state->tokens);
    }

    /* Encrypt the payload and add it to the buffer */
    mac_len = noise_symmetricstate_get_mac_length(state->symmetric);
    if ((max_size - size) < mac_len)
        return NOISE_ERROR_INVALID_LENGTH;
    if ((max_size - size - mac_len) < payload_size)
        return NOISE_ERROR_INVALID_LENGTH;
    if (payload_size)
        memcpy(message + size, payload, payload_size);
    err = noise_symmetricstate_encrypt_and_hash
        (state->symmetric, message + size, payload_size, &out_len);
    if (err != NOISE_ERROR_NONE)
        return err;
    size += out_len;

    /* Return the final size to the caller */
    *message_size = size;
    return NOISE_ERROR_NONE;
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
 * The \a payload and \a message buffers must not overlap in memory.
 *
 * \sa noise_handshakestate_read_message(), noise_handshakestate_get_action()
 */
int noise_handshakestate_write_message
    (NoiseHandshakeState *state, const void *payload, size_t payload_size,
     uint8_t *message, size_t *message_size)
{
    size_t max_size = 0;
    int err = NOISE_ERROR_NONE;

    /* Validate the message size and extract it.  We set the return size
       to zero and clear the message buffer in case this function bails out
       with an error later.  This is in case the caller forgets to check the
       error return value, and simply transmits the contents of "message".
       This will prevent the caller from accidentally leaking the previous
       contents of "message" onto the transport. */
    if (message_size) {
        max_size = *message_size;
        *message_size = 0;
        if (message)
            noise_clean(message, max_size);
    } else {
        err = NOISE_ERROR_INVALID_PARAM;
    }

    /* Validate the other parameters and state */
    if (err != NOISE_ERROR_NONE) {
        if (!state || !message)
            err = NOISE_ERROR_INVALID_PARAM;
        else if (!payload && payload_size != 0)
            err = NOISE_ERROR_INVALID_PARAM;
        else if (state->action != NOISE_ACTION_WRITE_MESSAGE)
            err = NOISE_ERROR_INVALID_STATE;
    }

    /* Perform the main write if no error so far */
    if (err == NOISE_ERROR_NONE) {
        err = noise_handshakestate_write
            (state, payload, payload_size, message, message_size, max_size);
    }

    /* If an error occurred, then fail the HandshakeState completely */
    if (err != NOISE_ERROR_NONE && state) {
        state->action = NOISE_ACTION_FAILED;
        if (message) {
            /* Clear the message buffer again in case we wrote some
               partial data to it before discovering the error */
            noise_clean(message, max_size);
        }
    }

    /* Finished */
    return err;
}

/**
 * \brief Internal implementation of noise_handshakestate_read_message().
 *
 * \param state The HandshakeState object.
 * \param message Points to the incoming handshake message to be unpacked.
 * \param message_size The length of the incoming handshake message in bytes.
 * \param payload Points to the buffer to fill with the message payload.
 * This can be NULL if the application does not need the message payload.
 * \param payload_size On exit, set to the number of bytes that were actually
 * written to \a payload.
 * \param max_size Maximum payload size that can be written to \a payload.
 *
 * \sa noise_handshakestate_read_message()
 */
static int noise_handshakestate_read
    (NoiseHandshakeState *state, uint8_t *message, size_t message_size,
     void *payload, size_t *payload_size, size_t max_size)
{
    size_t len;
    size_t out_len;
    size_t mac_len;
    uint8_t token;
    int err;

    /* Process tokens until the direction changes or the pattern ends */
    for (;;) {
        token = *(state->tokens);
        if (token == NOISE_TOKEN_END) {
            /* The pattern has finished, so the next action is "split" */
            state->action = NOISE_ACTION_SPLIT;
            break;
        } else if (token == NOISE_TOKEN_FLIP_DIR) {
            /* Changing directions, so this message is complete and
               the next action is "read message". */
            ++(state->tokens);
            state->action = NOISE_ACTION_WRITE_MESSAGE;
            break;
        }
        err = NOISE_ERROR_NONE;
        switch (token) {
        case NOISE_TOKEN_E:
            /* Save the remote ephemeral key and hash it */
            if (!state->dh_remote_ephemeral)
                return NOISE_ERROR_INVALID_STATE;
            len = state->dh_remote_ephemeral->public_key_len;
            if (message_size < len)
                return NOISE_ERROR_INVALID_LENGTH;
            err = noise_dhstate_set_public_key
                (state->dh_remote_ephemeral, message, len);
            if (err != NOISE_ERROR_NONE)
                break;
            if (noise_dhstate_is_null_public_key(state->dh_remote_ephemeral)) {
                /* The remote ephemeral key is null, which means that it is
                   not contributing anything to the security of the session
                   and is in fact downgrading the security to "none at all"
                   in some of the message patterns.  Reject all such keys. */
                return NOISE_ERROR_INVALID_PUBLIC_KEY;
            }
            message += len;
            message_size -= len;

            /* If the protocol is using pre-shared keys, then also mix
               the remote ephemeral key into the chaining key */
            if (state->symmetric->id.prefix_id == NOISE_PREFIX_PSK) {
                err = noise_symmetricstate_mix_key
                    (state->symmetric,
                     state->dh_remote_ephemeral->public_key, len);
            }
            break;
        case NOISE_TOKEN_S:
            /* Decrypt and read the remote static key */
            if (!state->dh_remote_static)
                return NOISE_ERROR_INVALID_STATE;
            mac_len = noise_symmetricstate_get_mac_length(state->symmetric);
            len = state->dh_remote_static->public_key_len + mac_len;
            if (message_size < len)
                return NOISE_ERROR_INVALID_LENGTH;
            err = noise_symmetricstate_decrypt_and_hash
                (state->symmetric, message, len, &out_len);
            if (err != NOISE_ERROR_NONE)
                break;
            err = noise_dhstate_set_public_key
                (state->dh_remote_static, message, out_len);
            if (err != NOISE_ERROR_NONE)
                break;
            message += len;
            message_size -= len;
            break;
        case NOISE_TOKEN_DHEE:
            /* DH operation with local and remote ephemeral keys */
            err = noise_handshake_mix_dh
                (state, state->dh_local_ephemeral, state->dh_remote_ephemeral);
            break;
        case NOISE_TOKEN_DHES:
            /* DH operation with remote ephemeral and local static keys */
            err = noise_handshake_mix_dh
                (state, state->dh_local_static, state->dh_remote_ephemeral);
            break;
        case NOISE_TOKEN_DHSE:
            /* DH operation with remote static and local ephemeral keys */
            err = noise_handshake_mix_dh
                (state, state->dh_local_ephemeral, state->dh_remote_static);
            break;
        case NOISE_TOKEN_DHSS:
            /* DH operation with local and remote static keys */
            err = noise_handshake_mix_dh
                (state, state->dh_local_static, state->dh_remote_static);
            break;
        default:
            /* Unknown token code in the pattern.  This shouldn't happen.
               If it does, then abort immediately. */
            err = NOISE_ERROR_INVALID_STATE;
            break;
        }
        if (err != NOISE_ERROR_NONE)
            return err;
        ++(state->tokens);
    }

    /* Decrypt the payload and return it in the payload buffer */
    mac_len = noise_symmetricstate_get_mac_length(state->symmetric);
    err = noise_symmetricstate_decrypt_and_hash
        (state->symmetric, message, message_size, &len);
    if (err != NOISE_ERROR_NONE)
        return err;
    if (len > max_size)
        return NOISE_ERROR_INVALID_LENGTH;
    if (payload)
        memcpy(payload, message, len);

    /* Return the final payload size to the caller */
    *payload_size = len;
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
 * \return NOISE_ERROR_INVALID_STATE if noise_handshakestate_get_action() is 
 * not NOISE_ACTION_READ_MESSAGE.
 * \return NOISE_ERROR_INVALID_LENGTH if the \a payload_size is too small
 * to contain all of the bytes that need to be written to \a payload.
 * \return NOISE_ERROR_MAC_FAILURE if the \a message failed to authenticate,
 * which terminates the handshake.
 * \return NOISE_ERROR_PUBLIC_KEY if an invalid remote public key is seen
 * during the processing of this message.
 *
 * If \a payload is NULL, then the message payload will be authenticated,
 * checked to be less than or equal to \a payload_size in length,
 * and then discarded.  If the application was expecting a zero-length
 * payload, then \a payload_size should be zero on entry.
 *
 * The \a payload and \a message buffers must not overlap in memory.
 *
 * The \a message buffer will be modified by this function to decrypt
 * sub-components while it is being processed.  The contents will be
 * cleared just before the function exits to avoid leaking decrypted
 * message data other than the \a payload.
 *
 * \sa noise_handshakestate_write_message(), noise_handshakestate_get_action()
 */
int noise_handshakestate_read_message
    (NoiseHandshakeState *state, uint8_t *message, size_t message_size,
     void *payload, size_t *payload_size)
{
    size_t max_size = 0;
    int err = NOISE_ERROR_NONE;

    /* Validate the payload size and extract it.  We set the return size
       to zero and clear the payload buffer in case this function bails out
       with an error later.  This is in case the caller forgets to check
       the error return value and simply passes the payload bytes up to the
       application.  This could lead to "replay attack" scenarios where the
       previous payload contents can be re-fed into the application to
       repeat a previous command. */
    if (payload_size) {
        max_size = *payload_size;
        *payload_size = 0;
        if (payload)
            noise_clean(payload, max_size);
    } else {
        err = NOISE_ERROR_INVALID_PARAM;
    }

    /* Validate the other parameters and state */
    if (err == NOISE_ERROR_NONE) {
        if (!state || !message)
            err = NOISE_ERROR_INVALID_PARAM;
        else if (state->action != NOISE_ACTION_READ_MESSAGE)
            err = NOISE_ERROR_INVALID_STATE;
    }

    /* Perform the main read if no error so far */
    if (err == NOISE_ERROR_NONE) {
        err = noise_handshakestate_read
            (state, message, message_size, payload, payload_size, max_size);
    }

    /* Clear the incoming message buffer to prevent leakage of decrypted data */
    if (message)
        noise_clean(message, message_size);

    /* If an error occurred, then fail the HandshakeState completely */
    if (err != NOISE_ERROR_NONE && state)
        state->action = NOISE_ACTION_FAILED;

    /* Finished */
    return err;
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
    /* Validate the parameters */
    if (!state || !c1)
        return NOISE_ERROR_INVALID_PARAM;
    if (state->action != NOISE_ACTION_SPLIT)
        return NOISE_ERROR_INVALID_STATE;
    if (!state->symmetric->cipher)
        return NOISE_ERROR_INVALID_STATE;

    /* Split the cipher objects out of the SymmetricState */
    return noise_symmetricstate_split(state->symmetric, c1, c2);
}

/**@}*/
