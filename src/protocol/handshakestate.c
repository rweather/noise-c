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
#include <stdlib.h>

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
 * See the \ref example_echo "echo example" for an overview of how
 * to use this API.
 */
/**@{*/

/**
 * \typedef NoiseHandshakeState
 * \brief Opaque object that represents a HandshakeState.
 */

/**
 * \brief Gets the initial requirements for a handshake pattern.
 *
 * \param flags The flags from the handshake pattern.
 * \param prefix_id The prefix identifier from the protocol name.
 * \param role The role, either initiator or responder.
 * \param is_fallback Non-zero if we are processing a fallback pattern.
 *
 * \return The key requirements for the handshake pattern.
 */
static int noise_handshakestate_requirements
    (NoisePatternFlags_t flags, int prefix_id, int role, int is_fallback)
{
    int requirements = 0;
    if (flags & NOISE_PAT_FLAG_LOCAL_STATIC) {
        requirements |= NOISE_REQ_LOCAL_REQUIRED;
    }
    if (flags & NOISE_PAT_FLAG_LOCAL_REQUIRED) {
        requirements |= NOISE_REQ_LOCAL_REQUIRED;
        requirements |= NOISE_REQ_LOCAL_PREMSG;
    }
    if (flags & NOISE_PAT_FLAG_REMOTE_REQUIRED) {
        requirements |= NOISE_REQ_REMOTE_REQUIRED;
        requirements |= NOISE_REQ_REMOTE_PREMSG;
    }
    if (flags & (NOISE_PAT_FLAG_REMOTE_EPHEM_REQ |
                 NOISE_PAT_FLAG_LOCAL_EPHEM_REQ)) {
        if (is_fallback)
            requirements |= NOISE_REQ_FALLBACK_PREMSG;
    }
    if (prefix_id == NOISE_PREFIX_PSK) {
        requirements |= NOISE_REQ_PSK;
    }
    return requirements;
}

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
    int dh_id;
    int hybrid_id;
    NoisePatternFlags_t flags;
    int extra_reqs = 0;
    int err;
    int local_dh_role;
    int remote_dh_role;

    /* Locate the information for the current handshake pattern */
    pattern = noise_pattern_lookup(symmetric->id.pattern_id);
    if (!pattern) {
        noise_symmetricstate_free(symmetric);
        return NOISE_ERROR_UNKNOWN_ID;
    }
    flags = ((NoisePatternFlags_t)(pattern[0])) |
           (((NoisePatternFlags_t)(pattern[1])) << 8);
    if ((flags & NOISE_PAT_FLAG_REMOTE_REQUIRED) != 0)
        extra_reqs |= NOISE_REQ_FALLBACK_POSSIBLE;
    if (role == NOISE_ROLE_RESPONDER) {
        /* Reverse the pattern flags so that the responder is "local" */
        flags = noise_pattern_reverse_flags(flags);
    }

    /* Determine the role to use for DHState objects */
    if ((flags & NOISE_PAT_FLAG_REMOTE_EPHEM_REQ) != 0) {
        /* Fallback pattern - reverse the DHState role */
        if (role == NOISE_ROLE_INITIATOR) {
            local_dh_role = NOISE_ROLE_RESPONDER;
            remote_dh_role = NOISE_ROLE_INITIATOR;
        } else {
            local_dh_role = NOISE_ROLE_INITIATOR;
            remote_dh_role = NOISE_ROLE_RESPONDER;
        }
    } else {
        /* Regular pattern */
        if (role == NOISE_ROLE_INITIATOR) {
            local_dh_role = NOISE_ROLE_INITIATOR;
            remote_dh_role = NOISE_ROLE_RESPONDER;
        } else {
            local_dh_role = NOISE_ROLE_RESPONDER;
            remote_dh_role = NOISE_ROLE_INITIATOR;
        }
    }

    /* Create the HandshakeState object */
    *state = noise_new(NoiseHandshakeState);
    if (!(*state)) {
        noise_symmetricstate_free(symmetric);
        return NOISE_ERROR_NO_MEMORY;
    }

    /* Initialize the HandshakeState */
    (*state)->requirements = extra_reqs | noise_handshakestate_requirements
        (flags, symmetric->id.prefix_id, role, 0);
    (*state)->action = NOISE_ACTION_NONE;
    (*state)->tokens = pattern + 2;
    (*state)->role = role;
    (*state)->symmetric = symmetric;

    /* Create DHState objects for all of the keys we will need later */
    err = NOISE_ERROR_NONE;
    dh_id = symmetric->id.dh_id;
    hybrid_id = symmetric->id.hybrid_id;
    if ((flags & NOISE_PAT_FLAG_LOCAL_STATIC) != 0) {
        err = noise_dhstate_new_by_id(&((*state)->dh_local_static), dh_id);
    }
    if ((flags & NOISE_PAT_FLAG_LOCAL_EPHEMERAL) != 0 && err == NOISE_ERROR_NONE) {
        err = noise_dhstate_new_by_id(&((*state)->dh_local_ephemeral), dh_id);
    }
    if ((flags & NOISE_PAT_FLAG_LOCAL_HYBRID) != 0 && err == NOISE_ERROR_NONE) {
        if (hybrid_id != NOISE_DH_NONE)
            err = noise_dhstate_new_by_id(&((*state)->dh_local_hybrid), hybrid_id);
        else
            err = NOISE_ERROR_NOT_APPLICABLE;
    } else if (hybrid_id != NOISE_DH_NONE) {
        err = NOISE_ERROR_NOT_APPLICABLE;
    }
    if ((flags & NOISE_PAT_FLAG_REMOTE_STATIC) != 0 && err == NOISE_ERROR_NONE) {
        err = noise_dhstate_new_by_id(&((*state)->dh_remote_static), dh_id);
    }
    if ((flags & NOISE_PAT_FLAG_REMOTE_EPHEMERAL) != 0 && err == NOISE_ERROR_NONE) {
        err = noise_dhstate_new_by_id(&((*state)->dh_remote_ephemeral), dh_id);
    }
    if ((flags & NOISE_PAT_FLAG_REMOTE_HYBRID) != 0 && err == NOISE_ERROR_NONE) {
        if (hybrid_id != NOISE_DH_NONE)
            err = noise_dhstate_new_by_id(&((*state)->dh_remote_hybrid), hybrid_id);
        else
            err = NOISE_ERROR_NOT_APPLICABLE;
    } else if (hybrid_id != NOISE_DH_NONE) {
        err = NOISE_ERROR_NOT_APPLICABLE;
    }

    /* Set the roles for all DHState objects except those for hybrid
       forward secrecy.  Those roles are implicit in whether the "f"
       or "g" token is used to refer to the value */
    noise_dhstate_set_role((*state)->dh_local_ephemeral, local_dh_role);
    noise_dhstate_set_role((*state)->dh_local_static, local_dh_role);
    noise_dhstate_set_role((*state)->dh_remote_ephemeral, remote_dh_role);
    noise_dhstate_set_role((*state)->dh_remote_static, remote_dh_role);

    /* If the DH algorithm is ephemeral-only, then we need to apply some
     * extra checks on the pattern: essentially, only "NN" is possible.
     * This check isn't needed for the hybrid secrecy DH objects as they
     * are by definition ephemeral-only */
    if (err == NOISE_ERROR_NONE) {
        if ((*state)->dh_local_static && (*state)->dh_local_static->ephemeral_only)
            err = NOISE_ERROR_NOT_APPLICABLE;
        if ((*state)->dh_remote_static && (*state)->dh_remote_static->ephemeral_only)
            err = NOISE_ERROR_NOT_APPLICABLE;
        if ((*state)->dh_local_ephemeral && (*state)->dh_local_ephemeral->ephemeral_only) {
            if (!((*state)->dh_remote_ephemeral))
                err = NOISE_ERROR_NOT_APPLICABLE;
        } else if ((*state)->dh_remote_ephemeral && (*state)->dh_remote_ephemeral->ephemeral_only) {
            err = NOISE_ERROR_NOT_APPLICABLE;
        }
    }

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
 * \return NOISE_ERROR_NOT_APPLICABLE if the combination of algorithm
 * identifiers in \a protocol_id is not permitted.
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
 * \return NOISE_ERROR_NOT_APPLICABLE if the combination of algorithm
 * identifiers in \a protocol_id is not permitted.
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
    if (state->dh_local_hybrid)
        noise_dhstate_free(state->dh_local_hybrid);
    if (state->dh_remote_static)
        noise_dhstate_free(state->dh_remote_static);
    if (state->dh_remote_ephemeral)
        noise_dhstate_free(state->dh_remote_ephemeral);
    if (state->dh_remote_hybrid)
        noise_dhstate_free(state->dh_remote_hybrid);
    if (state->dh_fixed_ephemeral)
        noise_dhstate_free(state->dh_fixed_ephemeral);
    if (state->dh_fixed_hybrid)
        noise_dhstate_free(state->dh_fixed_hybrid);
    noise_free(state->prologue, state->prologue_len);

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
 * \brief Gets the DHState object that contains the local static keypair.
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
 * \brief Gets the DHState object that contains the remote static public key.
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

/**
 * \brief Gets the DHState object that contains the local ephemeral keypair.
 *
 * \param state The HandshakeState object.
 *
 * \return Returns a pointer to the DHState object for the local ephemeral
 * keypair, or NULL if the system is out of memory or \a state is NULL.
 *
 * \note This function is intended for testing only.  It can be used to
 * establish a fixed ephemeral key for test vectors.  This function should
 * not be used in real applications.
 *
 * \sa noise_handshakestate_get_local_keypair_dh()
 */
NoiseDHState *noise_handshakestate_get_fixed_ephemeral_dh
    (NoiseHandshakeState *state)
{
    if (!state || !state->dh_local_ephemeral)
        return 0;

    if (!state->dh_fixed_ephemeral) {
        if (noise_dhstate_new_by_id
                (&(state->dh_fixed_ephemeral), state->symmetric->id.dh_id)
              != NOISE_ERROR_NONE) {
            return 0;
        }
        noise_dhstate_set_role
            (state->dh_fixed_ephemeral,
             noise_dhstate_get_role(state->dh_local_ephemeral));
    }

    return state->dh_fixed_ephemeral;
}

/**
 * \brief Gets the DHState object that contains the local additional
 * hybrid secrecy keypair.
 *
 * \param state The HandshakeState object.
 *
 * \return Returns a pointer to the DHState object for the local additional
 * hybrid secrecy keypair, or NULL if the system is out of memory,
 * \a state is NULL, or \a state does not support additional hybrid secrecy.
 *
 * \note This function is intended for testing only.  It can be used to
 * establish a fixed hybrid secrecy key for test vectors.  This function
 * should not be used in real applications.
 *
 * \sa noise_handshakestate_get_fixed_ephemeral_dh()
 */
NoiseDHState *noise_handshakestate_get_fixed_hybrid_dh
    (NoiseHandshakeState *state)
{
    if (!state || !state->dh_local_hybrid)
        return 0;

    if (!state->dh_fixed_hybrid) {
        if (noise_dhstate_new_by_id
                (&(state->dh_fixed_hybrid), state->symmetric->id.hybrid_id)
              != NOISE_ERROR_NONE) {
            return 0;
        }

        /* Normally hybrid keys do not get a role until the "f" or "g"
           tokens are encountered.  However for fixed test vectors we
           need to know the size of the private key ahead of time and
           hence the role.  Predict the future hybrid role from the
           current ephemeral role. */
        noise_dhstate_set_role
            (state->dh_fixed_hybrid,
             noise_dhstate_get_role(state->dh_local_ephemeral));
    }

    return state->dh_fixed_hybrid;
}

/**
 * \brief Determine if a HandshakeState object requires a pre shared key.
 *
 * \param state The HandshakeState object.
 *
 * \return Returns 1 if \a state requires a pre shared key, zero if the
 * pre shared key has already been supplied or it is not required.
 *
 * \sa noise_handshakestate_set_pre_shared_key(),
 * noise_handshakestate_has_pre_shared_key()
 */
int noise_handshakestate_needs_pre_shared_key(const NoiseHandshakeState *state)
{
    if (!state || state->pre_shared_key_len)
        return 0;
    else
        return (state->requirements & NOISE_REQ_PSK) != 0;
}

/**
 * \brief Determine if a HandshakeState object has already been configured
 * with a pre shared key.
 *
 * \param state The HandshakeState object.
 *
 * \return Returns 1 if \a state has a pre shared key, zero if not.
 *
 * \sa noise_handshakestate_set_pre_shared_key(),
 * noise_handshakestate_needs_pre_shared_key()
 */
int noise_handshakestate_has_pre_shared_key(const NoiseHandshakeState *state)
{
    if (!state)
        return 0;
    else
        return state->pre_shared_key_len != 0;
}

/**
 * \brief Sets the pre shared key for a HandshakeState.
 *
 * \param state The HandshakeState object.
 * \param key Points to the pre shared key.
 * \param key_len The length of the \a key in bytes.  This must be 32
 * to comply with the requirements from the Noise protocol specification.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state or \a key is NULL.
 * \return NOISE_ERROR_INVALID_LENGTH if \a key_len is not 32.
 * \return NOISE_ERROR_NOT_APPLICABLE if the protocol name does not
 * begin with "NoisePSK".
 * \return NOISE_ERROR_INVALID_STATE if this function is called after
 * the protocol has already started.
 *
 * \sa noise_handshakestate_start(), noise_handshakestate_set_prologue(),
 * noise_handshakestate_needs_pre_shared_key(),
 * noise_handshakestate_has_pre_shared_key()
 */
int noise_handshakestate_set_pre_shared_key
    (NoiseHandshakeState *state, const uint8_t *key, size_t key_len)
{
    /* Validate the parameters and state */
    if (!state || !key)
        return NOISE_ERROR_INVALID_PARAM;
    if (key_len != NOISE_PSK_LEN)
        return NOISE_ERROR_INVALID_LENGTH;
    if (state->symmetric->id.prefix_id != NOISE_PREFIX_PSK)
        return NOISE_ERROR_NOT_APPLICABLE;
    if (state->action != NOISE_ACTION_NONE)
        return NOISE_ERROR_INVALID_STATE;

    /* Record the pre-shared key for use in noise_handshakestate_start() */
    memcpy(state->pre_shared_key, key, key_len);
    state->pre_shared_key_len = key_len;
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
 * \return NOISE_ERROR_INVALID_STATE if this function is called after
 * the protocol has already started.
 * \return NOISE_ERROR_NO_MEMORY if there is insufficient memory to
 * save the \a prologue value.
 *
 * This function should be called immediately after
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

    /* Make a copy of the prologue for later */
    if (state->prologue && state->prologue_len == prologue_len) {
        memcpy(state->prologue, prologue, prologue_len);
    } else {
        noise_free(state->prologue, state->prologue_len);
        if (prologue_len) {
            state->prologue = (uint8_t *)malloc(prologue_len);
            if (!(state->prologue)) {
                state->prologue_len = 0;
                return NOISE_ERROR_NO_MEMORY;
            }
            memcpy(state->prologue, prologue, prologue_len);
        } else {
            state->prologue = 0;
        }
        state->prologue_len = prologue_len;
    }
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
    return !noise_dhstate_has_public_key(state->dh_remote_static);
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
 * \brief Mixes a public key value into the chaining key.
 *
 * \param state The HandshakeState object.
 * \param dh The DHState for the key to mix in.  Can be NULL.
 */
static void noise_handshakestate_mix_chaining_key
    (NoiseHandshakeState *state, const NoiseDHState *dh)
{
    if (noise_dhstate_has_public_key(dh)) {
        noise_symmetricstate_mix_key
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
 * start a fallback handshake pattern without first calling
 * noise_handshakestate_fallback() on a previous handshake.
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
            (state->requirements & NOISE_REQ_FALLBACK_PREMSG) == 0)
        return NOISE_ERROR_NOT_APPLICABLE;

    /* Check that we have satisfied all of the pattern requirements */
    if ((state->requirements & NOISE_REQ_LOCAL_REQUIRED) != 0 &&
            !noise_dhstate_has_keypair(state->dh_local_static))
        return NOISE_ERROR_LOCAL_KEY_REQUIRED;
    if ((state->requirements & NOISE_REQ_REMOTE_REQUIRED) != 0 &&
            !noise_dhstate_has_public_key(state->dh_remote_static))
        return NOISE_ERROR_REMOTE_KEY_REQUIRED;
    if ((state->requirements & NOISE_REQ_PSK) != 0 &&
            state->pre_shared_key_len == 0)
        return NOISE_ERROR_PSK_REQUIRED;

    /* Hash the prologue value */
    if (state->prologue_len) {
        noise_symmetricstate_mix_hash
            (state->symmetric, state->prologue, state->prologue_len);
    } else {
        /* No prologue, so hash an empty one */
        noise_symmetricstate_mix_hash
            (state->symmetric, state->pre_shared_key, 0);
    }

    /* Mix the pre shared key into the chaining key and handshake hash */
    if (state->pre_shared_key_len) {
        uint8_t temp[NOISE_MAX_HASHLEN];
        NoiseHashState *hash = state->symmetric->hash;
        noise_hashstate_hkdf
            (hash, state->symmetric->ck, hash->hash_len,
             state->pre_shared_key, state->pre_shared_key_len,
             state->symmetric->ck, hash->hash_len, temp, hash->hash_len);
        noise_symmetricstate_mix_hash(state->symmetric, temp, hash->hash_len);
        noise_clean(temp, sizeof(temp));
    }

    /* Mix the pre-supplied public keys into the handshake hash */
    if (state->role == NOISE_ROLE_INITIATOR) {
        if (state->requirements & NOISE_REQ_LOCAL_PREMSG)
            noise_handshakestate_mix_public_key(state, state->dh_local_static);
        if (state->requirements & NOISE_REQ_FALLBACK_PREMSG) {
            noise_handshakestate_mix_public_key(state, state->dh_remote_ephemeral);
            if (state->dh_remote_hybrid) {
                noise_handshakestate_mix_public_key
                    (state, state->dh_remote_hybrid);
            }
            if ((state->requirements & NOISE_REQ_PSK) != 0) {
                noise_handshakestate_mix_chaining_key
                    (state, state->dh_remote_ephemeral);
            }
        }
        if (state->requirements & NOISE_REQ_REMOTE_PREMSG)
            noise_handshakestate_mix_public_key(state, state->dh_remote_static);
    } else {
        if (state->requirements & NOISE_REQ_REMOTE_PREMSG)
            noise_handshakestate_mix_public_key(state, state->dh_remote_static);
        if (state->requirements & NOISE_REQ_FALLBACK_PREMSG) {
            noise_handshakestate_mix_public_key(state, state->dh_local_ephemeral);
            if (state->dh_local_hybrid) {
                noise_handshakestate_mix_public_key
                    (state, state->dh_local_hybrid);
            }
            if ((state->requirements & NOISE_REQ_PSK) != 0) {
                noise_handshakestate_mix_chaining_key
                    (state, state->dh_local_ephemeral);
            }
        }
        if (state->requirements & NOISE_REQ_LOCAL_PREMSG)
            noise_handshakestate_mix_public_key(state, state->dh_local_static);
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
 * original protocol name is not compatible with "XXfallback".
 *
 * This function is intended used to help implement the "Noise Pipes" protocol.
 * It resets a HandshakeState object with the original handshake pattern
 * (usually "IK"), converting it into an object with the handshake pattern
 * "XXfallback".  Information from the previous session such as the local
 * keypair, the initiator's ephemeral key, the prologue value, and the
 * pre-shared key, are passed to the new session.
 *
 * Once the fallback has been initiated, the application can set
 * new values for the handshake parameters if the values from the
 * previous session do not apply.  For example, the application may
 * use a different prologue for the fallback than for the original
 * session.
 *
 * After setting any new parameters, the application calls
 * noise_handshakestate_start() again to restart the handshake
 * from where it left off before the fallback.
 *
 * \note This function reverses the roles of initiator and responder.
 *
 * \sa noise_handshakestate_start(), noise_handshakestate_fallback_to()
 */
int noise_handshakestate_fallback(NoiseHandshakeState *state)
{
    return noise_handshakestate_fallback_to(state, NOISE_PATTERN_XX_FALLBACK);
}

/**
 * \brief Falls back to another handshake pattern.
 *
 * \param state The HandshakeState object.
 * \param pattern_id The identifier for the pattern to fallback to;
 * e.g. NOISE_PATTERN_XX_FALLBACK, NOISE_PATTERN_NX_FALLBACK, etc.
 *
 * \return NOISE_ERROR_NONE on error.
 * \return NOISE_ERROR_INVALID_PARAM if \a state is NULL.
 * \return NOISE_ERROR_INVALID_STATE if the previous protocol has not
 * been started or has not reached the fallback position yet.
 * \return NOISE_ERROR_INVALID_LENGTH if the new protocol name is too long.
 * \return NOISE_ERROR_NOT_APPLICABLE if the handshake pattern in the
 * original protocol name is not compatible with \a pattern_id.
 * \return NOISE_ERROR_NOT_APPLICABLE if \a pattern_id does not
 * identify a fallback pattern.
 *
 * This function is a generalization of the "Noise Pipes" protocol,
 * allowing for other combinations of patterns to be used for the
 * full handshake, abbreviated handshake, and fallback handshake.
 * For example, "NX/NK/NXfallback", "XX/XK/XXfallback", etc.
 *
 * This function resets a HandshakeState object with the original
 * handshake pattern, and converts it into an object with the new handshake
 * \a pattern_id.  Information from the previous session such as the local
 * keypair, the initiator's ephemeral key, the prologue value, and the
 * pre-shared key, are passed to the new session.
 *
 * Once the fallback has been initiated, the application can set
 * new values for the handshake parameters if the values from the
 * previous session do not apply.  For example, the application may
 * use a different prologue for the fallback than for the original
 * session.
 *
 * After setting any new parameters, the application calls
 * noise_handshakestate_start() again to restart the handshake
 * from where it left off before the fallback.
 *
 * The new pattern may have greater key requirements than the original;
 * for example changing from "NK" from "XXfallback" requires that the
 * initiator's static public key be set.  The application is responsible for
 * setting any extra keys before calling noise_handshakestate_start().
 *
 * \note This function reverses the roles of initiator and responder.
 *
 * \sa noise_handshakestate_start(), noise_handshakestate_fallback()
 */
int noise_handshakestate_fallback_to(NoiseHandshakeState *state, int pattern_id)
{
    char name[NOISE_MAX_PROTOCOL_NAME];
    size_t hash_len;
    size_t name_len;
    NoiseProtocolId id;
    const uint8_t *pattern;
    NoisePatternFlags_t flags;
    int err;

    /* Validate the parameter */
    if (!state)
        return NOISE_ERROR_INVALID_PARAM;

    /* The original pattern must end in "K" for fallback to be possible */
    if (state->symmetric->id.pattern_id < NOISE_PATTERN_NN ||
            (state->requirements & NOISE_REQ_FALLBACK_POSSIBLE) == 0)
        return NOISE_ERROR_NOT_APPLICABLE;

    /* Check that "pattern_id" supports fallback */
    pattern = noise_pattern_lookup(pattern_id);
    if (!pattern)
        return NOISE_ERROR_NOT_APPLICABLE;
    flags = ((NoisePatternFlags_t)(pattern[0])) |
           (((NoisePatternFlags_t)(pattern[1])) << 8);
    if ((flags & NOISE_PAT_FLAG_REMOTE_EPHEM_REQ) == 0)
        return NOISE_ERROR_NOT_APPLICABLE;

    /* The initiator should be waiting for a return message from the
       responder, and the responder should have failed on the first
       handshake message from the initiator.  We also allow the
       responder to fallback after processing the first message
       successfully; it decides to always fall back anyway. */
    if (state->role == NOISE_ROLE_INITIATOR) {
        if (state->action != NOISE_ACTION_FAILED &&
                state->action != NOISE_ACTION_READ_MESSAGE)
            return NOISE_ERROR_INVALID_STATE;
        if (!noise_dhstate_has_public_key(state->dh_local_ephemeral))
            return NOISE_ERROR_INVALID_STATE;
        if (state->dh_local_hybrid &&
                !noise_dhstate_has_public_key(state->dh_local_hybrid))
            return NOISE_ERROR_INVALID_STATE;
    } else {
        if (state->action != NOISE_ACTION_FAILED &&
                state->action != NOISE_ACTION_WRITE_MESSAGE)
            return NOISE_ERROR_INVALID_STATE;
        if (!noise_dhstate_has_public_key(state->dh_remote_ephemeral))
            return NOISE_ERROR_INVALID_STATE;
        if (state->dh_remote_hybrid &&
                !noise_dhstate_has_public_key(state->dh_remote_hybrid))
            return NOISE_ERROR_INVALID_STATE;
    }

    /* Format a new protocol name for the fallback variant */
    id = state->symmetric->id;
    id.pattern_id = pattern_id;
    err = noise_protocol_id_to_name(name, sizeof(name), &id);
    if (err != NOISE_ERROR_NONE)
        return err;

    /* Convert the HandshakeState to the fallback pattern */
    state->symmetric->id.pattern_id = pattern_id;
    if (state->role == NOISE_ROLE_INITIATOR) {
        noise_dhstate_clear_key(state->dh_remote_ephemeral);
        noise_dhstate_clear_key(state->dh_remote_hybrid);
        noise_dhstate_clear_key(state->dh_remote_static);
        state->role = NOISE_ROLE_RESPONDER;
    } else {
        noise_dhstate_clear_key(state->dh_local_ephemeral);
        noise_dhstate_clear_key(state->dh_local_hybrid);
        if (!(flags & NOISE_PAT_FLAG_REMOTE_REQUIRED))
            noise_dhstate_clear_key(state->dh_remote_static);
        state->role = NOISE_ROLE_INITIATOR;
    }

    /* Start a new token pattern for the fallback */
    state->tokens = pattern + 2;
    state->action = NOISE_ACTION_NONE;

    /* Set up the key requirements for the fallback */
    if (state->role == NOISE_ROLE_RESPONDER) {
        flags = noise_pattern_reverse_flags(flags);
    }
    state->requirements = noise_handshakestate_requirements
        (flags, id.prefix_id, state->role, 1);

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
             state->symmetric->h, hash_len);
    }
    memcpy(state->symmetric->ck, state->symmetric->h, hash_len);

    /* Reset the encryption key within the symmetric state to empty */
    state->symmetric->cipher->has_key = 0;
    state->symmetric->cipher->n = 0;

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
 * \return NOISE_ACTION_COMPLETE if the handshake has finished successfully
 * and noise_handshakestate_split() has been called.
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
 * \param message Points to the message buffer to be populated with
 * handshake details and the message payload.
 * \param payload Points to the message payload to be sent, which can
 * be NULL if no payload is required.
 *
 * \sa noise_handshakestate_write_message()
 */
static int noise_handshakestate_write
    (NoiseHandshakeState *state, NoiseBuffer *message, const NoiseBuffer *payload)
{
    NoiseBuffer rest;
    size_t len;
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

        /* Set "rest" to the rest of the "message" buffer after the
           current size.  This is the space we have left to write
           handshake values while processing this token. */
        rest.data = message->data + message->size;
        rest.size = 0;
        rest.max_size = message->max_size - message->size;

        /* Process the token */
        err = NOISE_ERROR_NONE;
        switch (token) {
        case NOISE_TOKEN_E:
            /* Generate a local ephemeral keypair and add the public
               key to the message.  If we are running fixed vector tests,
               then the ephemeral key may have already been provided. */
            if (!state->dh_local_ephemeral)
                return NOISE_ERROR_INVALID_STATE;
            if (!state->dh_fixed_ephemeral) {
                err = noise_dhstate_generate_dependent_keypair
                    (state->dh_local_ephemeral, state->dh_remote_ephemeral);
            } else {
                /* Use the fixed ephemeral key provided by the test harness.
                   To support New Hope we need to perform a dependent copy */
                state->dh_local_ephemeral->key_type =
                    state->dh_fixed_ephemeral->key_type;
                err = (*(state->dh_local_ephemeral->copy))
                    (state->dh_local_ephemeral, state->dh_fixed_ephemeral,
                     state->dh_remote_ephemeral);
            }
            if (err != NOISE_ERROR_NONE)
                break;
            len = state->dh_local_ephemeral->public_key_len;
            if (rest.max_size < len)
                return NOISE_ERROR_INVALID_LENGTH;
            memcpy(rest.data, state->dh_local_ephemeral->public_key, len);
            noise_symmetricstate_mix_hash(state->symmetric, rest.data, len);
            rest.size += len;

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
            if (rest.max_size < (len + mac_len))
                return NOISE_ERROR_INVALID_LENGTH;
            memcpy(rest.data, state->dh_local_static->public_key, len);
            rest.size += len;
            err = noise_symmetricstate_encrypt_and_hash(state->symmetric, &rest);
            if (err != NOISE_ERROR_NONE)
                break;
            break;
        case NOISE_TOKEN_EE:
            /* DH operation with initiator and responder ephemeral keys */
            err = noise_handshake_mix_dh
                (state, state->dh_local_ephemeral, state->dh_remote_ephemeral);
            break;
        case NOISE_TOKEN_ES:
            /* DH operation with initiator ephemeral and responder static keys */
            if (state->role == NOISE_ROLE_INITIATOR) {
                err = noise_handshake_mix_dh
                    (state, state->dh_local_ephemeral, state->dh_remote_static);
            } else {
                err = noise_handshake_mix_dh
                    (state, state->dh_local_static, state->dh_remote_ephemeral);
            }
            break;
        case NOISE_TOKEN_SE:
            /* DH operation with initiator static and responder ephemeral keys */
            if (state->role == NOISE_ROLE_INITIATOR) {
                err = noise_handshake_mix_dh
                    (state, state->dh_local_static, state->dh_remote_ephemeral);
            } else {
                err = noise_handshake_mix_dh
                    (state, state->dh_local_ephemeral, state->dh_remote_static);
            }
            break;
        case NOISE_TOKEN_SS:
            /* DH operation with initiator and responder static keys */
            err = noise_handshake_mix_dh
                (state, state->dh_local_static, state->dh_remote_static);
            break;
        case NOISE_TOKEN_F:
            /* Generate a local hybrid keypair and add the encrypted public
               key to the message.  If we are running fixed vector tests,
               then the hybrid key may have already been provided. */
            if (!state->dh_local_hybrid || !state->dh_remote_hybrid)
                return NOISE_ERROR_INVALID_STATE;
            if (state->dh_remote_hybrid->key_type == NOISE_KEY_TYPE_NO_KEY) {
                noise_dhstate_set_role
                    (state->dh_local_hybrid, NOISE_ROLE_INITIATOR);
            } else {
                noise_dhstate_set_role
                    (state->dh_local_hybrid, NOISE_ROLE_RESPONDER);
            }
            if (!state->dh_fixed_hybrid) {
                err = noise_dhstate_generate_dependent_keypair
                    (state->dh_local_hybrid, state->dh_remote_hybrid);
            } else {
                /* Use the fixed hybrid key provided by the test harness.
                   To support New Hope we need to perform a dependent copy */
                state->dh_local_hybrid->key_type =
                    state->dh_fixed_hybrid->key_type;
                err = (*(state->dh_local_hybrid->copy))
                    (state->dh_local_hybrid, state->dh_fixed_hybrid,
                     state->dh_remote_hybrid);
            }
            if (err != NOISE_ERROR_NONE)
                break;
            len = state->dh_local_hybrid->public_key_len;
            mac_len = noise_symmetricstate_get_mac_length(state->symmetric);
            if (rest.max_size < (len + mac_len))
                return NOISE_ERROR_INVALID_LENGTH;
            memcpy(rest.data, state->dh_local_hybrid->public_key, len);
            rest.size += len;
            err = noise_symmetricstate_encrypt_and_hash(state->symmetric, &rest);
            if (err != NOISE_ERROR_NONE)
                break;
            break;
        case NOISE_TOKEN_FF:
            /* DH operation with local and remote hybrid keys */
            err = noise_handshake_mix_dh
                (state, state->dh_local_hybrid, state->dh_remote_hybrid);
            break;
        default:
            /* Unknown token code in the pattern.  This shouldn't happen.
               If it does, then abort immediately. */
            err = NOISE_ERROR_INVALID_STATE;
            break;
        }
        if (err != NOISE_ERROR_NONE)
            return err;
        message->size += rest.size;
        ++(state->tokens);
    }

    /* Add the payload to the message buffer and encrypt it */
    mac_len = noise_symmetricstate_get_mac_length(state->symmetric);
    if ((message->max_size - message->size) < mac_len)
        return NOISE_ERROR_INVALID_LENGTH;
    if (payload) {
        if ((message->max_size - message->size - mac_len) < payload->size)
            return NOISE_ERROR_INVALID_LENGTH;
        rest.data = message->data + message->size;
        rest.size = payload->size;
        rest.max_size = message->max_size - message->size;
        memcpy(rest.data, payload->data, payload->size);
    } else {
        rest.data = message->data + message->size;
        rest.size = 0;
        rest.max_size = message->max_size - message->size;
    }
    err = noise_symmetricstate_encrypt_and_hash(state->symmetric, &rest);
    if (err != NOISE_ERROR_NONE)
        return err;

    /* Return the final size to the caller */
    message->size += rest.size;
    return NOISE_ERROR_NONE;
}

/**
 * \brief Writes a message payload using a HandshakeState.
 *
 * \param state The HandshakeState object.
 * \param message Points to the message buffer to be populated with
 * handshake details and the message payload.
 * \param payload Points to the message payload to be sent, which can
 * be NULL if no payload is required.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state or \a message is NULL.
 * \return NOISE_ERROR_INVALID_STATE if noise_handshakestate_get_action() is 
 * not NOISE_ACTION_WRITE_MESSAGE.
 * \return NOISE_ERROR_INVALID_LENGTH if \a message is too small to contain
 * all of the bytes that need to be written to it.
 *
 * The \a message and \a payload buffers must not overlap in memory.
 *
 * The following example demonstrates how to write a handshake message
 * into the application's <tt>msgbuf</tt> array:
 *
 * \code
 * NoiseBuffer payload;
 * uint8_t payloadbuf[PAYLOAD_LEN];
 * // Format the message payload into "payloadbuf".
 * noise_buffer_set_input(payload, payloadbuf, sizeof(payloadbuf));
 *
 * uint8_t msgbuf[MSGBUF_MAX];
 * NoiseBuffer message;
 * noise_buffer_set_output(message, msgbuf, sizeof(msgbuf));
 * err = noise_handshakestate_write_message(state, &message, &payload);
 * // Transmit the message.size bytes starting at message.data if no error.
 * \endcode
 *
 * \sa noise_handshakestate_read_message(), noise_handshakestate_get_action()
 */
int noise_handshakestate_write_message
    (NoiseHandshakeState *state, NoiseBuffer *message, const NoiseBuffer *payload)
{
    int err;

    /* Validate the parameters */
    if (!message)
        return NOISE_ERROR_INVALID_PARAM;
    message->size = 0;
    if (!state || !(message->data))
        return NOISE_ERROR_INVALID_PARAM;
    if (payload && !(payload->data))
        return NOISE_ERROR_INVALID_PARAM;
    if (state->action != NOISE_ACTION_WRITE_MESSAGE)
        return NOISE_ERROR_INVALID_STATE;

    /* Perform the write */
    err = noise_handshakestate_write(state, message, payload);
    if (err != NOISE_ERROR_NONE) {
        /* Set the state to "failed" and empty the message buffer */
        state->action = NOISE_ACTION_FAILED;
        message->size = 0;
    }
    return err;
}

/**
 * \brief Internal implementation of noise_handshakestate_read_message().
 *
 * \param state The HandshakeState object.
 * \param message Points to the incoming handshake message to be unpacked.
 * \param payload Points to the buffer to fill with the message payload.
 * This can be NULL if the application does not need the message payload.
 *
 * \sa noise_handshakestate_read_message()
 */
static int noise_handshakestate_read
    (NoiseHandshakeState *state, NoiseBuffer *message, NoiseBuffer *payload)
{
    NoiseBuffer msg;
    NoiseBuffer msg2;
    size_t len;
    size_t mac_len;
    uint8_t token;
    int err;

    /* Make a copy of the message buffer.  As we process tokens, the copy
       will become shorter and shorter until only the payload is left. */
    msg = *message;

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
            if (msg.size < len)
                return NOISE_ERROR_INVALID_LENGTH;
            err = noise_symmetricstate_mix_hash
                (state->symmetric, msg.data, len);
            if (err != NOISE_ERROR_NONE)
                break;
            err = noise_dhstate_set_public_key
                (state->dh_remote_ephemeral, msg.data, len);
            if (err != NOISE_ERROR_NONE)
                break;
            if (noise_dhstate_is_null_public_key(state->dh_remote_ephemeral)) {
                /* The remote ephemeral key is null, which means that it is
                   not contributing anything to the security of the session
                   and is in fact downgrading the security to "none at all"
                   in some of the message patterns.  Reject all such keys. */
                return NOISE_ERROR_INVALID_PUBLIC_KEY;
            }
            msg.data += len;
            msg.size -= len;
            msg.max_size -= len;

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
            if (msg.size < len)
                return NOISE_ERROR_INVALID_LENGTH;
            msg2.data = msg.data;
            msg2.size = len;
            msg2.max_size = len;
            err = noise_symmetricstate_decrypt_and_hash
                (state->symmetric, &msg2);
            if (err != NOISE_ERROR_NONE)
                break;
            err = noise_dhstate_set_public_key
                (state->dh_remote_static, msg2.data, msg2.size);
            if (err != NOISE_ERROR_NONE)
                break;
            msg.data += len;
            msg.size -= len;
            msg.max_size -= len;
            break;
        case NOISE_TOKEN_EE:
            /* DH operation with initiator and responder ephemeral keys */
            err = noise_handshake_mix_dh
                (state, state->dh_local_ephemeral, state->dh_remote_ephemeral);
            break;
        case NOISE_TOKEN_ES:
            /* DH operation with initiator ephemeral and responder static keys */
            if (state->role == NOISE_ROLE_INITIATOR) {
                err = noise_handshake_mix_dh
                    (state, state->dh_local_ephemeral, state->dh_remote_static);
            } else {
                err = noise_handshake_mix_dh
                    (state, state->dh_local_static, state->dh_remote_ephemeral);
            }
            break;
        case NOISE_TOKEN_SE:
            /* DH operation with initiator static and responder ephemeral keys */
            if (state->role == NOISE_ROLE_INITIATOR) {
                err = noise_handshake_mix_dh
                    (state, state->dh_local_static, state->dh_remote_ephemeral);
            } else {
                err = noise_handshake_mix_dh
                    (state, state->dh_local_ephemeral, state->dh_remote_static);
            }
            break;
        case NOISE_TOKEN_SS:
            /* DH operation with initiator and responder static keys */
            err = noise_handshake_mix_dh
                (state, state->dh_local_static, state->dh_remote_static);
            break;
        case NOISE_TOKEN_F:
            /* Decrypt and save the remote hybrid key */
            if (!state->dh_local_hybrid || !state->dh_remote_hybrid)
                return NOISE_ERROR_INVALID_STATE;
            if (state->dh_local_hybrid->key_type == NOISE_KEY_TYPE_NO_KEY) {
                noise_dhstate_set_role
                    (state->dh_remote_hybrid, NOISE_ROLE_INITIATOR);
            } else {
                noise_dhstate_set_role
                    (state->dh_remote_hybrid, NOISE_ROLE_RESPONDER);
            }
            mac_len = noise_symmetricstate_get_mac_length(state->symmetric);
            len = state->dh_remote_hybrid->public_key_len + mac_len;
            if (msg.size < len)
                return NOISE_ERROR_INVALID_LENGTH;
            msg2.data = msg.data;
            msg2.size = len;
            msg2.max_size = len;
            err = noise_symmetricstate_decrypt_and_hash
                (state->symmetric, &msg2);
            if (err != NOISE_ERROR_NONE)
                break;
            err = noise_dhstate_set_public_key
                (state->dh_remote_hybrid, msg2.data, msg2.size);
            if (err != NOISE_ERROR_NONE)
                break;
            msg.data += len;
            msg.size -= len;
            msg.max_size -= len;
            if (noise_dhstate_is_null_public_key(state->dh_remote_hybrid)) {
                /* The remote hybrid key is null, which means that it is
                   not contributing anything to the security of the session
                   and is in fact downgrading the security to "none at all"
                   in some of the message patterns.  Reject all such keys. */
                err = NOISE_ERROR_INVALID_PUBLIC_KEY;
                break;
            }
            break;
        case NOISE_TOKEN_FF:
            /* DH operation with local and remote hybrid keys */
            err = noise_handshake_mix_dh
                (state, state->dh_local_hybrid, state->dh_remote_hybrid);
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

    /* Decrypt the remaining bytes and return them in the payload buffer */
    mac_len = noise_symmetricstate_get_mac_length(state->symmetric);
    err = noise_symmetricstate_decrypt_and_hash(state->symmetric, &msg);
    if (err != NOISE_ERROR_NONE)
        return err;
    if (payload) {
        if (msg.size > payload->max_size)
            return NOISE_ERROR_INVALID_LENGTH;
        memcpy(payload->data, msg.data, msg.size);
        payload->size = msg.size;
    }
    return NOISE_ERROR_NONE;
}

/**
 * \brief Reads a message payload using a HandshakeState.
 *
 * \param state The HandshakeState object.
 * \param message Points to the incoming handshake message to be unpacked.
 * \param payload Points to the buffer to fill with the message payload.
 * This can be NULL if the application does not need the message payload.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state or \a message is NULL.
 * \return NOISE_ERROR_INVALID_STATE if noise_handshakestate_get_action() is 
 * not NOISE_ACTION_READ_MESSAGE.
 * \return NOISE_ERROR_INVALID_LENGTH if the size of \a message is incorrect
 * for the type of handshake packet that we expect.
 * \return NOISE_ERROR_INVALID_LENGTH if the size of \a payload is too small
 * to contain all of the payload bytes that were present in the \a message.
 * \return NOISE_ERROR_MAC_FAILURE if the \a message failed to authenticate,
 * which terminates the handshake.
 * \return NOISE_ERROR_PUBLIC_KEY if an invalid remote public key is seen
 * during the processing of this message.
 *
 * If \a payload is NULL, then the message payload will be authenticated
 * and then discarded, regardless of its length.  If the application was
 * expecting an empty payload and wants to verify that, then \a payload
 * should point to a non-NULL zero-length buffer.
 *
 * The \a message and \a payload buffers must not overlap in memory.
 *
 * The \a message buffer will be modified by this function to decrypt
 * sub-components while it is being processed.  The contents will be
 * cleared just before the function exits to avoid leaking decrypted
 * message data other than the \a payload.
 *
 * \sa noise_handshakestate_write_message(), noise_handshakestate_get_action()
 */
int noise_handshakestate_read_message
    (NoiseHandshakeState *state, NoiseBuffer *message, NoiseBuffer *payload)
{
    int err;

    /* Validate the parameters */
    if (payload) {
        if (!(payload->data))
            return NOISE_ERROR_INVALID_PARAM;
        payload->size = 0;
    }
    if (!state || !message || !(message->data))
        return NOISE_ERROR_INVALID_PARAM;
    if (message->size > message->max_size)
        return NOISE_ERROR_INVALID_LENGTH;
    if (state->action != NOISE_ACTION_READ_MESSAGE)
        return NOISE_ERROR_INVALID_STATE;

    /* Perform the read */
    err = noise_handshakestate_read(state, message, payload);
    noise_clean(message->data, message->size);
    if (err != NOISE_ERROR_NONE)
        state->action = NOISE_ACTION_FAILED;
    return err;
}

/**
 * \brief Splits the transport encryption CipherState objects out of
 * this HandshakeState object.
 *
 * \param state The HandshakeState object.
 * \param send Points to the variable where to place the pointer to the
 * CipherState object to use to send packets from local to remote.
 * This can be NULL if the application is using a one-way handshake pattern.
 * \param receive Points to the variable where to place the pointer to the
 * CipherState object to use to receive packets from the remote to local.
 * This can be NULL if the application is using a one-way handshake pattern.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state is NULL.
 * \return NOISE_ERROR_INVALID_PARAM if both \a send and \a receive are NULL.
 * \return NOISE_ERROR_INVALID_STATE if the \a state has already been split
 * or the handshake protocol has not completed successfully yet.
 * \return NOISE_ERROR_NO_MEMORY if there is insufficient memory to create
 * the new CipherState objects.
 *
 * Once a HandshakeState has been split, it is effectively finished and
 * cannot be used for future handshake operations.  If those operations are
 * invoked, the relevant functions will return NOISE_ERROR_INVALID_STATE.
 *
 * The \a send object should be used to protect messages from the local
 * side to the remote side, and the \a receive object should be used to
 * protect messages from the remote side to the local side.
 *
 * If the handshake pattern is one-way, then the application should call
 * noise_cipherstate_free() on the object that is not needed.  Alternatively,
 * the application can pass NULL to noise_handshakestate_split() as the
 * \a send or \a receive argument and the second CipherState will not be
 * created at all.
 *
 * \sa noise_handshakestate_get_handshake_hash()
 */
int noise_handshakestate_split
    (NoiseHandshakeState *state, NoiseCipherState **send, NoiseCipherState **receive)
{
    int swap;
    int err;

    /* Validate the parameters */
    if (!state)
        return NOISE_ERROR_INVALID_PARAM;
    if (!send && !receive)
        return NOISE_ERROR_INVALID_PARAM;
    if (state->action != NOISE_ACTION_SPLIT)
        return NOISE_ERROR_INVALID_STATE;
    if (!state->symmetric->cipher)
        return NOISE_ERROR_INVALID_STATE;

    /* Do we need to swap the CipherState objects for the role? */
    swap = (state->role == NOISE_ROLE_RESPONDER);

    /* Split the CipherState objects out of the SymmetricState */
    if (swap)
        err = noise_symmetricstate_split(state->symmetric, receive, send);
    else
        err = noise_symmetricstate_split(state->symmetric, send, receive);
    if (err == NOISE_ERROR_NONE)
        state->action = NOISE_ACTION_COMPLETE;
    return err;
}

/**
 * \brief Gets the handshake hash value once the handshake ends.
 *
 * \param state The HandshakeState object.
 * \param hash The buffer to receive the handshake hash value.
 * \param max_len The maximum length of the \a hash buffer.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a state or \a hash is NULL.
 * \return NOISE_ERROR_INVALID_STATE if the handshake has not successfully
 * completed yet.
 *
 * If \a max_len is greater than the length of the handshake hash,
 * then the extra bytes will be filled with zeroes.  If \a max_len
 * is less than the length of the handshake hash, then the value
 * will be truncated to the first \a max_len bytes.  Handshake hashes
 * are typically 32 or 64 bytes in length, depending upon the hash
 * algorithm that was used during the protocol.
 *
 * The handshake hash can be used to implement "channel binding".
 * The value will be a unique identifier for the session.
 *
 * \note The handshake hash is generated from publicly-known values
 * in the handshake.  If the application needs a unique secret identifier,
 * then it should combine the handshake hash with other randomly generated
 * data that is sent encrypted during the session.
 *
 * \sa noise_handshakestate_split()
 */
int noise_handshakestate_get_handshake_hash
    (const NoiseHandshakeState *state, uint8_t *hash, size_t max_len)
{
    size_t hash_len;

    /* Validate the parameters */
    if (!state || !hash)
        return NOISE_ERROR_INVALID_PARAM;
    if (state->action != NOISE_ACTION_SPLIT &&
            state->action != NOISE_ACTION_COMPLETE)
        return NOISE_ERROR_INVALID_STATE;

    /* Copy the handshake hash into the supplied buffer */
    hash_len = noise_hashstate_get_hash_length(state->symmetric->hash);
    if (hash_len <= max_len) {
        memcpy(hash, state->symmetric->h, hash_len);
        memset(hash + hash_len, 0, max_len - hash_len);
    } else {
        memcpy(hash, state->symmetric->h, max_len);
    }
    return NOISE_ERROR_NONE;
}

/**@}*/
