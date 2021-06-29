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
#include "crypto/newhope/newhope.h"
#include <string.h>

#define MAX_OF(a, b) ((a) > (b) ? (a) : (b))

typedef struct NoiseNewHopeState_s
{
    struct NoiseDHState_s parent;
    uint8_t random_data[64];
    uint16_t generated;
    poly private_key;
    uint8_t public_key[MAX_OF(NEWHOPE_SENDABYTES, NEWHOPE_SENDBBYTES)];

} NoiseNewHopeState;

static int noise_newhope_generate_keypair
    (NoiseDHState *state, const NoiseDHState *other)
{
    NoiseNewHopeState *st = (NoiseNewHopeState *)state;
    NoiseNewHopeState *os = (NoiseNewHopeState *)other;
    if (st->parent.role == NOISE_ROLE_RESPONDER) {
        /* Generating the keypair for Bob relative to Alice's parameters */
        if (!os || os->parent.key_type == NOISE_KEY_TYPE_NO_KEY)
            return NOISE_ERROR_INVALID_STATE;
        noise_rand_bytes(st->random_data, st->parent.private_key_len);
        newhope_sharedb((uint8_t *)&(st->private_key), st->public_key,
                        os->public_key, st->random_data);
    } else {
        /* Generate the keypair for Alice */
        noise_rand_bytes(st->random_data, st->parent.private_key_len);
        newhope_keygen(st->public_key, &(st->private_key), st->random_data);
    }
    st->generated = 1;
    return NOISE_ERROR_NONE;
}

static int noise_newhope_set_keypair_private
        (NoiseDHState *state, const uint8_t *private_key)
{
    /* The "private key" is actually the 64 or 32 bytes of random seed data */
    NoiseNewHopeState *st = (NoiseNewHopeState *)state;
    memcpy(st->random_data, private_key, st->parent.private_key_len);
    if (st->parent.role == NOISE_ROLE_RESPONDER) {
        /* Setting the keypair for Bob.  Because we don't know the public
           key for Alice we cannot generate the public key for Bob yet.
           Defer key generation until the call to calculate() */
        memset(st->public_key, 0, sizeof(st->public_key));
        st->generated = 0;
    } else {
        /* Generate the key pair for Alice from the supplied random data */
        newhope_keygen(st->public_key, &(st->private_key), st->random_data);
        st->generated = 1;
    }
    return NOISE_ERROR_NONE;
}

static int noise_newhope_set_keypair
        (NoiseDHState *state, const uint8_t *private_key,
         const uint8_t *public_key)
{
    /* Ignore the public key and re-generate from the private key */
    return noise_newhope_set_keypair_private(state, private_key);
}

static int noise_newhope_validate_public_key
        (const NoiseDHState *state, const uint8_t *public_key)
{
    /* Nothing to do here */
    return NOISE_ERROR_NONE;
}

static int noise_newhope_copy
    (NoiseDHState *state, const NoiseDHState *from, const NoiseDHState *other)
{
    NoiseNewHopeState *st = (NoiseNewHopeState *)state;
    const NoiseNewHopeState *from_st = (const NoiseNewHopeState *)from;
    const NoiseNewHopeState *other_st = (const NoiseNewHopeState *)other;
    memcpy(st->random_data, from_st->random_data, sizeof(st->random_data));
    st->generated = from_st->generated;
    memcpy(&(st->private_key), &(from_st->private_key),
           sizeof(st->private_key));
    memcpy(st->public_key, from_st->public_key, sizeof(st->public_key));
    if (st->parent.role == NOISE_ROLE_RESPONDER && !(st->generated) &&
            from_st->parent.key_type == NOISE_KEY_TYPE_KEYPAIR && other_st) {
        /* We are copying a key pair for Bob but we didn't have the
           public key for Alice when we set Bob's private key.  We have
           the public key for Alice now so generate Bob's actual key */
        newhope_sharedb((uint8_t *)&(st->private_key), st->public_key,
                        other_st->public_key, st->random_data);
        st->generated = 1;
    }
    return NOISE_ERROR_NONE;
}

static int noise_newhope_calculate
    (const NoiseDHState *private_key_state,
     const NoiseDHState *public_key_state,
     uint8_t *shared_key)
{
    NoiseNewHopeState *priv_st = (NoiseNewHopeState *)private_key_state;
    NoiseNewHopeState *pub_st = (NoiseNewHopeState *)public_key_state;
    if (priv_st->parent.role == NOISE_ROLE_RESPONDER) {
        if (!priv_st->generated) {
            /* Bob's private key was set explicitly, which means that we
               didn't know Alice's public key at the time.  We do know
               Alice's public key now, so generate Bob's key pair now */
            newhope_sharedb(shared_key, priv_st->public_key,
                            pub_st->public_key, priv_st->random_data);
        } else {
            /* We already generated the shared secret for Bob when we
             * generated the "keypair" for him. */
            memcpy(shared_key, &(priv_st->private_key), 32);
        }
    } else {
        /* Generate the shared secret for Alice */
        newhope_shareda(shared_key, &(priv_st->private_key), pub_st->public_key);
    }
    return NOISE_ERROR_NONE;
}

static void noise_newhope_change_role(NoiseDHState *state)
{
    /* Change the size of the keys based on the object's role */
    if (state->role == NOISE_ROLE_RESPONDER) {
        state->private_key_len = 32;
        state->public_key_len = NEWHOPE_SENDBBYTES;
    } else {
        state->private_key_len = 64;
        state->public_key_len = NEWHOPE_SENDABYTES;
    }
}

NoiseDHState *noise_newhope_new(void)
{
    NoiseNewHopeState *state = noise_new(NoiseNewHopeState);
    if (!state)
        return 0;
    state->parent.dh_id = NOISE_DH_NEWHOPE;
    state->parent.ephemeral_only = 1;
    state->parent.nulls_allowed = 0;
    state->parent.private_key_len = 64;
    state->parent.public_key_len = NEWHOPE_SENDABYTES;
    state->parent.shared_key_len = 32;
    state->parent.private_key = state->random_data;
    state->parent.public_key = state->public_key;
    state->parent.generate_keypair = noise_newhope_generate_keypair;
    state->parent.set_keypair = noise_newhope_set_keypair;
    state->parent.set_keypair_private = noise_newhope_set_keypair_private;
    state->parent.validate_public_key = noise_newhope_validate_public_key;
    state->parent.copy = noise_newhope_copy;
    state->parent.calculate = noise_newhope_calculate;
    state->parent.change_role = noise_newhope_change_role;
    return &(state->parent);
}
