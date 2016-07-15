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
#include "crypto/sha2/sha256.h"
#include <string.h>

#define TYPE_NONE   0
#define TYPE_ALICE  1
#define TYPE_BOB    2

#define MAX_OF(a, b) ((a) > (b) ? (a) : (b))

typedef struct NoiseNewHopeState_s
{
    struct NoiseDHState_s parent;
    poly private_key;
    uint8_t public_key[MAX_OF(NEWHOPE_SENDABYTES, NEWHOPE_SENDBBYTES)];
    int type;

} NoiseNewHopeState;

static void noise_newhope_generate_keypair(NoiseDHState *state)
{
    NoiseNewHopeState *st = (NoiseNewHopeState *)state;
    if (st->parent.mutual && st->parent.mutual->key_type != NOISE_KEY_TYPE_NO_KEY) {
        /* We already have a mutual public key for Alice, so we are
         * generating the public key and shared secret for Bob */
        newhope_sharedb((uint8_t *)&(st->private_key), st->public_key,
                        st->parent.mutual->public_key);
        st->parent.public_key_len = NEWHOPE_SENDBBYTES;
        st->type = TYPE_BOB;
    } else {
        /* No mutual public key, so generate the keypair for Alice */
        newhope_keygen(st->public_key, &(st->private_key));
        st->parent.public_key_len = NEWHOPE_SENDABYTES;
        st->type = TYPE_ALICE;

        /* Change the size of the mutual public key for Bob in preparation
         * for reading the incoming value off the wire later */
        if (st->parent.mutual)
            st->parent.mutual->public_key_len = NEWHOPE_SENDBBYTES;
    }
}

static int noise_newhope_validate_keypair
        (const NoiseDHState *state, const uint8_t *private_key,
         const uint8_t *public_key)
{
    /* Cannot set private keys for New Hope - can only generate them */
    return NOISE_ERROR_INVALID_PRIVATE_KEY;
}

static int noise_newhope_validate_public_key
        (const NoiseDHState *state, const uint8_t *public_key)
{
    /* Nothing to do here */
    return NOISE_ERROR_NONE;
}

static int noise_newhope_derive_public_key
        (const NoiseDHState *state, const uint8_t *private_key,
         uint8_t *public_key)
{
    /* Cannot set private keys for New Hope - can only generate them */
    return NOISE_ERROR_INVALID_PRIVATE_KEY;
}

static int noise_newhope_calculate
    (const NoiseDHState *private_key_state,
     const NoiseDHState *public_key_state,
     uint8_t *shared_key)
{
    NoiseNewHopeState *priv_st = (NoiseNewHopeState *)private_key_state;
    NoiseNewHopeState *pub_st = (NoiseNewHopeState *)public_key_state;
    if (priv_st->type == TYPE_BOB) {
        /* We already generated the shared secret for Bob when we
         * generated the "keypair" for him. */
        memcpy(shared_key, &(priv_st->private_key), 32);
    } else {
        /* Generate the shared secret for Alice */
        newhope_shareda(shared_key, &(priv_st->private_key), pub_st->public_key);
    }
    return NOISE_ERROR_NONE;
}

NoiseDHState *noise_newhope_new(void)
{
    NoiseNewHopeState *state = noise_new(NoiseNewHopeState);
    if (!state)
        return 0;
    state->parent.dh_id = NOISE_DH_NEWHOPE;
    state->parent.ephemeral_only = 1;
    state->parent.nulls_allowed = 0;
    state->parent.private_key_len = sizeof(poly);
    state->parent.public_key_len = NEWHOPE_SENDABYTES;
    state->parent.shared_key_len = 32;
    state->parent.private_key = (uint8_t *)&(state->private_key);
    state->parent.public_key = state->public_key;
    state->parent.generate_keypair = noise_newhope_generate_keypair;
    state->parent.validate_keypair = noise_newhope_validate_keypair;
    state->parent.validate_public_key = noise_newhope_validate_public_key;
    state->parent.derive_public_key = noise_newhope_derive_public_key;
    state->parent.calculate = noise_newhope_calculate;
    state->type = TYPE_NONE;
    return &(state->parent);
}

/* Implementation of random number generation needed by New Hope */
void randombytes(unsigned char *x,unsigned long long xlen)
{
    if (xlen == 32) {
        /* Generating seed material that may be sent in the clear.
         * Hash the kernel data with SHA256 in case the kernel RNG
         * is watermarking random data output */
        sha256_context_t hash;
        noise_rand_bytes(x, 32);
        sha256_reset(&hash);
        sha256_update(&hash, x, 32);
        sha256_finish(&hash, x);
        noise_clean(&hash, sizeof(hash));
    } else {
        /* New Hope currently only requests random data of size 32 */
        noise_rand_bytes(x, (size_t)xlen);
    }
}
