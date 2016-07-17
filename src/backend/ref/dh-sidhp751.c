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
#include "crypto/sidh/SIDH.h"
#include <string.h>

#define SIDH_PWORD_BITS         768
#define SIDH_OWORD_BITS         384

#define SIDH_BITS_TO_BYTES(b)   (((b) + 7) / 8)

#define SIDH_PRIVATE_KEY_LEN    SIDH_BITS_TO_BYTES(SIDH_OWORD_BITS)
#define SIDH_PUBLIC_KEY_LEN     SIDH_BITS_TO_BYTES(SIDH_PWORD_BITS * 8)
#define SIDH_SHARED_KEY_LEN     SIDH_BITS_TO_BYTES(SIDH_PWORD_BITS * 2)

#define SIDH_TYPE_ALICE         1
#define SIDH_TYPE_BOB           2

typedef struct NoiseSIDHState_s
{
    struct NoiseDHState_s parent;
    PCurveIsogenyStruct curve_data;
    uint8_t private_key[SIDH_PRIVATE_KEY_LEN];
    uint8_t public_key[SIDH_PUBLIC_KEY_LEN];
    int type;

} NoiseSIDHState;

static void noise_sidhp751_generate_keypair(NoiseDHState *state)
{
    NoiseSIDHState *st = (NoiseSIDHState *)state;
    if (st->parent.mutual && st->parent.mutual->key_type != NOISE_KEY_TYPE_NO_KEY) {
        /* We already have a mutual public key for Alice, so we are
         * generating the keypair for Bob */
        KeyGeneration_B(st->private_key, st->public_key, st->curve_data);
        st->type = SIDH_TYPE_BOB;
    } else {
        /* No mutual public key, so generate the keypair for Alice */
        KeyGeneration_A(st->private_key, st->public_key, st->curve_data);
        st->type = SIDH_TYPE_ALICE;

        /* Change the other object to "Bob" to validate the public key later */
        if (st->parent.mutual)
            ((NoiseSIDHState *)(st->parent.mutual))->type = SIDH_TYPE_BOB;
    }
}

static int noise_sidhp751_validate_keypair
        (const NoiseDHState *state, const uint8_t *private_key,
         const uint8_t *public_key)
{
    /* Cannot set private keys for SIDH - can only generate them */
    return NOISE_ERROR_INVALID_PRIVATE_KEY;
}

static int noise_sidhp751_validate_public_key
        (const NoiseDHState *state, const uint8_t *public_key)
{
    NoiseSIDHState *st = (NoiseSIDHState *)state;
    CRYPTO_STATUS status;
    bool valid = false;
    if (st->type == SIDH_TYPE_ALICE) {
        status = Validate_PKA
            ((uint8_t *)public_key, &valid, st->curve_data);
    } else {
        status = Validate_PKB
            ((uint8_t *)public_key, &valid, st->curve_data);
    }
    if (status != CRYPTO_SUCCESS || !valid)
        return NOISE_ERROR_INVALID_PUBLIC_KEY;
    return NOISE_ERROR_NONE;
}

static int noise_sidhp751_derive_public_key
        (const NoiseDHState *state, const uint8_t *private_key,
         uint8_t *public_key)
{
    /* Cannot set private keys for SIDH - can only generate them */
    return NOISE_ERROR_INVALID_PRIVATE_KEY;
}

static int noise_sidhp751_calculate
    (const NoiseDHState *private_key_state,
     const NoiseDHState *public_key_state,
     uint8_t *shared_key)
{
    NoiseSIDHState *priv_st = (NoiseSIDHState *)private_key_state;
    NoiseSIDHState *pub_st = (NoiseSIDHState *)public_key_state;
    CRYPTO_STATUS status;
    if (priv_st->type == SIDH_TYPE_ALICE) {
        status = SecretAgreement_A
            (priv_st->private_key, pub_st->public_key, shared_key,
             priv_st->curve_data);
    } else {
        status = SecretAgreement_B
            (priv_st->private_key, pub_st->public_key, shared_key,
             priv_st->curve_data);
    }
    if (status != CRYPTO_SUCCESS)
        return NOISE_ERROR_INVALID_PUBLIC_KEY;
    return NOISE_ERROR_NONE;
}

static void noise_sidhp751_destroy(NoiseDHState *state)
{
    NoiseSIDHState *st = (NoiseSIDHState *)state;
    if (st->curve_data) {
        SIDH_curve_free(st->curve_data);
        st->curve_data = 0;
    }
}

static CRYPTO_STATUS noise_sidhp751_random
    (unsigned int nbytes, unsigned char *random_array)
{
    noise_rand_bytes(random_array, nbytes);
    return CRYPTO_SUCCESS;
}

NoiseDHState *noise_sidhp751_new(void)
{
    NoiseSIDHState *state = noise_new(NoiseSIDHState);
    CRYPTO_STATUS status;
    if (!state)
        return 0;
    state->curve_data = SIDH_curve_allocate(&CurveIsogeny_SIDHp751);
    if (!state->curve_data) {
        noise_free(state, state->parent.size);
        return 0;
    }
    status = SIDH_curve_initialize
        (state->curve_data, noise_sidhp751_random, &CurveIsogeny_SIDHp751);
    if (status != CRYPTO_SUCCESS) {
        SIDH_curve_free(state->curve_data);
        noise_free(state, state->parent.size);
        return 0;
    }
    state->parent.dh_id = NOISE_DH_SIDHP751;
    state->parent.ephemeral_only = 1;
    state->parent.nulls_allowed = 0;
    state->parent.private_key_len = SIDH_PRIVATE_KEY_LEN;
    state->parent.public_key_len = SIDH_PUBLIC_KEY_LEN;
    state->parent.shared_key_len = SIDH_SHARED_KEY_LEN;
    state->parent.private_key = state->private_key;
    state->parent.public_key = state->public_key;
    state->parent.generate_keypair = noise_sidhp751_generate_keypair;
    state->parent.validate_keypair = noise_sidhp751_validate_keypair;
    state->parent.validate_public_key = noise_sidhp751_validate_public_key;
    state->parent.derive_public_key = noise_sidhp751_derive_public_key;
    state->parent.calculate = noise_sidhp751_calculate;
    state->parent.destroy = noise_sidhp751_destroy;
    state->type = SIDH_TYPE_ALICE;
    return &(state->parent);
}
