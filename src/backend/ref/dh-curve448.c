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

#include <protocol/internal.h>
#include <crypto/curve448/curve448.c>
#include <string.h>

typedef struct
{
    struct NoiseDHState_s parent;
    uint8_t private_key[56];
    uint8_t public_key[56];

} NoiseCurve448State;

/* Curve448 base point from RFC 7748, 5 in little-endian order */
static uint8_t const basepoint[56] = {5};

static int noise_curve448_generate_keypair
    (NoiseDHState *state, const NoiseDHState *other)
{
    NoiseCurve448State *st = (NoiseCurve448State *)state;

    /* Generate 56 bytes of random data and modify bits to put it
       into the correct form for Curve448 private keys.  This is the
       decodeScalar448() function from section 5 of RFC 7748 */
    noise_rand_bytes(st->private_key, 56);
    st->private_key[0] &= 0xFC;
    st->private_key[55] |= 0x80;

    /* Evaluate the curve operation to derive the public key */
    curve448_eval(st->public_key, st->private_key, basepoint);
    return NOISE_ERROR_NONE;
}

static int noise_curve448_set_keypair
        (NoiseDHState *state, const uint8_t *private_key,
         const uint8_t *public_key)
{
    /* Check that the public key actually corresponds to the private key */
    NoiseCurve448State *st = (NoiseCurve448State *)state;
    uint8_t temp[56];
    int equal;
    curve448_eval(temp, private_key, basepoint);
    equal = noise_is_equal(temp, public_key, 56);
    memcpy(st->private_key, private_key, 56);
    memcpy(st->public_key, public_key, 56);
    return NOISE_ERROR_INVALID_PUBLIC_KEY & (equal - 1);
}

static int noise_curve448_set_keypair_private
        (NoiseDHState *state, const uint8_t *private_key)
{
    NoiseCurve448State *st = (NoiseCurve448State *)state;
    memcpy(st->private_key, private_key, 56);
    curve448_eval(st->public_key, st->private_key, basepoint);
    return NOISE_ERROR_NONE;
}

static int noise_curve448_validate_public_key
        (const NoiseDHState *state, const uint8_t *public_key)
{
    /* Nothing to do here yet */
    return NOISE_ERROR_NONE;
}

static int noise_curve448_copy
    (NoiseDHState *state, const NoiseDHState *from, const NoiseDHState *other)
{
    NoiseCurve448State *st = (NoiseCurve448State *)state;
    const NoiseCurve448State *from_st = (const NoiseCurve448State *)from;
    memcpy(st->private_key, from_st->private_key, 56);
    memcpy(st->public_key, from_st->public_key, 56);
    return NOISE_ERROR_NONE;
}

static int noise_curve448_calculate
    (const NoiseDHState *private_key_state,
     const NoiseDHState *public_key_state,
     uint8_t *shared_key)
{
    int result = curve448_eval
        (shared_key, private_key_state->private_key,
         public_key_state->public_key);
    return NOISE_ERROR_INVALID_PUBLIC_KEY & (result - 1);
}

NoiseDHState *noise_curve448_new(void)
{
    NoiseCurve448State *state = noise_new(NoiseCurve448State);
    if (!state)
        return 0;
    state->parent.dh_id = NOISE_DH_CURVE448;
    state->parent.nulls_allowed = 1;
    state->parent.private_key_len = 56;
    state->parent.public_key_len = 56;
    state->parent.shared_key_len = 56;
    state->parent.private_key = state->private_key;
    state->parent.public_key = state->public_key;
    state->parent.generate_keypair = noise_curve448_generate_keypair;
    state->parent.set_keypair = noise_curve448_set_keypair;
    state->parent.set_keypair_private = noise_curve448_set_keypair_private;
    state->parent.validate_public_key = noise_curve448_validate_public_key;
    state->parent.copy = noise_curve448_copy;
    state->parent.calculate = noise_curve448_calculate;
    return &(state->parent);
}
