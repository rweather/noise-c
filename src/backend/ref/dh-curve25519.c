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
#include "crypto/ed25519/ed25519.h"

/* We use ed25519's faster curved25519_scalarmult_basepoint() function
   when deriving a public key from a private key.  Unfortunately ed25519
   doesn't have an equivalent function for general curve25519 calculations
   so we fall back to the curve25519-donna implementation for that. */

int curve25519_donna(uint8_t *mypublic, const uint8_t *secret, const uint8_t *basepoint);

typedef struct
{
    struct NoiseDHState_s parent;
    uint8_t private_key[32];
    uint8_t public_key[32];

} NoiseCurve25519State;

static void noise_curve25519_generate_keypair(NoiseDHState *state)
{
    NoiseCurve25519State *st = (NoiseCurve25519State *)state;
    noise_rand_bytes(st->private_key, 32);
    st->private_key[0] &= 0xF8;
    st->private_key[31] = (st->private_key[31] & 0x7F) | 0x40;
    curved25519_scalarmult_basepoint(st->public_key, st->private_key);
}

static int noise_curve25519_validate_keypair
        (const NoiseDHState *state, const uint8_t *private_key,
         const uint8_t *public_key)
{
    /* Check that the public key actually corresponds to the private key */
    uint8_t temp[32];
    int equal;
    curved25519_scalarmult_basepoint(temp, private_key);
    equal = noise_is_equal(temp, public_key, 32);
    return NOISE_ERROR_INVALID_PUBLIC_KEY & (equal - 1);
}

static int noise_curve25519_validate_public_key
        (const NoiseDHState *state, const uint8_t *public_key)
{
    /* Nothing to do here yet */
    return NOISE_ERROR_NONE;
}

static int noise_curve25519_derive_public_key
        (const NoiseDHState *state, const uint8_t *private_key,
         uint8_t *public_key)
{
    curved25519_scalarmult_basepoint(public_key, private_key);
    return NOISE_ERROR_NONE;
}

static int noise_curve25519_calculate
    (const NoiseDHState *private_key_state,
     const NoiseDHState *public_key_state,
     uint8_t *shared_key)
{
    /* Do we need to check that the public key is less than 2^255 - 19? */
    curve25519_donna(shared_key, private_key_state->private_key,
                     public_key_state->public_key);
    return NOISE_ERROR_NONE;
}

NoiseDHState *noise_curve25519_new(void)
{
    NoiseCurve25519State *state = noise_new(NoiseCurve25519State);
    if (!state)
        return 0;
    state->parent.dh_id = NOISE_DH_CURVE25519;
    state->parent.private_key_len = 32;
    state->parent.public_key_len = 32;
    state->parent.shared_key_len = 32;
    state->parent.private_key = state->private_key;
    state->parent.public_key = state->public_key;
    state->parent.generate_keypair = noise_curve25519_generate_keypair;
    state->parent.validate_keypair = noise_curve25519_validate_keypair;
    state->parent.validate_public_key = noise_curve25519_validate_public_key;
    state->parent.derive_public_key = noise_curve25519_derive_public_key;
    state->parent.calculate = noise_curve25519_calculate;
    return &(state->parent);
}

/* Choose the version of curve25519-donna based on the word size */
#if __WORDSIZE == 64 && defined(__GNUC__)
#include "crypto/donna/curve25519-donna-c64.c"
#else
#include "crypto/donna/curve25519-donna.c"
#endif
