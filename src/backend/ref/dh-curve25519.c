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

int curve25519_donna(uint8_t *mypublic, const uint8_t *secret, const uint8_t *basepoint);

static int noise_curve25519_generate_keypair
    (const NoiseDHState *state, uint8_t *private_key, uint8_t *public_key)
{
    static uint8_t const basepoint[32] = {9};
    noise_rand_bytes(private_key, 32);
    private_key[0] &= 0xF8;
    private_key[31] = (private_key[31] & 0x7F) | 0x40;
    curve25519_donna(public_key, private_key, basepoint);
    return NOISE_ERROR_NONE;
}

static int noise_curve25519_calculate
    (const NoiseDHState *state, uint8_t *shared_key,
     const uint8_t *private_key, const uint8_t *public_key)
{
    /* Do we need to check that the public key is less than 2^255 - 19? */
    curve25519_donna(shared_key, private_key, public_key);
    return NOISE_ERROR_NONE;
}

NoiseDHState *noise_curve25519_new(void)
{
    NoiseDHState *state = noise_new(NoiseDHState);
    if (!state)
        return 0;
    state->dh_id = NOISE_DH_CURVE25519;
    state->private_key_len = 32;
    state->public_key_len = 32;
    state->shared_key_len = 32;
    state->generate_keypair = noise_curve25519_generate_keypair;
    state->calculate = noise_curve25519_calculate;
    return state;
}
