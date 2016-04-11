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
#include "crypto/curve448/curve448.h"

static int noise_curve448_generate_keypair
    (const NoiseDHState *state, uint8_t *private_key, uint8_t *public_key)
{
    /* Curve448 base point from RFC 7748, 5 in little-endian order */
    static uint8_t const basepoint[56] = {5};

    /* Generate 56 bytes of random data and modify bits to put it
       into the correct form for Curve448 private keys.  This is the
       decodeScalar448() function from section 5 of RFC 7748 */
    noise_rand_bytes(private_key, 56);
    private_key[0] &= 0xFC;
    private_key[55] |= 0x80;

    /* Evaluate the curve operation to derive the public key */
    curve448_eval(public_key, private_key, basepoint);
    return NOISE_ERROR_NONE;
}

static int noise_curve448_calculate
    (const NoiseDHState *state, uint8_t *shared_key,
     const uint8_t *private_key, const uint8_t *public_key)
{
    int result = curve448_eval(shared_key, private_key, public_key);
    return NOISE_ERROR_INVALID_DH_KEY & (result - 1);
}

NoiseDHState *noise_curve448_new(void)
{
    NoiseDHState *state = noise_new(NoiseDHState);
    if (!state)
        return 0;
    state->dh_id = NOISE_DH_CURVE448;
    state->private_key_len = 56;
    state->public_key_len = 56;
    state->shared_key_len = 56;
    state->generate_keypair = noise_curve448_generate_keypair;
    state->calculate = noise_curve448_calculate;
    return state;
}
