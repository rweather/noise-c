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

typedef struct
{
    struct NoiseSignState_s parent;
    uint8_t private_key[32];
    uint8_t public_key[32];

} NoiseEd25519State;

static void noise_ed25519_generate_keypair(NoiseSignState *state)
{
    NoiseEd25519State *st = (NoiseEd25519State *)state;
    noise_rand_bytes(st->private_key, 32);
    st->private_key[0] &= 0xF8;
    st->private_key[31] = (st->private_key[31] & 0x7F) | 0x40;
    ed25519_publickey(st->private_key, st->public_key);
}

static int noise_ed25519_validate_keypair
        (const NoiseSignState *state, const uint8_t *private_key,
         const uint8_t *public_key)
{
    /* Check that the public key actually corresponds to the private key */
    uint8_t temp[32];
    int equal;
    ed25519_publickey(private_key, temp);
    equal = noise_is_equal(temp, public_key, 32);
    return NOISE_ERROR_INVALID_PUBLIC_KEY & (equal - 1);
}

static int noise_ed25519_validate_public_key
        (const NoiseSignState *state, const uint8_t *public_key)
{
    /* Nothing to do here yet */
    return NOISE_ERROR_NONE;
}

static int noise_ed25519_derive_public_key
        (const NoiseSignState *state, const uint8_t *private_key,
         uint8_t *public_key)
{
    ed25519_publickey(private_key, public_key);
    return NOISE_ERROR_NONE;
}

static int noise_ed25519_sign
        (const NoiseSignState *state, const uint8_t *message,
         size_t message_len, uint8_t *signature)
{
    const NoiseEd25519State *st = (const NoiseEd25519State *)state;
    ed25519_sign(message, message_len, st->private_key,
                 st->public_key, signature);
    return NOISE_ERROR_NONE;
}

static int noise_ed25519_verify
        (const NoiseSignState *state, const uint8_t *message,
         size_t message_len, const uint8_t *signature)
{
    const NoiseEd25519State *st = (const NoiseEd25519State *)state;
    int result = ed25519_sign_open
        (message, message_len, st->public_key, signature);
    return result ? NOISE_ERROR_INVALID_SIGNATURE : NOISE_ERROR_NONE;
}

NoiseSignState *noise_ed25519_new(void)
{
    NoiseEd25519State *state = noise_new(NoiseEd25519State);
    if (!state)
        return 0;
    state->parent.sign_id = NOISE_SIGN_ED25519;
    state->parent.private_key_len = 32;
    state->parent.public_key_len = 32;
    state->parent.signature_len = 64;
    state->parent.private_key = state->private_key;
    state->parent.public_key = state->public_key;
    state->parent.generate_keypair = noise_ed25519_generate_keypair;
    state->parent.validate_keypair = noise_ed25519_validate_keypair;
    state->parent.validate_public_key = noise_ed25519_validate_public_key;
    state->parent.derive_public_key = noise_ed25519_derive_public_key;
    state->parent.sign = noise_ed25519_sign;
    state->parent.verify = noise_ed25519_verify;
    return &(state->parent);
}
