/*
 * Copyright (C) 2016 Southern Storm Software, Pty Ltd.
 * Copyright (C) 2016 Topology LP.
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
#include <sodium.h>

typedef struct
{
    struct NoiseHashState_s parent;
    crypto_hash_sha512_state sha512;

} NoiseSHA512State;

static void noise_sha512_reset(NoiseHashState *state)
{
    NoiseSHA512State *st = (NoiseSHA512State *)state;
    crypto_hash_sha512_init(&(st->sha512));
}

static void noise_sha512_update(NoiseHashState *state, const uint8_t *data, size_t len)
{
    NoiseSHA512State *st = (NoiseSHA512State *)state;
    crypto_hash_sha512_update(&(st->sha512), data, len);
}

static void noise_sha512_finalize(NoiseHashState *state, uint8_t *hash)
{
    NoiseSHA512State *st = (NoiseSHA512State *)state;
    crypto_hash_sha512_final(&(st->sha512), hash);
}

NoiseHashState *noise_sha512_new(void)
{
    NoiseSHA512State *state = noise_new(NoiseSHA512State);
    if (!state)
        return 0;
    state->parent.hash_id = NOISE_HASH_SHA512;
    state->parent.hash_len = 64;
    state->parent.block_len = 128;
    state->parent.reset = noise_sha512_reset;
    state->parent.update = noise_sha512_update;
    state->parent.finalize = noise_sha512_finalize;
    return &(state->parent);
}
