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
#include "crypto/blake2/blake2s.h"

typedef struct
{
    struct NoiseHashState_s parent;
    BLAKE2s_context_t blake2;

} NoiseBLAKE2sState;

static void noise_blake2s_reset(NoiseHashState *state)
{
    NoiseBLAKE2sState *st = (NoiseBLAKE2sState *)state;
    BLAKE2s_reset(&(st->blake2));
}

static void noise_blake2s_update(NoiseHashState *state, const uint8_t *data, size_t len)
{
    NoiseBLAKE2sState *st = (NoiseBLAKE2sState *)state;
    BLAKE2s_update(&(st->blake2), data, len);
}

static void noise_blake2s_finalize(NoiseHashState *state, uint8_t *hash)
{
    NoiseBLAKE2sState *st = (NoiseBLAKE2sState *)state;
    BLAKE2s_finish(&(st->blake2), hash);
}

NoiseHashState *noise_blake2s_new(void)
{
    NoiseBLAKE2sState *state = noise_new(NoiseBLAKE2sState);
    if (!state)
        return 0;
    state->parent.hash_id = NOISE_HASH_BLAKE2s;
    state->parent.hash_len = 32;
    state->parent.block_len = 64;
    state->parent.reset = noise_blake2s_reset;
    state->parent.update = noise_blake2s_update;
    state->parent.finalize = noise_blake2s_finalize;
    return &(state->parent);
}
