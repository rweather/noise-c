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
#include "crypto/sha2/sha256.h"

typedef struct
{
    struct NoiseHashState_s parent;
    sha256_context_t sha256;

} NoiseSHA256State;

static void noise_sha256_reset(NoiseHashState *state)
{
    NoiseSHA256State *st = (NoiseSHA256State *)state;
    sha256_reset(&(st->sha256));
}

static void noise_sha256_update(NoiseHashState *state, const uint8_t *data, size_t len)
{
    NoiseSHA256State *st = (NoiseSHA256State *)state;
    sha256_update(&(st->sha256), data, len);
}

static void noise_sha256_finalize(NoiseHashState *state, uint8_t *hash)
{
    NoiseSHA256State *st = (NoiseSHA256State *)state;
    sha256_finish(&(st->sha256), hash);
}

NoiseHashState *noise_sha256_new(void)
{
    NoiseSHA256State *state = noise_new(NoiseSHA256State);
    if (!state)
        return 0;
    state->parent.hash_id = NOISE_HASH_SHA256;
    state->parent.hash_len = 32;
    state->parent.block_len = 64;
    state->parent.reset = noise_sha256_reset;
    state->parent.update = noise_sha256_update;
    state->parent.finalize = noise_sha256_finalize;
    return &(state->parent);
}
