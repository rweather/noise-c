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

#include <noise/symmetricstate.h>
#include <noise/identifiers.h>

int noise_symmetricstate_new(NoiseSymmetricState **state, const char *protocol)
{
    // TODO
    return NOISE_ERROR_UNKNOWN_NAME;
}

int noise_symmetricstate_free(NoiseSymmetricState *state)
{
    // TODO
    return NOISE_ERROR_NONE;
}

int noise_symmetricstate_get_cipher_id(const NoiseSymmetricState *state)
{
    // TODO
    return 0;
}

int noise_symmetricstate_get_hash_id(const NoiseSymmetricState *state)
{
    // TODO
    return 0;
}

int noise_symmetricstate_get_dh_id(const NoiseSymmetricState *state)
{
    // TODO
    return 0;
}

int noise_symmetricstate_mix_key
    (NoiseSymmetricState *state, const uint8_t *input, size_t size)
{
    // TODO
    return NOISE_ERROR_NONE;
}

int noise_symmetricstate_mix_hash
    (NoiseSymmetricState *state, const uint8_t *input, size_t size)
{
    // TODO
    return NOISE_ERROR_NONE;
}

int noise_symmetricstate_encrypt_and_hash
    (NoiseSymmetricState *state, uint8_t *data,
     size_t in_data_len, size_t *out_data_len)
{
    // TODO
    return NOISE_ERROR_NONE;
}

int noise_symmetricstate_decrypt_and_hash
    (NoiseSymmetricState *state, uint8_t *data,
     size_t in_data_len, size_t *out_data_len)
{
    // TODO
    return NOISE_ERROR_NONE;
}

int noise_symmetricstate_split
    (NoiseSymmetricState *state, NoiseCipherState **c1, NoiseCipherState **c2)
{
    // TODO
    return NOISE_ERROR_NONE;
}
