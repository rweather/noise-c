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

#ifndef NOISE_SYMMETRICSTATE_H
#define NOISE_SYMMETRICSTATE_H

#include <noise/protocol/cipherstate.h>
#include <noise/protocol/names.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct NoiseSymmetricState_s NoiseSymmetricState;

int noise_symmetricstate_new_by_id
    (NoiseSymmetricState **state, const NoiseProtocolId *id);
int noise_symmetricstate_new_by_name
    (NoiseSymmetricState **state, const char *name);
int noise_symmetricstate_free(NoiseSymmetricState *state);
int noise_symmetricstate_get_protocol_id
    (const NoiseSymmetricState *state, NoiseProtocolId *id);
int noise_symmetricstate_mix_key
    (NoiseSymmetricState *state, const uint8_t *input, size_t size);
int noise_symmetricstate_mix_hash
    (NoiseSymmetricState *state, const uint8_t *input, size_t size);
int noise_symmetricstate_encrypt_and_hash
    (NoiseSymmetricState *state, NoiseBuffer *buffer);
int noise_symmetricstate_decrypt_and_hash
    (NoiseSymmetricState *state, NoiseBuffer *buffer);
size_t noise_symmetricstate_get_mac_length(const NoiseSymmetricState *state);
int noise_symmetricstate_split
    (NoiseSymmetricState *state, NoiseCipherState **c1, NoiseCipherState **c2);

#ifdef __cplusplus
};
#endif

#endif
