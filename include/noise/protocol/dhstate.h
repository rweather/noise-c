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

#ifndef NOISE_DHSTATE_H
#define NOISE_DHSTATE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct NoiseDHState_s NoiseDHState;

int noise_dhstate_new_by_id(NoiseDHState **state, int id);
int noise_dhstate_new_by_name(NoiseDHState **state, const char *name);
int noise_dhstate_free(NoiseDHState *state);
int noise_dhstate_get_dh_id(const NoiseDHState *state);
size_t noise_dhstate_get_public_key_length(const NoiseDHState *state);
size_t noise_dhstate_get_private_key_length(const NoiseDHState *state);
size_t noise_dhstate_get_shared_key_length(const NoiseDHState *state);
int noise_dhstate_is_ephemeral_only(const NoiseDHState *state);
int noise_dhstate_has_keypair(const NoiseDHState *state);
int noise_dhstate_has_public_key(const NoiseDHState *state);
int noise_dhstate_generate_keypair(NoiseDHState *state);
int noise_dhstate_generate_dependent_keypair
    (NoiseDHState *state, const NoiseDHState *other);
int noise_dhstate_set_keypair
    (NoiseDHState *state, const uint8_t *private_key, size_t private_key_len,
     const uint8_t *public_key, size_t public_key_len);
int noise_dhstate_set_keypair_private
    (NoiseDHState *state, const uint8_t *private_key, size_t private_key_len);
int noise_dhstate_get_keypair
    (const NoiseDHState *state, uint8_t *private_key, size_t private_key_len,
     uint8_t *public_key, size_t public_key_len);
int noise_dhstate_set_public_key
    (NoiseDHState *state, const uint8_t *public_key, size_t public_key_len);
int noise_dhstate_get_public_key
    (const NoiseDHState *state, uint8_t *public_key, size_t public_key_len);
int noise_dhstate_set_null_public_key(NoiseDHState *state);
int noise_dhstate_is_null_public_key(const NoiseDHState *state);
int noise_dhstate_clear_key(NoiseDHState *state);
int noise_dhstate_calculate
    (const NoiseDHState *private_key_state,
     const NoiseDHState *public_key_state,
     uint8_t *shared_key, size_t shared_key_len);
int noise_dhstate_copy(NoiseDHState *state, const NoiseDHState *from);
int noise_dhstate_format_fingerprint
    (const NoiseDHState *state, int fingerprint_type, char *buffer, size_t len);
int noise_dhstate_get_role(const NoiseDHState *state);
int noise_dhstate_set_role(NoiseDHState *state, int role);

#ifdef __cplusplus
};
#endif

#endif
