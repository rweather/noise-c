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

#ifndef NOISE_SIGNSTATE_H
#define NOISE_SIGNSTATE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct NoiseSignState_s NoiseSignState;

int noise_signstate_new_by_id(NoiseSignState **state, int id);
int noise_signstate_new_by_name(NoiseSignState **state, const char *name);
int noise_signstate_free(NoiseSignState *state);
int noise_signstate_get_sign_id(const NoiseSignState *state);
size_t noise_signstate_get_public_key_length(const NoiseSignState *state);
size_t noise_signstate_get_private_key_length(const NoiseSignState *state);
size_t noise_signstate_get_signature_length(const NoiseSignState *state);
int noise_signstate_has_keypair(const NoiseSignState *state);
int noise_signstate_has_public_key(const NoiseSignState *state);
int noise_signstate_generate_keypair(NoiseSignState *state);
int noise_signstate_set_keypair
    (NoiseSignState *state, const uint8_t *private_key, size_t private_key_len,
     const uint8_t *public_key, size_t public_key_len);
int noise_signstate_set_keypair_private
    (NoiseSignState *state, const uint8_t *private_key, size_t private_key_len);
int noise_signstate_get_keypair
    (const NoiseSignState *state, uint8_t *private_key, size_t private_key_len,
     uint8_t *public_key, size_t public_key_len);
int noise_signstate_set_public_key
    (NoiseSignState *state, const uint8_t *public_key, size_t public_key_len);
int noise_signstate_get_public_key
    (const NoiseSignState *state, uint8_t *public_key, size_t public_key_len);
int noise_signstate_clear_key(NoiseSignState *state);
int noise_signstate_sign
    (const NoiseSignState *state, const uint8_t *message, size_t message_len,
     uint8_t *signature, size_t signature_len);
int noise_signstate_verify
    (const NoiseSignState *state, const uint8_t *message, size_t message_len,
     const uint8_t *signature, size_t signature_len);
int noise_signstate_copy(NoiseSignState *state, const NoiseSignState *from);
int noise_signstate_format_fingerprint
    (const NoiseSignState *state, int fingerprint_type,
     char *buffer, size_t len);
int noise_signstate_get_max_key_length(void);
int noise_signstate_get_max_signature_length(void);

#ifdef __cplusplus
};
#endif

#endif
