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

#ifndef NOISE_KEYSTATE_H
#define NOISE_KEYSTATE_H

#include <noise/protocol/buffer.h>
#include <noise/protocol/dhstate.h>
#include <noise/protocol/signstate.h>
#include <noise/protocol/handshakestate.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct NoiseKeyState_s NoiseKeyState;

int noise_keystate_new(NoiseKeyState **state);
int noise_keystate_free(NoiseKeyState *state);
int noise_keystate_load_from_file
    (NoiseKeyState *state, const char *filename, int rep, int type);
int noise_keystate_load_from_buffer
    (NoiseKeyState *state, const NoiseBuffer *buffer, int rep, int type);
int noise_keystate_save_to_file
    (NoiseKeyState *state, const char *filename, int rep);
int noise_keystate_save_to_buffer
    (NoiseKeyState *state, NoiseBuffer *buffer, int rep);
int noise_keystate_get_key_count(const NoiseKeyState *state);
int noise_keystate_get_key_type(const NoiseKeyState *state, int index);
int noise_keystate_find_key_type(const NoiseKeyState *state, int type);
int noise_keystate_has_private_key(const NoiseKeyState *state, int index);
int noise_keystate_copy_to_dhstate
    (const NoiseKeyState *state, int index, NoiseDHState *dh);
int noise_keystate_copy_to_signstate
    (const NoiseKeyState *state, int index, NoiseSignState *sign);
int noise_keystate_copy_to_handshake_local
    (const NoiseKeyState *state, int index, NoiseHandshakeState *handshake);
int noise_keystate_copy_to_handshake_remote
    (const NoiseKeyState *state, int index, NoiseHandshakeState *handshake);
int noise_keystate_add_from_dhstate
    (NoiseKeyState *state, const NoiseDHState *dh);
int noise_keystate_add_from_signstate
    (NoiseKeyState *state, const NoiseSignState *sign);
int noise_keystate_remove_key(NoiseKeyState *state, int index);
int noise_keystate_generate_key(NoiseKeyState *state, int type);
int noise_keystate_format_fingerprint
    (const NoiseKeyState *state, int index, int fingerprint_type,
     char *buffer, size_t len);
int noise_keystate_name_to_type(const char *name);

#ifdef __cplusplus
};
#endif

#endif
