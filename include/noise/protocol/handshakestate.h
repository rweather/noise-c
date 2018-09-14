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

#ifndef NOISE_HANDSHAKESTATE_H
#define NOISE_HANDSHAKESTATE_H

#include <noise/protocol/symmetricstate.h>
#include <noise/protocol/dhstate.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct NoiseHandshakeState_s NoiseHandshakeState;

int noise_handshakestate_new_by_id
    (NoiseHandshakeState **state, const NoiseProtocolId *protocol_id, int role);
int noise_handshakestate_new_by_name
    (NoiseHandshakeState **state, const char *protocol_name, int role);
int noise_handshakestate_free(NoiseHandshakeState *state);
int noise_handshakestate_get_role(const NoiseHandshakeState *state);
int noise_handshakestate_get_protocol_id
    (const NoiseHandshakeState *state, NoiseProtocolId *id);
NoiseDHState *noise_handshakestate_get_local_keypair_dh
    (const NoiseHandshakeState *state);
NoiseDHState *noise_handshakestate_get_remote_public_key_dh
    (const NoiseHandshakeState *state);
NoiseDHState *noise_handshakestate_get_fixed_ephemeral_dh
    (NoiseHandshakeState *state);
NoiseDHState *noise_handshakestate_get_fixed_hybrid_dh
    (NoiseHandshakeState *state);
int noise_handshakestate_needs_pre_shared_key(const NoiseHandshakeState *state);
int noise_handshakestate_has_pre_shared_key(const NoiseHandshakeState *state);
int noise_handshakestate_set_pre_shared_key
    (NoiseHandshakeState *state, const uint8_t *key, size_t key_len);
int noise_handshakestate_set_prologue
    (NoiseHandshakeState *state, const void *prologue, size_t prologue_len);
int noise_handshakestate_needs_local_keypair(const NoiseHandshakeState *state);
int noise_handshakestate_has_local_keypair(const NoiseHandshakeState *state);
int noise_handshakestate_needs_remote_public_key(const NoiseHandshakeState *state);
int noise_handshakestate_has_remote_public_key(const NoiseHandshakeState *state);
int noise_handshakestate_start(NoiseHandshakeState *state);
int noise_handshakestate_fallback(NoiseHandshakeState *state);
int noise_handshakestate_fallback_to(NoiseHandshakeState *state, int pattern_id);
int noise_handshakestate_get_action(const NoiseHandshakeState *state);
int noise_handshakestate_write_message
    (NoiseHandshakeState *state, NoiseBuffer *message, const NoiseBuffer *payload);
int noise_handshakestate_read_message
    (NoiseHandshakeState *state, NoiseBuffer *message, NoiseBuffer *payload);
int noise_handshakestate_split
    (NoiseHandshakeState *state, NoiseCipherState **send, NoiseCipherState **receive);
int noise_handshakestate_get_handshake_hash
    (const NoiseHandshakeState *state, uint8_t *hash, size_t max_len);
int noise_handshakestate_get_action_pattern
    (const NoiseHandshakeState *state, char *pattern, size_t max_len);
#ifdef __cplusplus
};
#endif

#endif
