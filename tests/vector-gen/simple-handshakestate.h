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

#ifndef __SIMPLE_HANDSHAKESTATE_H__
#define __SIMPLE_HANDSHAKESTATE_H__

#include "simple-symmetricstate.h"

#define MAX_DH_KEY_LEN  2048
#define MAX_PSK_LEN     32

#define ACTION_NONE     0
#define ACTION_READ     1
#define ACTION_WRITE    2
#define ACTION_SPLIT    3
#define ACTION_FAILED   4

typedef struct
{
    SymmetricState symmetric;
    NoiseDHState *dh_private;
    NoiseDHState *dh_public;
    NoiseDHState *hybrid_private;
    NoiseDHState *hybrid_public;
    uint8_t s[MAX_DH_KEY_LEN];
    size_t s_len;
    uint8_t s_public[MAX_DH_KEY_LEN];
    size_t s_public_len;
    uint8_t e[MAX_DH_KEY_LEN];
    size_t e_len;
    uint8_t e_public[MAX_DH_KEY_LEN];
    size_t e_public_len;
    uint8_t f[MAX_DH_KEY_LEN];
    size_t f_len;
    uint8_t f_public[MAX_DH_KEY_LEN];
    size_t f_public_len;
    uint8_t rs[MAX_DH_KEY_LEN];
    size_t rs_len;
    uint8_t re[MAX_DH_KEY_LEN];
    size_t re_len;
    uint8_t rf[MAX_DH_KEY_LEN];
    size_t rf_len;
    uint8_t psk[MAX_PSK_LEN];
    size_t psk_len;
    int action;
    const uint8_t *pattern;
    int is_initiator;

} HandshakeState;

void HandshakeState_new(HandshakeState *handshake);
void HandshakeState_free(HandshakeState *handshake);
void Initialize(HandshakeState *handshake, const char *protocol_name,
                int is_initiator, int is_fallback,
                const uint8_t *prologue, size_t prologue_len,
                const uint8_t *s, size_t s_len,
                const uint8_t *e, size_t e_len,
                const uint8_t *f, size_t f_len,
                const uint8_t *rs, size_t rs_len,
                const uint8_t *re, size_t re_len,
                const uint8_t *rf, size_t rf_len,
                const uint8_t *psk, size_t psk_len);
int WriteMessage(HandshakeState *handshake, const Buffer payload, Buffer *message);
int ReadMessage(HandshakeState *handshake, const Buffer message, Buffer *payload);

#endif
