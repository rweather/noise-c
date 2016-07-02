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

#include "simple-handshakestate.h"
#include "internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void HandshakeState_new(HandshakeState *handshake)
{
    memset(handshake, 0, sizeof(HandshakeState));
    SymmetricState_new(&(handshake->symmetric));
}

void HandshakeState_free(HandshakeState *handshake)
{
    SymmetricState_free(&(handshake->symmetric));
    noise_dhstate_free(handshake->dh_private);
    noise_dhstate_free(handshake->dh_public);
}

void Initialize(HandshakeState *handshake, const char *protocol_name,
                int is_initiator, const uint8_t *prologue, size_t prologue_len,
                const uint8_t *s, size_t s_len,
                const uint8_t *e, size_t e_len,
                const uint8_t *rs, size_t rs_len,
                const uint8_t *re, size_t re_len,
                const uint8_t *psk, size_t psk_len)
{
    NoiseProtocolId id;
    size_t name_len = strlen(protocol_name);
    const uint8_t *pattern;
    uint8_t flags;
    int err;
    err = noise_protocol_name_to_id(&id, protocol_name, name_len);
    if (err != NOISE_ERROR_NONE) {
        noise_perror("Initialize", err);
        exit(1);
    }
    err = noise_dhstate_new_by_id(&(handshake->dh_private), id.dh_id);
    if (err != NOISE_ERROR_NONE) {
        noise_perror("Initialize DH Private", err);
        exit(1);
    }
    err = noise_dhstate_new_by_id(&(handshake->dh_public), id.dh_id);
    if (err != NOISE_ERROR_NONE) {
        noise_perror("Initialize DH Public", err);
        exit(1);
    }
    pattern = noise_pattern_lookup(id.pattern_id);
    flags = *pattern++;
    memcpy(handshake->s, s, s_len);
    handshake->s_len = s_len;
    memcpy(handshake->e, e, e_len);
    handshake->e_len = e_len;
    memcpy(handshake->re, re, re_len);
    handshake->re_len = re_len;
    memcpy(handshake->rs, rs, rs_len);
    handshake->rs_len = rs_len;
    memcpy(handshake->psk, psk, psk_len);
    handshake->psk_len = psk_len;
    if (handshake->s_len) {
        noise_dhstate_set_keypair_private
            (handshake->dh_private, handshake->s, handshake->s_len);
        handshake->s_public_len = handshake->s_len;
        noise_dhstate_get_public_key
            (handshake->dh_private, handshake->s_public, handshake->s_public_len);
    } else {
        handshake->s_public_len = 0;
    }
    if (handshake->e_len) {
        noise_dhstate_set_keypair_private
            (handshake->dh_private, handshake->e, handshake->e_len);
        handshake->e_public_len = handshake->e_len;
        noise_dhstate_get_public_key
            (handshake->dh_private, handshake->e_public, handshake->e_public_len);
    } else {
        handshake->e_public_len = 0;
    }
    InitializeSymmetric(&(handshake->symmetric), protocol_name);
    MixHash(&(handshake->symmetric), prologue, prologue_len);
    if (handshake->psk_len) {
        uint8_t temp[MAX_HASHLEN];
        noise_hashstate_hkdf
            (handshake->symmetric.hash, handshake->symmetric.ck,
             handshake->symmetric.hash_len, handshake->psk, handshake->psk_len,
             handshake->symmetric.ck, handshake->symmetric.hash_len,
             temp, handshake->symmetric.hash_len);
        MixHash(&(handshake->symmetric), temp, handshake->symmetric.hash_len);
    }
    if (is_initiator) {
        if (flags & NOISE_PAT_FLAG_LOCAL_REQUIRED) {
            MixHash(&(handshake->symmetric), handshake->s_public,
                    handshake->s_public_len);
        }
        if (flags & NOISE_PAT_FLAG_REMOTE_REQUIRED) {
            MixHash(&(handshake->symmetric), handshake->rs, handshake->rs_len);
        }
        if (flags & NOISE_PAT_FLAG_REMOTE_EPHEM_REQ) {
            MixHash(&(handshake->symmetric), handshake->re, handshake->re_len);
        }
    } else {
        if (flags & NOISE_PAT_FLAG_LOCAL_REQUIRED) {
            MixHash(&(handshake->symmetric), handshake->rs, handshake->rs_len);
        }
        if (flags & NOISE_PAT_FLAG_REMOTE_REQUIRED) {
            MixHash(&(handshake->symmetric), handshake->s_public,
                    handshake->s_public_len);
        }
        if (flags & NOISE_PAT_FLAG_REMOTE_EPHEM_REQ) {
            MixHash(&(handshake->symmetric), handshake->e_public,
                    handshake->e_public_len);
        }
    }
    handshake->pattern = pattern;
    if (is_initiator) {
        handshake->action = ACTION_WRITE;
    } else {
        handshake->action = ACTION_READ;
    }
}

int WriteMessage(HandshakeState *handshake, const Buffer payload, Buffer *message)
{
    size_t index = 0;
    Buffer data;
    if (handshake->action != ACTION_WRITE) {
        fprintf(stderr, "Unexpected write\n");
        exit(1);
    }
    while (*(handshake->pattern) != NOISE_TOKEN_END &&
                *(handshake->pattern) != NOISE_TOKEN_FLIP_DIR) {
        switch (*(handshake->pattern)++) {
        case NOISE_TOKEN_E:
            memcpy(message->data + index, handshake->e_public,
                   handshake->e_public_len);
            index += handshake->e_public_len;
            MixHash(&(handshake->symmetric), handshake->e_public,
                    handshake->e_public_len);
            if (handshake->psk_len) {
                MixKey(&(handshake->symmetric), handshake->e_public,
                       handshake->e_public_len);
            }
            break;

        case NOISE_TOKEN_S:
            memcpy(data.data, handshake->s_public, handshake->s_public_len);
            data.size = handshake->s_public_len;
            data = EncryptAndHash(&(handshake->symmetric), data);
            memcpy(message->data + index, data.data, data.size);
            index += data.size;
            break;

        case NOISE_TOKEN_DHEE:
            noise_dhstate_set_keypair_private
                (handshake->dh_private, handshake->e, handshake->e_len);
            noise_dhstate_set_public_key
                (handshake->dh_public, handshake->re, handshake->re_len);
            noise_dhstate_calculate
                (handshake->dh_private, handshake->dh_public,
                 data.data, handshake->e_len);
            MixKey(&(handshake->symmetric), data.data, handshake->e_len);
            break;

        case NOISE_TOKEN_DHES:
            noise_dhstate_set_keypair_private
                (handshake->dh_private, handshake->e, handshake->e_len);
            noise_dhstate_set_public_key
                (handshake->dh_public, handshake->rs, handshake->rs_len);
            noise_dhstate_calculate
                (handshake->dh_private, handshake->dh_public,
                 data.data, handshake->e_len);
            MixKey(&(handshake->symmetric), data.data, handshake->e_len);
            break;

        case NOISE_TOKEN_DHSE:
            noise_dhstate_set_keypair_private
                (handshake->dh_private, handshake->s, handshake->s_len);
            noise_dhstate_set_public_key
                (handshake->dh_public, handshake->re, handshake->re_len);
            noise_dhstate_calculate
                (handshake->dh_private, handshake->dh_public,
                 data.data, handshake->e_len);
            MixKey(&(handshake->symmetric), data.data, handshake->e_len);
            break;

        case NOISE_TOKEN_DHSS:
            noise_dhstate_set_keypair_private
                (handshake->dh_private, handshake->s, handshake->s_len);
            noise_dhstate_set_public_key
                (handshake->dh_public, handshake->rs, handshake->rs_len);
            noise_dhstate_calculate
                (handshake->dh_private, handshake->dh_public,
                 data.data, handshake->e_len);
            MixKey(&(handshake->symmetric), data.data, handshake->e_len);
            break;
        }
    }
    data = EncryptAndHash(&(handshake->symmetric), payload);
    memcpy(message->data + index, data.data, data.size);
    index += data.size;
    message->size = index;
    if (*(handshake->pattern) == NOISE_TOKEN_END) {
        handshake->action = ACTION_SPLIT;
        return 1;
    } else {
        handshake->action = ACTION_READ;
        ++(handshake->pattern);
        return 0;
    }
}

int ReadMessage(HandshakeState *handshake, const Buffer message, Buffer *payload)
{
    size_t index = 0;
    Buffer data;
    if (handshake->action != ACTION_READ) {
        fprintf(stderr, "Unexpected read\n");
        exit(1);
    }
    while (*(handshake->pattern) != NOISE_TOKEN_END &&
                *(handshake->pattern) != NOISE_TOKEN_FLIP_DIR) {
        switch (*(handshake->pattern)++) {
        case NOISE_TOKEN_E:
            handshake->re_len = noise_dhstate_get_public_key_length
                (handshake->dh_public);
            memcpy(handshake->re, message.data + index, handshake->re_len);
            index += handshake->re_len;
            MixHash(&(handshake->symmetric), handshake->re, handshake->re_len);
            if (handshake->psk_len) {
                MixKey(&(handshake->symmetric), handshake->re,
                       handshake->re_len);
            }
            break;

        case NOISE_TOKEN_S:
            handshake->rs_len = noise_dhstate_get_public_key_length
                (handshake->dh_public);
            if (HasKey(&(handshake->symmetric.cipher))) {
                memcpy(data.data, message.data + index, handshake->rs_len + 16);
                data.size = handshake->rs_len + 16;
            } else {
                memcpy(data.data, message.data + index, handshake->rs_len);
                data.size = handshake->rs_len;
            }
            index += data.size;
            DecryptAndHash(&(handshake->symmetric), data, &data);
            memcpy(handshake->rs, data.data, handshake->rs_len);
            break;

        case NOISE_TOKEN_DHEE:
            noise_dhstate_set_keypair_private
                (handshake->dh_private, handshake->e, handshake->e_len);
            noise_dhstate_set_public_key
                (handshake->dh_public, handshake->re, handshake->re_len);
            noise_dhstate_calculate
                (handshake->dh_private, handshake->dh_public,
                 data.data, handshake->e_len);
            MixKey(&(handshake->symmetric), data.data, handshake->e_len);
            break;

        case NOISE_TOKEN_DHES:
            noise_dhstate_set_keypair_private
                (handshake->dh_private, handshake->s, handshake->s_len);
            noise_dhstate_set_public_key
                (handshake->dh_public, handshake->re, handshake->re_len);
            noise_dhstate_calculate
                (handshake->dh_private, handshake->dh_public,
                 data.data, handshake->e_len);
            MixKey(&(handshake->symmetric), data.data, handshake->e_len);
            break;

        case NOISE_TOKEN_DHSE:
            noise_dhstate_set_keypair_private
                (handshake->dh_private, handshake->e, handshake->e_len);
            noise_dhstate_set_public_key
                (handshake->dh_public, handshake->rs, handshake->rs_len);
            noise_dhstate_calculate
                (handshake->dh_private, handshake->dh_public,
                 data.data, handshake->e_len);
            MixKey(&(handshake->symmetric), data.data, handshake->e_len);
            break;

        case NOISE_TOKEN_DHSS:
            noise_dhstate_set_keypair_private
                (handshake->dh_private, handshake->s, handshake->s_len);
            noise_dhstate_set_public_key
                (handshake->dh_public, handshake->rs, handshake->rs_len);
            noise_dhstate_calculate
                (handshake->dh_private, handshake->dh_public,
                 data.data, handshake->e_len);
            MixKey(&(handshake->symmetric), data.data, handshake->e_len);
            break;
        }
    }
    memcpy(data.data, message.data + index, message.size - index);
    data.size = message.size - index;
    DecryptAndHash(&(handshake->symmetric), data, payload);
    if (*(handshake->pattern) == NOISE_TOKEN_END) {
        handshake->action = ACTION_SPLIT;
        return 1;
    } else {
        handshake->action = ACTION_WRITE;
        ++(handshake->pattern);
        return 0;
    }
}
