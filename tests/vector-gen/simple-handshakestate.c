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
    noise_dhstate_free(handshake->hybrid_private);
    noise_dhstate_free(handshake->hybrid_public);
}

void Initialize(HandshakeState *handshake, const char *protocol_name,
                int is_initiator, int is_fallback,
                const uint8_t *prologue, size_t prologue_len,
                const uint8_t *s, size_t s_len,
                const uint8_t *e, size_t e_len,
                const uint8_t *f, size_t f_len,
                const uint8_t *rs, size_t rs_len,
                const uint8_t *re, size_t re_len,
                const uint8_t *rf, size_t rf_len,
                const uint8_t *psk, size_t psk_len)
{
    NoiseProtocolId id;
    size_t name_len = strlen(protocol_name);
    size_t public_key_len;
    size_t private_key_len;
    size_t hybrid_public_key_len;
    size_t hybrid_private_key_len;
    const uint8_t *pattern;
    NoisePatternFlags_t flags;
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
    if (id.hybrid_id != NOISE_DH_NONE) {
        err = noise_dhstate_new_by_id
            (&(handshake->hybrid_private), id.hybrid_id);
        if (err != NOISE_ERROR_NONE) {
            noise_perror("Initialize Forward DH Private", err);
            exit(1);
        }
        err = noise_dhstate_new_by_id
            (&(handshake->hybrid_public), id.hybrid_id);
        if (err != NOISE_ERROR_NONE) {
            noise_perror("Initialize Forward DH Public", err);
            exit(1);
        }
    }
    if (is_initiator != is_fallback) {
        noise_dhstate_set_role(handshake->dh_private, NOISE_ROLE_INITIATOR);
        noise_dhstate_set_role(handshake->dh_public, NOISE_ROLE_RESPONDER);
        noise_dhstate_set_role(handshake->hybrid_private, NOISE_ROLE_INITIATOR);
        noise_dhstate_set_role(handshake->hybrid_public, NOISE_ROLE_RESPONDER);
    } else {
        noise_dhstate_set_role(handshake->dh_private, NOISE_ROLE_RESPONDER);
        noise_dhstate_set_role(handshake->dh_public, NOISE_ROLE_INITIATOR);
        noise_dhstate_set_role(handshake->hybrid_private, NOISE_ROLE_RESPONDER);
        noise_dhstate_set_role(handshake->hybrid_public, NOISE_ROLE_INITIATOR);
    }
    public_key_len = noise_dhstate_get_public_key_length(handshake->dh_public);
    private_key_len = noise_dhstate_get_private_key_length(handshake->dh_private);
    hybrid_public_key_len =
        noise_dhstate_get_public_key_length(handshake->hybrid_public);
    hybrid_private_key_len =
        noise_dhstate_get_private_key_length(handshake->hybrid_private);
    if (s_len > private_key_len || e_len > private_key_len ||
            rs_len > public_key_len || re_len > public_key_len ||
            f_len > hybrid_private_key_len ||
            rf_len > hybrid_public_key_len ||
            private_key_len > MAX_DH_KEY_LEN ||
            public_key_len > MAX_DH_KEY_LEN ||
            hybrid_private_key_len > MAX_DH_KEY_LEN ||
            hybrid_public_key_len > MAX_DH_KEY_LEN) {
        fprintf(stderr, "Out of range key sizes\n");
        exit(1);
    }
    pattern = noise_pattern_lookup(id.pattern_id);
    flags = ((NoisePatternFlags_t)(pattern[0])) |
           (((NoisePatternFlags_t)(pattern[1])) << 8);
    pattern += 2;
    memcpy(handshake->s, s, s_len);
    handshake->s_len = s_len;
    memcpy(handshake->e, e, e_len);
    handshake->e_len = e_len;
    memcpy(handshake->f, f, f_len);
    handshake->f_len = f_len;
    memcpy(handshake->re, re, re_len);
    handshake->re_len = re_len;
    memcpy(handshake->rf, rf, rf_len);
    handshake->rf_len = rf_len;
    memcpy(handshake->rs, rs, rs_len);
    handshake->rs_len = rs_len;
    memcpy(handshake->psk, psk, psk_len);
    handshake->psk_len = psk_len;
    if (handshake->s_len) {
        noise_dhstate_set_keypair_private
            (handshake->dh_private, handshake->s, handshake->s_len);
        handshake->s_public_len =
            noise_dhstate_get_public_key_length(handshake->dh_private);
        noise_dhstate_get_public_key
            (handshake->dh_private, handshake->s_public, handshake->s_public_len);
    } else {
        handshake->s_public_len = 0;
    }
    if (handshake->e_len) {
        noise_dhstate_set_keypair_private
            (handshake->dh_private, handshake->e, handshake->e_len);
        handshake->e_public_len =
            noise_dhstate_get_public_key_length(handshake->dh_private);
        noise_dhstate_get_public_key
            (handshake->dh_private, handshake->e_public, handshake->e_public_len);
    } else {
        handshake->e_public_len = 0;
    }
    if (handshake->f_len) {
        noise_dhstate_set_keypair_private
            (handshake->hybrid_private, handshake->f, handshake->f_len);
        handshake->f_public_len =
            noise_dhstate_get_public_key_length(handshake->hybrid_private);
        noise_dhstate_get_public_key
            (handshake->hybrid_private, handshake->f_public,
             handshake->f_public_len);
    } else {
        handshake->f_public_len = 0;
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
        if (flags & NOISE_PAT_FLAG_REMOTE_EPHEM_REQ) {
            MixHash(&(handshake->symmetric), handshake->re, handshake->re_len);
            if (handshake->psk_len) {
                MixKey(&(handshake->symmetric), handshake->re,
                       handshake->re_len);
            }
        }
        if (flags & NOISE_PAT_FLAG_REMOTE_HYBRID_REQ) {
            MixHash(&(handshake->symmetric), handshake->rf,
                    handshake->rf_len);
        }
        if (flags & NOISE_PAT_FLAG_REMOTE_REQUIRED) {
            MixHash(&(handshake->symmetric), handshake->rs, handshake->rs_len);
        }
    } else {
        if (flags & NOISE_PAT_FLAG_LOCAL_REQUIRED) {
            MixHash(&(handshake->symmetric), handshake->rs, handshake->rs_len);
        }
        if (flags & NOISE_PAT_FLAG_REMOTE_EPHEM_REQ) {
            MixHash(&(handshake->symmetric), handshake->e_public,
                    handshake->e_public_len);
            if (handshake->psk_len) {
                MixKey(&(handshake->symmetric), handshake->e_public,
                       handshake->e_public_len);
            }
        }
        if (flags & NOISE_PAT_FLAG_REMOTE_HYBRID_REQ) {
            MixHash(&(handshake->symmetric), handshake->f_public,
                    handshake->f_public_len);
        }
        if (flags & NOISE_PAT_FLAG_REMOTE_REQUIRED) {
            MixHash(&(handshake->symmetric), handshake->s_public,
                    handshake->s_public_len);
        }
    }
    handshake->pattern = pattern;
    handshake->is_initiator = is_initiator;
    if (is_initiator) {
        handshake->action = ACTION_WRITE;
    } else {
        handshake->action = ACTION_READ;
    }
}

int WriteMessage(HandshakeState *handshake, const Buffer payload, Buffer *message)
{
    size_t index = 0;
    size_t len;
    Buffer data;
    if (handshake->action != ACTION_WRITE) {
        fprintf(stderr, "Unexpected write\n");
        exit(1);
    }
    while (*(handshake->pattern) != NOISE_TOKEN_END &&
                *(handshake->pattern) != NOISE_TOKEN_FLIP_DIR) {
        switch (*(handshake->pattern)++) {
        case NOISE_TOKEN_E:
            if (noise_dhstate_get_dh_id(handshake->dh_private)
                        == NOISE_DH_NEWHOPE &&
                    noise_dhstate_get_role(handshake->dh_private)
                        == NOISE_ROLE_RESPONDER) {
                /* New Hope needs special support for dependent fixed keygen.
                   The public key for Bob isn't generated until calculate() */
                len = noise_dhstate_get_public_key_length(handshake->dh_private);
                noise_dhstate_set_keypair_private
                    (handshake->dh_private, handshake->e, handshake->e_len);
                noise_dhstate_set_public_key
                    (handshake->dh_public, handshake->re, handshake->re_len);
                noise_dhstate_calculate
                    (handshake->dh_private, handshake->dh_public,
                     message->data + index, 32);
                noise_dhstate_get_public_key
                    (handshake->dh_private, message->data + index, len);
            } else {
                len = handshake->e_public_len;
                memcpy(message->data + index, handshake->e_public, len);
            }
            MixHash(&(handshake->symmetric), message->data + index, len);
            if (handshake->psk_len) {
                MixKey(&(handshake->symmetric), message->data + index, len);
            }
            index += len;
            break;

        case NOISE_TOKEN_F:
            if (handshake->hybrid_private) {
                if (noise_dhstate_get_dh_id(handshake->hybrid_private)
                            == NOISE_DH_NEWHOPE &&
                        noise_dhstate_get_role(handshake->hybrid_private)
                            == NOISE_ROLE_RESPONDER) {
                    /* New Hope needs special support for dependent fixed
                       keygen.  The public key for Bob isn't generated until
                       calculate() */
                    len = noise_dhstate_get_public_key_length
                        (handshake->hybrid_private);
                    noise_dhstate_set_keypair_private
                        (handshake->hybrid_private, handshake->f,
                         handshake->f_len);
                    noise_dhstate_set_public_key
                        (handshake->hybrid_public, handshake->rf,
                         handshake->rf_len);
                    noise_dhstate_calculate
                        (handshake->hybrid_private, handshake->hybrid_public,
                         data.data, 32);
                    noise_dhstate_get_public_key
                        (handshake->hybrid_private, data.data, len);
                } else {
                    len = handshake->f_public_len;
                    memcpy(data.data, handshake->f_public, len);
                }
                data.size = len;
                data = EncryptAndHash(&(handshake->symmetric), data);
                memcpy(message->data + index, data.data, data.size);
                index += data.size;
            }
            break;

        case NOISE_TOKEN_S:
            memcpy(data.data, handshake->s_public, handshake->s_public_len);
            data.size = handshake->s_public_len;
            data = EncryptAndHash(&(handshake->symmetric), data);
            memcpy(message->data + index, data.data, data.size);
            index += data.size;
            break;

        case NOISE_TOKEN_FF:
            if (handshake->hybrid_private) {
                noise_dhstate_set_keypair_private
                    (handshake->hybrid_private, handshake->f,
                     handshake->f_len);
                noise_dhstate_set_public_key
                    (handshake->hybrid_public, handshake->rf,
                     handshake->rf_len);
                len = noise_dhstate_get_shared_key_length
                    (handshake->hybrid_private);
                noise_dhstate_calculate
                    (handshake->hybrid_private, handshake->hybrid_public,
                     data.data, len);
                MixKey(&(handshake->symmetric), data.data, len);
            }
            break;

        case NOISE_TOKEN_EE:
            noise_dhstate_set_keypair_private
                (handshake->dh_private, handshake->e, handshake->e_len);
            noise_dhstate_set_public_key
                (handshake->dh_public, handshake->re, handshake->re_len);
            len = noise_dhstate_get_shared_key_length(handshake->dh_private);
            noise_dhstate_calculate
                (handshake->dh_private, handshake->dh_public, data.data, len);
            MixKey(&(handshake->symmetric), data.data, len);
            break;

        case NOISE_TOKEN_ES:
            if (handshake->is_initiator) {
                noise_dhstate_set_keypair_private
                    (handshake->dh_private, handshake->e, handshake->e_len);
                noise_dhstate_set_public_key
                    (handshake->dh_public, handshake->rs, handshake->rs_len);
            } else {
                noise_dhstate_set_keypair_private
                    (handshake->dh_private, handshake->s, handshake->s_len);
                noise_dhstate_set_public_key
                    (handshake->dh_public, handshake->re, handshake->re_len);
            }
            len = noise_dhstate_get_shared_key_length(handshake->dh_private);
            noise_dhstate_calculate
                (handshake->dh_private, handshake->dh_public, data.data, len);
            MixKey(&(handshake->symmetric), data.data, len);
            break;

        case NOISE_TOKEN_SE:
            if (handshake->is_initiator) {
                noise_dhstate_set_keypair_private
                    (handshake->dh_private, handshake->s, handshake->s_len);
                noise_dhstate_set_public_key
                    (handshake->dh_public, handshake->re, handshake->re_len);
            } else {
                noise_dhstate_set_keypair_private
                    (handshake->dh_private, handshake->e, handshake->e_len);
                noise_dhstate_set_public_key
                    (handshake->dh_public, handshake->rs, handshake->rs_len);
            }
            len = noise_dhstate_get_shared_key_length(handshake->dh_private);
            noise_dhstate_calculate
                (handshake->dh_private, handshake->dh_public, data.data, len);
            MixKey(&(handshake->symmetric), data.data, len);
            break;

        case NOISE_TOKEN_SS:
            noise_dhstate_set_keypair_private
                (handshake->dh_private, handshake->s, handshake->s_len);
            noise_dhstate_set_public_key
                (handshake->dh_public, handshake->rs, handshake->rs_len);
            len = noise_dhstate_get_shared_key_length(handshake->dh_private);
            noise_dhstate_calculate
                (handshake->dh_private, handshake->dh_public, data.data, len);
            MixKey(&(handshake->symmetric), data.data, len);
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
    size_t len;
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

        case NOISE_TOKEN_F:
            if (handshake->hybrid_public) {
                handshake->rf_len = noise_dhstate_get_public_key_length
                    (handshake->hybrid_public);
                if (HasKey(&(handshake->symmetric.cipher))) {
                    memcpy(data.data, message.data + index, handshake->rf_len + 16);
                    data.size = handshake->rf_len + 16;
                } else {
                    memcpy(data.data, message.data + index, handshake->rf_len);
                    data.size = handshake->rf_len;
                }
                index += data.size;
                DecryptAndHash(&(handshake->symmetric), data, &data);
                memcpy(handshake->rf, data.data, handshake->rf_len);
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

        case NOISE_TOKEN_EE:
            noise_dhstate_set_keypair_private
                (handshake->dh_private, handshake->e, handshake->e_len);
            noise_dhstate_set_public_key
                (handshake->dh_public, handshake->re, handshake->re_len);
            len = noise_dhstate_get_shared_key_length(handshake->dh_private);
            noise_dhstate_calculate
                (handshake->dh_private, handshake->dh_public, data.data, len);
            MixKey(&(handshake->symmetric), data.data, len);
            break;

        case NOISE_TOKEN_FF:
            if (handshake->hybrid_private) {
                noise_dhstate_set_keypair_private
                    (handshake->hybrid_private, handshake->f,
                     handshake->f_len);
                noise_dhstate_set_public_key
                    (handshake->hybrid_public, handshake->rf,
                     handshake->rf_len);
                len = noise_dhstate_get_shared_key_length
                    (handshake->hybrid_private);
                noise_dhstate_calculate
                    (handshake->hybrid_private, handshake->hybrid_public,
                     data.data, len);
                MixKey(&(handshake->symmetric), data.data, len);
            }
            break;

        case NOISE_TOKEN_ES:
            if (handshake->is_initiator) {
                noise_dhstate_set_keypair_private
                    (handshake->dh_private, handshake->e, handshake->e_len);
                noise_dhstate_set_public_key
                    (handshake->dh_public, handshake->rs, handshake->rs_len);
            } else {
                noise_dhstate_set_keypair_private
                    (handshake->dh_private, handshake->s, handshake->s_len);
                noise_dhstate_set_public_key
                    (handshake->dh_public, handshake->re, handshake->re_len);
            }
            len = noise_dhstate_get_shared_key_length(handshake->dh_private);
            noise_dhstate_calculate
                (handshake->dh_private, handshake->dh_public, data.data, len);
            MixKey(&(handshake->symmetric), data.data, len);
            break;

        case NOISE_TOKEN_SE:
            if (handshake->is_initiator) {
                noise_dhstate_set_keypair_private
                    (handshake->dh_private, handshake->s, handshake->s_len);
                noise_dhstate_set_public_key
                    (handshake->dh_public, handshake->re, handshake->re_len);
            } else {
                noise_dhstate_set_keypair_private
                    (handshake->dh_private, handshake->e, handshake->e_len);
                noise_dhstate_set_public_key
                    (handshake->dh_public, handshake->rs, handshake->rs_len);
            }
            len = noise_dhstate_get_shared_key_length(handshake->dh_private);
            noise_dhstate_calculate
                (handshake->dh_private, handshake->dh_public, data.data, len);
            MixKey(&(handshake->symmetric), data.data, len);
            break;

        case NOISE_TOKEN_SS:
            noise_dhstate_set_keypair_private
                (handshake->dh_private, handshake->s, handshake->s_len);
            noise_dhstate_set_public_key
                (handshake->dh_public, handshake->rs, handshake->rs_len);
            len = noise_dhstate_get_shared_key_length(handshake->dh_private);
            noise_dhstate_calculate
                (handshake->dh_private, handshake->dh_public, data.data, len);
            MixKey(&(handshake->symmetric), data.data, len);
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
