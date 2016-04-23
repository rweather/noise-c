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

#include "test-helpers.h"
#include "protocol/internal.h"

/* Key values for testing purposes */
static uint8_t const init_private_25519[32] = {
    0xe6, 0x1e, 0xf9, 0x91, 0x9c, 0xde, 0x45, 0xdd,
    0x5f, 0x82, 0x16, 0x64, 0x04, 0xbd, 0x08, 0xe3,
    0x8b, 0xce, 0xb5, 0xdf, 0xdf, 0xde, 0xd0, 0xa3,
    0x4c, 0x8d, 0xf7, 0xed, 0x54, 0x22, 0x14, 0xd1
};
static uint8_t init_public_25519[32];
static uint8_t const init_private_448[56] = {
    0x34, 0xd5, 0x64, 0xc4, 0xbe, 0x96, 0x3d, 0x1b,
    0x2a, 0x89, 0xfc, 0xfe, 0x83, 0xe6, 0xa7, 0x2b,
    0x5e, 0x3f, 0x5e, 0x31, 0x27, 0xf9, 0xf5, 0x96,
    0xff, 0xc7, 0x57, 0x5e, 0x41, 0x8d, 0xfc, 0x1f,
    0x4e, 0x82, 0x7c, 0xfc, 0x10, 0xc9, 0xfe, 0xd3,
    0x8e, 0x92, 0xad, 0x56, 0xdd, 0xf8, 0xf0, 0x85,
    0x71, 0x43, 0x0d, 0xf2, 0xe7, 0x6d, 0x54, 0x11
};
static uint8_t init_public_448[56];
static uint8_t const resp_private_25519[32] = {
    0x4a, 0x3a, 0xcb, 0xfd, 0xb1, 0x63, 0xde, 0xc6,
    0x51, 0xdf, 0xa3, 0x19, 0x4d, 0xec, 0xe6, 0x76,
    0xd4, 0x37, 0x02, 0x9c, 0x62, 0xa4, 0x08, 0xb4,
    0xc5, 0xea, 0x91, 0x14, 0x24, 0x6e, 0x48, 0x93
};
static uint8_t resp_public_25519[32];
static uint8_t const resp_private_448[56] = {
    0xa9, 0xb4, 0x59, 0x71, 0x18, 0x08, 0x82, 0xa7,
    0x9b, 0x89, 0xa3, 0x39, 0x95, 0x44, 0xa4, 0x25,
    0xef, 0x81, 0x36, 0xd2, 0x78, 0xef, 0xa4, 0x43,
    0xed, 0x67, 0xd3, 0xff, 0x9d, 0x36, 0xe8, 0x83,
    0xbc, 0x33, 0x0c, 0x62, 0x95, 0xbb, 0xf6, 0xed,
    0x73, 0xff, 0x6f, 0xd1, 0x0c, 0xbe, 0xd7, 0x67,
    0xad, 0x05, 0xce, 0x03, 0xeb, 0xd2, 0x7c, 0x7c
};
static uint8_t resp_public_448[56];
static uint8_t const psk[32] = {
    0xf3, 0xd9, 0x4d, 0xa3, 0x74, 0x53, 0x90, 0x36,
    0x62, 0xf7, 0xd2, 0x16, 0xfc, 0xd2, 0x0f, 0xd9,
    0x9f, 0xc0, 0xeb, 0xc2, 0x7a, 0x62, 0xc0, 0xc4,
    0xf9, 0xd7, 0xe1, 0x25, 0x18, 0xef, 0x1d, 0xe6
};

/* Derive the public key values for testing purposes */
static void handshakestate_derive_keys(void)
{
    NoiseDHState *dh;

    /* Curve25519 keys */
    compare(noise_dhstate_new_by_id(&dh, NOISE_DH_CURVE25519),
            NOISE_ERROR_NONE);
    compare(noise_dhstate_set_keypair_private
                (dh, init_private_25519, sizeof(init_private_25519)),
            NOISE_ERROR_NONE);
    compare(noise_dhstate_get_public_key
                (dh, init_public_25519, sizeof(init_public_25519)),
            NOISE_ERROR_NONE);
    compare(noise_dhstate_set_keypair_private
                (dh, resp_private_25519, sizeof(resp_private_25519)),
            NOISE_ERROR_NONE);
    compare(noise_dhstate_get_public_key
                (dh, resp_public_25519, sizeof(resp_public_25519)),
            NOISE_ERROR_NONE);
    compare(noise_dhstate_free(dh), NOISE_ERROR_NONE);

    /* Curve448 keys */
    compare(noise_dhstate_new_by_id(&dh, NOISE_DH_CURVE448),
            NOISE_ERROR_NONE);
    compare(noise_dhstate_set_keypair_private
                (dh, init_private_448, sizeof(init_private_448)),
            NOISE_ERROR_NONE);
    compare(noise_dhstate_get_public_key
                (dh, init_public_448, sizeof(init_public_448)),
            NOISE_ERROR_NONE);
    compare(noise_dhstate_set_keypair_private
                (dh, resp_private_448, sizeof(resp_private_448)),
            NOISE_ERROR_NONE);
    compare(noise_dhstate_get_public_key
                (dh, resp_public_448, sizeof(resp_public_448)),
            NOISE_ERROR_NONE);
    compare(noise_dhstate_free(dh), NOISE_ERROR_NONE);
}

/* Check the behaviour of a specific handshake protocol.  These tests check
   whether the initiator and responder can talk to each other via the
   protocol but they do not check for correct bytes on the wire.  Wire checks
   are done by the separate vector tests. */
static void check_handshake_protocol(const char *name, int is_one_way)
{
    NoiseHandshakeState *initiator;
    NoiseHandshakeState *responder;
    NoiseHandshakeState *send;
    NoiseHandshakeState *recv;
    NoiseProtocolId id, id2;
    NoiseDHState *dh;
    const uint8_t *pattern;
    uint8_t init_flags;
    uint8_t resp_flags;
    uint8_t message[4096];
    uint8_t payload[23];
    NoiseBuffer mbuf;
    NoiseBuffer pbuf;
    int action;

    /* Set the name of this test for error reporting */
    data_name = name;

    /* Convert the name into a protocol identifier and look up the pattern */
    compare(noise_protocol_name_to_id(&id, name, strlen(name)),
            NOISE_ERROR_NONE);
    pattern = noise_pattern_lookup(id.pattern_id);
    verify(pattern != 0);
    init_flags = *pattern;
    resp_flags = noise_pattern_reverse_flags(init_flags);

    /* Create two objects for the initiator and responder,
       one by name and the other by identifier. */
    compare(noise_handshakestate_new_by_name
                (&initiator, name, NOISE_ROLE_INITIATOR),
            NOISE_ERROR_NONE);
    compare(noise_handshakestate_new_by_id
                (&responder, &id, NOISE_ROLE_RESPONDER),
            NOISE_ERROR_NONE);

    /* Check that the "needs" functions report results consistent
       with the requirements of the protocol */
    compare(noise_handshakestate_needs_local_keypair(initiator),
            (init_flags & NOISE_PAT_FLAG_LOCAL_STATIC) != 0);
    compare(noise_handshakestate_needs_remote_public_key(initiator),
            (init_flags & NOISE_PAT_FLAG_REMOTE_REQUIRED) != 0);
    compare(noise_handshakestate_needs_pre_shared_key(initiator),
            id.prefix_id == NOISE_PREFIX_PSK);
    compare(noise_handshakestate_needs_local_keypair(responder),
            (resp_flags & NOISE_PAT_FLAG_LOCAL_STATIC) != 0);
    compare(noise_handshakestate_needs_remote_public_key(responder),
            (resp_flags & NOISE_PAT_FLAG_REMOTE_REQUIRED) != 0);
    compare(noise_handshakestate_needs_pre_shared_key(responder),
            id.prefix_id == NOISE_PREFIX_PSK);

    /* Check other properties */
    compare(noise_handshakestate_get_role(initiator), NOISE_ROLE_INITIATOR);
    compare(noise_handshakestate_get_role(responder), NOISE_ROLE_RESPONDER);
    memset(&id2, 0xAA, sizeof(id2));
    compare(noise_handshakestate_get_protocol_id(initiator, &id2),
            NOISE_ERROR_NONE);
    verify(!memcmp(&id, &id2, sizeof(id)));
    memset(&id2, 0x66, sizeof(id2));
    compare(noise_handshakestate_get_protocol_id(responder, &id2),
            NOISE_ERROR_NONE);
    verify(!memcmp(&id, &id2, sizeof(id)));

    /* Specify a fixed prologue on each end */
    compare(noise_handshakestate_set_prologue(initiator, "Hello", 5),
            NOISE_ERROR_NONE);
    compare(noise_handshakestate_set_prologue(responder, "Hello", 5),
            NOISE_ERROR_NONE);

    /* Set the keys that are needed on each end */
    compare(noise_handshakestate_has_local_keypair(initiator), 0);
    if (noise_handshakestate_needs_local_keypair(initiator)) {
        compare(noise_handshakestate_start(initiator),
                NOISE_ERROR_LOCAL_KEY_REQUIRED);
        dh = noise_handshakestate_get_local_keypair_dh(initiator);
        if (noise_dhstate_get_dh_id(dh) == NOISE_DH_CURVE25519) {
            compare(noise_dhstate_set_keypair_private
                        (dh, init_private_25519, sizeof(init_private_25519)),
                    NOISE_ERROR_NONE);
        } else {
            compare(noise_dhstate_set_keypair_private
                        (dh, init_private_448, sizeof(init_private_448)),
                    NOISE_ERROR_NONE);
        }
        compare(noise_handshakestate_has_local_keypair(initiator), 1);
    } else {
        dh = noise_handshakestate_get_local_keypair_dh(initiator);
        verify(dh == 0);
    }
    compare(noise_handshakestate_has_remote_public_key(initiator), 0);
    if (noise_handshakestate_needs_remote_public_key(initiator)) {
        compare(noise_handshakestate_start(initiator),
                NOISE_ERROR_REMOTE_KEY_REQUIRED);
        dh = noise_handshakestate_get_remote_public_key_dh(initiator);
        if (noise_dhstate_get_dh_id(dh) == NOISE_DH_CURVE25519) {
            compare(noise_dhstate_set_public_key
                        (dh, resp_public_25519, sizeof(resp_public_25519)),
                    NOISE_ERROR_NONE);
        } else {
            compare(noise_dhstate_set_public_key
                        (dh, resp_public_448, sizeof(resp_public_448)),
                    NOISE_ERROR_NONE);
        }
        compare(noise_handshakestate_has_remote_public_key(initiator), 1);
    } else {
        dh = noise_handshakestate_get_remote_public_key_dh(initiator);
        verify(dh == 0);
    }
    compare(noise_handshakestate_has_local_keypair(responder), 0);
    if (noise_handshakestate_needs_local_keypair(responder)) {
        compare(noise_handshakestate_start(responder),
                NOISE_ERROR_LOCAL_KEY_REQUIRED);
        dh = noise_handshakestate_get_local_keypair_dh(responder);
        if (noise_dhstate_get_dh_id(dh) == NOISE_DH_CURVE25519) {
            compare(noise_dhstate_set_keypair_private
                        (dh, resp_private_25519, sizeof(resp_private_25519)),
                    NOISE_ERROR_NONE);
        } else {
            compare(noise_dhstate_set_keypair_private
                        (dh, resp_private_448, sizeof(resp_private_448)),
                    NOISE_ERROR_NONE);
        }
        compare(noise_handshakestate_has_local_keypair(responder), 1);
    } else {
        dh = noise_handshakestate_get_local_keypair_dh(responder);
        verify(dh == 0);
    }
    compare(noise_handshakestate_has_remote_public_key(responder), 0);
    if (noise_handshakestate_needs_remote_public_key(responder)) {
        compare(noise_handshakestate_start(responder),
                NOISE_ERROR_REMOTE_KEY_REQUIRED);
        dh = noise_handshakestate_get_remote_public_key_dh(responder);
        if (noise_dhstate_get_dh_id(dh) == NOISE_DH_CURVE25519) {
            compare(noise_dhstate_set_public_key
                        (dh, init_public_25519, sizeof(init_public_25519)),
                    NOISE_ERROR_NONE);
        } else {
            compare(noise_dhstate_set_public_key
                        (dh, init_public_448, sizeof(init_public_448)),
                    NOISE_ERROR_NONE);
        }
        compare(noise_handshakestate_has_remote_public_key(responder), 1);
    } else {
        dh = noise_handshakestate_get_remote_public_key_dh(responder);
        verify(dh == 0);
    }
    compare(noise_handshakestate_has_pre_shared_key(initiator), 0);
    if (noise_handshakestate_needs_pre_shared_key(initiator)) {
        compare(noise_handshakestate_start(initiator),
                NOISE_ERROR_PSK_REQUIRED);
        compare(noise_handshakestate_set_pre_shared_key
                    (initiator, psk, sizeof(psk)),
                NOISE_ERROR_NONE);
        compare(noise_handshakestate_has_pre_shared_key(initiator), 1);
    } else {
        compare(noise_handshakestate_set_pre_shared_key
                    (initiator, psk, sizeof(psk)),
                NOISE_ERROR_NOT_APPLICABLE);
    }
    compare(noise_handshakestate_has_pre_shared_key(responder), 0);
    if (noise_handshakestate_needs_pre_shared_key(responder)) {
        compare(noise_handshakestate_start(responder),
                NOISE_ERROR_PSK_REQUIRED);
        compare(noise_handshakestate_set_pre_shared_key
                    (responder, psk, sizeof(psk)),
                NOISE_ERROR_NONE);
        compare(noise_handshakestate_has_pre_shared_key(responder), 1);
    } else {
        compare(noise_handshakestate_set_pre_shared_key
                    (initiator, psk, sizeof(psk)),
                NOISE_ERROR_NOT_APPLICABLE);
    }

    /* Start the handshake running */
    compare(noise_handshakestate_start(initiator), NOISE_ERROR_NONE);
    compare(noise_handshakestate_start(responder), NOISE_ERROR_NONE);

    /* Starting the handshake again should fail (already running) */
    compare(noise_handshakestate_start(initiator), NOISE_ERROR_INVALID_STATE);
    compare(noise_handshakestate_start(responder), NOISE_ERROR_INVALID_STATE);

    /* Run the two handshakes in parallel while something to read/write */
    memset(payload, 0xAA, sizeof(payload));
    for (;;) {
        /* Which direction for this message? */
        action = noise_handshakestate_get_action(initiator);
        if (action == NOISE_ACTION_WRITE_MESSAGE) {
            send = initiator;
            recv = responder;
        } else if (action == NOISE_ACTION_READ_MESSAGE) {
            send = responder;
            recv = initiator;
        } else {
            break;
        }

        /* Check that the objects have the right action for this step */
        compare(noise_handshakestate_get_action(send),
                NOISE_ACTION_WRITE_MESSAGE);
        compare(noise_handshakestate_get_action(recv),
                NOISE_ACTION_READ_MESSAGE);

        /* Cannot perform the wrong operation on the sender or receiver */
        noise_buffer_set_output(mbuf, message, sizeof(message));
        noise_buffer_set_output(pbuf, payload, sizeof(payload));
        compare(noise_handshakestate_read_message(send, &mbuf, &pbuf),
                NOISE_ERROR_INVALID_STATE);
        noise_buffer_set_output(mbuf, message, sizeof(message));
        noise_buffer_set_input(pbuf, payload, sizeof(payload));
        compare(noise_handshakestate_write_message(recv, &mbuf, &pbuf),
                NOISE_ERROR_INVALID_STATE);

        /* Parameter errors */
        compare(noise_handshakestate_write_message(0, &mbuf, &pbuf),
                NOISE_ERROR_INVALID_PARAM);
        compare(noise_handshakestate_write_message(send, 0, &pbuf),
                NOISE_ERROR_INVALID_PARAM);
        mbuf.data = 0;
        compare(noise_handshakestate_write_message(send, &mbuf, &pbuf),
                NOISE_ERROR_INVALID_PARAM);
        noise_buffer_set_output(mbuf, message, sizeof(message));
        pbuf.data = 0;
        compare(noise_handshakestate_write_message(send, &mbuf, &pbuf),
                NOISE_ERROR_INVALID_PARAM);
        noise_buffer_set_output(mbuf, message, sizeof(message));
        noise_buffer_set_output(pbuf, payload, sizeof(payload));
        compare(noise_handshakestate_read_message(0, &mbuf, &pbuf),
                NOISE_ERROR_INVALID_PARAM);
        compare(noise_handshakestate_read_message(recv, 0, &pbuf),
                NOISE_ERROR_INVALID_PARAM);
        mbuf.data = 0;
        compare(noise_handshakestate_read_message(recv, &mbuf, &pbuf),
                NOISE_ERROR_INVALID_PARAM);
        noise_buffer_set_output(mbuf, message, sizeof(message));
        pbuf.data = 0;
        compare(noise_handshakestate_read_message(recv, &mbuf, &pbuf),
                NOISE_ERROR_INVALID_PARAM);

        /* Transfer the message to the other side properly */
        noise_buffer_set_output(mbuf, message, sizeof(message));
        noise_buffer_set_input(pbuf, payload, sizeof(payload));
        compare(noise_handshakestate_write_message(send, &mbuf, &pbuf),
                NOISE_ERROR_NONE);
        noise_buffer_set_output(pbuf, payload, sizeof(payload));
        compare(noise_handshakestate_read_message(recv, &mbuf, &pbuf),
                NOISE_ERROR_NONE);
    }

    /* Both handshakes should now have "split" */
    compare(noise_handshakestate_get_action(initiator), NOISE_ACTION_SPLIT);
    compare(noise_handshakestate_get_action(responder), NOISE_ACTION_SPLIT);

    /* Check for various error conditions */
    compare(noise_handshakestate_get_protocol_id(0, &id2),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_handshakestate_get_protocol_id(initiator, 0),
            NOISE_ERROR_INVALID_PARAM);

    /* Clean up */
    compare(noise_handshakestate_free(initiator), NOISE_ERROR_NONE);
    compare(noise_handshakestate_free(responder), NOISE_ERROR_NONE);
}

static void handshakestate_check_protocols(void)
{
    check_handshake_protocol("Noise_NN_25519_ChaChaPoly_BLAKE2s", 0);
}

static void handshakestate_check_errors(void)
{
    NoiseHandshakeState *state;
    NoiseProtocolId id;

    /* NULL parameters in various positions */
    compare(noise_handshakestate_has_local_keypair(0), 0);
    compare(noise_handshakestate_has_remote_public_key(0), 0);
    compare(noise_handshakestate_needs_remote_public_key(0), 0);
    compare(noise_handshakestate_needs_pre_shared_key(0), 0);
    compare(noise_handshakestate_has_pre_shared_key(0), 0);
    compare(noise_handshakestate_get_role(0), 0);
    compare(noise_handshakestate_get_action(0), NOISE_ACTION_NONE);
    compare(noise_handshakestate_start(0), NOISE_ERROR_INVALID_PARAM);

    /* If the id/name/role is unknown, state parameter should be set to NULL */
    memset(&id, 0, sizeof(id));
    state = (NoiseHandshakeState *)8;
    compare(noise_handshakestate_new_by_id(&state, &id, NOISE_ROLE_INITIATOR),
            NOISE_ERROR_UNKNOWN_ID);
    verify(state == NULL);
    state = (NoiseHandshakeState *)8;
    compare(noise_handshakestate_new_by_name(&state, 0, NOISE_ROLE_RESPONDER),
            NOISE_ERROR_INVALID_PARAM);
    verify(state == NULL);
    state = (NoiseHandshakeState *)8;
    compare(noise_handshakestate_new_by_name
                (&state, "Noise_XX_25519_ChaChaPony_BLAKE2s",
                 NOISE_ROLE_INITIATOR),
            NOISE_ERROR_UNKNOWN_NAME);
    state = (NoiseHandshakeState *)8;
    compare(noise_handshakestate_new_by_name
                (&state, "Noise_XX_25519_ChaChaPoly_BLAKE2s",
                 NOISE_DH_CURVE25519),
            NOISE_ERROR_INVALID_PARAM);
    verify(state == NULL);
    id.prefix_id = NOISE_PREFIX_STANDARD;
    id.pattern_id = NOISE_PATTERN_XX;
    id.dh_id = NOISE_DH_CURVE25519;
    id.cipher_id = NOISE_CIPHER_CHACHAPOLY;
    id.hash_id = NOISE_HASH_BLAKE2s;
    state = (NoiseHandshakeState *)8;
    compare(noise_handshakestate_new_by_id(&state, &id, NOISE_DH_CURVE25519),
            NOISE_ERROR_INVALID_PARAM);
    verify(state == NULL);
}

void test_handshakestate(void)
{
    handshakestate_derive_keys();
    handshakestate_check_protocols();
    handshakestate_check_errors();
}
