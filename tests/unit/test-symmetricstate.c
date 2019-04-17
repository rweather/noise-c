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

#define MAX_HASH_OUTPUT 64
#define MAX_DATA_LEN    128

typedef struct
{
    uint8_t hash[MAX_HASH_OUTPUT];

} HashValue;

typedef struct
{
    HashValue v1;
    HashValue v2;

} HKDFValue;

static NoiseHashState *hashstate = 0;
static size_t hash_len = 0;

/* Simple implementation of the HASH(data) function from the spec */
static HashValue HASH(const void *data, size_t len)
{
    HashValue result;
    memset(&result, 0, sizeof(result));
    compare(noise_hashstate_hash_one
                (hashstate, (const uint8_t *)data, len, result.hash, hash_len),
            NOISE_ERROR_NONE);
    return result;
}

/* Simple implementation of HASH(h || data) */
static HashValue HASHTwo(const HashValue h, const void *data, size_t len)
{
    HashValue result;
    memset(&result, 0, sizeof(result));
    compare(noise_hashstate_hash_two
                (hashstate, h.hash, hash_len,
                 (const uint8_t *)data, len, result.hash, hash_len),
            NOISE_ERROR_NONE);
    return result;
}

/* Pads a value or hashes it if it is too long for the hash output */
static HashValue PadOrHash(const void *data, size_t len)
{
    HashValue result;
    memset(&result, 0, sizeof(result));
    if (len <= hash_len)
        memcpy(result.hash, data, len);
    else
        result = HASH(data, len);
    return result;
}

/* Simple implementation of the HKDF(key, data) function from the spec */
static HKDFValue HKDF(const HashValue key, const uint8_t *data, size_t data_len)
{
    HKDFValue result;
    memset(&result, 0, sizeof(result));
    compare(noise_hashstate_hkdf
                (hashstate, key.hash, hash_len, data, data_len,
                 result.v1.hash, hash_len, result.v2.hash, hash_len),
            NOISE_ERROR_NONE);
    return result;
}

/* Checks the behaviour of a SymmetricState object that was just created.
   We walk the SymmetricState through its paces step by step and verify
   that it does what the specification requires.  Essentially we have a
   second SymmetricState implementation here which we bounce off the first. */
static void check_symmetric_object
    (NoiseSymmetricState *state1, NoiseSymmetricState *state2,
     NoiseSymmetricState *state3, const NoiseProtocolId *id,
     const char *protocol)
{
    static const char *data_vals[] = {
        "abcdefghijklmnopqrstuvwxyz",
        "0123456789",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    };
    size_t num_data_vals = sizeof(data_vals) / sizeof(data_vals[0]);
    HashValue ck, h;
    HKDFValue temp;
    const uint8_t *data;
    size_t index, len;
    size_t key_len;
    size_t mac_len;
    uint8_t buffer[MAX_DATA_LEN];
    uint8_t buffer2[MAX_DATA_LEN];
    uint8_t buffer3[MAX_DATA_LEN];
    NoiseCipherState *cipherstate;
    NoiseCipherState *c1;
    NoiseCipherState *c2;
    NoiseProtocolId temp_id;
    NoiseBuffer mbuf;

    /* We run two SymmetricState objects in parallel, state1 and state2.
       The state1 object is used to encrypt and state2 is used to decrypt. */

    /* Check the initial SymmetricState properties */
    memset(&temp_id, 0xAA, sizeof(temp_id));
    compare(noise_symmetricstate_get_protocol_id(state1, &temp_id),
            NOISE_ERROR_NONE);
    verify(!memcmp(&temp_id, id, sizeof(temp_id)));
    memset(&temp_id, 0x66, sizeof(temp_id));
    compare(noise_symmetricstate_get_protocol_id(state2, &temp_id),
            NOISE_ERROR_NONE);
    verify(!memcmp(&temp_id, id, sizeof(temp_id)));
    memset(&temp_id, 0x66, sizeof(temp_id));
    compare(noise_symmetricstate_get_protocol_id(state3, &temp_id),
            NOISE_ERROR_NONE);
    verify(!memcmp(&temp_id, id, sizeof(temp_id)));
    compare(noise_symmetricstate_get_protocol_id(0, &temp_id),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_symmetricstate_get_protocol_id(state1, 0),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_symmetricstate_get_mac_length(state1), 0);
    compare(noise_symmetricstate_get_mac_length(state2), 0);
    compare(noise_symmetricstate_get_mac_length(state3), 0);

    /* Create a HashState and CipherState to simulate expected behaviour */
    compare(noise_hashstate_new_by_id(&hashstate, id->hash_id),
            NOISE_ERROR_NONE);
    hash_len = noise_hashstate_get_hash_length(hashstate);
    compare(noise_cipherstate_new_by_id(&cipherstate, id->cipher_id),
            NOISE_ERROR_NONE);
    key_len = noise_cipherstate_get_key_length(cipherstate);
    mac_len = noise_cipherstate_get_mac_length(cipherstate);

    /* Check the expected original state of "ck" and "h" which should
       be the padded or hashed value of the protocol name */
    ck = h = PadOrHash(protocol, strlen(protocol));
    verify(!memcmp(ck.hash, state1->ck, hash_len));
    verify(!memcmp(h.hash, state1->h, hash_len));
    verify(!memcmp(ck.hash, state2->ck, hash_len));
    verify(!memcmp(h.hash, state2->h, hash_len));
    verify(!memcmp(ck.hash, state3->ck, hash_len));
    verify(!memcmp(h.hash, state3->h, hash_len));

    /* The encryption key should not currently be set */
    verify(!noise_cipherstate_has_key(state1->cipher));
    verify(!noise_cipherstate_has_key(state2->cipher));
    verify(!noise_cipherstate_has_key(state3->cipher));

    /* Mix data into the handshake hash */
    for (index = 0; index < num_data_vals; ++index) {
        len = strlen(data_vals[index]);
        data = (const uint8_t *)(data_vals[index]);
        h = HASHTwo(h, data, len);
        compare(noise_symmetricstate_mix_hash(state1, data, len),
                NOISE_ERROR_NONE);
        compare(noise_symmetricstate_mix_hash(state2, data, len),
                NOISE_ERROR_NONE);
        compare(noise_symmetricstate_mix_hash(state3, data, len),
                NOISE_ERROR_NONE);
        verify(!memcmp(ck.hash, state1->ck, hash_len));
        verify(!memcmp(h.hash, state1->h, hash_len));
        verify(!memcmp(ck.hash, state2->ck, hash_len));
        verify(!memcmp(h.hash, state2->h, hash_len));
        verify(!memcmp(ck.hash, state3->ck, hash_len));
        verify(!memcmp(h.hash, state3->h, hash_len));
        compare(noise_symmetricstate_mix_hash(0, data, len),
                NOISE_ERROR_INVALID_PARAM);
        compare(noise_symmetricstate_mix_hash(state1, 0, len),
                NOISE_ERROR_INVALID_PARAM);
    }

    /* Encrypt with state1 and decrypt with state2/state3.  The encryption
       key has not been set yet, so the messages should be in plaintext. */
    for (index = 0; index < num_data_vals; ++index) {
        len = strlen(data_vals[index]);
        data = (const uint8_t *)(data_vals[index]);
        memcpy(buffer, data, len);
        noise_buffer_set_inout(mbuf, buffer, len, sizeof(buffer));
        compare(noise_symmetricstate_encrypt_and_hash(state1, &mbuf),
                NOISE_ERROR_NONE);
        compare(mbuf.size, len);
        verify(!memcmp(mbuf.data, data, len));
        memcpy(buffer2, buffer, len);
        h = HASHTwo(h, buffer, len);
        noise_buffer_set_input(mbuf, buffer, len);
        compare(noise_symmetricstate_decrypt_and_hash(state2, &mbuf),
                NOISE_ERROR_NONE);
        compare(mbuf.size, len);
        verify(!memcmp(mbuf.data, data, len));
        noise_buffer_set_input(mbuf, buffer2, len);
        compare(noise_symmetricstate_decrypt_and_hash(state3, &mbuf),
                NOISE_ERROR_NONE);
        compare(mbuf.size, len);
        verify(!memcmp(mbuf.data, data, len));
        verify(!memcmp(ck.hash, state1->ck, hash_len));
        verify(!memcmp(h.hash, state1->h, hash_len));
        verify(!memcmp(ck.hash, state2->ck, hash_len));
        verify(!memcmp(h.hash, state2->h, hash_len));
        verify(!memcmp(ck.hash, state3->ck, hash_len));
        verify(!memcmp(h.hash, state3->h, hash_len));
        compare(noise_symmetricstate_get_mac_length(state1), 0);
        compare(noise_symmetricstate_get_mac_length(state2), 0);
        compare(noise_symmetricstate_get_mac_length(state3), 0);
        noise_buffer_set_inout(mbuf, buffer, len, sizeof(buffer));
        compare(noise_symmetricstate_encrypt_and_hash(0, &mbuf),
                NOISE_ERROR_INVALID_PARAM);
        compare(noise_symmetricstate_encrypt_and_hash(state1, 0),
                NOISE_ERROR_INVALID_PARAM);
        mbuf.data = 0;
        compare(noise_symmetricstate_encrypt_and_hash(state1, &mbuf),
                NOISE_ERROR_INVALID_PARAM);
        noise_buffer_set_input(mbuf, buffer, NOISE_MAX_PAYLOAD_LEN + 1);
        compare(noise_symmetricstate_encrypt_and_hash(state1, &mbuf),
                NOISE_ERROR_INVALID_LENGTH);
        noise_buffer_set_input(mbuf, buffer, len);
        compare(noise_symmetricstate_decrypt_and_hash(0, &mbuf),
                NOISE_ERROR_INVALID_PARAM);
        compare(noise_symmetricstate_decrypt_and_hash(state1, 0),
                NOISE_ERROR_INVALID_PARAM);
        mbuf.data = 0;
        compare(noise_symmetricstate_decrypt_and_hash(state1, &mbuf),
                NOISE_ERROR_INVALID_PARAM);
        noise_buffer_set_input(mbuf, buffer, NOISE_MAX_PAYLOAD_LEN + 1);
        compare(noise_symmetricstate_decrypt_and_hash(state1, &mbuf),
                NOISE_ERROR_INVALID_LENGTH);
    }

    /* The encryption key should still not be set */
    verify(!noise_cipherstate_has_key(state1->cipher));
    verify(!noise_cipherstate_has_key(state2->cipher));
    verify(!noise_cipherstate_has_key(state3->cipher));

    /* Mix data into the chaining key */
    memset(&temp, 0, sizeof(temp));
    for (index = 0; index < num_data_vals; ++index) {
        len = strlen(data_vals[index]);
        data = (const uint8_t *)(data_vals[index]);
        temp = HKDF(ck, data, len);
        compare(noise_symmetricstate_mix_key(state1, data, len),
                NOISE_ERROR_NONE);
        compare(noise_symmetricstate_mix_key(state2, data, len),
                NOISE_ERROR_NONE);
        compare(noise_symmetricstate_mix_key(state3, data, len),
                NOISE_ERROR_NONE);
        ck = temp.v1;
        verify(!memcmp(ck.hash, state1->ck, hash_len));
        verify(!memcmp(h.hash, state1->h, hash_len));
        verify(!memcmp(ck.hash, state2->ck, hash_len));
        verify(!memcmp(h.hash, state2->h, hash_len));
        verify(!memcmp(ck.hash, state3->ck, hash_len));
        verify(!memcmp(h.hash, state3->h, hash_len));
        compare(noise_symmetricstate_get_mac_length(state1), mac_len);
        compare(noise_symmetricstate_get_mac_length(state2), mac_len);
        compare(noise_symmetricstate_get_mac_length(state3), mac_len);
        compare(noise_symmetricstate_mix_key(0, data, len),
                NOISE_ERROR_INVALID_PARAM);
        compare(noise_symmetricstate_mix_key(state1, 0, len),
                NOISE_ERROR_INVALID_PARAM);
    }

    /* We should have an encryption key now.  Set on the simulated objects. */
    verify(noise_cipherstate_has_key(state1->cipher));
    verify(noise_cipherstate_has_key(state2->cipher));
    verify(noise_cipherstate_has_key(state3->cipher));
    compare(noise_cipherstate_init_key(cipherstate, temp.v2.hash, key_len),
            NOISE_ERROR_NONE);

    /* Encrypt with state1 and decrypt with state2.  Real encryption now. */
    compare(noise_symmetricstate_get_mac_length(state1), mac_len);
    compare(noise_symmetricstate_get_mac_length(state2), mac_len);
    for (index = 0; index < num_data_vals; ++index) {
        len = strlen(data_vals[index]);
        data = (const uint8_t *)(data_vals[index]);
        memcpy(buffer, data, len);
        memcpy(buffer2, data, len);
        noise_buffer_set_inout(mbuf, buffer2, len, sizeof(buffer2));
        compare(noise_cipherstate_encrypt_with_ad
                    (cipherstate, h.hash, hash_len, &mbuf),
                NOISE_ERROR_NONE);
        compare(mbuf.size, len + mac_len);
        noise_buffer_set_inout(mbuf, buffer, len, sizeof(buffer));
        compare(noise_symmetricstate_encrypt_and_hash(state1, &mbuf),
                NOISE_ERROR_NONE);
        compare(mbuf.size, len + mac_len);
        verify(!memcmp(mbuf.data, buffer2, len + mac_len));
        memcpy(buffer3, buffer, len + mac_len);
        h = HASHTwo(h, buffer, len + mac_len);
        noise_buffer_set_input(mbuf, buffer, len + mac_len);
        compare(noise_symmetricstate_decrypt_and_hash(state2, &mbuf),
                NOISE_ERROR_NONE);
        compare(mbuf.size, len);
        verify(!memcmp(mbuf.data, data, len));
        noise_buffer_set_input(mbuf, buffer3, len + mac_len);
        compare(noise_symmetricstate_decrypt_and_hash(state3, &mbuf),
                NOISE_ERROR_NONE);
        compare(mbuf.size, len);
        verify(!memcmp(mbuf.data, data, len));
        noise_buffer_set_inout(mbuf, buffer, len, sizeof(buffer));
        compare(noise_symmetricstate_encrypt_and_hash(0, &mbuf),
                NOISE_ERROR_INVALID_PARAM);
        compare(noise_symmetricstate_encrypt_and_hash(state1, 0),
                NOISE_ERROR_INVALID_PARAM);
        mbuf.data = 0;
        compare(noise_symmetricstate_encrypt_and_hash(state1, &mbuf),
                NOISE_ERROR_INVALID_PARAM);
        noise_buffer_set_input(mbuf, buffer, NOISE_MAX_PAYLOAD_LEN - mac_len + 1);
        compare(noise_symmetricstate_encrypt_and_hash(state1, &mbuf),
                NOISE_ERROR_INVALID_LENGTH);
        noise_buffer_set_input(mbuf, buffer, len);
        compare(noise_symmetricstate_decrypt_and_hash(0, &mbuf),
                NOISE_ERROR_INVALID_PARAM);
        compare(noise_symmetricstate_decrypt_and_hash(state1, 0),
                NOISE_ERROR_INVALID_PARAM);
        mbuf.data = 0;
        compare(noise_symmetricstate_decrypt_and_hash(state1, &mbuf),
                NOISE_ERROR_INVALID_PARAM);
        noise_buffer_set_input(mbuf, buffer, NOISE_MAX_PAYLOAD_LEN + 1);
        compare(noise_symmetricstate_decrypt_and_hash(state1, &mbuf),
                NOISE_ERROR_INVALID_LENGTH);
    }

    /* Final check on the chaining key and handshake hash */
    verify(!memcmp(ck.hash, state1->ck, hash_len));
    verify(!memcmp(h.hash, state1->h, hash_len));
    verify(!memcmp(ck.hash, state2->ck, hash_len));
    verify(!memcmp(h.hash, state2->h, hash_len));
    verify(!memcmp(ck.hash, state3->ck, hash_len));
    verify(!memcmp(h.hash, state3->h, hash_len));

    /* Split the SymmetricState */
    compare(noise_symmetricstate_split(0, &c1, &c2),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_symmetricstate_split(state1, 0, 0),
            NOISE_ERROR_INVALID_PARAM);
    c1 = c2 = 0;
    compare(noise_symmetricstate_split(state1, &c1, &c2),
            NOISE_ERROR_NONE);
    verify(c1 != 0);
    verify(c2 != 0);
    verify(noise_cipherstate_has_key(c1));
    verify(noise_cipherstate_has_key(c2));

    /* Check that the encryption keys in c1 and c2 are as expected */
    temp = HKDF(ck, buffer, 0);
    compare(noise_cipherstate_init_key(cipherstate, temp.v1.hash, key_len),
            NOISE_ERROR_NONE);
    for (index = 0; index < num_data_vals; ++index) {
        len = strlen(data_vals[index]);
        data = (const uint8_t *)(data_vals[index]);
        memcpy(buffer, data, len);
        memcpy(buffer2, data, len);
        noise_buffer_set_inout(mbuf, buffer2, len, sizeof(buffer2));
        compare(noise_cipherstate_encrypt_with_ad
                   (cipherstate, (const uint8_t *)&index, sizeof(index), &mbuf),
                NOISE_ERROR_NONE);
        compare(mbuf.size, len + mac_len);
        noise_buffer_set_inout(mbuf, buffer, len, sizeof(buffer));
        compare(noise_cipherstate_encrypt_with_ad
                    (c1, (const uint8_t *)&index, sizeof(index), &mbuf),
                NOISE_ERROR_NONE);
        compare(mbuf.size, len + mac_len);
        verify(!memcmp(mbuf.data, buffer2, len + mac_len));
    }
    compare(noise_cipherstate_init_key(cipherstate, temp.v2.hash, key_len),
            NOISE_ERROR_NONE);
    for (index = 0; index < num_data_vals; ++index) {
        len = strlen(data_vals[index]);
        data = (const uint8_t *)(data_vals[index]);
        memcpy(buffer, data, len);
        memcpy(buffer2, data, len);
        noise_buffer_set_inout(mbuf, buffer2, len, sizeof(buffer2));
        compare(noise_cipherstate_encrypt_with_ad
                   (cipherstate, (const uint8_t *)&index, sizeof(index), &mbuf),
                NOISE_ERROR_NONE);
        compare(mbuf.size, len + mac_len);
        noise_buffer_set_inout(mbuf, buffer, len, sizeof(buffer));
        compare(noise_cipherstate_encrypt_with_ad
                    (c2, (const uint8_t *)&index, sizeof(index), &mbuf),
                NOISE_ERROR_NONE);
        compare(mbuf.size, len + mac_len);
        verify(!memcmp(mbuf.data, buffer2, len + mac_len));
    }
    compare(noise_cipherstate_free(c1), NOISE_ERROR_NONE);
    compare(noise_cipherstate_free(c2), NOISE_ERROR_NONE);

    /* Check errors that are only reported once the SymmetricState is split */
    compare(noise_symmetricstate_mix_hash(state1, buffer, 8),
            NOISE_ERROR_INVALID_STATE);
    compare(noise_symmetricstate_mix_key(state1, buffer, 8),
            NOISE_ERROR_INVALID_STATE);
    noise_buffer_set_inout(mbuf, buffer, len, sizeof(buffer));
    compare(noise_symmetricstate_encrypt_and_hash(state1, &mbuf),
            NOISE_ERROR_INVALID_STATE);
    compare(noise_symmetricstate_decrypt_and_hash(state1, &mbuf),
            NOISE_ERROR_INVALID_STATE);
    compare(noise_symmetricstate_split(state1, &c1, &c2),
            NOISE_ERROR_INVALID_STATE);
    compare(noise_symmetricstate_split(state1, 0, &c2),
            NOISE_ERROR_INVALID_STATE);
    compare(noise_symmetricstate_split(state1, &c1, 0),
            NOISE_ERROR_INVALID_STATE);

    /* Split the second SymmetricState, with c2 optional */
    c1 = 0;
    c2 = (NoiseCipherState *)(-1);
    compare(noise_symmetricstate_split(state2, &c1, 0),
            NOISE_ERROR_NONE);
    verify(c1 != 0);
    verify(c2 == (NoiseCipherState *)(-1));
    c2 = 0;
    verify(noise_cipherstate_has_key(c1));
    verify(!noise_cipherstate_has_key(c2));

    /* Check that c1 encrypts in the same way as before */
    compare(noise_cipherstate_init_key(cipherstate, temp.v1.hash, key_len),
            NOISE_ERROR_NONE);
    for (index = 0; index < num_data_vals; ++index) {
        len = strlen(data_vals[index]);
        data = (const uint8_t *)(data_vals[index]);
        memcpy(buffer, data, len);
        memcpy(buffer2, data, len);
        noise_buffer_set_inout(mbuf, buffer2, len, sizeof(buffer2));
        compare(noise_cipherstate_encrypt_with_ad
                   (cipherstate, (const uint8_t *)&index, sizeof(index), &mbuf),
                NOISE_ERROR_NONE);
        compare(mbuf.size, len + mac_len);
        noise_buffer_set_inout(mbuf, buffer, len, sizeof(buffer));
        compare(noise_cipherstate_encrypt_with_ad
                    (c1, (const uint8_t *)&index, sizeof(index), &mbuf),
                NOISE_ERROR_NONE);
        compare(mbuf.size, len + mac_len);
        verify(!memcmp(mbuf.data, buffer2, len + mac_len));
    }
    compare(noise_cipherstate_free(c1), NOISE_ERROR_NONE);
    compare(noise_cipherstate_free(c2), NOISE_ERROR_INVALID_PARAM);

    /* Split the third SymmetricState, with c1 optional */
    c1 = (NoiseCipherState *)(-1);
    c2 = 0;
    compare(noise_symmetricstate_split(state3, 0, &c2),
            NOISE_ERROR_NONE);
    verify(c1 == (NoiseCipherState *)(-1));
    verify(c2 != 0);
    c1 = 0;
    verify(!noise_cipherstate_has_key(c1));
    verify(noise_cipherstate_has_key(c2));

    /* Check that c2 encrypts in the same way as before */
    compare(noise_cipherstate_init_key(cipherstate, temp.v2.hash, key_len),
            NOISE_ERROR_NONE);
    for (index = 0; index < num_data_vals; ++index) {
        len = strlen(data_vals[index]);
        data = (const uint8_t *)(data_vals[index]);
        memcpy(buffer, data, len);
        memcpy(buffer2, data, len);
        noise_buffer_set_inout(mbuf, buffer2, len, sizeof(buffer2));
        compare(noise_cipherstate_encrypt_with_ad
                   (cipherstate, (const uint8_t *)&index, sizeof(index), &mbuf),
                NOISE_ERROR_NONE);
        compare(mbuf.size, len + mac_len);
        noise_buffer_set_inout(mbuf, buffer, len, sizeof(buffer));
        compare(noise_cipherstate_encrypt_with_ad
                    (c2, (const uint8_t *)&index, sizeof(index), &mbuf),
                NOISE_ERROR_NONE);
        compare(mbuf.size, len + mac_len);
        verify(!memcmp(mbuf.data, buffer2, len + mac_len));
    }

    /* Clean up */
    compare(noise_hashstate_free(hashstate), NOISE_ERROR_NONE);
    compare(noise_cipherstate_free(cipherstate), NOISE_ERROR_NONE);
    compare(noise_cipherstate_free(c1), NOISE_ERROR_INVALID_PARAM);
    compare(noise_cipherstate_free(c2), NOISE_ERROR_NONE);
    hashstate = 0;
}

/* Create SymmetricState objects by id or name and check their behaviour */
static void check_symmetric(const char *protocol)
{
    NoiseSymmetricState *state1;
    NoiseSymmetricState *state2;
    NoiseSymmetricState *state3;
    NoiseProtocolId id;

    /* Set the name of the protocol for reporting test failures */
    data_name = protocol;

    /* Parse the protocol name into a set of identifiers */
    compare(noise_protocol_name_to_id(&id, protocol, strlen(protocol)),
            NOISE_ERROR_NONE);

    /* Check the behaviour of SymmetricState when creating by identifier */
    compare(noise_symmetricstate_new_by_id(&state1, &id),
            NOISE_ERROR_NONE);
    compare(noise_symmetricstate_new_by_id(&state2, &id),
            NOISE_ERROR_NONE);
    compare(noise_symmetricstate_new_by_id(&state3, &id),
            NOISE_ERROR_NONE);
    check_symmetric_object(state1, state2, state3, &id, protocol);
    compare(noise_symmetricstate_free(state1), NOISE_ERROR_NONE);
    compare(noise_symmetricstate_free(state2), NOISE_ERROR_NONE);
    compare(noise_symmetricstate_free(state3), NOISE_ERROR_NONE);

    /* Check the behaviour of SymmetricState when creating by name */
    compare(noise_symmetricstate_new_by_name(&state1, protocol),
            NOISE_ERROR_NONE);
    compare(noise_symmetricstate_new_by_name(&state2, protocol),
            NOISE_ERROR_NONE);
    compare(noise_symmetricstate_new_by_name(&state3, protocol),
            NOISE_ERROR_NONE);
    check_symmetric_object(state1, state2, state3, &id, protocol);
    compare(noise_symmetricstate_free(state1), NOISE_ERROR_NONE);
    compare(noise_symmetricstate_free(state2), NOISE_ERROR_NONE);
    compare(noise_symmetricstate_free(state3), NOISE_ERROR_NONE);
}

static void symmetricstate_check_protocols(void)
{
    check_symmetric("Noise_XX_25519_AESGCM_SHA256");
    check_symmetric("Noise_N_25519_ChaChaPoly_BLAKE2s");
    check_symmetric("Noise_XXfallback_448_AESGCM_SHA512");
    check_symmetric("Noise_IK_448_ChaChaPoly_BLAKE2b");

    check_symmetric("NoisePSK_XX_25519_AESGCM_SHA256");
    check_symmetric("NoisePSK_N_25519_ChaChaPoly_BLAKE2s");
    check_symmetric("NoisePSK_XXfallback_448_AESGCM_SHA512");
    check_symmetric("NoisePSK_IK_448_ChaChaPoly_BLAKE2b");
}

/* Check other error conditions that can be reported by the functions */
static void symmetricstate_check_errors(void)
{
    NoiseSymmetricState *state;
    NoiseProtocolId id = {0};

    /* NULL parameters in various positions */
    compare(noise_symmetricstate_free(0),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_symmetricstate_new_by_id(0, &id),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_symmetricstate_new_by_id(&state, 0),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_symmetricstate_new_by_name
                (0, "Noise_N_25519_ChaChaPoly_BLAKE2s"),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_symmetricstate_new_by_name(&state, 0),
            NOISE_ERROR_INVALID_PARAM);

    /* If the id/name is unknown, the state parameter should be set to NULL */
    state = (NoiseSymmetricState *)8;
    compare(noise_symmetricstate_new_by_id(&state, &id),
            NOISE_ERROR_UNKNOWN_ID);
    verify(state == NULL);
    state = (NoiseSymmetricState *)8;
    compare(noise_symmetricstate_new_by_name(&state, 0),
            NOISE_ERROR_INVALID_PARAM);
    verify(state == NULL);
    state = (NoiseSymmetricState *)8;
    compare(noise_symmetricstate_new_by_name
                (&state, "Noise_N_25519_ChaChaPony_BLAKE2s"),
            NOISE_ERROR_UNKNOWN_NAME);
    verify(state == NULL);
}

void test_symmetricstate(void)
{
    symmetricstate_check_protocols();
    symmetricstate_check_errors();
}
