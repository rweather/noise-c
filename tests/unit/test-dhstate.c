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

#define MAX_DH_KEY_LEN 80

/* Check raw DH output against test vectors */
static void check_dh(int id, size_t private_key_len, size_t public_key_len,
                     size_t shared_key_len, const char *name, int is_null,
                     const char *private_key, const char *public_key,
                     const char *shared_key)
{
    NoiseDHState *state;
    uint8_t priv_key[MAX_DH_KEY_LEN];
    uint8_t pub_key[MAX_DH_KEY_LEN];
    uint8_t share_key[MAX_DH_KEY_LEN];
    uint8_t temp[MAX_DH_KEY_LEN];

    /* Convert the test strings into binary data */
    compare(string_to_data(priv_key, sizeof(priv_key), private_key),
            private_key_len);
    compare(string_to_data(pub_key, sizeof(pub_key), public_key),
            public_key_len);
    compare(string_to_data(share_key, sizeof(share_key), shared_key),
            shared_key_len);

    /* Create the DH object and check its properties */
    compare(noise_dhstate_new_by_id(&state, id), NOISE_ERROR_NONE);
    compare(noise_dhstate_get_dh_id(state), id);
    compare(noise_dhstate_get_private_key_length(state), private_key_len);
    compare(noise_dhstate_get_public_key_length(state), public_key_len);
    compare(noise_dhstate_get_shared_key_length(state), shared_key_len);

    /* Calculate the shared key and check against the test data */
    memset(temp, 0xAA, sizeof(temp));
    compare(noise_dhstate_calculate
                (state, temp, shared_key_len,
                 priv_key, private_key_len,
                 pub_key, public_key_len),
            NOISE_ERROR_NONE);
    verify(!memcmp(temp, share_key, shared_key_len));

    /* Check the behaviour of null public keys */
    if (is_null) {
        verify(noise_dhstate_is_null_public_key(state, pub_key, public_key_len));
        verify(noise_dhstate_is_null_public_key(state, share_key, shared_key_len));
        memset(temp, 0xAA, sizeof(temp));
        compare(noise_dhstate_get_null_public_key(state, temp, public_key_len),
                NOISE_ERROR_NONE);
        verify(!memcmp(temp, pub_key, public_key_len));
        memset(temp, 0x66, sizeof(temp));
        compare(noise_dhstate_get_null_public_key(state, temp, shared_key_len),
                NOISE_ERROR_NONE);
        verify(!memcmp(temp, share_key, shared_key_len));
        verify(!noise_dhstate_is_null_public_key(state, pub_key, public_key_len - 1));
        verify(!noise_dhstate_is_null_public_key(0, pub_key, public_key_len));
        verify(!noise_dhstate_is_null_public_key(state, 0, public_key_len));
    } else {
        verify(!noise_dhstate_is_null_public_key(state, pub_key, public_key_len));
        verify(!noise_dhstate_is_null_public_key(state, share_key, shared_key_len));
    }

    /* Check parameter error conditions */
    compare(noise_dhstate_calculate
                (0, temp, shared_key_len,
                 priv_key, private_key_len,
                 pub_key, public_key_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_dhstate_calculate
                (state, 0, shared_key_len,
                 priv_key, private_key_len,
                 pub_key, public_key_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_dhstate_calculate
                (state, temp, shared_key_len,
                 0, private_key_len,
                 pub_key, public_key_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_dhstate_calculate
                (state, temp, shared_key_len,
                 priv_key, private_key_len,
                 0, public_key_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_dhstate_calculate
                (state, temp, shared_key_len + 1,
                 priv_key, private_key_len,
                 pub_key, public_key_len),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_dhstate_calculate
                (state, temp, shared_key_len,
                 priv_key, private_key_len - 1,
                 pub_key, public_key_len),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_dhstate_calculate
                (state, temp, shared_key_len,
                 priv_key, private_key_len,
                 pub_key, public_key_len * 2),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_dhstate_get_null_public_key(0, temp, public_key_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_dhstate_get_null_public_key(state, 0, public_key_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_dhstate_get_null_public_key(state, temp, public_key_len - 1),
            NOISE_ERROR_INVALID_LENGTH);

    /* Re-create the object by name and check its properties again */
    compare(noise_dhstate_free(state), NOISE_ERROR_NONE);
    compare(noise_dhstate_new_by_name(&state, name), NOISE_ERROR_NONE);
    compare(noise_dhstate_get_dh_id(state), id);
    compare(noise_dhstate_get_private_key_length(state), private_key_len);
    compare(noise_dhstate_get_public_key_length(state), public_key_len);
    compare(noise_dhstate_get_shared_key_length(state), shared_key_len);

    /* Make sure that it is still the same object by checking DH outputs */
    memset(temp, 0xAA, sizeof(temp));
    compare(noise_dhstate_calculate
                (state, temp, shared_key_len,
                 priv_key, private_key_len,
                 pub_key, public_key_len),
            NOISE_ERROR_NONE);
    verify(!memcmp(temp, share_key, shared_key_len));

    /* Clean up */
    compare(noise_dhstate_free(state), NOISE_ERROR_NONE);
}

/* Check against test vectors from the various specifications
   to validate that the algorithms work as low level primitives */
static void dhstate_check_test_vectors(void)
{
    /* Curve25519 - From section 6.1 of RFC 7748 */
    check_dh
        (NOISE_DH_CURVE25519, 32, 32, 32, "25519", 0,
         /* Alice's private key */
         "0x77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
         /* Bob's public key */
         "0xde9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
         /* Shared secret */
         "0x4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    check_dh
        (NOISE_DH_CURVE25519, 32, 32, 32, "25519", 0,
         /* Bob's private key */
         "0x5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
         /* Alice's public key */
         "0x8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
         /* Shared secret */
         "0x4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    /* Curve25519 - Check the behaviour of null public keys */
    check_dh
        (NOISE_DH_CURVE25519, 32, 32, 32, "25519", 1,
         /* Alice's private key */
         "0x77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
         /* Null public key */
         "0x0000000000000000000000000000000000000000000000000000000000000000",
         /* Shared secret - also null */
         "0x0000000000000000000000000000000000000000000000000000000000000000");

    /* Curve448 - From section 6.2 of RFC 7748 */
    check_dh
        (NOISE_DH_CURVE448, 56, 56, 56, "448", 0,
         /* Alice's private key */
         "0x9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d"
           "d9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b",
         /* Bob's public key */
         "0x3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b430"
           "27d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609",
         /* Shared secret */
         "0x07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282b"
           "b60c0b56fd2464c335543936521c24403085d59a449a5037514a879d");
    check_dh
        (NOISE_DH_CURVE448, 56, 56, 56, "448", 0,
         /* Bob's private key */
         "0x1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d"
           "6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d",
         /* Alices's public key */
         "0x9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c"
           "22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0",
         /* Shared secret */
         "0x07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282b"
           "b60c0b56fd2464c335543936521c24403085d59a449a5037514a879d");

    /* Curve448 - Check the behaviour of null public keys */
    check_dh
        (NOISE_DH_CURVE448, 56, 56, 56, "448", 1,
         /* Alice's private key */
         "0x9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d"
           "d9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b",
         /* Null public key */
         "0x00000000000000000000000000000000000000000000000000000000"
           "00000000000000000000000000000000000000000000000000000000",
         /* Shared secret - also null */
         "0x00000000000000000000000000000000000000000000000000000000"
           "00000000000000000000000000000000000000000000000000000000");
}

/* Check the generation and use of new key pairs */
static void check_dh_generate(int id)
{
    NoiseDHState *state;
    uint8_t alice_priv[MAX_DH_KEY_LEN];
    uint8_t alice_pub[MAX_DH_KEY_LEN];
    uint8_t bob_priv[MAX_DH_KEY_LEN];
    uint8_t bob_pub[MAX_DH_KEY_LEN];
    uint8_t shared1[MAX_DH_KEY_LEN];
    uint8_t shared2[MAX_DH_KEY_LEN];
    size_t private_key_len;
    size_t public_key_len;
    size_t shared_key_len;

    /* Create the DH object and get its properties */
    compare(noise_dhstate_new_by_id(&state, id), NOISE_ERROR_NONE);
    compare(noise_dhstate_get_dh_id(state), id);
    private_key_len = noise_dhstate_get_private_key_length(state);
    public_key_len = noise_dhstate_get_public_key_length(state);
    shared_key_len = noise_dhstate_get_shared_key_length(state);

    /* Generate keypairs for Alice and Bob */
    compare(noise_dhstate_generate_keypair
                (state, alice_priv, private_key_len,
                 alice_pub, public_key_len),
            NOISE_ERROR_NONE);
    compare(noise_dhstate_generate_keypair
                (state, bob_priv, private_key_len,
                 bob_pub, public_key_len),
            NOISE_ERROR_NONE);

    /* Calculate the shared key on both ends and compare */
    memset(shared1, 0xAA, sizeof(shared1));
    memset(shared2, 0x66, sizeof(shared2));
    compare(noise_dhstate_calculate
                (state, shared1, shared_key_len,
                 alice_priv, private_key_len,
                 bob_pub, public_key_len),
            NOISE_ERROR_NONE);
    compare(noise_dhstate_calculate
                (state, shared2, shared_key_len,
                 bob_priv, private_key_len,
                 alice_pub, public_key_len),
            NOISE_ERROR_NONE);
    verify(!memcmp(shared1, shared2, shared_key_len));

    /* Check parameter error conditions */
    compare(noise_dhstate_generate_keypair
                (0, alice_priv, private_key_len,
                 alice_pub, public_key_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_dhstate_generate_keypair
                (state, 0, private_key_len,
                 alice_pub, public_key_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_dhstate_generate_keypair
                (state, alice_priv, private_key_len,
                 0, public_key_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_dhstate_generate_keypair
                (state, alice_priv, private_key_len - 1,
                 alice_pub, public_key_len),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_dhstate_generate_keypair
                (state, alice_priv, private_key_len,
                 alice_pub, public_key_len + 1),
            NOISE_ERROR_INVALID_LENGTH);

    /* Clean up */
    compare(noise_dhstate_free(state), NOISE_ERROR_NONE);
}

/* Check the generation and use of new key pairs */
static void dhstate_check_generate_keypair(void)
{
    check_dh_generate(NOISE_DH_CURVE25519);
    check_dh_generate(NOISE_DH_CURVE448);
}

/* Check other error conditions that can be reported by the functions */
static void dhstate_check_errors(void)
{
    NoiseDHState *state;

    /* NULL parameters in various positions */
    compare(noise_dhstate_free(0), NOISE_ERROR_INVALID_PARAM);
    compare(noise_dhstate_get_dh_id(0), NOISE_DH_NONE);
    compare(noise_dhstate_get_private_key_length(0), 0);
    compare(noise_dhstate_get_public_key_length(0), 0);
    compare(noise_dhstate_get_shared_key_length(0), 0);
    compare(noise_dhstate_new_by_id(0, NOISE_DH_CURVE25519),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_dhstate_new_by_name(0, "Cuve25519"),
            NOISE_ERROR_INVALID_PARAM);

    /* If the id/name is unknown, the state parameter should be set to NULL */
    state = (NoiseDHState *)8;
    compare(noise_dhstate_new_by_id(&state, NOISE_HASH_SHA512),
            NOISE_ERROR_UNKNOWN_ID);
    verify(state == NULL);
    state = (NoiseDHState *)8;
    compare(noise_dhstate_new_by_name(&state, 0),
            NOISE_ERROR_INVALID_PARAM);
    verify(state == NULL);
    state = (NoiseDHState *)8;
    compare(noise_dhstate_new_by_name(&state, "Curve25519"), /* Should be "25519" */
            NOISE_ERROR_UNKNOWN_NAME);
    verify(state == NULL);
}

void test_dhstate(void)
{
    dhstate_check_test_vectors();
    dhstate_check_generate_keypair();
    dhstate_check_errors();
}
