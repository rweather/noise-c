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

#define MAX_DH_KEY_LEN 2048

/* Check raw DH output against test vectors */
static void check_dh(int id, size_t private_key_len, size_t public_key_len,
                     size_t other_public_key_len, size_t shared_key_len,
                     const char *name, int is_null, int role,
                     const char *private_key, const char *public_key,
                     const char *other_public_key, const char *shared_key)
{
    int inverse_role =
        (role == NOISE_ROLE_INITIATOR) ? NOISE_ROLE_RESPONDER
                                       : NOISE_ROLE_INITIATOR;
    NoiseDHState *state1;
    NoiseDHState *state2;
    NoiseDHState *state3;
    static uint8_t priv_key[MAX_DH_KEY_LEN];
    static uint8_t pub_key[MAX_DH_KEY_LEN];
    static uint8_t other_pub_key[MAX_DH_KEY_LEN];
    static uint8_t share_key[MAX_DH_KEY_LEN];
    static uint8_t temp[MAX_DH_KEY_LEN];
    static uint8_t temp2[MAX_DH_KEY_LEN];

    /* Convert the test strings into binary data */
    compare(string_to_data(priv_key, sizeof(priv_key), private_key),
            private_key_len);
    compare(string_to_data(pub_key, sizeof(pub_key), public_key),
            public_key_len);
    compare(string_to_data(other_pub_key, sizeof(other_pub_key),
            other_public_key), other_public_key_len);
    compare(string_to_data(share_key, sizeof(share_key), shared_key),
            shared_key_len);

    /* Create the first DH object and check its properties */
    compare(noise_dhstate_new_by_id(&state1, id), NOISE_ERROR_NONE);
    compare(noise_dhstate_get_dh_id(state1), id);
    compare(noise_dhstate_set_role(state1, role), NOISE_ERROR_NONE);
    compare(noise_dhstate_get_private_key_length(state1), private_key_len);
    compare(noise_dhstate_get_public_key_length(state1), public_key_len);
    compare(noise_dhstate_get_shared_key_length(state1), shared_key_len);
    verify(!noise_dhstate_has_keypair(state1));
    verify(!noise_dhstate_has_public_key(state1));
    verify(!noise_dhstate_is_null_public_key(state1));
    verify(private_key_len <= MAX_DH_KEY_LEN);
    verify(public_key_len <= MAX_DH_KEY_LEN);
    verify(shared_key_len <= MAX_DH_KEY_LEN);

    /* Create the second DH object */
    compare(noise_dhstate_new_by_id(&state2, id), NOISE_ERROR_NONE);
    compare(noise_dhstate_set_role(state2, inverse_role), NOISE_ERROR_NONE);
    compare(noise_dhstate_get_dh_id(state2), id);
    if (public_key_len == other_public_key_len)
        compare(noise_dhstate_get_private_key_length(state2), private_key_len);
    compare(noise_dhstate_get_public_key_length(state2), other_public_key_len);
    compare(noise_dhstate_get_shared_key_length(state2), shared_key_len);
    verify(!noise_dhstate_has_keypair(state2));
    verify(!noise_dhstate_has_public_key(state2));
    verify(!noise_dhstate_is_null_public_key(state2));

    /* Set the keys on the DH objects */
    compare(noise_dhstate_set_keypair
                (state1, priv_key, private_key_len, pub_key, public_key_len),
            NOISE_ERROR_NONE);
    compare(noise_dhstate_set_public_key
                (state2, other_pub_key, other_public_key_len),
            NOISE_ERROR_NONE);
    verify(noise_dhstate_has_keypair(state1));
    verify(noise_dhstate_has_public_key(state1));
    verify(!noise_dhstate_is_null_public_key(state1));
    verify(!noise_dhstate_has_keypair(state2));
    verify(noise_dhstate_has_public_key(state2));
    compare(noise_dhstate_is_null_public_key(state2), is_null);

    /* Calculate the shared key and check against the test data */
    memset(temp, 0xAA, sizeof(temp));
    compare(noise_dhstate_calculate(state1, state2, temp, shared_key_len),
            NOISE_ERROR_NONE);
    verify(!memcmp(temp, share_key, shared_key_len));

    /* Fetch the keys back from the objects and compare */
    memset(temp, 0xAA, sizeof(temp));
    memset(temp2, 0x66, sizeof(temp2));
    compare(noise_dhstate_get_keypair
                (state1, temp, private_key_len, temp2, public_key_len),
            NOISE_ERROR_NONE);
    verify(!memcmp(temp, priv_key, private_key_len));
    verify(!memcmp(temp2, pub_key, public_key_len));
    memset(temp, 0xAA, sizeof(temp));
    compare(noise_dhstate_get_public_key(state2, temp, other_public_key_len),
            NOISE_ERROR_NONE);
    verify(!memcmp(temp, other_pub_key, other_public_key_len));

    /* Check parameter error conditions */
    compare(noise_dhstate_set_keypair
                (0, priv_key, private_key_len, pub_key, public_key_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_dhstate_set_keypair
                (state1, 0, private_key_len, pub_key, public_key_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_dhstate_set_keypair
                (state1, priv_key, private_key_len, 0, public_key_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_dhstate_set_keypair
                (state1, priv_key, private_key_len - 1, pub_key, public_key_len),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_dhstate_set_keypair
                (state1, priv_key, private_key_len + 1, pub_key, public_key_len),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_dhstate_set_keypair
                (state1, priv_key, private_key_len, pub_key, public_key_len + 1),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_dhstate_set_keypair
                (state1, priv_key, private_key_len, pub_key, public_key_len - 1),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_dhstate_get_keypair
                (0, temp, private_key_len, temp2, public_key_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_dhstate_get_keypair
                (state1, 0, private_key_len, temp2, public_key_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_dhstate_get_keypair
                (state1, temp, private_key_len, 0, public_key_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_dhstate_get_keypair
                (state1, temp, private_key_len - 1, temp2, public_key_len),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_dhstate_get_keypair
                (state1, temp, private_key_len + 1, temp2, public_key_len),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_dhstate_get_keypair
                (state1, temp, private_key_len, temp2, public_key_len - 1),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_dhstate_get_keypair
                (state1, temp, private_key_len, temp2, public_key_len + 1),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_dhstate_set_public_key
                (0, other_pub_key, public_key_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_dhstate_set_public_key
                (state2, 0, public_key_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_dhstate_set_public_key
                (state2, other_pub_key, public_key_len - 1),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_dhstate_set_public_key
                (state2, other_pub_key, public_key_len + 1),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_dhstate_get_public_key(0, temp, public_key_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_dhstate_get_public_key(state2, 0, public_key_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_dhstate_get_public_key(state2, temp, public_key_len - 1),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_dhstate_get_public_key(state2, temp, public_key_len + 1),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_dhstate_calculate(0, state2, temp, shared_key_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_dhstate_calculate(state1, 0, temp, shared_key_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_dhstate_calculate(state1, state2, 0, shared_key_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_dhstate_calculate(state1, state2, temp, shared_key_len - 1),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_dhstate_calculate(state1, state2, temp, shared_key_len + 1),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_dhstate_calculate(state2, state1, temp, shared_key_len),
            NOISE_ERROR_INVALID_PRIVATE_KEY);

    /* Cannot mix algorithm types */
    if (id == NOISE_DH_CURVE25519) {
        compare(noise_dhstate_new_by_id(&state3, NOISE_DH_CURVE448),
                NOISE_ERROR_NONE);
    } else {
        compare(noise_dhstate_new_by_id(&state3, NOISE_DH_CURVE25519),
                NOISE_ERROR_NONE);
    }
    compare(noise_dhstate_calculate(state1, state3, temp, shared_key_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_dhstate_free(state3), NOISE_ERROR_NONE);

    /* Re-create the objects by name and check their properties again */
    compare(noise_dhstate_free(state1), NOISE_ERROR_NONE);
    compare(noise_dhstate_free(state2), NOISE_ERROR_NONE);
    compare(noise_dhstate_new_by_name(&state1, name), NOISE_ERROR_NONE);
    compare(noise_dhstate_new_by_name(&state2, name), NOISE_ERROR_NONE);
    compare(noise_dhstate_set_role(state1, role), NOISE_ERROR_NONE);
    compare(noise_dhstate_set_role(state2, inverse_role), NOISE_ERROR_NONE);
    compare(noise_dhstate_get_dh_id(state1), id);
    compare(noise_dhstate_get_dh_id(state2), id);
    compare(noise_dhstate_get_private_key_length(state1), private_key_len);
    compare(noise_dhstate_get_public_key_length(state1), public_key_len);
    compare(noise_dhstate_get_shared_key_length(state1), shared_key_len);
    if (public_key_len == other_public_key_len)
        compare(noise_dhstate_get_private_key_length(state2), private_key_len);
    compare(noise_dhstate_get_public_key_length(state2), other_public_key_len);
    compare(noise_dhstate_get_shared_key_length(state2), shared_key_len);
    verify(!noise_dhstate_has_keypair(state1));
    verify(!noise_dhstate_has_public_key(state1));
    verify(!noise_dhstate_is_null_public_key(state1));
    verify(!noise_dhstate_has_keypair(state2));
    verify(!noise_dhstate_has_public_key(state2));
    verify(!noise_dhstate_is_null_public_key(state2));

    /* Make sure that it is still the same object by checking DH outputs.
       This time we derive state1's public key from the private key rather
       than use the value from the test data. */
    compare(noise_dhstate_set_keypair_private
                (state1, priv_key, private_key_len),
            NOISE_ERROR_NONE);
    compare(noise_dhstate_set_public_key
                (state2, other_pub_key, other_public_key_len),
            NOISE_ERROR_NONE);
    memset(temp, 0xAA, sizeof(temp));
    compare(noise_dhstate_calculate(state1, state2, temp, shared_key_len),
            NOISE_ERROR_NONE);
    verify(!memcmp(temp, share_key, shared_key_len));

    /* Deliberately null the other public key and check for a null result */
    if (id == NOISE_DH_CURVE25519 || id == NOISE_DH_CURVE448) {
        compare(noise_dhstate_set_null_public_key(state2), NOISE_ERROR_NONE);
        verify(noise_dhstate_is_null_public_key(state2));
        verify(noise_dhstate_has_public_key(state2));
        memset(temp, 0xAA, sizeof(temp));
        compare(noise_dhstate_calculate(state1, state2, temp, shared_key_len),
                NOISE_ERROR_NONE);
        memset(temp2, 0, sizeof(temp));
        verify(!memcmp(temp, temp2, shared_key_len));
    }

    /* Clear the first key and check that it returns to default properties */
    compare(noise_dhstate_clear_key(state1), NOISE_ERROR_NONE);
    verify(!noise_dhstate_has_keypair(state1));
    verify(!noise_dhstate_has_public_key(state1));
    verify(!noise_dhstate_is_null_public_key(state1));
    compare(noise_dhstate_get_keypair
                (state1, temp, private_key_len, temp2, public_key_len),
            NOISE_ERROR_INVALID_STATE);
    compare(noise_dhstate_get_public_key(state1, temp, public_key_len),
            NOISE_ERROR_NONE);

    /* Deliberately mess up the first keypair and perform validation.
       The existing Curve25519 and Curve448 back ends validate the
       public key but all private key values are valid. */
    if (id == NOISE_DH_CURVE25519 || id == NOISE_DH_CURVE448) {
        priv_key[private_key_len / 2] ^= 0x01;
        compare(noise_dhstate_set_keypair
                    (state1, priv_key, private_key_len,
                     pub_key, public_key_len),
                NOISE_ERROR_INVALID_PUBLIC_KEY);
        priv_key[private_key_len / 2] ^= 0x01;
        compare(noise_dhstate_set_keypair
                    (state1, priv_key, private_key_len,
                     pub_key, public_key_len),
                NOISE_ERROR_NONE);
        pub_key[public_key_len / 2] ^= 0x01;
        compare(noise_dhstate_set_keypair
                    (state1, priv_key, private_key_len,
                     pub_key, public_key_len),
                NOISE_ERROR_INVALID_PUBLIC_KEY);
        pub_key[public_key_len / 2] ^= 0x01;
        compare(noise_dhstate_set_keypair
                    (state1, priv_key, private_key_len,
                     pub_key, public_key_len),
                NOISE_ERROR_NONE);
    }

    /* Clean up */
    compare(noise_dhstate_free(state1), NOISE_ERROR_NONE);
    compare(noise_dhstate_free(state2), NOISE_ERROR_NONE);
}

/* Check against test vectors from the various specifications
   to validate that the algorithms work as low level primitives */
static void dhstate_check_test_vectors(void)
{
    /* Curve25519 - From section 6.1 of RFC 7748 */
    check_dh
        (NOISE_DH_CURVE25519, 32, 32, 32, 32, "25519", 0, NOISE_ROLE_INITIATOR,
         /* Alice's private key */
         "0x77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
         /* Alice's public key */
         "0x8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
         /* Bob's public key */
         "0xde9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
         /* Shared secret */
         "0x4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    check_dh
        (NOISE_DH_CURVE25519, 32, 32, 32, 32, "25519", 0, NOISE_ROLE_RESPONDER,
         /* Bob's private key */
         "0x5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
         /* Bob's public key */
         "0xde9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
         /* Alice's public key */
         "0x8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
         /* Shared secret */
         "0x4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    /* Curve25519 - Check the behaviour of null public keys */
    check_dh
        (NOISE_DH_CURVE25519, 32, 32, 32, 32, "25519", 1, NOISE_ROLE_INITIATOR,
         /* Alice's private key */
         "0x77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
         /* Alice's public key */
         "0x8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
         /* Null public key */
         "0x0000000000000000000000000000000000000000000000000000000000000000",
         /* Shared secret - also null */
         "0x0000000000000000000000000000000000000000000000000000000000000000");

    /* Curve448 - From section 6.2 of RFC 7748 */
    check_dh
        (NOISE_DH_CURVE448, 56, 56, 56, 56, "448", 0, NOISE_ROLE_INITIATOR,
         /* Alice's private key */
         "0x9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d"
           "d9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b",
         /* Alices's public key */
         "0x9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c"
           "22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0",
         /* Bob's public key */
         "0x3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b430"
           "27d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609",
         /* Shared secret */
         "0x07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282b"
           "b60c0b56fd2464c335543936521c24403085d59a449a5037514a879d");
    check_dh
        (NOISE_DH_CURVE448, 56, 56, 56, 56, "448", 0, NOISE_ROLE_RESPONDER,
         /* Bob's private key */
         "0x1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d"
           "6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d",
         /* Bob's public key */
         "0x3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b430"
           "27d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609",
         /* Alices's public key */
         "0x9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c"
           "22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0",
         /* Shared secret */
         "0x07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282b"
           "b60c0b56fd2464c335543936521c24403085d59a449a5037514a879d");

    /* Curve448 - Check the behaviour of null public keys */
    check_dh
        (NOISE_DH_CURVE448, 56, 56, 56, 56, "448", 1, NOISE_ROLE_INITIATOR,
         /* Alice's private key */
         "0x9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d"
           "d9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b",
         /* Alices's public key */
         "0x9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c"
           "22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0",
         /* Null public key */
         "0x00000000000000000000000000000000000000000000000000000000"
           "00000000000000000000000000000000000000000000000000000000",
         /* Shared secret - also null */
         "0x00000000000000000000000000000000000000000000000000000000"
           "00000000000000000000000000000000000000000000000000000000");

    /* NewHope - Test vectors from the reference implementation of "torref" */
    check_dh
        (NOISE_DH_NEWHOPE, 64, 1824, 2048, 32, "NewHope",
         0, NOISE_ROLE_INITIATOR,
         /* Alice's private key */
         "0x934d60b35624d740b30a7f227af2ae7c678e4e04e13c5f509eade2b79aea77e2"
           "3e2a2ea6c9c476fc4937b013c993a793d6c0ab9960695ba838f649da539ca3d0",
         /* Alice's public key */
         "0xa857f3c12d1ea43ccd04ebc9ed8d785369e47e76325aac7788dc7498676452db"
           "778e7d50d397c5e1794adf2593dbc322ac214c7337d3d83ad7a819a3635653d3"
           "2e8133b4a5888a0ae022497a1010a71d37c628a05ee0e2a0326d2728ef335bb9"
           "904232eaa1799c620f2b5d21ca46eca6ba5076c6a50447835fd53441c856e38e"
           "7e8ad26a4f5bd239c73fc2889b0aeb44bffdbee787c1f2a4be05f993d22b16f8"
           "ad45930c593c5065f5c43b566ccc7e5761a0a792d91c42e18755888472e91399"
           "a07f3e48b813644a19dd0e9a1ae2fa5f88961e0f0b16f05c151f8b91e0006423"
           "adcfc372e9c261e02f973696706870899dc7196a262ccf2ef689e8027788390a"
           "5b2012a91c45e6f87189c290bfd8de694a52d9e9f22db495968566e480501583"
           "9fab857d40520a541e81d8710dc79ebabae0754ed9a5858908811214562d07c1"
           "3440f3152ca9eee11523066de0b48937b34de8e15d8849099576a5205c84510b"
           "1789e17daf9b6c09c44c005edc2c6071c4e4b8bbe5cbf879b98fc1649a2162e4"
           "2282116fb4c6126711c2b8d83d15bfa38f9726c6c952824d05ca9f86bff00e4e"
           "b46b2c4e4955bbc202653f85e43c193226470aa14f239fe87010d2b4f1cef0b6"
           "159f4774a9a0250dc725d4f90d6c5b8941a5e8510c37d135208276415e9b5235"
           "a7d420f6e14989700403621193e97c18670e662d69a84db81cc0f2d118da3639"
           "a9c3564fde48c34c5057a025195c2b130217f515729631667d5e8b6e053c49c3"
           "f038abe42580c0a8372e9c19404a0d8c26682bf0be984677adcbf9ebe20866a2"
           "7ac2e7b69f94a0c6c0e9b13c9758695365dcb10f05f65502ae584986c5e1f338"
           "864e2365645df0a6c7e57a8b839612aca05049d8c2476deab9b7ef591909c6cd"
           "00b77186eca6e839d0699bb8e3a70646e606abd38a221f64704d5b69282e308f"
           "ae9b8f3632d1328c1a8130bc046a7348e932ce903388086e3439ba6da26cdba2"
           "15f9287cecfc33f5a683d4a053284f3e4101c09a404f6a4e3cdb121a89a9170a"
           "5125c339b4b7f4a31012479e4c11d726528191594ac2d9b4f40cb2a768ab1331"
           "a268b36bbfbaaae493b04dd21aca0a6159226ee92950a368180ee7f45aa94759"
           "aef037786a29e7f54733da5d076abec3ad5dbc1043cd48f0226e8b92730111d8"
           "8b5a43623058d642086afe5452d8a5a793bac60a664e06cbce9bdf85bc2bc908"
           "c408a0b1761125574ef802c6abea6ada34b77eca22662604488f8e76229d740a"
           "2de0609061dc63f4c0adb054fa543dcd2fa0135a391568bb99d262a3c0a7564a"
           "ec6637599ef3890ec1934ca38627d84e9fe0e8baf6a174ad1767ed84eeda59a5"
           "0345f9954c498f4c882ac9650e038efa76626d17421690d499750f2967732557"
           "b5a8960a66c7695e460748b0145f5607f008fbca75a5b053c7b74a3388329287"
           "94579c683efae120163f6ca76f6cb7594826603241ed236d9cb4c1c774e74d5e"
           "3b605406b800ca70b36338a05149599cd4b1704f295c66c3355911d4782a8885"
           "1a187a3f4bc7f7978ac8369eed9b42fe9c16a882df139de45f2eeb1a61dec425"
           "432838d9e5145aecc534d04c729ac568b74845795715473b2488928a9f8f6ab8"
           "9f212bcfa9a5b4581145c759e967fca8a4ba1b2da80e40ad48c2cb44ea7a57f5"
           "4de8f22b7932c4acdb704e98194443b732a819003c9e16170c4a0009eb004602"
           "8881aacad75914326a792f687483299667c0aee2a99c12ec4ad6db41f1869557"
           "88c8d600559e837563ac8e9c46da26a034d56ba3e1684bb9ac81721329707a2a"
           "9fd4e5ec179f4479bce275986c59b9346eb1106f2414788f86d5b7fe167fdea1"
           "41647c93298008414f49567222860ac5c141f8e163e75556bb4542b7021716a5"
           "e7044bf4eb460ab915ca642e4225ed031933e89282c10337e9923912c5dbe741"
           "ec9aa2c5593aea9e6899656e2dc9e2359fe59243f05f515b974b4e991cb89855"
           "4c00c142d827a00cc1401f6d0c675cada73ee69692e7ee0913b5af5c970082e8"
           "c4b4305bb398c21c7fa14b4c89c55d5cfd19a6c16c9d589a2e751060f8313dc7"
           "b9a736c044e10afe6bfea4be885963182f8eaebfa2eecbb6b1025f5c4df780e6"
           "92066e5fb484d17758522ac4a8b5b4ffe438115165aa42195e8612417ff7c3e6"
           "a07eacaf8daff57639447949cbb987c21c03c1817d6a2d4e8930d652023926a6"
           "7bc7d2772505b665e02fe7437c57bc0ca57acdf5649aaa3a16f569aeb5a38c27"
           "c1b80faea8acb515006e8023bef6e08d11a218ad3b68923c4645a8f409f2aaeb"
           "df5174952474a8e68b26417148d8144fb106600ca6dbb0883b1a0c03ce8580d8"
           "7a88995c5854dc75839d53f4e939ee3ed0820cb737ec49fde77c9987e0535859"
           "82300824841c0c5d8686819ce111317867c15068911e092fed4aba53a7a1b940"
           "6f648c22026bfd27634b5c774b00252c41550b0a2d0040d684c20259aa95d095"
           "f8bb3a0ca4dae2e0c4fd68c94e9f330fa96f271e7f0953799b9e5c5b15798178"
           "349a9e8c91d116780ff9c7db6089ed4c06b34edaa848bbffd98542827e5331be",
         /* Bob's public key */
         "0x49a57402d42988e29808f7865989a000fa3b6a5d4fe6009c58490db2af400369"
           "92d53dc6e13348725072ba65ac647ab9419d50a2a2ea94454211d41b0e6c2c7e"
           "20e652696da304931d11b3f2a82f98d4b35116b4dfc5fc49f9693a4d0663b434"
           "4c041b4e7337f845a238df3713f095b358c7f5588460a05bef96fbef2cb3e60e"
           "5c1028554b136aac611b5a8525c0f0580ea08612470e15b7e04a3b0ff2091d3c"
           "85a3504d1b81f85021c45e5a84262c236ef850489aa49b4f000705a1b0eb15c1"
           "14c69a18ca81d1fb973d02405b0ef5ab8cb05b4e04b630d69a6347a4a9e2f045"
           "7d1eaf065fec596e6e7c725e66172f18fbe0747db3f9532333be163e4d890ed7"
           "6bad7725def4c9014a1b22dd65d4865a1b241a06657a0e8389212e2af5c9aeb1"
           "aa0b09b58c09bd50d8cac36a5130a311357dc5b6d7deeaa412be5444885ad82e"
           "e143aee82c7074617503c0c7186838901acc6858f186389b244496b41ab1735d"
           "922958697f0a83950228515f7052820660659ee025a142c915737d4b7c55e926"
           "43aac4fe9296d53409427a2649feb5a19b69213919789007a74226fd51f316eb"
           "d5425864e59ae891bb6680c6253e5a0c11b7b0060f838d66708486654adc52a3"
           "286b96a08c468088985d31aa7a3cf5a3e2e50ea46b7c5125a0e6ae2769d9d6e9"
           "1f0a0a2b281e327a3e3d8e13e262a8b843bb9ee4008c0979e5673028aa2e530e"
           "026c91dcf1ab90aa0419ec8286ef281d201ef971cfca3636f650666e13991413"
           "68973521ce486b50b35bc4cd5379986e631a4e201411aa74ce9103c5449bdd20"
           "d7a8675c15e7c297824b5562261169c8ab4529148562c6c76dbdb22b9b63c85d"
           "8fc04ba4c1c33265dbdcfbd6bc389ac6e4471724021ecd84b4b5536197a1132c"
           "9a81cabaed9bf2c4a61c97a3169bf5c095bd2a90ead898b6a73e27730ac67aa8"
           "24949797c96134f01410c99c6c5310e3824914156c670d39e18bc888c99ce7d5"
           "643aa00868553184246e1c5bed06654410f46d5cf88f2c7637ab9ff83388b644"
           "925a1ad9861e971d4f84ad153d5c6e9d812338b004a2e5eb03a8771c85e43a2f"
           "78861919d0c7eef42b95d0cae4d3ba60a946b7337db02e08a3e9ba40993d1fcc"
           "a05ba8e2b20da76f5ad225ac3dc372787c5e279cc14c34b49487d19a28087e24"
           "6e1ada142265e47a189301ba102a0dd0148d4368149cfa2eb4785b5ca6ae6c18"
           "00697e130b194d62c650b46b1c96e6d8558c6ec78fc71db00ef2ded7d75069b5"
           "690b40f3ea0aa2bd67c1b66fd8944b4d7ef786490ec2db06f3065d0cdb5582f7"
           "b9514bd6670eda618a4e45519feafa1e47094bb543ac309d8281eb130145543f"
           "cdda792ad43e82970b914240a4e68036d6046225c392af527d9233c80953e521"
           "8917a203f5f38078334edc3810430907370d1a03d11274c206f041f5318ba94b"
           "fa35b8f431e8accf22a3612b9c6a35a6a31c87f29e54334dae698eeb5e0bbd45"
           "27112d0cab4b3213751a9853b8c590f6c7c26babe27320030062ce94940c6de6"
           "9878244846a6d9646685780421e06972025a99e3bfd6d689367c9360c5ffc084"
           "a20dfa33a492ae8ad07982c88e57eae7e33b62a8bc698e4b78c6686663c81f10"
           "fb026bcf6a5a95bf7c2b5298bd8097e044bd87092067cd476d19f72503704b45"
           "8526627f6c6ab94227a9b0300509d1f36926f17d27e4bba6f6306b3710939980"
           "ddb9d5cabce5513931d68b7315e7e9739c585f35516c0d2fad42664500206543"
           "6be217841e0c6b2a9b50d9479a51c1469b550ea7832a70da0868262e281a95dd"
           "000b03179b92b14865a8da5273667b2d11bb59eaf20b49ec8ce2f0386957cf13"
           "a064252fe1c9a1a5ba91baa285cb32b5ccad67a48982e2525feb4c0740960c7d"
           "3544ae268b0c35ec1b09838a5a6a2f9c5f7998708720c0adb7a2912859e9ffb5"
           "6c211b3649cbe9f6f10d23242e34d89035ded63a6071205a0de9f5d867a22c10"
           "e4d7db721c86231e6e41dd4a6415aec056016e8dd8199bea768c20c0464c965c"
           "fe6da32de06a5fa5098054f855b69462c00d3f260be52327c1125420e4678711"
           "ac5bc0b8b6e547df85c475842847213bfcf1506d2c7b8785c53ac7e27e11e399"
           "b3da87b762f11d5d4056a329b848a7a5e398751f284269967d194876b2bbec85"
           "5acb0518bae9f0479b0d51d515c2daa530872b6afdb1df940c001099c7461923"
           "064e4b28c92459670f0d90a45428cbc4d847226210a245b281f6b91538eefe1a"
           "4b849ecaddda613add1d7e56c3fbe7dc72749a6f8b6ae4063bddbf3625e40542"
           "0d5b791e94b30faf132841bd6e1fc99798db4540748f5bd3943a12cb5bbb96a6"
           "04374658c4b7a8aa8033cbd5380496bb61ae7fb32750202b10f8d780555e220f"
           "97b5cc3e0da60e51883fac186d2f2d3601d975a2cc34b9f65869dfd467d4f11c"
           "9a7f10481b6da299e5ca41d07c6d40e9c9170789157799dadf32bd9a184feb09"
           "3569b43a91adfbc708d81f46c7b2a6c48c703040d3a52a64a5679dc7d4fa3a6f"
           "e4d9f5e29e4857f6e52638a222db14a3d8a9c39505f2b15b1a08a5f8c26edf77"
           "56b2c73db3a57bf00f6fea59d868dc3760caeedd080a0b3982848f8720fd1691"
           "149e94abb9dc9b94bd36de4e9978b6641a6ad74d466bba314fab1bac59c00da0"
           "b65a16d3728978adf02b5818e4dbd08bdfd38c0e9d38a1994b3dac845fcd9c6e"
           "01dda07dd01a71b90692674b73037facc9ada5fe9ae012c96b09fdce37102389"
           "6bd7bbd520be6328b26e07a7bf11e30aeda8478e7b3cf69b6af9a62ee7ceb0b0"
           "0912998f8d41abf370d1910fe2f1c4a293480b83f6d79173dfe94fb917cb7b39"
           "b0ff07dfb50697b66fbe8f48ef0509ee9663f45a9341567df69e826119a8c27e",
         /* Shared secret */
         "0x78d62ad989a3bd740f87b2cf6f914dfe8cb1ea52c4c9ad82ddac9a45ba8e59cb");
    check_dh
        (NOISE_DH_NEWHOPE, 32, 2048, 1824, 32, "NewHope",
         0, NOISE_ROLE_RESPONDER,
         /* Bob's private key */
         "0xbac5ba881dd35c59719670004692d675b83c98db6a0e55800bafeb7e70491bf4",
         /* Bob's public key */
         "0x49a57402d42988e29808f7865989a000fa3b6a5d4fe6009c58490db2af400369"
           "92d53dc6e13348725072ba65ac647ab9419d50a2a2ea94454211d41b0e6c2c7e"
           "20e652696da304931d11b3f2a82f98d4b35116b4dfc5fc49f9693a4d0663b434"
           "4c041b4e7337f845a238df3713f095b358c7f5588460a05bef96fbef2cb3e60e"
           "5c1028554b136aac611b5a8525c0f0580ea08612470e15b7e04a3b0ff2091d3c"
           "85a3504d1b81f85021c45e5a84262c236ef850489aa49b4f000705a1b0eb15c1"
           "14c69a18ca81d1fb973d02405b0ef5ab8cb05b4e04b630d69a6347a4a9e2f045"
           "7d1eaf065fec596e6e7c725e66172f18fbe0747db3f9532333be163e4d890ed7"
           "6bad7725def4c9014a1b22dd65d4865a1b241a06657a0e8389212e2af5c9aeb1"
           "aa0b09b58c09bd50d8cac36a5130a311357dc5b6d7deeaa412be5444885ad82e"
           "e143aee82c7074617503c0c7186838901acc6858f186389b244496b41ab1735d"
           "922958697f0a83950228515f7052820660659ee025a142c915737d4b7c55e926"
           "43aac4fe9296d53409427a2649feb5a19b69213919789007a74226fd51f316eb"
           "d5425864e59ae891bb6680c6253e5a0c11b7b0060f838d66708486654adc52a3"
           "286b96a08c468088985d31aa7a3cf5a3e2e50ea46b7c5125a0e6ae2769d9d6e9"
           "1f0a0a2b281e327a3e3d8e13e262a8b843bb9ee4008c0979e5673028aa2e530e"
           "026c91dcf1ab90aa0419ec8286ef281d201ef971cfca3636f650666e13991413"
           "68973521ce486b50b35bc4cd5379986e631a4e201411aa74ce9103c5449bdd20"
           "d7a8675c15e7c297824b5562261169c8ab4529148562c6c76dbdb22b9b63c85d"
           "8fc04ba4c1c33265dbdcfbd6bc389ac6e4471724021ecd84b4b5536197a1132c"
           "9a81cabaed9bf2c4a61c97a3169bf5c095bd2a90ead898b6a73e27730ac67aa8"
           "24949797c96134f01410c99c6c5310e3824914156c670d39e18bc888c99ce7d5"
           "643aa00868553184246e1c5bed06654410f46d5cf88f2c7637ab9ff83388b644"
           "925a1ad9861e971d4f84ad153d5c6e9d812338b004a2e5eb03a8771c85e43a2f"
           "78861919d0c7eef42b95d0cae4d3ba60a946b7337db02e08a3e9ba40993d1fcc"
           "a05ba8e2b20da76f5ad225ac3dc372787c5e279cc14c34b49487d19a28087e24"
           "6e1ada142265e47a189301ba102a0dd0148d4368149cfa2eb4785b5ca6ae6c18"
           "00697e130b194d62c650b46b1c96e6d8558c6ec78fc71db00ef2ded7d75069b5"
           "690b40f3ea0aa2bd67c1b66fd8944b4d7ef786490ec2db06f3065d0cdb5582f7"
           "b9514bd6670eda618a4e45519feafa1e47094bb543ac309d8281eb130145543f"
           "cdda792ad43e82970b914240a4e68036d6046225c392af527d9233c80953e521"
           "8917a203f5f38078334edc3810430907370d1a03d11274c206f041f5318ba94b"
           "fa35b8f431e8accf22a3612b9c6a35a6a31c87f29e54334dae698eeb5e0bbd45"
           "27112d0cab4b3213751a9853b8c590f6c7c26babe27320030062ce94940c6de6"
           "9878244846a6d9646685780421e06972025a99e3bfd6d689367c9360c5ffc084"
           "a20dfa33a492ae8ad07982c88e57eae7e33b62a8bc698e4b78c6686663c81f10"
           "fb026bcf6a5a95bf7c2b5298bd8097e044bd87092067cd476d19f72503704b45"
           "8526627f6c6ab94227a9b0300509d1f36926f17d27e4bba6f6306b3710939980"
           "ddb9d5cabce5513931d68b7315e7e9739c585f35516c0d2fad42664500206543"
           "6be217841e0c6b2a9b50d9479a51c1469b550ea7832a70da0868262e281a95dd"
           "000b03179b92b14865a8da5273667b2d11bb59eaf20b49ec8ce2f0386957cf13"
           "a064252fe1c9a1a5ba91baa285cb32b5ccad67a48982e2525feb4c0740960c7d"
           "3544ae268b0c35ec1b09838a5a6a2f9c5f7998708720c0adb7a2912859e9ffb5"
           "6c211b3649cbe9f6f10d23242e34d89035ded63a6071205a0de9f5d867a22c10"
           "e4d7db721c86231e6e41dd4a6415aec056016e8dd8199bea768c20c0464c965c"
           "fe6da32de06a5fa5098054f855b69462c00d3f260be52327c1125420e4678711"
           "ac5bc0b8b6e547df85c475842847213bfcf1506d2c7b8785c53ac7e27e11e399"
           "b3da87b762f11d5d4056a329b848a7a5e398751f284269967d194876b2bbec85"
           "5acb0518bae9f0479b0d51d515c2daa530872b6afdb1df940c001099c7461923"
           "064e4b28c92459670f0d90a45428cbc4d847226210a245b281f6b91538eefe1a"
           "4b849ecaddda613add1d7e56c3fbe7dc72749a6f8b6ae4063bddbf3625e40542"
           "0d5b791e94b30faf132841bd6e1fc99798db4540748f5bd3943a12cb5bbb96a6"
           "04374658c4b7a8aa8033cbd5380496bb61ae7fb32750202b10f8d780555e220f"
           "97b5cc3e0da60e51883fac186d2f2d3601d975a2cc34b9f65869dfd467d4f11c"
           "9a7f10481b6da299e5ca41d07c6d40e9c9170789157799dadf32bd9a184feb09"
           "3569b43a91adfbc708d81f46c7b2a6c48c703040d3a52a64a5679dc7d4fa3a6f"
           "e4d9f5e29e4857f6e52638a222db14a3d8a9c39505f2b15b1a08a5f8c26edf77"
           "56b2c73db3a57bf00f6fea59d868dc3760caeedd080a0b3982848f8720fd1691"
           "149e94abb9dc9b94bd36de4e9978b6641a6ad74d466bba314fab1bac59c00da0"
           "b65a16d3728978adf02b5818e4dbd08bdfd38c0e9d38a1994b3dac845fcd9c6e"
           "01dda07dd01a71b90692674b73037facc9ada5fe9ae012c96b09fdce37102389"
           "6bd7bbd520be6328b26e07a7bf11e30aeda8478e7b3cf69b6af9a62ee7ceb0b0"
           "0912998f8d41abf370d1910fe2f1c4a293480b83f6d79173dfe94fb917cb7b39"
           "b0ff07dfb50697b66fbe8f48ef0509ee9663f45a9341567df69e826119a8c27e",
         /* Alice's public key */
         "0xa857f3c12d1ea43ccd04ebc9ed8d785369e47e76325aac7788dc7498676452db"
           "778e7d50d397c5e1794adf2593dbc322ac214c7337d3d83ad7a819a3635653d3"
           "2e8133b4a5888a0ae022497a1010a71d37c628a05ee0e2a0326d2728ef335bb9"
           "904232eaa1799c620f2b5d21ca46eca6ba5076c6a50447835fd53441c856e38e"
           "7e8ad26a4f5bd239c73fc2889b0aeb44bffdbee787c1f2a4be05f993d22b16f8"
           "ad45930c593c5065f5c43b566ccc7e5761a0a792d91c42e18755888472e91399"
           "a07f3e48b813644a19dd0e9a1ae2fa5f88961e0f0b16f05c151f8b91e0006423"
           "adcfc372e9c261e02f973696706870899dc7196a262ccf2ef689e8027788390a"
           "5b2012a91c45e6f87189c290bfd8de694a52d9e9f22db495968566e480501583"
           "9fab857d40520a541e81d8710dc79ebabae0754ed9a5858908811214562d07c1"
           "3440f3152ca9eee11523066de0b48937b34de8e15d8849099576a5205c84510b"
           "1789e17daf9b6c09c44c005edc2c6071c4e4b8bbe5cbf879b98fc1649a2162e4"
           "2282116fb4c6126711c2b8d83d15bfa38f9726c6c952824d05ca9f86bff00e4e"
           "b46b2c4e4955bbc202653f85e43c193226470aa14f239fe87010d2b4f1cef0b6"
           "159f4774a9a0250dc725d4f90d6c5b8941a5e8510c37d135208276415e9b5235"
           "a7d420f6e14989700403621193e97c18670e662d69a84db81cc0f2d118da3639"
           "a9c3564fde48c34c5057a025195c2b130217f515729631667d5e8b6e053c49c3"
           "f038abe42580c0a8372e9c19404a0d8c26682bf0be984677adcbf9ebe20866a2"
           "7ac2e7b69f94a0c6c0e9b13c9758695365dcb10f05f65502ae584986c5e1f338"
           "864e2365645df0a6c7e57a8b839612aca05049d8c2476deab9b7ef591909c6cd"
           "00b77186eca6e839d0699bb8e3a70646e606abd38a221f64704d5b69282e308f"
           "ae9b8f3632d1328c1a8130bc046a7348e932ce903388086e3439ba6da26cdba2"
           "15f9287cecfc33f5a683d4a053284f3e4101c09a404f6a4e3cdb121a89a9170a"
           "5125c339b4b7f4a31012479e4c11d726528191594ac2d9b4f40cb2a768ab1331"
           "a268b36bbfbaaae493b04dd21aca0a6159226ee92950a368180ee7f45aa94759"
           "aef037786a29e7f54733da5d076abec3ad5dbc1043cd48f0226e8b92730111d8"
           "8b5a43623058d642086afe5452d8a5a793bac60a664e06cbce9bdf85bc2bc908"
           "c408a0b1761125574ef802c6abea6ada34b77eca22662604488f8e76229d740a"
           "2de0609061dc63f4c0adb054fa543dcd2fa0135a391568bb99d262a3c0a7564a"
           "ec6637599ef3890ec1934ca38627d84e9fe0e8baf6a174ad1767ed84eeda59a5"
           "0345f9954c498f4c882ac9650e038efa76626d17421690d499750f2967732557"
           "b5a8960a66c7695e460748b0145f5607f008fbca75a5b053c7b74a3388329287"
           "94579c683efae120163f6ca76f6cb7594826603241ed236d9cb4c1c774e74d5e"
           "3b605406b800ca70b36338a05149599cd4b1704f295c66c3355911d4782a8885"
           "1a187a3f4bc7f7978ac8369eed9b42fe9c16a882df139de45f2eeb1a61dec425"
           "432838d9e5145aecc534d04c729ac568b74845795715473b2488928a9f8f6ab8"
           "9f212bcfa9a5b4581145c759e967fca8a4ba1b2da80e40ad48c2cb44ea7a57f5"
           "4de8f22b7932c4acdb704e98194443b732a819003c9e16170c4a0009eb004602"
           "8881aacad75914326a792f687483299667c0aee2a99c12ec4ad6db41f1869557"
           "88c8d600559e837563ac8e9c46da26a034d56ba3e1684bb9ac81721329707a2a"
           "9fd4e5ec179f4479bce275986c59b9346eb1106f2414788f86d5b7fe167fdea1"
           "41647c93298008414f49567222860ac5c141f8e163e75556bb4542b7021716a5"
           "e7044bf4eb460ab915ca642e4225ed031933e89282c10337e9923912c5dbe741"
           "ec9aa2c5593aea9e6899656e2dc9e2359fe59243f05f515b974b4e991cb89855"
           "4c00c142d827a00cc1401f6d0c675cada73ee69692e7ee0913b5af5c970082e8"
           "c4b4305bb398c21c7fa14b4c89c55d5cfd19a6c16c9d589a2e751060f8313dc7"
           "b9a736c044e10afe6bfea4be885963182f8eaebfa2eecbb6b1025f5c4df780e6"
           "92066e5fb484d17758522ac4a8b5b4ffe438115165aa42195e8612417ff7c3e6"
           "a07eacaf8daff57639447949cbb987c21c03c1817d6a2d4e8930d652023926a6"
           "7bc7d2772505b665e02fe7437c57bc0ca57acdf5649aaa3a16f569aeb5a38c27"
           "c1b80faea8acb515006e8023bef6e08d11a218ad3b68923c4645a8f409f2aaeb"
           "df5174952474a8e68b26417148d8144fb106600ca6dbb0883b1a0c03ce8580d8"
           "7a88995c5854dc75839d53f4e939ee3ed0820cb737ec49fde77c9987e0535859"
           "82300824841c0c5d8686819ce111317867c15068911e092fed4aba53a7a1b940"
           "6f648c22026bfd27634b5c774b00252c41550b0a2d0040d684c20259aa95d095"
           "f8bb3a0ca4dae2e0c4fd68c94e9f330fa96f271e7f0953799b9e5c5b15798178"
           "349a9e8c91d116780ff9c7db6089ed4c06b34edaa848bbffd98542827e5331be",
         /* Shared secret */
         "0x78d62ad989a3bd740f87b2cf6f914dfe8cb1ea52c4c9ad82ddac9a45ba8e59cb");
}

/* Check the generation and use of new key pairs */
static void check_dh_generate(int id)
{
    NoiseDHState *state1;
    NoiseDHState *state2;
    uint8_t shared1[MAX_DH_KEY_LEN];
    uint8_t shared2[MAX_DH_KEY_LEN];
    size_t shared_key_len;

    /* Create the DH objects and get the properties */
    compare(noise_dhstate_new_by_id(&state1, id), NOISE_ERROR_NONE);
    compare(noise_dhstate_new_by_id(&state2, id), NOISE_ERROR_NONE);
    compare(noise_dhstate_get_dh_id(state1), id);
    compare(noise_dhstate_get_dh_id(state2), id);
    shared_key_len = noise_dhstate_get_shared_key_length(state1);
    verify(shared_key_len <= MAX_DH_KEY_LEN);

    /* Set the roles for the two DHState objects */
    compare(noise_dhstate_set_role(state1, NOISE_ROLE_INITIATOR),
            NOISE_ERROR_NONE);
    compare(noise_dhstate_set_role(state2, NOISE_ROLE_RESPONDER),
            NOISE_ERROR_NONE);

    /* Generate keypairs for Alice and Bob */
    compare(noise_dhstate_generate_keypair(state1), NOISE_ERROR_NONE);
    if (id != NOISE_DH_NEWHOPE) {
        verify(!noise_dhstate_is_ephemeral_only(state1));
        verify(!noise_dhstate_is_ephemeral_only(state2));
        compare(noise_dhstate_generate_keypair(state2), NOISE_ERROR_NONE);
    } else {
        /* Check the NewHope parameters */
        verify(noise_dhstate_is_ephemeral_only(state1));
        verify(noise_dhstate_is_ephemeral_only(state2));
        compare(noise_dhstate_get_private_key_length(state1), 64);
        compare(noise_dhstate_get_public_key_length(state1), 1824);
        compare(noise_dhstate_get_private_key_length(state2), 32);
        compare(noise_dhstate_get_public_key_length(state2), 2048);

        /* NewHope is "mutual" so Bob's object needs to know about Alice's
         * so that it will generate Bob's "keypair" with respect to the
         * parameters in Alice's public key. */
        compare(noise_dhstate_generate_dependent_keypair(state2, state1),
                NOISE_ERROR_NONE);
    }

    /* Calculate the shared key on both ends and compare */
    memset(shared1, 0xAA, sizeof(shared1));
    memset(shared2, 0x66, sizeof(shared2));
    compare(noise_dhstate_calculate(state1, state2, shared1, shared_key_len),
            NOISE_ERROR_NONE);
    compare(noise_dhstate_calculate (state2, state1, shared2, shared_key_len),
            NOISE_ERROR_NONE);
    verify(!memcmp(shared1, shared2, shared_key_len));

    /* Check parameter error conditions */
    compare(noise_dhstate_generate_keypair(0), NOISE_ERROR_INVALID_PARAM);

    /* Clean up */
    compare(noise_dhstate_free(state1), NOISE_ERROR_NONE);
    compare(noise_dhstate_free(state2), NOISE_ERROR_NONE);
}

/* Check the generation and use of new key pairs */
static void dhstate_check_generate_keypair(void)
{
    check_dh_generate(NOISE_DH_CURVE25519);
    check_dh_generate(NOISE_DH_CURVE448);
    check_dh_generate(NOISE_DH_NEWHOPE);
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
    compare(noise_dhstate_has_keypair(0), 0);
    compare(noise_dhstate_has_public_key(0), 0);
    compare(noise_dhstate_new_by_id(0, NOISE_DH_CURVE25519),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_dhstate_new_by_name(0, "25519"), NOISE_ERROR_INVALID_PARAM);
    compare(noise_dhstate_generate_keypair(0), NOISE_ERROR_INVALID_PARAM);
    compare(noise_dhstate_set_null_public_key(0), NOISE_ERROR_INVALID_PARAM);
    compare(noise_dhstate_is_null_public_key(0), 0);

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
