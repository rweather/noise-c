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

#define MAX_SIGN_KEY_LEN 80
#define MAX_MESSAGE_LEN 1024
#define MAX_SIGNATURE_LEN 128

/* Check raw signature output against test vectors */
static void check_sign(int id, size_t private_key_len, size_t public_key_len,
                       size_t signature_len, const char *name,
                       const char *private_key, const char *public_key,
                       const char *message, const char *signature)
{
    NoiseSignState *state1;
    NoiseSignState *state2;
    uint8_t priv_key[MAX_SIGN_KEY_LEN];
    uint8_t pub_key[MAX_SIGN_KEY_LEN];
    uint8_t msg[MAX_MESSAGE_LEN];
    uint8_t sig[MAX_SIGNATURE_LEN];
    size_t msg_len;
    uint8_t temp[MAX_SIGNATURE_LEN];
    uint8_t temp2[MAX_SIGN_KEY_LEN];

    /* Convert the test strings into binary data */
    compare(string_to_data(priv_key, sizeof(priv_key), private_key),
            private_key_len);
    compare(string_to_data(pub_key, sizeof(pub_key), public_key),
            public_key_len);
    msg_len = string_to_data(msg, sizeof(msg), message);
    compare(string_to_data(sig, sizeof(sig), signature),
            signature_len);

    /* Create the signing object and check its properties */
    compare(noise_signstate_new_by_id(&state1, id), NOISE_ERROR_NONE);
    compare(noise_signstate_get_sign_id(state1), id);
    compare(noise_signstate_get_private_key_length(state1), private_key_len);
    compare(noise_signstate_get_public_key_length(state1), public_key_len);
    compare(noise_signstate_get_signature_length(state1), signature_len);
    verify(!noise_signstate_has_keypair(state1));
    verify(!noise_signstate_has_public_key(state1));
    verify(private_key_len <= noise_signstate_get_max_key_length());
    verify(public_key_len <= noise_signstate_get_max_key_length());
    verify(signature_len <= noise_signstate_get_max_signature_length());

    /* Create a second signing object for verification */
    compare(noise_signstate_new_by_id(&state2, id), NOISE_ERROR_NONE);
    compare(noise_signstate_get_sign_id(state2), id);
    compare(noise_signstate_get_private_key_length(state2), private_key_len);
    compare(noise_signstate_get_public_key_length(state2), public_key_len);
    compare(noise_signstate_get_signature_length(state2), signature_len);
    verify(!noise_signstate_has_keypair(state2));
    verify(!noise_signstate_has_public_key(state2));

    /* Set the keys on the two objects */
    compare(noise_signstate_set_keypair
                (state1, priv_key, private_key_len, pub_key, public_key_len),
            NOISE_ERROR_NONE);
    compare(noise_signstate_set_public_key(state2, pub_key, public_key_len),
            NOISE_ERROR_NONE);
    verify(noise_signstate_has_keypair(state1));
    verify(noise_signstate_has_public_key(state1));
    verify(!noise_signstate_has_keypair(state2));
    verify(noise_signstate_has_public_key(state2));

    /* Create the signature with the first object */
    memset(temp, 0xAA, sizeof(temp));
    compare(noise_signstate_sign(state1, msg, msg_len, temp, signature_len),
            NOISE_ERROR_NONE);
    verify(!memcmp(temp, sig, signature_len));

    /* Verify the signature with the second object */
    compare(noise_signstate_verify(state2, msg, msg_len, temp, signature_len),
            NOISE_ERROR_NONE);

    /* Fetch the keys back from the objects and compare */
    memset(temp, 0xAA, sizeof(temp));
    memset(temp2, 0x66, sizeof(temp2));
    compare(noise_signstate_get_keypair
                (state1, temp, private_key_len, temp2, public_key_len),
            NOISE_ERROR_NONE);
    verify(!memcmp(temp, priv_key, private_key_len));
    verify(!memcmp(temp2, pub_key, public_key_len));
    memset(temp, 0xAA, sizeof(temp));
    compare(noise_signstate_get_public_key(state2, temp, public_key_len),
            NOISE_ERROR_NONE);
    verify(!memcmp(temp, pub_key, public_key_len));

    /* Check parameter error conditions */
    compare(noise_signstate_set_keypair
                (0, priv_key, private_key_len, pub_key, public_key_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_signstate_set_keypair
                (state1, 0, private_key_len, pub_key, public_key_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_signstate_set_keypair
                (state1, priv_key, private_key_len, 0, public_key_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_signstate_set_keypair
                (state1, priv_key, private_key_len - 1, pub_key, public_key_len),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_signstate_set_keypair
                (state1, priv_key, private_key_len + 1, pub_key, public_key_len),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_signstate_set_keypair
                (state1, priv_key, private_key_len, pub_key, public_key_len + 1),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_signstate_set_keypair
                (state1, priv_key, private_key_len, pub_key, public_key_len - 1),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_signstate_get_keypair
                (0, temp, private_key_len, temp2, public_key_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_signstate_get_keypair
                (state1, 0, private_key_len, temp2, public_key_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_signstate_get_keypair
                (state1, temp, private_key_len, 0, public_key_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_signstate_get_keypair
                (state1, temp, private_key_len - 1, temp2, public_key_len),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_signstate_get_keypair
                (state1, temp, private_key_len + 1, temp2, public_key_len),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_signstate_get_keypair
                (state1, temp, private_key_len, temp2, public_key_len - 1),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_signstate_get_keypair
                (state1, temp, private_key_len, temp2, public_key_len + 1),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_signstate_set_public_key
                (0, pub_key, public_key_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_signstate_set_public_key
                (state2, 0, public_key_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_signstate_set_public_key
                (state2, pub_key, public_key_len - 1),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_signstate_set_public_key
                (state2, pub_key, public_key_len + 1),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_signstate_get_public_key(0, temp, public_key_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_signstate_get_public_key(state2, 0, public_key_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_signstate_get_public_key(state2, temp, public_key_len - 1),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_signstate_get_public_key(state2, temp, public_key_len + 1),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_signstate_sign(0, msg, msg_len, temp, signature_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_signstate_sign(state1, 0, msg_len, temp, signature_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_signstate_sign(state1, msg, msg_len, 0, signature_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_signstate_sign(state1, msg, msg_len, temp, signature_len - 1),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_signstate_sign(state1, msg, msg_len, temp, signature_len + 1),
            NOISE_ERROR_INVALID_LENGTH);

    /* Re-create the objects by name and check their properties again */
    compare(noise_signstate_free(state1), NOISE_ERROR_NONE);
    compare(noise_signstate_free(state2), NOISE_ERROR_NONE);
    compare(noise_signstate_new_by_name(&state1, name), NOISE_ERROR_NONE);
    compare(noise_signstate_new_by_name(&state2, name), NOISE_ERROR_NONE);
    compare(noise_signstate_get_sign_id(state1), id);
    compare(noise_signstate_get_sign_id(state2), id);
    compare(noise_signstate_get_private_key_length(state1), private_key_len);
    compare(noise_signstate_get_public_key_length(state1), public_key_len);
    compare(noise_signstate_get_signature_length(state1), signature_len);
    compare(noise_signstate_get_private_key_length(state2), private_key_len);
    compare(noise_signstate_get_public_key_length(state2), public_key_len);
    compare(noise_signstate_get_signature_length(state2), signature_len);
    verify(!noise_signstate_has_keypair(state1));
    verify(!noise_signstate_has_public_key(state1));
    verify(!noise_signstate_has_keypair(state2));
    verify(!noise_signstate_has_public_key(state2));

    /* Make sure that it is still the same object by checking signatures.
       This time we derive state1's public key from the private key rather
       than use the value from the test data. */
    compare(noise_signstate_set_keypair_private
                (state1, priv_key, private_key_len),
            NOISE_ERROR_NONE);
    compare(noise_signstate_set_public_key
                (state2, pub_key, public_key_len),
            NOISE_ERROR_NONE);
    memset(temp, 0xAA, sizeof(temp));
    compare(noise_signstate_sign(state1, msg, msg_len, temp, signature_len),
            NOISE_ERROR_NONE);
    verify(!memcmp(temp, sig, signature_len));
    compare(noise_signstate_verify(state2, msg, msg_len, temp, signature_len),
            NOISE_ERROR_NONE);

    /* Deliberately mess up the signature and check that it doesn't verify */
    temp[signature_len / 2] ^= 0x01;
    compare(noise_signstate_verify(state2, msg, msg_len, temp, signature_len),
            NOISE_ERROR_INVALID_SIGNATURE);

    /* Clear the first key and check that it returns to default properties */
    compare(noise_signstate_clear_key(state1), NOISE_ERROR_NONE);
    verify(!noise_signstate_has_keypair(state1));
    verify(!noise_signstate_has_public_key(state1));
    compare(noise_signstate_get_keypair
                (state1, temp, private_key_len, temp2, public_key_len),
            NOISE_ERROR_INVALID_STATE);
    compare(noise_signstate_get_public_key(state1, temp, public_key_len),
            NOISE_ERROR_INVALID_STATE);

    /* Deliberately mess up the keypair and perform validation.
       The Ed25519 back end validates the public key but all private
       key values are valid. */
    priv_key[private_key_len / 2] ^= 0x01;
    compare(noise_signstate_set_keypair
                (state1, priv_key, private_key_len, pub_key, public_key_len),
            NOISE_ERROR_INVALID_PUBLIC_KEY);
    priv_key[private_key_len / 2] ^= 0x01;
    compare(noise_signstate_set_keypair
                (state1, priv_key, private_key_len, pub_key, public_key_len),
            NOISE_ERROR_NONE);
    pub_key[public_key_len / 2] ^= 0x01;
    compare(noise_signstate_set_keypair
                (state1, priv_key, private_key_len, pub_key, public_key_len),
            NOISE_ERROR_INVALID_PUBLIC_KEY);
    pub_key[public_key_len / 2] ^= 0x01;
    compare(noise_signstate_set_keypair
                (state1, priv_key, private_key_len, pub_key, public_key_len),
            NOISE_ERROR_NONE);

    /* Clean up */
    compare(noise_signstate_free(state1), NOISE_ERROR_NONE);
    compare(noise_signstate_free(state2), NOISE_ERROR_NONE);
}

/* Check against test vectors from the various specifications
   to validate that the algorithms work as low level primitives */
static void signstate_check_test_vectors(void)
{
    /* Ed25519 - From section 7.1 of
       https://tools.ietf.org/html/draft-irtf-cfrg-eddsa-05 */
    check_sign
        (NOISE_SIGN_ED25519, 32, 32, 64, "Ed25519",
         "0x9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
         "0xd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
         "",
         "0xe5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
           "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
    check_sign
        (NOISE_SIGN_ED25519, 32, 32, 64, "Ed25519",
         "0x4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
         "0x3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
         "0x72",
         "0x92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
           "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");
    check_sign
        (NOISE_SIGN_ED25519, 32, 32, 64, "Ed25519",
         "0xc5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
         "0xfc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
         "0xaf82",
         "0x6291d657deec24024827e69c3abe01a3 0ce548a284743a445e3680d7db5ac3ac"
           "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a");
    check_sign
        (NOISE_SIGN_ED25519, 32, 32, 64, "Ed25519",
         "0xf5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
         "0x278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
         "0x08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98"
           "fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d8"
           "79de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d"
           "658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc"
           "1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4fe"
           "ba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e"
           "06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbef"
           "efd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7"
           "aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed1"
           "85ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2"
           "d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24"
           "554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f270"
           "88d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc"
           "2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b07"
           "07e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128ba"
           "b27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51a"
           "ddd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429e"
           "c96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb7"
           "51fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c"
           "42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8"
           "ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34df"
           "f7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08"
           "d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649"
           "de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e4"
           "88acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a3"
           "2ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e"
           "6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5f"
           "b93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b5"
           "0d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1"
           "369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380d"
           "b2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c"
           "0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0",
         "0x0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350"
           "aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03");
    check_sign
        (NOISE_SIGN_ED25519, 32, 32, 64, "Ed25519",
         "0x833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
         "0xec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
         "0xddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
           "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
         "0xdc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589"
           "09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704");
}

/* Check the generation and use of new key pairs */
static void check_dh_generate(int id)
{
    NoiseSignState *state1;
    NoiseSignState *state2;
    uint8_t pub_key[MAX_SIGN_KEY_LEN];
    uint8_t msg[MAX_MESSAGE_LEN];
    uint8_t sig[MAX_SIGNATURE_LEN];
    size_t public_key_len;
    size_t signature_len;

    /* Create the objects and get the properties */
    compare(noise_signstate_new_by_id(&state1, id), NOISE_ERROR_NONE);
    compare(noise_signstate_new_by_id(&state2, id), NOISE_ERROR_NONE);
    compare(noise_signstate_get_sign_id(state1), id);
    compare(noise_signstate_get_sign_id(state2), id);
    public_key_len = noise_signstate_get_public_key_length(state1);
    signature_len = noise_signstate_get_signature_length(state1);

    /* Generate a new keypair in the first object */
    compare(noise_signstate_generate_keypair(state1), NOISE_ERROR_NONE);

    /* Transfer the public key to the second object */
    compare(noise_signstate_get_public_key(state1, pub_key, public_key_len),
            NOISE_ERROR_NONE);
    compare(noise_signstate_set_public_key(state2, pub_key, public_key_len),
            NOISE_ERROR_NONE);

    /* Sign a message and verify it */
    memset(msg, 0xAA, sizeof(msg));
    memset(sig, 0x66, sizeof(sig));
    compare(noise_signstate_sign(state1, msg, sizeof(msg), sig, signature_len),
            NOISE_ERROR_NONE);
    compare(noise_signstate_verify(state2, msg, sizeof(msg), sig, signature_len),
            NOISE_ERROR_NONE);

    /* Clean up */
    compare(noise_signstate_free(state1), NOISE_ERROR_NONE);
    compare(noise_signstate_free(state2), NOISE_ERROR_NONE);
}

/* Check the generation and use of new key pairs */
static void signstate_check_generate_keypair(void)
{
    check_dh_generate(NOISE_SIGN_ED25519);
}

/* Check other error conditions that can be reported by the functions */
static void signstate_check_errors(void)
{
    NoiseSignState *state;

    /* NULL parameters in various positions */
    compare(noise_signstate_free(0), NOISE_ERROR_INVALID_PARAM);
    compare(noise_signstate_get_sign_id(0), NOISE_DH_NONE);
    compare(noise_signstate_get_private_key_length(0), 0);
    compare(noise_signstate_get_public_key_length(0), 0);
    compare(noise_signstate_get_signature_length(0), 0);
    compare(noise_signstate_has_keypair(0), 0);
    compare(noise_signstate_has_public_key(0), 0);
    compare(noise_signstate_new_by_id(0, NOISE_SIGN_ED25519),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_signstate_new_by_name(0, "Ed25519"),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_signstate_generate_keypair(0), NOISE_ERROR_INVALID_PARAM);

    /* If the id/name is unknown, the state parameter should be set to NULL */
    state = (NoiseSignState *)8;
    compare(noise_signstate_new_by_id(&state, NOISE_DH_CURVE25519),
            NOISE_ERROR_UNKNOWN_ID);
    verify(state == NULL);
    state = (NoiseSignState *)8;
    compare(noise_signstate_new_by_name(&state, 0),
            NOISE_ERROR_INVALID_PARAM);
    verify(state == NULL);
    state = (NoiseSignState *)8;
    compare(noise_signstate_new_by_name(&state, "Eggs25519"),
            NOISE_ERROR_UNKNOWN_NAME);
    verify(state == NULL);
}

void test_signstate(void)
{
    signstate_check_test_vectors();
    signstate_check_generate_keypair();
    signstate_check_errors();
}
