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

#define MAX_HASH_INPUT  128
#define MAX_HASH_OUTPUT 64
#define MAX_BLOCK_LEN   128

/* Check raw hash output against test vectors */
static void check_hash(int id, size_t hash_len, size_t block_len,
                       const char *name, const char *data, const char *hash)
{
    NoiseHashState *state;
    uint8_t input[MAX_HASH_INPUT];
    uint8_t output[MAX_HASH_OUTPUT];
    uint8_t temp[MAX_HASH_OUTPUT];
    size_t input_len;
    size_t index;

    /* Convert the test strings into binary data */
    input_len = string_to_data(input, sizeof(input), data);
    compare(string_to_data(output, sizeof(output), hash), hash_len);

    /* Create the hash object and check its properties */
    compare(noise_hashstate_new_by_id(&state, id), NOISE_ERROR_NONE);
    compare(noise_hashstate_get_hash_id(state), id);
    compare(noise_hashstate_get_hash_length(state), hash_len);
    compare(noise_hashstate_get_block_length(state), block_len);

    /* Check hashing all data in one hit */
    memset(temp, 0xAA, sizeof(temp));
    compare(noise_hashstate_hash_one(state, input, input_len, temp),
            NOISE_ERROR_NONE);
    verify(!memcmp(temp, output, hash_len));

    /* Check hashing the data split into two separate parts */
    for (index = 0; index < input_len; ++index) {
        memset(temp, 0xAA, sizeof(temp));
        compare(noise_hashstate_hash_two
            (state, input, index, input + index, input_len - index, temp),
            NOISE_ERROR_NONE);
        verify(!memcmp(temp, output, hash_len));
    }

    /* Check parameter error conditions */
    compare(noise_hashstate_hash_one(0, input, input_len, temp),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_hashstate_hash_one(state, 0, input_len, temp),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_hashstate_hash_one(state, input, input_len, 0),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_hashstate_hash_two(0, input, 10, input + 10, 13, temp),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_hashstate_hash_two(state, 0, 10, input + 10, 13, temp),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_hashstate_hash_two(state, input, 10, 0, 13, temp),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_hashstate_hash_two(state, input, 10, input + 10, 13, 0),
            NOISE_ERROR_INVALID_PARAM);

    /* Re-create the object by name and check its properties again */
    compare(noise_hashstate_free(state), NOISE_ERROR_NONE);
    compare(noise_hashstate_new_by_name(&state, name), NOISE_ERROR_NONE);
    compare(noise_hashstate_get_hash_id(state), id);
    compare(noise_hashstate_get_hash_length(state), hash_len);
    compare(noise_hashstate_get_block_length(state), block_len);

    /* Make sure that it is still the same object by checking hash outputs */
    memset(temp, 0xAA, sizeof(temp));
    compare(noise_hashstate_hash_one(state, input, input_len, temp),
            NOISE_ERROR_NONE);
    verify(!memcmp(temp, output, hash_len));

    /* Clean up */
    compare(noise_hashstate_free(state), NOISE_ERROR_NONE);
}

/* Check against test vectors from the various specifications
   to validate that the algorithms work as low level primitives */
static void hashstate_check_test_vectors(void)
{
    /* BLAKE2s */
    check_hash
        (NOISE_HASH_BLAKE2s, 32, 64, "BLAKE2s",
         "",
         "0x69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9");
    check_hash
        (NOISE_HASH_BLAKE2s, 32, 64, "BLAKE2s",
         "abc",
         "0x508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
    check_hash
        (NOISE_HASH_BLAKE2s, 32, 64, "BLAKE2s",
         "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "0x6f4df5116a6f332edab1d9e10ee87df6557beab6259d7663f3bcd5722c13f189");
    check_hash
        (NOISE_HASH_BLAKE2s, 32, 64, "BLAKE2s",
         "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
         "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
         "0x358dd2ed0780d4054e76cb6f3a5bce2841e8e2f547431d4d09db21b66d941fc7");

    /* BLAKE2b */
    check_hash
        (NOISE_HASH_BLAKE2b, 64, 128, "BLAKE2b",
         "",
         "0x786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419"
           "d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce");
    check_hash
        (NOISE_HASH_BLAKE2b, 64, 128, "BLAKE2b",
         "abc",
         "0xba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
           "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923");
    check_hash
        (NOISE_HASH_BLAKE2b, 64, 128, "BLAKE2b",
         "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "0x7285ff3e8bd768d69be62b3bf18765a325917fa9744ac2f582a20850bc2b1141"
           "ed1b3e4528595acc90772bdf2d37dc8a47130b44f33a02e8730e5ad8e166e888");
    check_hash
        (NOISE_HASH_BLAKE2b, 64, 128, "BLAKE2b",
         "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
         "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
         "0xce741ac5930fe346811175c5227bb7bfcd47f42612fae46c0809514f9e0e3a11"
           "ee1773287147cdeaeedff50709aa716341fe65240f4ad6777d6bfaf9726e5e52");

    /* SHA256 */
    check_hash
        (NOISE_HASH_SHA256, 32, 64, "SHA256",
         "",
         "0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    check_hash
        (NOISE_HASH_SHA256, 32, 64, "SHA256",
         "abc",
         "0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    check_hash
        (NOISE_HASH_SHA256, 32, 64, "SHA256",
         "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "0x248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

    /* SHA512 */
    check_hash
        (NOISE_HASH_SHA512, 64, 128, "SHA512",
         "",
         "0xcf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
           "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
    check_hash
        (NOISE_HASH_SHA512, 64, 128, "SHA512",
         "abc",
         "0xddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
           "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    check_hash
        (NOISE_HASH_SHA512, 64, 128, "SHA512",
         "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
         "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
         "0x8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
           "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
}

/* Formats a key for the simple implementation of HMAC */
static void format_hmac_key(NoiseHashState *state, uint8_t *block,
                            const uint8_t *key, size_t key_len, uint8_t pad)
{
    size_t hash_len = noise_hashstate_get_hash_length(state);
    size_t block_len = noise_hashstate_get_block_length(state);
    if (key_len <= block_len) {
        memcpy(block, key, key_len);
        memset(block + key_len, 0, block_len - key_len);
    } else {
        noise_hashstate_hash_one(state, key, key_len, block);
        memset(block + hash_len, 0, block_len - hash_len);
    }
    while (block_len > 0) {
        --block_len;
        block[block_len] ^= pad;
    }
}

/* Simple implementation of HMAC for cross-checking the library */
static void hmac(NoiseHashState *state, uint8_t *hash,
                 const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len)
{
    size_t hash_len = noise_hashstate_get_hash_length(state);
    size_t block_len = noise_hashstate_get_block_length(state);
    uint8_t block[MAX_BLOCK_LEN];
    format_hmac_key(state, block, key, key_len, 0x36);
    noise_hashstate_hash_two(state, block, block_len, data, data_len, hash);
    format_hmac_key(state, block, key, key_len, 0x5C);
    noise_hashstate_hash_two(state, block, block_len, hash, hash_len, hash);
}

/* Simple implementation of HKDF for cross-checking the library */
static void hkdf(NoiseHashState *state, uint8_t *output1, uint8_t *output2,
                 const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len)
{
    size_t hash_len = noise_hashstate_get_hash_length(state);
    uint8_t temp_key[MAX_HASH_OUTPUT];
    uint8_t output[MAX_HASH_OUTPUT + 1];
    hmac(state, temp_key, key, key_len, data, data_len);
    output[0] = 0x01;
    hmac(state, output, temp_key, hash_len, output, 1);
    memcpy(output1, output, hash_len);
    output[hash_len] = 0x02;
    hmac(state, output, temp_key, hash_len, output, hash_len + 1);
    memcpy(output2, output, hash_len);
}

/* Check the behaviour of the noise_hashstate_hkdf() function */
static void hashstate_check_hkdf_algorithm(int id)
{
    NoiseHashState *state;
    size_t hash_len, index;
    uint8_t key[MAX_HASH_OUTPUT];
    uint8_t data[MAX_HASH_INPUT];
    uint8_t expected1[MAX_HASH_OUTPUT];
    uint8_t expected2[MAX_HASH_OUTPUT];
    uint8_t output1[MAX_HASH_OUTPUT];
    uint8_t output2[MAX_HASH_OUTPUT];

    /* Create a hash object */
    compare(noise_hashstate_new_by_id(&state, id), NOISE_ERROR_NONE);
    hash_len = noise_hashstate_get_hash_length(state);

    /* Calculate the expected HKDF output with the simple implementation */
    memset(key, 0xAA, sizeof(key));
    memset(data, 0x66, sizeof(data));
    hkdf(state, expected1, expected2, key, sizeof(key), data, sizeof(data));

    /* Compare against what noise_hashstate_hkdf() produces */
    memset(output1, 0xE6, sizeof(output1));
    memset(output2, 0x6E, sizeof(output2));
    compare(noise_hashstate_hkdf(state, key, sizeof(key), data, sizeof(data),
                                 output1, hash_len, output2, hash_len),
            NOISE_ERROR_NONE);
    verify(!memcmp(output1, expected1, hash_len));
    verify(!memcmp(output2, expected2, hash_len));

    /* Call noise_hashstate_hkdf() again, but ask it to truncate the output */
    memset(output1, 0xE6, sizeof(output1));
    memset(output2, 0x6E, sizeof(output2));
    compare(noise_hashstate_hkdf(state, key, sizeof(key), data, sizeof(data),
                                 output1, hash_len / 2, output2, hash_len / 2),
            NOISE_ERROR_NONE);
    verify(!memcmp(output1, expected1, hash_len / 2));
    verify(!memcmp(output2, expected2, hash_len / 2));
    for (index = (hash_len / 2); index < hash_len; ++index) {
        /* Check that the function didn't write beyond our requested length */
        compare(output1[index], 0xE6);
        compare(output2[index], 0x6E);
    }

    /* Check parameter error conditions */
    compare(noise_hashstate_hkdf(0, key, sizeof(key), data, sizeof(data),
                                 output1, hash_len, output2, hash_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_hashstate_hkdf(state, 0, sizeof(key), data, sizeof(data),
                                 output1, hash_len, output2, hash_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_hashstate_hkdf(state, key, sizeof(key), 0, sizeof(data),
                                 output1, hash_len, output2, hash_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_hashstate_hkdf(state, key, sizeof(key), data, sizeof(data),
                                 0, hash_len, output2, hash_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_hashstate_hkdf(state, key, sizeof(key), data, sizeof(data),
                                 output1, hash_len, 0, hash_len),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_hashstate_hkdf(state, key, sizeof(key), data, sizeof(data),
                                 output1, hash_len + 1, output2, hash_len),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_hashstate_hkdf(state, key, sizeof(key), data, sizeof(data),
                                 output1, hash_len, output2, hash_len + 1),
            NOISE_ERROR_INVALID_LENGTH);

    /* Clean up */
    compare(noise_hashstate_free(state), NOISE_ERROR_NONE);
}

/* Check the behaviour of the noise_hashstate_hkdf() function */
static void hashstate_check_hkdf(void)
{
    hashstate_check_hkdf_algorithm(NOISE_HASH_BLAKE2s);
    hashstate_check_hkdf_algorithm(NOISE_HASH_BLAKE2b);
    hashstate_check_hkdf_algorithm(NOISE_HASH_SHA256);
    hashstate_check_hkdf_algorithm(NOISE_HASH_SHA512);
}

/* Check other error conditions that can be reported by the functions */
static void hashstate_check_errors(void)
{
    NoiseHashState *state;

    /* NULL parameters in various positions */
    compare(noise_hashstate_free(0), NOISE_ERROR_INVALID_PARAM);
    compare(noise_hashstate_get_hash_id(0), NOISE_HASH_NONE);
    compare(noise_hashstate_get_hash_length(0), 0);
    compare(noise_hashstate_get_block_length(0), 0);
    compare(noise_hashstate_new_by_id(0, NOISE_HASH_BLAKE2s),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_hashstate_new_by_name(0, "BLAKE2s"),
            NOISE_ERROR_INVALID_PARAM);

    /* If the id/name is unknown, the state parameter should be set to NULL */
    state = (NoiseHashState *)8;
    compare(noise_hashstate_new_by_id(&state, NOISE_CIPHER_CHACHAPOLY),
            NOISE_ERROR_UNKNOWN_ID);
    verify(state == NULL);
    state = (NoiseHashState *)8;
    compare(noise_hashstate_new_by_name(&state, 0),
            NOISE_ERROR_INVALID_PARAM);
    verify(state == NULL);
    state = (NoiseHashState *)8;
    compare(noise_hashstate_new_by_name(&state, "BLAKE3s"),
            NOISE_ERROR_UNKNOWN_NAME);
    verify(state == NULL);
}

void test_hashstate(void)
{
    hashstate_check_test_vectors();
    hashstate_check_hkdf();
    hashstate_check_errors();
}
