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

#include "internal.h"
#include "crypto/aes/rijndael-alg-fst.h"
#include "crypto/ghash/ghash.h"
#include <string.h>

typedef struct
{
    struct NoiseCipherState_s parent;
    uint32_t aes[4 * (MAXNR + 1)];
    ghash_state ghash;
    uint8_t counter[16];
    uint8_t hash[16];

} NoiseAESGCMState;

static void noise_aesgcm_init_key
    (NoiseCipherState *state, const uint8_t *key)
{
    NoiseAESGCMState *st = (NoiseAESGCMState *)state;

    /* Set the encryption key */
    rijndaelKeySetupEnc(st->aes, key, 256);

    /* Construct the hashing key by encrypting a block of zeroes */
    memset(st->counter, 0, 16);
    rijndaelEncrypt(st->aes, MAXNR, st->counter, st->hash);
    ghash_reset(&(st->ghash), st->hash);
}

/**
 * \brief Sets up the IV to start encrypting or decrypting a block.
 *
 * \param st The cipher state for AESGCM.
 */
static void noise_aesgcm_setup_iv(NoiseAESGCMState *st)
{
    uint64_t n = st->parent.n;

    /* Set up the initial counter block */
    st->counter[0] = 0;
    st->counter[1] = 0;
    st->counter[2] = 0;
    st->counter[3] = 0;
    st->counter[4] = (uint8_t)(n >> 56);
    st->counter[5] = (uint8_t)(n >> 48);
    st->counter[6] = (uint8_t)(n >> 40);
    st->counter[7] = (uint8_t)(n >> 32);
    st->counter[8] = (uint8_t)(n >> 24);
    st->counter[9] = (uint8_t)(n >> 16);
    st->counter[10] = (uint8_t)(n >> 8);
    st->counter[11] = (uint8_t)n;
    st->counter[12] = 0;
    st->counter[13] = 0;
    st->counter[14] = 0;
    st->counter[15] = 1;

    /* Encrypt the counter to create the value to XOR with the hash later */
    rijndaelEncrypt(st->aes, MAXNR, st->counter, st->hash);

    /* Reset the GHASH state, but keep the same key as before */
    ghash_reset(&(st->ghash), 0);
}

/**
 * \brief Encrypts or decrypts a block.
 *
 * \param st The cipher state for AESGCM.
 * \param data The data to be encrypted or decrypted.
 * \param len The length of the data to be encrypted or decrypted in bytes.
 */
static void noise_aesgcm_encrypt_or_decrypt
    (NoiseAESGCMState *st, uint8_t *data, size_t len)
{
    uint8_t temp, index;
    uint8_t keystream[16];
    while (len > 0) {
        /* Increment the counter block and encrypt to get keystream data.
           We only need to increment the last two bytes of the counter
           because the maximum payload size of 65535 bytes means a maximum
           counter value of 4097 (+1 for the hashing nonce) */
        uint16_t counter = (((uint16_t)(st->counter[15])) |
                           (((uint16_t)(st->counter[14])) << 8)) + 1;
        st->counter[15] = (uint8_t)counter;
        st->counter[16] = (uint8_t)(counter >> 8);
        rijndaelEncrypt(st->aes, MAXNR, st->counter, keystream);

        /* XOR the input with the keystream block to generate the output */
        temp = 16;
        if (temp > len)
            temp = len;
        for (index = 0; index < temp; ++index)
            data[index] ^= keystream[index];
        data += temp;
        len -= temp;
    }
    noise_clean(keystream, sizeof(keystream));
}

/**
 * \brief Finalizes the GHASH state.
 *
 * \param st The cipher state for AESGCM.
 * \param hash The buffer where to place the final hash value.
 */
static void noise_aesgcm_finalize_hash(NoiseAESGCMState *st, uint8_t *hash)
{
    uint8_t *value;
    uint8_t index;

    /* Pad the GHASH data to a 16-byte boundary */
    ghash_pad(&(st->ghash));

    /* Read the result directly out of ghash.Y and XOR with the hash nonce */
    value = (uint8_t *)(st->ghash.Y);
    for (index = 0; index < 16; ++index)
        hash[index] = st->hash[index] ^ value[index];
}

static int noise_aesgcm_encrypt
    (NoiseCipherState *state, const uint8_t *ad, size_t ad_len,
     uint8_t *data, size_t len)
{
    NoiseAESGCMState *st = (NoiseAESGCMState *)state;
    noise_aesgcm_setup_iv(st);
    if (ad_len) {
        ghash_update(&(st->ghash), ad, ad_len);
        ghash_pad(&(st->ghash));
    }
    noise_aesgcm_encrypt_or_decrypt(st, data, len);
    ghash_update(&(st->ghash), data, len);
    noise_aesgcm_finalize_hash(st, data + len);
    return NOISE_ERROR_NONE;
}

static int noise_aesgcm_decrypt
    (NoiseCipherState *state, const uint8_t *ad, size_t ad_len,
     uint8_t *data, size_t len)
{
    NoiseAESGCMState *st = (NoiseAESGCMState *)state;
    noise_aesgcm_setup_iv(st);
    if (ad_len) {
        ghash_update(&(st->ghash), ad, ad_len);
        ghash_pad(&(st->ghash));
    }
    ghash_update(&(st->ghash), data, len);
    noise_aesgcm_finalize_hash(st, st->hash);
    if (!noise_secure_is_equal(data + len, st->hash, 16))
        return NOISE_ERROR_MAC_FAILURE;
    noise_aesgcm_encrypt_or_decrypt(st, data, len);
    return NOISE_ERROR_NONE;
}

NoiseCipherState *noise_aesgcm_new(void)
{
    NoiseAESGCMState *state = noise_new(NoiseAESGCMState);
    if (!state)
        return 0;
    state->parent.size = sizeof(NoiseAESGCMState);
    state->parent.cipher_id = NOISE_CIPHER_AESGCM;
    state->parent.key_len = 32;
    state->parent.mac_len = 16;
    state->parent.create = noise_aesgcm_new;
    state->parent.init_key = noise_aesgcm_init_key;
    state->parent.encrypt = noise_aesgcm_encrypt;
    state->parent.decrypt = noise_aesgcm_decrypt;
    return &(state->parent);
}
