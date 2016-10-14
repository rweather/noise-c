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

/*
    These performance tests output results in "MD5 units".  One such unit
    is the time taken to MD5 1Mb worth of data.  This allows different
    algorithms to be compared as "1.3 times MD5", "0.8 times MD5", etc.

    This allows different implementations of the same algorithms to be
    compared to determine if they are faster or slower than others.
*/

#include <noise/protocol.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "md5.h"
#if defined(__APPLE__)
#include <sys/time.h>
#endif
#if defined(__WIN32__) || defined(WIN32)
#include <windows.h>
#endif

#define BLOCK_SIZE      1024
#define BLOCKS_PER_MB   1024
#define MB_COUNT        200
#define DH_COUNT        1000
#define PQ_DH_COUNT     2000

typedef uint64_t timestamp_t;

static double units;

#if defined(__WIN32__) || defined(WIN32)

static timestamp_t current_timestamp(void)
{
    return GetTickCount();
}

static double elapsed_to_seconds(timestamp_t start, timestamp_t end)
{
    return (end - start) / 1000.0;
}

#elif defined(__APPLE__)

static timestamp_t current_timestamp(void)
{
    struct timeval now;
    gettimeofday(&now, NULL);
    return ((uint64_t)(now.tv_sec)) * 1000000ULL + now.tv_usec;
}

static double elapsed_to_seconds(timestamp_t start, timestamp_t end)
{
    return (end - start) / 1000000.0;
}

#else

static timestamp_t current_timestamp(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
    return ((uint64_t)(ts.tv_sec)) * 1000000000ULL + ts.tv_nsec;
}

static double elapsed_to_seconds(timestamp_t start, timestamp_t end)
{
    return (end - start) / 1000000000.0;
}

#endif

/* Calibrates the performance measurements to determine the "MD5 unit" */
static void calibrate_md5(void)
{
    md5_context_t context;
    uint8_t data[BLOCK_SIZE];
    timestamp_t start, end;
    int count;
    memset(data, 0xAA, sizeof(data));
    md5_reset(&context);
    start = current_timestamp();
    for (count = 0; count < (MB_COUNT * BLOCKS_PER_MB); ++count)
        md5_update(&context, data, sizeof(data));
    end = current_timestamp();
    units = elapsed_to_seconds(start, end) / (double)MB_COUNT;
}

/* Measure the performance of a hashing primitive */
static void perf_hash(int id)
{
    NoiseHashState *hash;
    uint8_t data[BLOCK_SIZE];
    timestamp_t start, end;
    int count;
    double elapsed;

    if (noise_hashstate_new_by_id(&hash, id) != NOISE_ERROR_NONE)
        return;

    memset(data, 0xAA, sizeof(data));
    noise_hashstate_reset(hash);
    start = current_timestamp();
    for (count = 0; count < (MB_COUNT * BLOCKS_PER_MB); ++count)
        noise_hashstate_update(hash, data, sizeof(data));
    end = current_timestamp();

    elapsed = elapsed_to_seconds(start, end) / (double)MB_COUNT;
    printf("%-20s%8.2f          %8.2f\n",
           noise_id_to_name(NOISE_HASH_CATEGORY, id),
           1.0 / elapsed, units / elapsed);

    noise_hashstate_free(hash);
}

/* Measure the performance of an AEAD primitive */
static void perf_cipher(int id)
{
    static uint8_t const key[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
    };
    static uint8_t const ad[32] = {
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x20,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40
    };
    NoiseCipherState *cipher;
    uint8_t data[BLOCK_SIZE + 16];
    timestamp_t start, end;
    int count;
    double elapsed;
    NoiseBuffer mbuf;

    if (noise_cipherstate_new_by_id(&cipher, id) != NOISE_ERROR_NONE)
        return;

    memset(data, 0xAA, sizeof(data));
    noise_cipherstate_init_key(cipher, key, sizeof(key));
    start = current_timestamp();
    for (count = 0; count < (MB_COUNT * BLOCKS_PER_MB); ++count) {
        noise_buffer_set_inout(mbuf, data, sizeof(data) - 16, sizeof(data));
        noise_cipherstate_encrypt_with_ad(cipher, ad, sizeof(ad), &mbuf);
    }
    end = current_timestamp();

    elapsed = elapsed_to_seconds(start, end) / (double)MB_COUNT;
    printf("%-20s%8.2f          %8.2f\n",
           noise_id_to_name(NOISE_CIPHER_CATEGORY, id),
           1.0 / elapsed, units / elapsed);

    noise_cipherstate_free(cipher);
}

/* Measure the performance of a DH primitive when deriving keys */
static void perf_dh_derive(int id)
{
    char name[64];
    NoiseDHState *dh;
    uint8_t private_key[56];
    size_t key_len;
    timestamp_t start, end;
    int count;
    double elapsed;

    if (noise_dhstate_new_by_id(&dh, id) != NOISE_ERROR_NONE)
        return;
    key_len = noise_dhstate_get_private_key_length(dh);

    memset(private_key, 0xAA, sizeof(private_key));
    start = current_timestamp();
    for (count = 0; count < DH_COUNT; ++count)
        noise_dhstate_set_keypair_private(dh, private_key, key_len);
    end = current_timestamp();

    elapsed = elapsed_to_seconds(start, end) / (double)DH_COUNT;
    snprintf(name, sizeof(name), "%s derive key",
             noise_id_to_name(NOISE_DH_CATEGORY, id));
    printf("%-20s%8.2f          %8.2f\n", name, 1.0 / elapsed, units / elapsed);

    noise_dhstate_free(dh);
}

/* Measure the performance of a DH primitive when calculating with keys */
static void perf_dh_calculate(int id)
{
    char name[64];
    NoiseDHState *dh1;
    NoiseDHState *dh2;
    uint8_t private_key1[56];
    uint8_t private_key2[56];
    uint8_t shared_key[56];
    size_t key_len;
    timestamp_t start, end;
    int count;
    double elapsed;

    if (noise_dhstate_new_by_id(&dh1, id) != NOISE_ERROR_NONE)
        return;
    noise_dhstate_new_by_id(&dh2, id);
    key_len = noise_dhstate_get_private_key_length(dh1);

    memset(private_key1, 0xAA, sizeof(private_key1));
    memset(private_key2, 0x66, sizeof(private_key2));
    noise_dhstate_set_keypair_private(dh1, private_key1, key_len);
    noise_dhstate_set_keypair_private(dh2, private_key2, key_len);

    start = current_timestamp();
    for (count = 0; count < DH_COUNT; ++count)
        noise_dhstate_calculate(dh1, dh2, shared_key, key_len);
    end = current_timestamp();

    elapsed = elapsed_to_seconds(start, end) / (double)DH_COUNT;
    snprintf(name, sizeof(name), "%s calculate",
             noise_id_to_name(NOISE_DH_CATEGORY, id));
    printf("%-20s%8.2f          %8.2f\n", name, 1.0 / elapsed, units / elapsed);

    noise_dhstate_free(dh1);
    noise_dhstate_free(dh2);
}

/* Measure the performance of an ephemeral-only DH primitive (e.g NewHope) */
static void perf_dh_ephemeral_only(int id)
{
    char name[64];
    NoiseDHState *dh1;
    NoiseDHState *dh2;
    uint8_t shared_key[32];
    timestamp_t start, end;
    int count;
    double elapsed;

    if (noise_dhstate_new_by_id(&dh1, id) != NOISE_ERROR_NONE)
        return;
    if (noise_dhstate_new_by_id(&dh2, id) != NOISE_ERROR_NONE) {
        noise_dhstate_free(dh1);
        return;
    }

    start = current_timestamp();
    for (count = 0; count < PQ_DH_COUNT; ++count)
        noise_dhstate_generate_keypair(dh1);
    end = current_timestamp();

    elapsed = elapsed_to_seconds(start, end) / (double)PQ_DH_COUNT;
    snprintf(name, sizeof(name), "%s generate",
             noise_id_to_name(NOISE_DH_CATEGORY, id));
    printf("%-20s%8.2f          %8.2f\n", name, 1.0 / elapsed, units / elapsed);

    start = current_timestamp();
    for (count = 0; count < PQ_DH_COUNT; ++count)
        noise_dhstate_generate_dependent_keypair(dh2, dh1);
    end = current_timestamp();

    elapsed = elapsed_to_seconds(start, end) / (double)PQ_DH_COUNT;
    snprintf(name, sizeof(name), "%s sharedb",
             noise_id_to_name(NOISE_DH_CATEGORY, id));
    printf("%-20s%8.2f          %8.2f\n", name, 1.0 / elapsed, units / elapsed);

    start = current_timestamp();
    for (count = 0; count < PQ_DH_COUNT; ++count)
        noise_dhstate_calculate(dh1, dh2, shared_key, sizeof(shared_key));
    end = current_timestamp();

    elapsed = elapsed_to_seconds(start, end) / (double)PQ_DH_COUNT;
    snprintf(name, sizeof(name), "%s shareda",
             noise_id_to_name(NOISE_DH_CATEGORY, id));
    printf("%-20s%8.2f          %8.2f\n", name, 1.0 / elapsed, units / elapsed);

    noise_dhstate_free(dh1);
    noise_dhstate_free(dh2);
}

/* Measure the performance of a signing primitive when deriving keys */
static void perf_sign_derive(int id)
{
    char name[64];
    NoiseSignState *sign;
    uint8_t private_key[64];
    size_t key_len;
    timestamp_t start, end;
    int count;
    double elapsed;

    if (noise_signstate_new_by_id(&sign, id) != NOISE_ERROR_NONE)
        return;
    key_len = noise_signstate_get_private_key_length(sign);

    memset(private_key, 0xAA, sizeof(private_key));
    start = current_timestamp();
    for (count = 0; count < DH_COUNT; ++count)
        noise_signstate_set_keypair_private(sign, private_key, key_len);
    end = current_timestamp();

    elapsed = elapsed_to_seconds(start, end) / (double)DH_COUNT;
    snprintf(name, sizeof(name), "%s derive key",
             noise_id_to_name(NOISE_SIGN_CATEGORY, id));
    printf("%-20s%8.2f          %8.2f\n", name, 1.0 / elapsed, units / elapsed);

    noise_signstate_free(sign);
}

/* Measure the performance of a signing primitive when signing messages */
static void perf_sign_sign(int id)
{
    char name[64];
    NoiseSignState *sign;
    uint8_t private_key[56];
    uint8_t message[32];
    uint8_t sig[56 * 2];
    size_t key_len;
    size_t sig_len;
    timestamp_t start, end;
    int count;
    double elapsed;

    if (noise_signstate_new_by_id(&sign, id) != NOISE_ERROR_NONE)
        return;
    key_len = noise_signstate_get_private_key_length(sign);
    sig_len = noise_signstate_get_signature_length(sign);
    memset(private_key, 0xAA, sizeof(private_key));
    noise_signstate_set_keypair_private(sign, private_key, key_len);
    memset(message, 0x66, sizeof(message));

    start = current_timestamp();
    for (count = 0; count < DH_COUNT; ++count)
        noise_signstate_sign(sign, message, sizeof(message), sig, sig_len);
    end = current_timestamp();

    elapsed = elapsed_to_seconds(start, end) / (double)DH_COUNT;
    snprintf(name, sizeof(name), "%s sign",
             noise_id_to_name(NOISE_SIGN_CATEGORY, id));
    printf("%-20s%8.2f          %8.2f\n", name, 1.0 / elapsed, units / elapsed);

    noise_signstate_free(sign);
}

/* Measure the performance of a signing primitive when verifying messages */
static void perf_sign_verify(int id)
{
    char name[64];
    NoiseSignState *sign;
    uint8_t private_key[56];
    uint8_t message[32];
    uint8_t sig[56 * 2];
    size_t key_len;
    size_t sig_len;
    timestamp_t start, end;
    int count;
    double elapsed;

    if (noise_signstate_new_by_id(&sign, id) != NOISE_ERROR_NONE)
        return;
    key_len = noise_signstate_get_private_key_length(sign);
    sig_len = noise_signstate_get_signature_length(sign);
    memset(private_key, 0xAA, sizeof(private_key));
    noise_signstate_set_keypair_private(sign, private_key, key_len);
    memset(message, 0x66, sizeof(message));
    noise_signstate_sign(sign, message, sizeof(message), sig, sig_len);

    start = current_timestamp();
    for (count = 0; count < DH_COUNT; ++count)
        noise_signstate_verify(sign, message, sizeof(message), sig, sig_len);
    end = current_timestamp();

    elapsed = elapsed_to_seconds(start, end) / (double)DH_COUNT;
    snprintf(name, sizeof(name), "%s verify",
             noise_id_to_name(NOISE_SIGN_CATEGORY, id));
    printf("%-20s%8.2f          %8.2f\n", name, 1.0 / elapsed, units / elapsed);

    noise_signstate_free(sign);
}

int main(int argc, char *argv[])
{
    if (noise_init() != NOISE_ERROR_NONE) {
        fprintf(stderr, "Noise initialization failed\n");
        return 1;
    }

    /* Print the header */
    printf("Algorithm             MB/sec         MD5 units\n");

    /* Calibrate the performance measurements */
    calibrate_md5();
    printf("%-20s%8.2f          %8.2f\n", "MD5 calibration", 1.0 / units, 1.0);

    /* Measure the performance of the hashing primitives */
    perf_hash(NOISE_HASH_BLAKE2s);
    perf_hash(NOISE_HASH_BLAKE2b);
    perf_hash(NOISE_HASH_SHA256);
    perf_hash(NOISE_HASH_SHA512);

    /* Measure the performance of the AEAD primitives */
    perf_cipher(NOISE_CIPHER_CHACHAPOLY);
    perf_cipher(NOISE_CIPHER_AESGCM);

    /* Measure the performance of the DH primitives */
    printf("\n");
    printf("Pubkey algorithm     ops/sec         MD5 units\n");
    perf_dh_derive(NOISE_DH_CURVE25519);
    perf_dh_derive(NOISE_DH_CURVE448);
    perf_dh_calculate(NOISE_DH_CURVE25519);
    perf_dh_calculate(NOISE_DH_CURVE448);
    perf_dh_ephemeral_only(NOISE_DH_NEWHOPE);

    /* Measure the performance of the signing primitives */
    perf_sign_derive(NOISE_SIGN_ED25519);
    perf_sign_sign(NOISE_SIGN_ED25519);
    perf_sign_verify(NOISE_SIGN_ED25519);

    /* Done */
    return 0;
}
