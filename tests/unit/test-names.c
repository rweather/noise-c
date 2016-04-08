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

/* Check that a known mapping is present in the algorithm_names table */
static void check_id(const char *name, int id)
{
    int category = id & NOISE_ID(0xFF, 0);
    char adjusted[32];

    /* Check the expected mappings */
    verify(!strcmp(noise_id_to_name(category, id), name));
    verify(!strcmp(noise_id_to_name(0, id), name));
    compare(noise_name_to_id(category, name, strlen(name)), id);
    compare(noise_name_to_id(0, name, strlen(name)), id);

    /* Check that the name length must be exact for a match */
    if (category != NOISE_PATTERN_CATEGORY) {
        /* Doesn't work for patterns which can be prefixes of each other */
        compare(noise_name_to_id(category, name, strlen(name) - 1), 0);
        compare(noise_name_to_id(0, name, strlen(name) - 1), 0);
    }
    strcpy(adjusted, name);
    strcat(adjusted, "Z");
    compare(noise_name_to_id(category, adjusted, strlen(name) + 1), 0);
    compare(noise_name_to_id(0, adjusted, strlen(name) + 1), 0);

    /* Check that we cannot find the name/id under the wrong category */
    category ^= 0x0100;
    verify(noise_id_to_name(category, id) == NULL);
    compare(noise_name_to_id(category, name, strlen(name)), 0);
}

void test_names(void)
{
    /* Check for known names/identifiers */
    check_id("ChaChaPoly", NOISE_CIPHER_CHACHAPOLY);
    check_id("AESGCM", NOISE_CIPHER_AESGCM);

    check_id("BLAKE2s", NOISE_HASH_BLAKE2s);
    check_id("BLAKE2b", NOISE_HASH_BLAKE2b);
    check_id("SHA256", NOISE_HASH_SHA256);
    check_id("SHA512", NOISE_HASH_SHA512);

    check_id("25519", NOISE_DH_CURVE25519);
    check_id("448", NOISE_DH_CURVE448);

    check_id("N", NOISE_PATTERN_N);
    check_id("X", NOISE_PATTERN_X);
    check_id("K", NOISE_PATTERN_K);
    check_id("NN", NOISE_PATTERN_NN);
    check_id("NK", NOISE_PATTERN_NK);
    check_id("NX", NOISE_PATTERN_NX);
    check_id("XN", NOISE_PATTERN_XN);
    check_id("XK", NOISE_PATTERN_XK);
    check_id("XX", NOISE_PATTERN_XX);
    check_id("XR", NOISE_PATTERN_XR);
    check_id("KN", NOISE_PATTERN_KN);
    check_id("KK", NOISE_PATTERN_KK);
    check_id("KX", NOISE_PATTERN_KX);
    check_id("IN", NOISE_PATTERN_IN);
    check_id("IK", NOISE_PATTERN_IK);
    check_id("IX", NOISE_PATTERN_IX);
    check_id("XXfallback", NOISE_PATTERN_XX_FALLBACK);

    check_id("Noise", NOISE_PREFIX_STANDARD);
    check_id("NoisePSK", NOISE_PREFIX_PSK);

    /* Check for unknown names/identifiers */
    compare(noise_name_to_id(NOISE_CIPHER_CATEGORY, "AESGCM-128", 10), 0);
    compare(noise_name_to_id(0, "AESGCM-128", 10), 0);
    compare(noise_id_to_name(NOISE_CIPHER_CATEGORY, NOISE_ID('C', 200)), 0);
    compare(noise_id_to_name(0, NOISE_ID('C', 200)), 0);
}
