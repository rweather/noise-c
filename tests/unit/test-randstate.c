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

#define MAX_RAND_DATA 256

/* Check if a data array consists of all the same byte */
static int is_all(const uint8_t *data, size_t size, uint8_t value)
{
    while (size > 0) {
        if (*data++ != value)
            return 0;
        --size;
    }
    return 1;
}

void test_randstate(void)
{
    NoiseRandState *rand1;
    NoiseRandState *rand2;
    uint8_t temp1[MAX_RAND_DATA];
    uint8_t temp2[MAX_RAND_DATA];
    uint8_t temp3[MAX_RAND_DATA];
    uint8_t temp4[MAX_RAND_DATA];
    size_t count;

    /* Create the random number generators */
    compare(noise_randstate_new(&rand1), NOISE_ERROR_NONE);
    compare(noise_randstate_new(&rand2), NOISE_ERROR_NONE);

    /*
     * Check that the two objects generate different sequences and that
     * each object outputs different data from itself each time.
     *
     * There is an infintessimal chance that these tests fails with
     * exactly the same output.  The output is random after all and
     * every event is equally likely in a uniform random stream.
     * But the chances are so remote that we can ignore the problem.
     *
     * If it happens for you, then hooray!  And then run the test again.
     * It is only a problem if it keeps happening.
     */
    memset(temp3, 0, sizeof(temp3));
    memset(temp4, 0, sizeof(temp4));
    for (count = 0; count < 100; ++count) {
        compare(noise_randstate_generate(rand1, temp1, sizeof(temp1)),
                NOISE_ERROR_NONE);
        compare(noise_randstate_generate(rand2, temp2, sizeof(temp2)),
                NOISE_ERROR_NONE);
        verify(memcmp(temp1, temp2, sizeof(temp1)) != 0);
        if (count) {
            verify(memcmp(temp1, temp3, sizeof(temp1)) != 0);
            verify(memcmp(temp2, temp4, sizeof(temp2)) != 0);
        }
        memcpy(temp3, temp1, sizeof(temp1));
        memcpy(temp4, temp2, sizeof(temp2));
    }

    /* Reseed - no way to check if this actually does something */
    compare(noise_randstate_reseed(rand1), NOISE_ERROR_NONE);
    compare(noise_randstate_reseed(rand2), NOISE_ERROR_NONE);

    /* Check message padding */
    memset(temp1, 0xAA, sizeof(temp1));
    compare(noise_randstate_pad(rand1, temp1, 29, 51, NOISE_PADDING_ZERO),
            NOISE_ERROR_NONE);
    verify(is_all(temp1, 29, 0xAA));
    verify(is_all(temp1 + 29, 51 - 29, 0));
    verify(is_all(temp1 + 51, sizeof(temp1) - 51, 0xAA));
    memset(temp1, 0x66, sizeof(temp1));
    compare(noise_randstate_pad(rand1, temp1, 29, 100, NOISE_PADDING_RANDOM),
            NOISE_ERROR_NONE);
    verify(is_all(temp1, 29, 0x66));
    verify(!is_all(temp1 + 29, 100 - 29, 0x66));
    verify(!is_all(temp1 + 29, 100 - 29, 0x00));
    verify(is_all(temp1 + 100, sizeof(temp1) - 100, 0x66));
    memset(temp1, 0x55, sizeof(temp1));
    compare(noise_randstate_pad(rand1, temp1, 29, 100, NOISE_ID('G', 55)),
            NOISE_ERROR_NONE);
    verify(is_all(temp1, 29, 0x55));
    verify(!is_all(temp1 + 29, 100 - 29, 0x55));
    verify(!is_all(temp1 + 29, 100 - 29, 0x00));
    verify(is_all(temp1 + 100, sizeof(temp1) - 100, 0x55));
    memset(temp1, 0x55, 29);
    memset(temp1 + 29, 0xAA, sizeof(temp1) - 29);
    compare(noise_randstate_pad(rand1, temp1, 29, 28, NOISE_PADDING_ZERO),
            NOISE_ERROR_NONE);
    verify(is_all(temp1, 29, 0x55));
    verify(is_all(temp1 + 29, sizeof(temp1) - 29, 0xAA));

    /* Check for error conditions */
    compare(noise_randstate_new(0), NOISE_ERROR_INVALID_PARAM);
    compare(noise_randstate_free(0), NOISE_ERROR_INVALID_PARAM);
    compare(noise_randstate_reseed(0), NOISE_ERROR_INVALID_PARAM);
    compare(noise_randstate_generate(rand1, 0, sizeof(temp1)),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_randstate_pad(rand1, 0, 28, sizeof(temp1), NOISE_PADDING_ZERO),
            NOISE_ERROR_INVALID_PARAM);

    /* Check that the padding region is zeroed if the state argument is NULL */
    memset(temp1, 0xAA, sizeof(temp1));
    compare(noise_randstate_pad(0, temp1, 28, sizeof(temp1), NOISE_PADDING_RANDOM),
            NOISE_ERROR_INVALID_PARAM);
    verify(is_all(temp1, 28, 0xAA));
    verify(is_all(temp1 + 28, sizeof(temp1) - 28, 0x00));

    /* Check that generation with a NULL state also zeroes the output */
    memset(temp1, 0xAA, sizeof(temp1));
    compare(noise_randstate_generate(0, temp1, sizeof(temp1)),
            NOISE_ERROR_INVALID_PARAM);
    verify(is_all(temp1, sizeof(temp1), 0x00));

    /* Clean up */
    compare(noise_randstate_free(rand1), NOISE_ERROR_NONE);
    compare(noise_randstate_free(rand2), NOISE_ERROR_NONE);
}
