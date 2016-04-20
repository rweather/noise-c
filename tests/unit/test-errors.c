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

#define NOISE_MIN_ERROR     NOISE_ID('E', 1)
#define NOISE_MAX_ERROR     NOISE_ID('E', 17)

void test_errors(void)
{
    char buffer[64];
    int err;

    /* Check that every known error code has a meaningful message defined
       and that it is properly NUL-terminated within the specified size. */
    for (err = NOISE_MIN_ERROR; err < NOISE_MAX_ERROR; ++err) {
        memset(buffer, 0xAA, sizeof(buffer));
        compare(noise_strerror(err, buffer, sizeof(buffer)), 0);
        verify(memchr(buffer, 0, sizeof(buffer)) != 0);
        verify(strncmp(buffer, "Unknown error 0x", 16) != 0);
        verify(strncmp(buffer, "END", 3) != 0);
        memset(buffer, 0xAA, sizeof(buffer));
        compare(noise_strerror(err, buffer, 5), 0);
        verify(memchr(buffer, 0, sizeof(buffer)) != 0);
    }

    /* Check some specific errors */
    err = NOISE_ERROR_NONE;
    memset(buffer, 0xAA, sizeof(buffer));
    compare(noise_strerror(err, buffer, sizeof(buffer)), 0);
    verify(memchr(buffer, 0, sizeof(buffer)) != 0);
    compare(strcmp(buffer, "No error"), 0);
    err = NOISE_ERROR_NO_MEMORY;
    memset(buffer, 0xAA, sizeof(buffer));
    compare(noise_strerror(err, buffer, sizeof(buffer)), 0);
    verify(memchr(buffer, 0, sizeof(buffer)) != 0);
    compare(strcmp(buffer, "Out of memory"), 0);
    err = NOISE_ERROR_INVALID_NONCE;
    memset(buffer, 0xAA, sizeof(buffer));
    compare(noise_strerror(err, buffer, sizeof(buffer)), 0);
    verify(memchr(buffer, 0, sizeof(buffer)) != 0);
    compare(strcmp(buffer, "Invalid nonce"), 0);

    /* Check that out of range error codes map to "Unknown error" */
    err = NOISE_MIN_ERROR - 1;
    memset(buffer, 0xAA, sizeof(buffer));
    compare(noise_strerror(err, buffer, sizeof(buffer)), 0);
    verify(memchr(buffer, 0, sizeof(buffer)) != 0);
    verify(strncmp(buffer, "Unknown error 0x", 16) == 0);
    err = NOISE_MAX_ERROR + 1;
    memset(buffer, 0xAA, sizeof(buffer));
    compare(noise_strerror(err, buffer, sizeof(buffer)), 0);
    verify(memchr(buffer, 0, sizeof(buffer)) != 0);
    verify(strncmp(buffer, "Unknown error 0x", 16) == 0);

    /* Dump the error strings to help test if the right string is
       associated with the right code */
    if (verbose) {
        #define dump_error(name) noise_perror(#name, name)
        dump_error(NOISE_ERROR_NONE);
        dump_error(NOISE_ERROR_NO_MEMORY);
        dump_error(NOISE_ERROR_UNKNOWN_ID);
        dump_error(NOISE_ERROR_UNKNOWN_NAME);
        dump_error(NOISE_ERROR_MAC_FAILURE);
        dump_error(NOISE_ERROR_NOT_APPLICABLE);
        dump_error(NOISE_ERROR_SYSTEM);
        dump_error(NOISE_ERROR_REMOTE_KEY_REQUIRED);
        dump_error(NOISE_ERROR_LOCAL_KEY_REQUIRED);
        dump_error(NOISE_ERROR_PSK_REQUIRED);
        dump_error(NOISE_ERROR_INVALID_LENGTH);
        dump_error(NOISE_ERROR_INVALID_PARAM);
        dump_error(NOISE_ERROR_INVALID_STATE);
        dump_error(NOISE_ERROR_INVALID_NONCE);
        dump_error(NOISE_ERROR_INVALID_PRIVATE_KEY);
        dump_error(NOISE_ERROR_INVALID_PUBLIC_KEY);
        dump_error(NOISE_ERROR_INVALID_FORMAT);
        dump_error(NOISE_ERROR_INVALID_SIGNATURE);
    }
}
