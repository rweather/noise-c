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
#include <stdio.h>
#include <string.h>

/**
 * \file errors.h
 * \brief Error reporting interface
 */

/**
 * \file errors.c
 * \brief Error reporting implementation
 */

/**
 * \defgroup error_reports Error reporting
 */
/**@{*/

/** @cond */

/* Default English strings for all known error codes */
static const char * const error_strings[] = {
    "No error",
    "Out of memory",
    "Unknown identifier",
    "Unknown name",
    "MAC failure",
    "Not applicable",
    "System error",
    "Remote public key required",
    "Local keypair required",
    "Pre shared key required",
    "Invalid length",
    "Invalid parameter",
    "Invalid state",
    "Invalid nonce",
    "Invalid private key",
    "Invalid public key",
    "Invalid format",
    "Invalid signature",
    "END"
};
#define num_error_strings (sizeof(error_strings) / sizeof(error_strings[0]) - 1)

/** @endcond */

/**
 * \brief Gets the string for an error code from the internal table.
 *
 * \param err The error code.
 * \return A pointer to the string, or NULL if there is no string for \a err.
 */
static const char *noise_errstr(int err)
{
    if (err == NOISE_ERROR_NONE)
        return error_strings[0];
    if (err < NOISE_ID('E', 1) || err >= NOISE_ID('E', num_error_strings))
        return 0;
    return error_strings[err - NOISE_ID('E', 0)];
}

/**
 * \brief Prints a descriptive string for an error to stderr.
 *
 * \param s The extra string to display, which defines the context in which
 * the error occurred.
 * \param err The error code.
 */
void noise_perror(const char *s, int err)
{
    const char *errstr = noise_errstr(err);
    if (!s)
        s = "(null)";
    if (errstr)
        fprintf(stderr, "%s: %s\n", s, errstr);
    else
        fprintf(stderr, "%s: Unknown error 0x%x\n", s, err);
}

/**
 * \brief Gets the descriptive string for an error code.
 *
 * \param err The error code.
 * \param buf The buffer to write the descriptive string to.
 * \param size The size of the buffer.
 *
 * \return Returns zero if the error string was returned or -1 if
 * \a buf is NULL or \a size is zero.
 *
 * The string may be truncated if \a size is not large enough.
 * This function guarantees to NUL-terminate the returned string.
 */
int noise_strerror(int err, char *buf, size_t size)
{
    const char *errstr = noise_errstr(err);
    if (!buf || !size)
        return -1;
    if (errstr)
        strncpy(buf, errstr, size);
    else
        snprintf(buf, size, "Unknown error 0x%x", err);
    buf[size - 1] = '\0';
    return 0;
}

/**@}*/
