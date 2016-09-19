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

/* This module gets random entropy from the operating system.  The code
   here is very platform and OS dependent and will probably need work to
   port it to new platforms. */

#include "internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(__WIN32__) || defined(WIN32) || defined(__CYGWIN32__)
#include <windows.h>
#include <wincrypt.h>
#else
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#endif

/**
 * \file rand_os.c
 * \brief Access to the system random number generator.
 *
 * This module provides access to the system random number generator for
 * obtaining random data to generate ephemeral keys during a session
 * and static keys for permanent storage.
 *
 * This module will require modification when porting to new systems.
 */

#if defined(linux) || defined(__linux) || defined(__linux__) || defined(__APPLE__)
#define RANDOM_DEVICE   "/dev/urandom"
#endif
#if defined(__WIN32__) || defined(WIN32) || defined(__CYGWIN32__)
#define RANDOM_WIN32    1
#endif

/**
 * \brief Gets cryptographically-strong random bytes from the operating system.
 *
 * \param bytes The buffer to fill with random bytes.
 * \param size The number of random bytes to obtain.
 *
 * This function should not block waiting for entropy.
 *
 * \note Not part of the public API.
 */
void noise_rand_bytes(void *bytes, size_t size)
{
#if defined(RANDOM_DEVICE)
    int fd = open(RANDOM_DEVICE, O_RDONLY);
    if (fd >= 0) {
        for (;;) {
            int len = read(fd, bytes, size);
            if (len == (int)size) {
                /* We have the bytes we wanted */
                close(fd);
                return;
            } else if (len >= 0) {
                /* Short read - this shouldn't happen.  Treat it as "no data" */
                break;
            } else if (errno != EINTR) {
                /* Some other error than "interrupted due to signal" */
                perror(RANDOM_DEVICE);
                break;
            }
        }
        close(fd);
    } else {
        perror(RANDOM_DEVICE);
    }
#elif defined(RANDOM_WIN32)
    /* http://msdn.microsoft.com/en-us/library/windows/desktop/aa379942(v=vs.85).aspx */
    HCRYPTPROV provider = 0;
    memset(bytes, 0, size);
    if (CryptAcquireContextW(&provider, 0, 0, PROV_RSA_FULL,
                             CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        CryptGenRandom(provider, size, bytes);
        CryptReleaseContext(provider, 0);
        return;
    }
#endif
    fprintf(stderr, "Do not know how to generate random numbers!  Abort!\n");
    exit(1);
}

#ifdef ED25519_CUSTOMRANDOM

/* We are building against ed25519-donna, which needs a random function */

void ed25519_randombytes_unsafe(void *p, size_t len)
{
    noise_rand_bytes(p, len);
}

#endif
