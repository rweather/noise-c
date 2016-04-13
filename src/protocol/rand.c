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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

/**
 * \file rand.c
 * \brief Access to the system random number generator.
 *
 * This module provides access to the system random number generator for
 * obtaining random data to generate ephemeral keys during a session
 * and static keys for permanent storage.
 *
 * This module will require modification when porting to new systems.
 */

#if defined(linux) || defined(__linux) || defined(__linux__)
#define RANDOM_DEVICE   "/dev/urandom"
#endif

/**
 * \brief Gets cryptographically-strong random bytes from the system.
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
    } else {
        perror(RANDOM_DEVICE);
    }
#endif
    fprintf(stderr, "Do not know how to generate random numbers!  Abort!\n");
    exit(1);
}
