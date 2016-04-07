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

#if defined(linux) || defined(__linux) || defined(__linux__)
#define RANDOM_DEVICE   "/dev/urandom"
#endif

/**
 * \def noise_new(type)
 * \brief Allocates a structure from the system and zeroes it.
 *
 * \param type The structure type, which determines the size of the
 * requested block, and the return type.
 *
 * \return Pointer to the allocated memory or NULL if the system is
 * out of memory.
 *
 * \sa noise_calloc(), noise_free()
 */

/**
 * \brief Allocates memory from the system and zeroes it.
 *
 * \param size The number of bytes of memory to allocate.
 *
 * \return Pointer to the allocated memory or NULL if the system is
 * out of memory.
 *
 * \note If the caller is allocating a structure, then noise_new()
 * is a better option to ensure type-safety.
 *
 * \sa noise_new(), noise_free()
 */
void *noise_calloc(size_t size)
{
    return calloc(1, size);
}

/**
 * \brief Destroys the contents of a block of memory and free it.
 *
 * \param ptr Points to the memory to be freed.
 * \param size The number of bytes at \a ptr.
 *
 * \sa noise_calloc()
 */
void noise_free(void *ptr, size_t size)
{
    if (ptr) {
        noise_clean(ptr, size);
        free(ptr);
    }
}

/**
 * \brief Cleans a block of memory to destroy its contents.
 *
 * \param data Points to the block of memory to be cleaned.
 * \param size The size of the block in bytes.
 *
 * This function tries to perform the operation in a way that should
 * work around compilers and linkers that optimize away memset() calls
 * for memory that the compiler thinks is no longer live.
 */
void noise_clean(void *data, size_t size)
{
    volatile uint8_t *d = (volatile uint8_t *)data;
    while (size > 0) {
        *d++ = 0;
        --size;
    }
}

/**
 * \brief Determine if two blocks of memory are equal in constant time.
 *
 * \param s1 Points to the first block of memory.
 * \param s2 Points to the second block of memory.
 * \param size Number of bytes in each block.
 *
 * \return Returns 1 if the blocks are equal, 0 if they are not.
 */
int noise_secure_is_equal(const void *s1, const void *s2, size_t size)
{
    const uint8_t *str1 = (const unsigned char *)s1;
    const uint8_t *str2 = (const unsigned char *)s2;
    uint8_t temp = 0;
    while (size > 0) {
        temp |= *str1 ^ *str2;
        ++str1;
        ++str2;
        --size;
    }
    return (0x0100 - (int)temp) >> 8;
}

/**
 * \brief Gets cryptographically-strong random bytes from the system.
 *
 * \param bytes The buffer to fill with random bytes.
 * \param size The number of random bytes to obtain.
 *
 * This function should not block waiting for entropy.
 */
void noise_rand_bytes(void *bytes, size_t size)
{
#if defined(RANDOM_DEVICE)
    /* Probably should use system calls for this to avoid leaving
     * random data lying around in stdio buffers.  FIXME */
    FILE *file = fopen(RANDOM_DEVICE, "r");
    if (file) {
        if (fread(bytes, 1, size, file) == (int)size) {
            fclose(file);
            return;
        }
        perror(RANDOM_DEVICE);
        fclose(file);
    } else {
        perror(RANDOM_DEVICE);
    }
#endif
    fprintf(stderr, "Don't know how to generate random numbers!  Abort!\n");
    exit(1);
}

/**
 * \brief Maps an algorithm name to the corresponding identifier.
 *
 * \param name The name to be mapped.
 * \param name_len The length of the name in bytes.
 * \param mappings The name mapping table, which must be terminated by an
 * entry with the name field set to NULL.
 *
 * \return Returns the algorithm identifier, or 0 if the \a name is unknown.
 */
int noise_map_name(const char *name, size_t name_len,
                   const NoiseIdMapping *mappings)
{
    while (mappings->name) {
        if (mappings->name_len == name_len &&
                !memcmp(mappings->name, name, name_len)) {
            return mappings->id;
        }
        ++mappings;
    }
    return 0;
}
