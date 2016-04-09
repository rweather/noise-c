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
#include <stdlib.h>

/**
 * \file util.c
 * \brief Internal utilities used to implement the library.
 *
 * \note The definitions in this module are not part of the public API.
 */

/**
 * \def noise_new(type)
 * \brief Allocates an object from the system and initializes it.
 *
 * \param type The structure type, which determines the size of the
 * requested block, and the return type.
 *
 * \return Pointer to the allocated memory or NULL if the system is
 * out of memory.
 *
 * The object is assumed to start with a size_t field, which will be
 * initialized with the size of \a type.  This is intended for use
 * with noise_free() to destroy the object's contents when it is
 * deallocated.
 *
 * \sa noise_new_object(), noise_free()
 */

/**
 * \brief Allocates memory from the system for an object.
 *
 * \param size The number of bytes of memory to allocate for the object.
 *
 * \return Pointer to the allocated memory or NULL if the system is
 * out of memory.
 *
 * If \a size is greater than or equal to sizeof(size_t), then the
 * first few bytes in the returned memory will be set to \a size.
 * That is, the object is assumed to start with a size field.
 * All other bytes in the object are initialized to zero.
 *
 * \note If the caller is allocating a structure, then noise_new()
 * is a better option to ensure type-safety.
 *
 * \sa noise_new(), noise_free()
 */
void *noise_new_object(size_t size)
{
    void *ptr = calloc(1, size);
    if (!ptr || size < sizeof(size_t))
        return ptr;
    *((size_t *)ptr) = size;
    return ptr;
}

/**
 * \brief Destroys the contents of a block of memory and free it.
 *
 * \param ptr Points to the memory to be freed.
 * \param size The number of bytes at \a ptr.
 *
 * \sa noise_new()
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
