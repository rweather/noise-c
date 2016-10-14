/*
 * Copyright (C) 2016 Southern Storm Software, Pty Ltd.
 * Copyright (C) 2016 Topology LP.
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
#if USE_LIBSODIUM
#include <sodium.h>
typedef crypto_hash_sha256_state sha256_context_t;
#define sha256_reset(ctx) crypto_hash_sha256_init(ctx)
#define sha256_update(ctx, pub, pub_len) crypto_hash_sha256_update(ctx, pub, pub_len)
#define sha256_finish(ctx, hash) crypto_hash_sha256_final(ctx, hash)
#else
#include "crypto/sha2/sha256.h"
#endif
#if USE_OPENSSL
#include <openssl/err.h>
#include <openssl/evp.h>
#endif
#include <stdlib.h>
#if HAVE_PTHREAD
#include <pthread.h>
static pthread_once_t noise_is_initialized = PTHREAD_ONCE_INIT;
#endif

/**
 * \file util.h
 * \brief Utility function interface
 */

/**
 * \file util.c
 * \brief Utility function implementation
 */

void noise_init_helper(void)
{
#if USE_LIBSODIUM
    if (sodium_init() < 0)
        return;
#endif
#if USE_OPENSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
#endif
}

/**
 * \defgroup utils Utilities
 *
 * The functions in this module are intended to assist applications that
 * make use of the Noise protocol library.
 *
 * The noise_clean() function is probably the most useful function here.
 * It zeroes the contents of a buffer in a way that the compiler will
 * hopefully not optimize away like it might optimize memset().
 */
/**@{*/

/**
 * \fn noise_init()
 * \brief Initializes the Noise-c library.
 *
 * \return NOISE_ERROR_NONE on success.
 *
 * This will initialize the underlying crypto libraries.
 * You don't need to call this if you initialize the crypto libraries (eg. libsodium, OpenSSL) yourself.
 */
int noise_init(void)
{
#if HAVE_PTHREAD
    if (pthread_once(&noise_is_initialized, noise_init_helper) != 0)
        return NOISE_ERROR_SYSTEM;
#else
    noise_init_helper();
#endif

    return NOISE_ERROR_NONE;
}

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
 * deallocated.  The remaining bytes are initialized to zero.
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
 * The remaining bytes in the object are initialized to zero.
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
int noise_is_equal(const void *s1, const void *s2, size_t size)
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
 * \brief Determine if a block of memory consists of all zero bytes.
 *
 * \param data Points to the block of memory.
 * \param size The length of the \a data in bytes.
 *
 * \return Returns 1 if all bytes of \a data are zero, or 0 if any of the
 * bytes are non-zero.
 */
int noise_is_zero(const void *data, size_t size)
{
    const uint8_t *d = (const uint8_t *)data;
    uint8_t temp = 0;
    while (size > 0) {
        temp |= *d++;
        --size;
    }
    return (0x0100 - (int)temp) >> 8;
}

/**
 * \brief Formats the fingerprint for a raw public key value.
 *
 * \param fingerprint_type The type of fingerprint to format,
 * NOISE_FINGERPRINT_BASIC or NOISE_FINGERPRINT_FULL.
 * \param buffer The buffer to write the fingerprint string to, including a
 * terminating NUL.
 * \param len The length of \a buffer in bytes.
 * \param public_key Points to the public key to be formatted.
 * \param public_key_len Length of the \a public_key in bytes.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a buffer or \a public_key is NULL.
 * \return NOISE_ERROR_INVALID_PARAM if \a fingerprint_type is not a
 * supported fingerprint type.
 * \return NOISE_ERROR_INVALID_LENGTH if \a len is not large enough to
 * hold the entire fingerprint string.
 *
 * This is a low-level formatting function.  It is usually better to
 * call one of noise_dhstate_format_fingerprint(),
 * noise_signstate_format_fingerprint(), or noise_keystate_format_fingerprint()
 * instead.
 */
int noise_format_fingerprint
    (int fingerprint_type, char *buffer, size_t len,
     const uint8_t *public_key, size_t public_key_len)
{
    static char const hexchars[] = "0123456789abcdef";
    sha256_context_t sha256;
    uint8_t hash[32];
    size_t f_len;
    size_t posn;

    /* Validate the parameters */
    if (!buffer)
        return NOISE_ERROR_INVALID_PARAM;
    if (!len)
        return NOISE_ERROR_INVALID_LENGTH;
    *buffer = '\0'; /* In case we bail out with an error later */
    if (!public_key)
        return NOISE_ERROR_INVALID_PARAM;

    /* Validate the fingerprint type and get the desired length */
    if (fingerprint_type == NOISE_FINGERPRINT_BASIC)
        f_len = 16;
    else if (fingerprint_type == NOISE_FINGERPRINT_FULL)
        f_len = 32;
    else
        return NOISE_ERROR_INVALID_PARAM;

    /* Check the length of the buffer */
    if ((f_len * 3) > len)
        return NOISE_ERROR_INVALID_LENGTH;

    /* Hash the public key with SHA256 */
    sha256_reset(&sha256);
    sha256_update(&sha256, public_key, public_key_len);
    sha256_finish(&sha256, hash);
    noise_clean(&sha256, sizeof(sha256));

    /* Format the fingerprint in hexadecimal within the buffer */
    for (posn = 0; posn < f_len; ++posn) {
        uint8_t byte = hash[posn];
        buffer[posn * 3] = hexchars[(byte >> 4) & 0x0F];
        buffer[posn * 3 + 1] = hexchars[byte & 0x0F];
        buffer[posn * 3 + 2] = ':';
    }
    buffer[f_len * 3 - 1] = '\0';
    noise_clean(hash, sizeof(hash));
    return NOISE_ERROR_NONE;
}

/**@}*/
