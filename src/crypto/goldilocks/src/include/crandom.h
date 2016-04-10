/* Copyright (c) 2011 Stanford University.
 * Copyright (c) 2014-2015 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

/**
 * @file crandom.h
 * @author Mike Hamburg
 * @brief A miniature version of the (as of yet incomplete) crandom project.
 */

#ifndef __GOLDI_CRANDOM_H__
#define __GOLDI_CRANDOM_H__ 1

#define _XOPEN_SOURCE 600
#include <stdint.h>  /* for uint64_t */
#include <fcntl.h>   /* for open */
#include <errno.h>   /* for returning errors after open */
#include <stdlib.h>  /* for abort */
#include <string.h>  /* for memcpy */
#include <strings.h> /* for bzero */
#include <unistd.h>  /* for read */

/**
 * @brief The state of a crandom generator.
 *
 * This object is opaque.  It is not protected by a lock, and so must
 * not be accessed by multiple threads at the same time.
 */
struct crandom_state_t {
    /** @privatesection */
    /* unsigned char seed[32]; */
    /* unsigned char buffer[96]; */
    unsigned char seedBuffer[32+96];
    uint64_t ctr;
    uint64_t magic;
    unsigned int fill;
    int reseed_countdown;
    int reseed_interval;
    int reseeds_mandatory;
    int randomfd;
} __attribute__((aligned(16))) ;
typedef struct crandom_state_t crandom_state_a_t[1];

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize a crandom state from the chosen file.
 * 
 * This function initializes a state from a given state file, or
 * from a random device (eg. /dev/random or /dev/urandom).
 *
 * You must check the return value of this function.
 *
 * @param [out] state The crandom state variable to initalize.
 * @param [in] filename The name of the seed file or random device.
 * @param [in] reseed_interval The number of 96-byte blocks which can be
 *        generated without reseeding.  Suggest 10000.
 * @param [in] reseeds_mandatory If nonzero, call abort() if a reseed fails.
 *        Suggest 1.
 *
 * @retval 0 Success.
 * @retval Nonzero An error to be interpreted by strerror().
 */
int
crandom_init_from_file (
    crandom_state_a_t state,
    const char *filename,
    int reseed_interval,
    int reseeds_mandatory
) __attribute__((warn_unused_result));


/**
 * Initialize a crandom state from a buffer, for deterministic operation.
 * 
 * This function is used to initialize a crandom state deterministically,
 * mainly for testing purposes.  It can also be used to expand a secret
 * random value deterministically.
 *
 * @warning The crandom implementation is not guaranteed to be stable.
 * That is, a later release might produce a different random stream from
 * the same seed.
 *
 * @param [out] state The crandom state variable to initalize.
 * @param [in] initial_seed The seed value.
 */
void
crandom_init_from_buffer (
    crandom_state_a_t state,
    const char initial_seed[32]
);

/**
 * Fill the output buffer with random data.
 *
 * This function uses the given crandom state to produce pseudorandom data
 * in the output buffer.
 *
 * This function may perform reads from the state's random device if it needs
 * to reseed.  This could block if that file is a blocking source, such as
 * a pipe or /dev/random on Linux.  If reseeding fails and the state has
 * reseeds_mandatory set, this function will call abort().  Otherwise, it will
 * return an error code, but it will still randomize the buffer.
 *
 * If called on a corrupted, uninitialized or destroyed state, this function
 * will abort().
 *
 * @warning This function is not thread-safe with respect to the state.  Don't
 * call it from multiple threads with the same state at the same time.
 *
 * @param [inout] state The crandom state to use for generation.
 * @param [out] output The buffer to fill with random data.
 * @param [in] length The length of the buffer.
 *
 * @retval 0 Success.
 * @retval Nonezero A non-mandatory reseed operation failed.
 */
int
crandom_generate (
    crandom_state_a_t state,
    unsigned char *output,
    unsigned long long length
);

/**
 * Destroy the random state.  Further calls to crandom_generate() on that state
 * will abort().
 *
 * @param [inout] state The state to be destroyed.
 */
void
crandom_destroy (
    crandom_state_a_t state
);

#ifdef __cplusplus
}; /* extern "C" */
#endif

#endif /* __GOLDI_CRANDOM_H__ */
