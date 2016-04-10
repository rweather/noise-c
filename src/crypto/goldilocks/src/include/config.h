/**
 * @file config.h
 * @copyright
 *   Copyright (c) 2014 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief Goldilocks top-level configuration flags.
 */

#ifndef __GOLDILOCKS_CONFIG_H__
#define __GOLDILOCKS_CONFIG_H__ 1

/** @brief crandom architecture detection.
 * With this flag set to 1, crandom will assume that any flag
 * supported by -march and friends (MIGHT_HAVE) will actually
 * be available on the target machine (MUST_HAVE), instead of
 * trying to detect it.
 *
 * Without this flag, crandom can detect, eg, that while -mavx
 * was passed, the currint machine doesn't support AVX, and can
 * fall back to SSE2 or whatever.  But the rest of the
 * Goldilocks code doesn't support this, so it'll still crash
 * with an illegal instruction error.
 *
 * Setting this flag will make the library smaller.
 */
#define CRANDOM_MIGHT_IS_MUST           1

/**
 * @brief Causes crandom to refuse to buffer requests bigger
 * than this size.  Setting 0 disables buffering for all
 * requests, which hurts performance.
 *
 * The advantage is that if a user process forks or is VM-
 * snapshotted, the buffer is not adjusted (FUTURE).  However,
 * with the buffer disabled, the refresh routines will stir
 * in entropy from RDTSC and/or RDRAND, making this operation
 * mostly-safe.
 */
#define EXPERIMENT_CRANDOM_BUFFER_CUTOFF_BYTES 0

/**
 * @brief Goldilocks uses libpthread mutexes to provide
 * thread-safety.  If you disable this flag, it won't link
 * libpthread, but it won't be thread-safe either.
 */
#define GOLDILOCKS_USE_PTHREAD          1

/**
 * @brief Experiment to change the hash inputs for ECDH,
 * in a way that obliterates the result -- overwriting it with
 * a safe pseudorandom value -- if the public key is invalid.
 * That way users who ignore the status result won't be
 * exposed to invalid key attacks. 
 */
#define EXPERIMENT_ECDH_OBLITERATE_CT   1

/**
 * @brief Whether or not define the signing functions, which
 * currently require SHA-512.
 */
#define GOLDI_IMPLEMENT_SIGNATURES      1

/**
 * @brief Whether or not to define and implement functions
 * working with pre-computed keys.
 */
#define GOLDI_IMPLEMENT_PRECOMPUTED_KEYS 1

/**
 * @brief ECDH adds public keys into the hash, to prevent
 * esoteric attacks.
 */
#define EXPERIMENT_ECDH_STIR_IN_PUBKEYS 1

#endif /* __GOLDILOCKS_CONFIG_H__ */
