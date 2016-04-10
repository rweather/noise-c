/**
 * @file magic.h
 * @copyright
 *   Copyright (c) 2014 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief Curve-independent declarations of magic numbers.
 */

#ifndef __GOLDI_MAGIC_H__
#define __GOLDI_MAGIC_H__ 1

#include "word.h"

/**
 * @brief If true, use wider tables for the precomputed combs.
 */
#ifndef USE_BIG_COMBS
#if defined(__ARM_NEON__)
#define USE_BIG_COMBS 1
#else
#define USE_BIG_COMBS (WORD_BITS==64)
#endif
#endif

/* TODO: standardize notation */

/** @brief The number of words in the Goldilocks field. */
#define GOLDI_FIELD_WORDS DIV_CEIL(FIELD_BITS,WORD_BITS)

/** @brief The number of bits in the Goldilocks curve's cofactor (cofactor=4). */
#define COFACTOR_BITS 2

/** @brief The number of bits in a Goldilocks scalar. */
#define SCALAR_BITS (FIELD_BITS - COFACTOR_BITS)

/** @brief The number of bytes in a Goldilocks scalar. */
#define SCALAR_BYTES (1+(SCALAR_BITS)/8)

/** @brief The number of words in the Goldilocks field. */
#define SCALAR_WORDS WORDS_FOR_BITS(SCALAR_BITS)

#include "f_magic.h"

/**
 * @brief sqrt(d-1), used for point formats and twisting.
 */
extern const field_a_t sqrt_d_minus_1;

/**
 * @brief The base point for Goldilocks.
 */
extern const affine_a_t goldilocks_base_point;

/**
 * @brief The Goldilocks prime subgroup order.
 */ 
extern const struct barrett_prime_t curve_prime_order;

/**
 * @brief Window size for fixed-window signed binary scalarmul.
 * Table size is 2^(this - 1).
 */
#define SCALARMUL_FIXED_WINDOW_SIZE 5

/**
 * @brief Even/odd adjustments for fixed window with
 * ROUNDUP(SCALAR_BITS,SCALARMUL_FIXED_WINDOW_SIZE).
 */
extern const word_t SCALARMUL_FIXED_WINDOW_ADJUSTMENT[2*SCALAR_WORDS];

/**
 * @brief Table size for wNAF signed binary (variable-time) scalarmul.
 * Table size is 2^this.
 */
#define SCALARMUL_WNAF_TABLE_BITS 3

/**
 * @brief Table size for wNAF signed binary (variable-time) linear combo.
 * Table size is 2^this.
 */
#define SCALARMUL_WNAF_COMBO_TABLE_BITS 4

/**
 * @brief The bit width of the precomputed WNAF tables.  Size is 2^this elements.
 */
#define WNAF_PRECMP_BITS 5

/**
 * @brief crandom magic structure guard constant = "return 4", cf xkcd #221
 */
#define CRANDOM_MAGIC 0x72657475726e2034ull


#endif /* __GOLDI_MAGIC_H__ */
