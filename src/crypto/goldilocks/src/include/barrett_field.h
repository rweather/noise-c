/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */
#ifndef __BARRETT_FIELD_H__
#define __BARRETT_FIELD_H__ 1

/**
 * @file barrett_field.h
 * @brief Slow routines for generic primes in Barrett form.
 *
 * @warning These routines are very slow, roughly implemented, and should be made more
 * flexible in the future.  I might even outright switch to Montgomery form.
 */

#include "word.h"

#ifdef __cplusplus
extern "C" {
#endif
    
/**
 * @brief A Barrett-form prime, 2^k - c.
 * @todo Support primes of other forms.
 */
struct barrett_prime_t {
    uint32_t nwords_p;   /**< The number of bits in p, i.e. ceiling((k-1) / WORD_BITS) */
    uint32_t p_shift;    /**< c mod WORD_BITS. */
    uint32_t nwords_lo;  /**< The number of nonzero low words. */
    const word_t *p_lo;  /**< The low words. */
};

/**
 * The Goldilocks prime.  I'm not sure this is the right place for it, but oh well.
 */
extern const struct barrett_prime_t curve_prime_order;

/**
 * Reduce a number (with optional high carry word) mod p.
 *
 * @param [in,out] a The value to be reduced.
 * @param [in] nwords_a The number of words in a.
 * @param [in] a_carry A high word to be carried into the computation.
 * @param [in] prime The Barrett prime.
 */
void
barrett_reduce(
    word_t *a,
    uint32_t nwords_a,
    word_t a_carry,
    const struct barrett_prime_t *prime
);
    
/**
 * out = a+(c&mask), returning a carry.
 *
 * @param [out] out The output, of length nwords_a.
 * @param [in] a The "always" addend.
 * @param [in] nwords_a The number of words in a.
 * @param [in] c The "sometimes" addend.
 * @param [in] nwords_c The number of words in c.
 * @param [in] mask A mask of whether to add or not.
 * @return A carry word.
 */
word_t
add_nr_ext_packed(
    word_t *out,
    const word_t *a,
    uint32_t nwords_a,
    const word_t *c,
    uint32_t nwords_c,
    word_t mask
);
  
/**
 * out = a-(c&mask), returning a borrow.
 *
 * @param [out] out The output, of length nwords_a.
 * @param [in] a The "always" minuend.
 * @param [in] nwords_a The number of words in a.
 * @param [in] c The "sometimes" subtrahend.
 * @param [in] nwords_c The number of words in c.
 * @param [in] mask A mask of whether to add or not.
 * @return A borrow word.
 */  
word_t
sub_nr_ext_packed(
    word_t *out,
    const word_t *a,
    uint32_t nwords_a,
    const word_t *c,
    uint32_t nwords_c,
    word_t mask
);

/**
 * a -> reduce(-a) mod p
 *
 * @param [in] a The value to be reduced and negated.
 * @param [in] nwords_a The number of words in a.  Must be >= nwords_p.
 * @param [in] prime The prime.
 */   
void
barrett_negate (
    word_t *a,
    uint32_t nwords_a,
    const struct barrett_prime_t *prime
);

/*
 * If doMac, accum = accum + a*b mod p.
 * Otherwise, accum = a*b mod p.
 *
 * This function is not __restrict__; you may pass accum,
 * a, b, etc all from the same location.
 */
void
barrett_mul_or_mac(
    word_t *accum,
    uint32_t nwords_accum,

    const word_t *a,
    uint32_t nwords_a,

    const word_t *b,
    uint32_t nwords_b,

    const struct barrett_prime_t *prime,
    
    mask_t doMac
);
    
static inline void
barrett_mul(
    word_t *out,
    uint32_t nwords_out,

    const word_t *a,
    uint32_t nwords_a,

    const word_t *b,
    uint32_t nwords_b,

    const struct barrett_prime_t *prime
) {
    barrett_mul_or_mac(out,nwords_out,a,nwords_a,b,nwords_b,prime,0);
}
    
static inline void
barrett_mac(
    word_t *out,
    uint32_t nwords_out,

    const word_t *a,
    uint32_t nwords_a,

    const word_t *b,
    uint32_t nwords_b,

    const struct barrett_prime_t *prime
) {
    barrett_mul_or_mac(out,nwords_out,a,nwords_a,b,nwords_b,prime,-(mask_t)1);
}

mask_t
barrett_deserialize (
    word_t *x,
    const uint8_t *serial,
    const struct barrett_prime_t *prime
);

void
barrett_serialize (
    uint8_t *serial,
    const word_t *x,
    uint32_t nserial
);
    
void
barrett_deserialize_and_reduce (
    word_t *x,
    const uint8_t *serial,
    uint32_t nserial,
    const struct barrett_prime_t *prime
);

#ifdef __cplusplus
}; /* extern "C" */
#endif

#endif /* __BARRETT_FIELD_H__ */
