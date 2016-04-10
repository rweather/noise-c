/**
 * @file field.h
 * @brief Generic field header.
 * @copyright
 *   Copyright (c) 2014 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 */

#ifndef __FIELD_H__
#define __FIELD_H__

#include "constant_time.h"
#include "f_field.h"
#include <string.h>

typedef struct field_t field_a_t[1];
#define field_a_restrict_t struct field_t *__restrict__

#define is32 (GOLDI_BITS == 32 || FIELD_BITS != 448)
#if (is32)
#define IF32(s) (s)
#else
#define IF32(s)
#endif

/** @brief Bytes in a field element */
#define FIELD_BYTES          (1+(FIELD_BITS-1)/8)

/** @brief Words in a field element */
#define FIELD_WORDS          (1+(FIELD_BITS-1)/sizeof(word_t))

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

/**
 * @brief For GMP tests: little-endian representation of the field modulus.
 */
extern const uint8_t FIELD_MODULUS[FIELD_BYTES];

/**
 * Copy one field element to another.
 */
static inline void
__attribute__((unused,always_inline))        
field_copy (
    field_a_restrict_t a,
    const field_a_restrict_t b
) {
    memcpy(a,b,sizeof(*a));
}

/**
 * Returns 1/sqrt(+- x).
 * 
 * The Legendre symbol of the result is the same as that of the
 * input.
 * 
 * If x=0, returns 0.
 */
void
field_isr (
    field_a_t       a,
    const field_a_t x
);
    
/**
 * Batch inverts out[i] = 1/in[i]
 * 
 * If any input is zero, all the outputs will be zero.
 */     
void
field_simultaneous_invert (
    field_a_t *__restrict__ out,
    const field_a_t *in,
    unsigned int n
);

/**
 * Returns 1/x.
 * 
 * If x=0, returns 0.
 */
void
field_inverse (
    field_a_t       a,
    const field_a_t x
);

/**
 * Returns -1 if a==b, 0 otherwise.
 */
mask_t
field_eq (
    const field_a_t a,
    const field_a_t b
);
    
/**
 * Square x, n times.
 */
static __inline__ void
__attribute__((unused,always_inline))
field_sqrn (
    field_a_restrict_t y,
    const field_a_t x,
    int n
) {
    field_a_t tmp;
    assert(n>0);
    if (n&1) {
        field_sqr(y,x);
        n--;
    } else {
        field_sqr(tmp,x);
        field_sqr(y,tmp);
        n-=2;
    }
    for (; n; n-=2) {
        field_sqr(tmp,y);
        field_sqr(y,tmp);
    }
}

/* Multiply by signed curve constant */
static __inline__ void
field_mulw_scc (
    field_a_restrict_t out,
    const field_a_t a,
    int64_t scc
) {
    if (scc >= 0) {
        field_mulw(out, a, scc);
    } else {
        field_mulw(out, a, -scc);
        field_neg_RAW(out,out);
        field_bias(out,2);
    }
}

/* Multiply by signed curve constant and weak reduce if biased */
static __inline__ void
field_mulw_scc_wr (
    field_a_restrict_t out,
    const field_a_t a,
    int64_t scc
) {
    field_mulw_scc(out, a, scc);
    if (scc < 0)
        field_weak_reduce(out);
}

static __inline__ void
field_subx_RAW (
    field_a_t d,
    const field_a_t a,
    const field_a_t b
) {
    field_sub_RAW ( d, a, b );
    field_bias( d, 2 );
    IF32( field_weak_reduce ( d ) );
}

static __inline__ void
field_sub (
    field_a_t d,
    const field_a_t a,
    const field_a_t b
) {
    field_sub_RAW ( d, a, b );
    field_bias( d, 2 );
    field_weak_reduce ( d );
}

static __inline__ void
field_add (
    field_a_t d,
    const field_a_t a,
    const field_a_t b
) {
    field_add_RAW ( d, a, b );
    field_weak_reduce ( d );
}

static __inline__ void
field_subw (
    field_a_t d,
    word_t c
) {
    field_subw_RAW ( d, c );
    field_bias( d, 1 );
    field_weak_reduce ( d );
}

static __inline__ void
field_neg (
    field_a_t d,
    const field_a_t a
) {
    field_neg_RAW ( d, a );
    field_bias( d, 2 );
    field_weak_reduce ( d );
}

/**
 * Negate a in place if doNegate.
 */
static inline void
__attribute__((unused,always_inline)) 
field_cond_neg (
    field_a_t a,
    mask_t doNegate
) {
	field_a_t negated;
    field_neg(negated, a);
	constant_time_select(a, negated, a, sizeof(negated), doNegate);
}

/** Require the warning annotation on raw routines */
#define ANALYZE_THIS_ROUTINE_CAREFULLY const int ANNOTATE___ANALYZE_THIS_ROUTINE_CAREFULLY = 0;
#define MUST_BE_CAREFUL (void) ANNOTATE___ANALYZE_THIS_ROUTINE_CAREFULLY
#define field_add_nr(a,b,c) { MUST_BE_CAREFUL; field_add_RAW(a,b,c); }
#define field_sub_nr(a,b,c) { MUST_BE_CAREFUL; field_sub_RAW(a,b,c); }
#define field_subx_nr(a,b,c) { MUST_BE_CAREFUL; field_subx_RAW(a,b,c); }

#endif // __FIELD_H__
