/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

#include "barrett_field.h"
#include <string.h>
#include <assert.h>

word_t
add_nr_ext_packed(
    word_t *out,
    const word_t *a,
    uint32_t nwords_a,
    const word_t *c,
    uint32_t nwords_c,
    word_t mask
) {
    uint32_t i;
    dword_t carry = 0;
    for (i=0; i<nwords_c; i++) {
        out[i] = carry = carry + a[i] + (c[i]&mask);
        carry >>= WORD_BITS;
    }
    for (; i<nwords_a; i++) {
        out[i] = carry = carry + a[i];
        carry >>= WORD_BITS;
    }
    return carry;
}

static __inline__ word_t
add_nr_packed(
    word_t *a,
    const word_t *c,
    uint32_t nwords
) {
    uint32_t i;
    dword_t carry = 0;
    for (i=0; i<nwords; i++) {
        a[i] = carry = carry + a[i] + c[i];
        carry >>= WORD_BITS;
    }
    return carry;
}

word_t
sub_nr_ext_packed(
    word_t *out,
    const word_t *a,
    uint32_t nwords_a,
    const word_t *c,
    uint32_t nwords_c,
    word_t mask
) {
    uint32_t i;
    dsword_t carry = 0;
    for (i=0; i<nwords_c; i++) {
        out[i] = carry = carry + a[i] - (c[i]&mask);
        carry >>= WORD_BITS;
    }
    for (; i<nwords_a; i++) {
        out[i] = carry = carry + a[i];
        carry >>= WORD_BITS;
    }
    return carry;
}

static word_t
widemac(
    word_t *accum,
    uint32_t nwords_accum,
    const word_t *mier,
    uint32_t nwords_mier,
    word_t mand,
    word_t carry
) {
    uint32_t i;
    assert(nwords_mier <= nwords_accum);
    
    for (i=0; i<nwords_mier; i++) {
#ifdef __clang_analyzer__
        /* always true, but this satisfies scan-build (bug in scan-build?) */
        assert(i<nwords_accum);
#endif
        /* UMAAL chain for the wordy part of p */
        dword_t product = ((dword_t)mand) * mier[i];
        product += accum[i];
        product += carry;
        accum[i] = product;
        carry = product >> WORD_BITS;
    }
    
    for (; i<nwords_accum; i++) {
        dword_t sum = ((dword_t)carry) + accum[i];
        accum[i] = sum;
        carry = sum >> WORD_BITS;
    }
    
    return carry;
}

void
barrett_negate (
    word_t *a,
    uint32_t nwords_a,
    const struct barrett_prime_t *prime
) {
    uint32_t i;
    dsword_t carry = 0;
    
    barrett_reduce(a,nwords_a,0,prime);
    
    /* Have p = 2^big - p_lo.  Want p - a = 2^big - p_lo - a */
    
    for (i=0; i<prime->nwords_lo; i++) {
        a[i] = carry = carry - prime->p_lo[i] - a[i];
        carry >>= WORD_BITS;
    }
    for (; i<prime->nwords_p; i++) {
        a[i] = carry = carry - a[i];
        if (i<prime->nwords_p-1) {
            carry >>= WORD_BITS;
        }
    }
    
    a[prime->nwords_p-1] = carry = carry + (((word_t)1) << prime->p_shift);
    
    for (; i<nwords_a; i++) {
        assert(!a[i]);
    }
    
    assert(!(carry>>WORD_BITS));
}

void
barrett_reduce(
    word_t *a,
    uint32_t nwords_a,
    word_t a_carry,
    const struct barrett_prime_t *prime
) {
    uint32_t repeat, nwords_left_in_a=nwords_a;
    
    /* Is there a point to this a_carry business? */
    assert(a_carry < ((word_t)1) << prime->p_shift);
    assert(nwords_a >= prime->nwords_p);
    assert(prime->nwords_p > 0); /* scan-build: prevent underflow */
    
    for (; nwords_left_in_a >= prime->nwords_p; nwords_left_in_a--) {
        for (repeat=0; repeat<2; repeat++) {
            /* PERF: surely a more careful implementation could
             * avoid this double round
             */
            word_t mand = a[nwords_left_in_a-1] >> prime->p_shift;
            a[nwords_left_in_a-1] &= (((word_t)1)<<prime->p_shift)-1;
            if (prime->p_shift && !repeat) {
                /* collect high bits when there are any */
                if (nwords_left_in_a < nwords_a) {
                    mand |= a[nwords_left_in_a] << (WORD_BITS-prime->p_shift);
                    a[nwords_left_in_a] = 0;
                } else {
                    mand |= a_carry << (WORD_BITS-prime->p_shift);
                }
            }
            
            word_t carry = widemac(
                a+nwords_left_in_a-prime->nwords_p,
                prime->nwords_p,
                prime->p_lo,
                prime->nwords_lo,
                mand,
                0
            );
            assert(!carry);
            (void)carry;
        }
    }
    
    assert(nwords_left_in_a == prime->nwords_p-1);
    
    /* OK, but it still isn't reduced.  Add and subtract p_lo. */
    word_t cout = add_nr_ext_packed(a,a,prime->nwords_p,prime->p_lo,prime->nwords_lo,-1);
    if (prime->p_shift) {
        cout = (cout<<(WORD_BITS-prime->p_shift)) + (a[prime->nwords_p-1]>>prime->p_shift);
        a[prime->nwords_p-1] &= (((word_t)1)<<prime->p_shift)-1;
    }
    
    /* mask = carry-1: if no carry then do sub, otherwise don't */
    sub_nr_ext_packed(a,a,prime->nwords_p,prime->p_lo,prime->nwords_lo,cout-1);
}

/* PERF: This function is horribly slow.  Enough to break 1%. */
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
) {
    assert(nwords_accum >= prime->nwords_p);
    
    /* nwords_tmp = max(nwords_a + 1, nwords_p + 1, nwords_accum if doMac); */
    uint32_t nwords_tmp = (nwords_a > prime->nwords_p) ? nwords_a : prime->nwords_p;
    nwords_tmp++;
    assert(nwords_tmp > 0); /* scan-build: prevent underflow. */
    if (nwords_tmp < nwords_accum && doMac)
        nwords_tmp = nwords_accum;
    
    word_t tmp[nwords_tmp];
    int bpos, idown;
    uint32_t i;
    
    for (i=0; i<nwords_tmp; i++) {
        tmp[i] = 0;
    }
    
    for (bpos=nwords_b-1; bpos >= 0; bpos--) {
        /* Invariant at the beginning of the loop: the high word is unused. */
        assert(tmp[nwords_tmp-1] == 0);
        
        /* shift up */
        for (idown=nwords_tmp-2; idown>=0; idown--) {
            tmp[idown+1] = tmp[idown];
        }
        tmp[0] = 0;

        /* mac and reduce */
        word_t carry = widemac(tmp, nwords_tmp, a, nwords_a, b[bpos], 0);
        
        /* the mac can't carry, because nwords_tmp >= nwords_a+1 and its high word is clear */
        assert(!carry);
        barrett_reduce(tmp, nwords_tmp, carry, prime);
        
        /* at this point, the number of words used is nwords_p <= nwords_tmp-1,
         * so the high word is again clear */
    }
    
    if (doMac) {
        word_t cout = add_nr_packed(tmp, accum, nwords_accum);
        barrett_reduce(tmp, nwords_tmp, cout, prime);
    }
    
    for (i=0; i<nwords_tmp && i<nwords_accum; i++) {
        accum[i] = tmp[i];
    }
    for (; i<nwords_tmp; i++) {
        assert(tmp[i] == 0);
    }
    for (; i<nwords_accum; i++) {
        accum[i] = 0;
    }
}
mask_t
barrett_deserialize (
    word_t *x,
    const uint8_t *serial,
    const struct barrett_prime_t *prime
) {
    unsigned int i,j,nserial = prime->nwords_p * sizeof(word_t);
    if (prime->p_shift) {
        nserial -= (WORD_BITS - prime->p_shift) / 8;
    }

    
    /* Track x < p, p = 2^k - p_lo <==> x + p_lo < 2^k */
    dword_t carry = 0;
    
    for (i=0; i*sizeof(word_t)<nserial; i++) {
        carry >>= WORD_BITS;
        
        word_t the = 0;
        for (j=0; j<sizeof(word_t) && sizeof(word_t)*i+j < nserial; j++) {
            the |= ((word_t)serial[sizeof(word_t)*i+j]) << (8*j);
        }
        x[i] = the;
        
        carry += the;
        if (i < prime->nwords_lo) carry += prime->p_lo[i];
    }
    
    /* check for reduction */
    if (prime->p_shift) {
        carry >>= prime->p_shift;
    } else {
        carry >>= WORD_BITS;
    }
    
    /* at this point, carry > 0 indicates failure */
    dsword_t scarry = carry;
    scarry = -scarry;
    scarry >>= WORD_BITS;
    scarry >>= WORD_BITS;
    
    return (mask_t) ~scarry;
}
    
void
barrett_deserialize_and_reduce (
    word_t *x,
    const uint8_t *serial,
    uint32_t nserial,
    const struct barrett_prime_t *prime
) {
    unsigned int size = (nserial + sizeof(word_t) - 1)/sizeof(word_t);
    if (size < prime->nwords_p) {
        size = prime->nwords_p;
    }
    word_t tmp[size];
    memset(tmp,0,sizeof(tmp));
    
    unsigned int i,j;
    for (i=0; i*sizeof(word_t)<nserial; i++) {
        word_t the = 0;
        for (j=0; j<sizeof(word_t) && sizeof(word_t)*i+j < nserial; j++) {
            the |= ((word_t)serial[sizeof(word_t)*i+j]) << (8*j);
        }
        tmp[i] = the;
    }
    
    barrett_reduce(tmp,size,0,prime);
    for (i=0; i<prime->nwords_p; i++) {
        x[i] = tmp[i];
    }
    for (; i<size; i++) {
        assert(!tmp[i]);
    }
}

void
barrett_serialize (
    uint8_t *serial,
    const word_t *x,
    uint32_t nserial
) {
    unsigned int i,j;
    for (i=0; i*sizeof(word_t)<nserial; i++) {
        for (j=0; j<sizeof(word_t); j++) {
            serial[sizeof(word_t)*i+j] = x[i]>>(8*j);
        }
    }
}
