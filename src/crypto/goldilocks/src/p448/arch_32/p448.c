/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

#include "word.h"
#include "p448.h"

static inline mask_t __attribute__((always_inline))
is_zero (
    word_t x
) {
    dword_t xx = x;
    xx--;
    return xx >> WORD_BITS;
}

static uint64_t widemul_32 (
    const uint32_t a,
    const uint32_t b
) {
    return ((uint64_t)a)* b;
}

void
p448_mul (
    p448_t *__restrict__ cs,
    const p448_t *as,
    const p448_t *bs
) { 
    const uint32_t *a = as->limb, *b = bs->limb;
    uint32_t *c = cs->limb;

    uint64_t accum0 = 0, accum1 = 0, accum2 = 0;
    uint32_t mask = (1<<28) - 1;  

    uint32_t aa[8], bb[8];
    
    int i,j;
    for (i=0; i<8; i++) {
        aa[i] = a[i] + a[i+8];
        bb[i] = b[i] + b[i+8];
    }
    
    for (j=0; j<8; j++) {
        accum2 = 0;
    
        for (i=0; i<=j; i++) {      
            accum2 += widemul_32(a[j-i],b[i]);
            accum1 += widemul_32(aa[j-i],bb[i]);
            accum0 += widemul_32(a[8+j-i], b[8+i]);
        }
        
        accum1 -= accum2;
        accum0 += accum2;
        accum2 = 0;
        
        for (; i<8; i++) {
            accum0 -= widemul_32(a[8+j-i], b[i]);
            accum2 += widemul_32(aa[8+j-i], bb[i]);
            accum1 += widemul_32(a[16+j-i], b[8+i]);
        }

        accum1 += accum2;
        accum0 += accum2;

        c[j] = ((uint32_t)(accum0)) & mask;
        c[j+8] = ((uint32_t)(accum1)) & mask;

        accum0 >>= 28;
        accum1 >>= 28;
    }
    
    accum0 += accum1;
    accum0 += c[8];
    accum1 += c[0];
    c[8] = ((uint32_t)(accum0)) & mask;
    c[0] = ((uint32_t)(accum1)) & mask;
    
    accum0 >>= 28;
    accum1 >>= 28;
    c[9] += ((uint32_t)(accum0));
    c[1] += ((uint32_t)(accum1));
}

void
p448_mulw (
    p448_t *__restrict__ cs,
    const p448_t *as,
    uint64_t b
) {
    const uint32_t bhi = b>>28, blo = b & ((1<<28)-1);
    
    const uint32_t *a = as->limb;
    uint32_t *c = cs->limb;

    uint64_t accum0, accum8;
    uint32_t mask = (1ull<<28)-1;  

    int i;

    accum0 = widemul_32(blo, a[0]);
    accum8 = widemul_32(blo, a[8]);
    accum0 += widemul_32(bhi, a[15]);
    accum8 += widemul_32(bhi, a[15] + a[7]);

    c[0] = accum0 & mask; accum0 >>= 28;
    c[8] = accum8 & mask; accum8 >>= 28;
    
    for (i=1; i<8; i++) {
        accum0 += widemul_32(blo, a[i]);
        accum8 += widemul_32(blo, a[i+8]);
        
        accum0 += widemul_32(bhi, a[i-1]);
        accum8 += widemul_32(bhi, a[i+7]);

        c[i] = accum0 & mask; accum0 >>= 28;
        c[i+8] = accum8 & mask; accum8 >>= 28;
    }

    accum0 += accum8 + c[8];
    c[8] = accum0 & mask;
    c[9] += accum0 >> 28;

    accum8 += c[0];
    c[0] = accum8 & mask;
    c[1] += accum8 >> 28;
}

void
p448_sqr (
    p448_t *__restrict__ cs,
    const p448_t *as
) {
    p448_mul(cs,as,as); /* PERF */
}

void
p448_strong_reduce (
    p448_t *a
) {
    word_t mask = (1ull<<28)-1;

    /* first, clear high */
    a->limb[8] += a->limb[15]>>28;
    a->limb[0] += a->limb[15]>>28;
    a->limb[15] &= mask;

    /* now the total is less than 2^448 - 2^(448-56) + 2^(448-56+8) < 2p */

    /* compute total_value - p.  No need to reduce mod p. */

    dsword_t scarry = 0;
    int i;
    for (i=0; i<16; i++) {
        scarry = scarry + a->limb[i] - ((i==8)?mask-1:mask);
        a->limb[i] = scarry & mask;
        scarry >>= 28;
    }

    /* uncommon case: it was >= p, so now scarry = 0 and this = x
    * common case: it was < p, so now scarry = -1 and this = x - p + 2^448
    * so let's add back in p.  will carry back off the top for 2^448.
    */

    assert(is_zero(scarry) | is_zero(scarry+1));

    word_t scarry_mask = scarry & mask;
    dword_t carry = 0;

    /* add it back */
    for (i=0; i<16; i++) {
        carry = carry + a->limb[i] + ((i==8)?(scarry_mask&~1):scarry_mask);
        a->limb[i] = carry & mask;
        carry >>= 28;
    }

    assert(is_zero(carry + scarry));
}

mask_t
p448_is_zero (
    const struct p448_t *a
) {
    struct p448_t b;
    p448_copy(&b,a);
    p448_strong_reduce(&b);

    uint32_t any = 0;
    int i;
    for (i=0; i<16; i++) {
        any |= b.limb[i];
    }
    return is_zero(any);
}

void
p448_serialize (
    uint8_t *serial,
    const struct p448_t *x
) {
    int i,j;
    p448_t red;
    p448_copy(&red, x);
    p448_strong_reduce(&red);
    for (i=0; i<8; i++) {
        uint64_t limb = red.limb[2*i] + (((uint64_t)red.limb[2*i+1])<<28);
        for (j=0; j<7; j++) {
            serial[7*i+j] = limb;
            limb >>= 8;
        }
        assert(limb == 0);
    }
}

mask_t
p448_deserialize (
    p448_t *x,
    const uint8_t serial[56]
) {
    int i,j;
    for (i=0; i<8; i++) {
        uint64_t out = 0;
        for (j=0; j<7; j++) {
            out |= ((uint64_t)serial[7*i+j])<<(8*j);
        }
        x->limb[2*i] = out & ((1ull<<28)-1);
        x->limb[2*i+1] = out >> 28;
    }
    
    /* Check for reduction.
     *
     * The idea is to create a variable ge which is all ones (rather, 56 ones)
     * if and only if the low $i$ words of $x$ are >= those of p.
     *
     * Remember p = little_endian(1111,1111,1111,1111,1110,1111,1111,1111)
     */
    uint32_t ge = -1, mask = (1ull<<28)-1;
    for (i=0; i<8; i++) {
        ge &= x->limb[i];
    }
    
    /* At this point, ge = 1111 iff bottom are all 1111.  Now propagate if 1110, or set if 1111 */
    ge = (ge & (x->limb[8] + 1)) | is_zero(x->limb[8] ^ mask);
    
    /* Propagate the rest */
    for (i=9; i<16; i++) {
        ge &= x->limb[i];
    }
    
    return ~is_zero(ge ^ mask);
}

