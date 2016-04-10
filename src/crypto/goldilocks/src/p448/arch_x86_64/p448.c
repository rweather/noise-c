/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

#include "p448.h"
#include "x86-64-arith.h"

void
p448_mul (
    p448_t *__restrict__ cs,
    const p448_t *as,
    const p448_t *bs
) {
    const uint64_t *a = as->limb, *b = bs->limb;
    uint64_t *c = cs->limb;

    __uint128_t accum0 = 0, accum1 = 0, accum2;
    uint64_t mask = (1ull<<56) - 1;  

    uint64_t aa[4] __attribute__((aligned(32))), bb[4] __attribute__((aligned(32))), bbb[4] __attribute__((aligned(32)));

    /* For some reason clang doesn't vectorize this without prompting? */
    unsigned int i;
    for (i=0; i<sizeof(aa)/sizeof(uint64xn_t); i++) {
        ((uint64xn_t*)aa)[i] = ((const uint64xn_t*)a)[i] + ((const uint64xn_t*)(&a[4]))[i];
        ((uint64xn_t*)bb)[i] = ((const uint64xn_t*)b)[i] + ((const uint64xn_t*)(&b[4]))[i]; 
        ((uint64xn_t*)bbb)[i] = ((const uint64xn_t*)bb)[i] + ((const uint64xn_t*)(&b[4]))[i];     
    }
    /*
    for (int i=0; i<4; i++) {
    aa[i] = a[i] + a[i+4];
    bb[i] = b[i] + b[i+4];
    }
    */

    accum2  = widemul(&a[0],&b[3]);
    accum0  = widemul(&aa[0],&bb[3]);
    accum1  = widemul(&a[4],&b[7]);

    mac(&accum2, &a[1], &b[2]);
    mac(&accum0, &aa[1], &bb[2]);
    mac(&accum1, &a[5], &b[6]);

    mac(&accum2, &a[2], &b[1]);
    mac(&accum0, &aa[2], &bb[1]);
    mac(&accum1, &a[6], &b[5]);

    mac(&accum2, &a[3], &b[0]);
    mac(&accum0, &aa[3], &bb[0]);
    mac(&accum1, &a[7], &b[4]);

    accum0 -= accum2;
    accum1 += accum2;

    c[3] = ((uint64_t)(accum1)) & mask;
    c[7] = ((uint64_t)(accum0)) & mask;

    accum0 >>= 56;
    accum1 >>= 56;
    
    mac(&accum0, &aa[1],&bb[3]);
    mac(&accum1, &a[5], &b[7]);
    mac(&accum0, &aa[2], &bb[2]);
    mac(&accum1, &a[6], &b[6]);
    mac(&accum0, &aa[3], &bb[1]);
    accum1 += accum0;

    accum2 = widemul(&a[0],&b[0]);
    accum1 -= accum2;
    accum0 += accum2;
    
    msb(&accum0, &a[1], &b[3]);
    msb(&accum0, &a[2], &b[2]);
    mac(&accum1, &a[7], &b[5]);
    msb(&accum0, &a[3], &b[1]);
    mac(&accum1, &aa[0], &bb[0]);
    mac(&accum0, &a[4], &b[4]);

    c[0] = ((uint64_t)(accum0)) & mask;
    c[4] = ((uint64_t)(accum1)) & mask;

    accum0 >>= 56;
    accum1 >>= 56;

    accum2  = widemul(&a[2],&b[7]);
    mac(&accum0, &a[6], &bb[3]);
    mac(&accum1, &aa[2], &bbb[3]);

    mac(&accum2, &a[3], &b[6]);
    mac(&accum0, &a[7], &bb[2]);
    mac(&accum1, &aa[3], &bbb[2]);

    mac(&accum2, &a[0],&b[1]);
    mac(&accum1, &aa[0], &bb[1]);
    mac(&accum0, &a[4], &b[5]);

    mac(&accum2, &a[1], &b[0]);
    mac(&accum1, &aa[1], &bb[0]);
    mac(&accum0, &a[5], &b[4]);

    accum1 -= accum2;
    accum0 += accum2;

    c[1] = ((uint64_t)(accum0)) & mask;
    c[5] = ((uint64_t)(accum1)) & mask;

    accum0 >>= 56;
    accum1 >>= 56;

    accum2  = widemul(&a[3],&b[7]);
    mac(&accum0, &a[7], &bb[3]);
    mac(&accum1, &aa[3], &bbb[3]);

    mac(&accum2, &a[0],&b[2]);
    mac(&accum1, &aa[0], &bb[2]);
    mac(&accum0, &a[4], &b[6]);

    mac(&accum2, &a[1], &b[1]);
    mac(&accum1, &aa[1], &bb[1]);
    mac(&accum0, &a[5], &b[5]);

    mac(&accum2, &a[2], &b[0]);
    mac(&accum1, &aa[2], &bb[0]);
    mac(&accum0, &a[6], &b[4]);

    accum1 -= accum2;
    accum0 += accum2;

    c[2] = ((uint64_t)(accum0)) & mask;
    c[6] = ((uint64_t)(accum1)) & mask;

    accum0 >>= 56;
    accum1 >>= 56;

    accum0 += c[3];
    accum1 += c[7];
    c[3] = ((uint64_t)(accum0)) & mask;
    c[7] = ((uint64_t)(accum1)) & mask;

    /* we could almost stop here, but it wouldn't be stable, so... */

    accum0 >>= 56;
    accum1 >>= 56;
    c[4] += ((uint64_t)(accum0)) + ((uint64_t)(accum1));
    c[0] += ((uint64_t)(accum1));
}

void
p448_mulw (
    p448_t *__restrict__ cs,
    const p448_t *as,
    uint64_t b
) {
    const uint64_t *a = as->limb;
    uint64_t *c = cs->limb;

    __uint128_t accum0, accum4;
    uint64_t mask = (1ull<<56) - 1;  

    accum0 = widemul_rm(b, &a[0]);
    accum4 = widemul_rm(b, &a[4]);

    c[0] = accum0 & mask; accum0 >>= 56;
    c[4] = accum4 & mask; accum4 >>= 56;

    mac_rm(&accum0, b, &a[1]);
    mac_rm(&accum4, b, &a[5]);

    c[1] = accum0 & mask; accum0 >>= 56;
    c[5] = accum4 & mask; accum4 >>= 56;

    mac_rm(&accum0, b, &a[2]);
    mac_rm(&accum4, b, &a[6]);

    c[2] = accum0 & mask; accum0 >>= 56;
    c[6] = accum4 & mask; accum4 >>= 56;

    mac_rm(&accum0, b, &a[3]);
    mac_rm(&accum4, b, &a[7]);

    c[3] = accum0 & mask; accum0 >>= 56;
    c[7] = accum4 & mask; accum4 >>= 56;
    
    accum0 += accum4 + c[4];
    c[4] = accum0 & mask;
    c[5] += accum0 >> 56;

    accum4 += c[0];
    c[0] = accum4 & mask;
    c[1] += accum4 >> 56;
}

void
p448_sqr (
    p448_t *__restrict__ cs,
    const p448_t *as
) {
    const uint64_t *a = as->limb;
    uint64_t *c = cs->limb;

    __uint128_t accum0 = 0, accum1 = 0, accum2;
    uint64_t mask = (1ull<<56) - 1;  

    uint64_t aa[4] __attribute__((aligned(32)));

    /* For some reason clang doesn't vectorize this without prompting? */
    unsigned int i;
    for (i=0; i<sizeof(aa)/sizeof(uint64xn_t); i++) {
      ((uint64xn_t*)aa)[i] = ((const uint64xn_t*)a)[i] + ((const uint64xn_t*)(&a[4]))[i];
    }

    accum2  = widemul(&a[0],&a[3]);
    accum0  = widemul(&aa[0],&aa[3]);
    accum1  = widemul(&a[4],&a[7]);

    mac(&accum2, &a[1], &a[2]);
    mac(&accum0, &aa[1], &aa[2]);
    mac(&accum1, &a[5], &a[6]);

    accum0 -= accum2;
    accum1 += accum2;

    c[3] = ((uint64_t)(accum1))<<1 & mask;
    c[7] = ((uint64_t)(accum0))<<1 & mask;

    accum0 >>= 55;
    accum1 >>= 55;

    mac2(&accum0, &aa[1],&aa[3]);
    mac2(&accum1, &a[5], &a[7]);
    mac(&accum0, &aa[2], &aa[2]);
    accum1 += accum0;

    msb2(&accum0, &a[1], &a[3]);
    mac(&accum1, &a[6], &a[6]);
    
    accum2 = widemul(&a[0],&a[0]);
    accum1 -= accum2;
    accum0 += accum2;

    msb(&accum0, &a[2], &a[2]);
    mac(&accum1, &aa[0], &aa[0]);
    mac(&accum0, &a[4], &a[4]);

    c[0] = ((uint64_t)(accum0)) & mask;
    c[4] = ((uint64_t)(accum1)) & mask;

    accum0 >>= 56;
    accum1 >>= 56;

    accum2  = widemul2(&aa[2],&aa[3]);
    msb2(&accum0, &a[2], &a[3]);
    mac2(&accum1, &a[6], &a[7]);

    accum1 += accum2;
    accum0 += accum2;

    accum2  = widemul2(&a[0],&a[1]);
    mac2(&accum1, &aa[0], &aa[1]);
    mac2(&accum0, &a[4], &a[5]);

    accum1 -= accum2;
    accum0 += accum2;

    c[1] = ((uint64_t)(accum0)) & mask;
    c[5] = ((uint64_t)(accum1)) & mask;

    accum0 >>= 56;
    accum1 >>= 56;

    accum2  = widemul(&aa[3],&aa[3]);
    msb(&accum0, &a[3], &a[3]);
    mac(&accum1, &a[7], &a[7]);

    accum1 += accum2;
    accum0 += accum2;

    accum2  = widemul2(&a[0],&a[2]);
    mac2(&accum1, &aa[0], &aa[2]);
    mac2(&accum0, &a[4], &a[6]);

    mac(&accum2, &a[1], &a[1]);
    mac(&accum1, &aa[1], &aa[1]);
    mac(&accum0, &a[5], &a[5]);

    accum1 -= accum2;
    accum0 += accum2;

    c[2] = ((uint64_t)(accum0)) & mask;
    c[6] = ((uint64_t)(accum1)) & mask;

    accum0 >>= 56;
    accum1 >>= 56;

    accum0 += c[3];
    accum1 += c[7];
    c[3] = ((uint64_t)(accum0)) & mask;
    c[7] = ((uint64_t)(accum1)) & mask;

    /* we could almost stop here, but it wouldn't be stable, so... */

    accum0 >>= 56;
    accum1 >>= 56;
    c[4] += ((uint64_t)(accum0)) + ((uint64_t)(accum1));
    c[0] += ((uint64_t)(accum1));
}

void
p448_strong_reduce (
    p448_t *a
) {
    uint64_t mask = (1ull<<56)-1;

    /* first, clear high */
    a->limb[4] += a->limb[7]>>56;
    a->limb[0] += a->limb[7]>>56;
    a->limb[7] &= mask;

    /* now the total is less than 2^448 - 2^(448-56) + 2^(448-56+8) < 2p */

    /* compute total_value - p.  No need to reduce mod p. */

    __int128_t scarry = 0;
    int i;
    for (i=0; i<8; i++) {
        scarry = scarry + a->limb[i] - ((i==4)?mask-1:mask);
        a->limb[i] = scarry & mask;
        scarry >>= 56;
    }

    /* uncommon case: it was >= p, so now scarry = 0 and this = x
    * common case: it was < p, so now scarry = -1 and this = x - p + 2^448
    * so let's add back in p.  will carry back off the top for 2^448.
    */

    assert(is_zero(scarry) | is_zero(scarry+1));

    uint64_t scarry_mask = scarry & mask;
    __uint128_t carry = 0;

    /* add it back */
    for (i=0; i<8; i++) {
        carry = carry + a->limb[i] + ((i==4)?(scarry_mask&~1):scarry_mask);
        a->limb[i] = carry & mask;
        carry >>= 56;
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

    uint64_t any = 0;
    int i;
    for (i=0; i<8; i++) {
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
        for (j=0; j<7; j++) {
            serial[7*i+j] = red.limb[i];
            red.limb[i] >>= 8;
        }
        assert(red.limb[i] == 0);
    }
}

mask_t
p448_deserialize (
    p448_t *x,
    const uint8_t serial[56]
) {
    int i,j;
    for (i=0; i<8; i++) {
        word_t out = 0;
        for (j=0; j<7; j++) {
            out |= ((word_t)serial[7*i+j])<<(8*j);
        }
        x->limb[i] = out;
    }
    
    /* Check for reduction.
     *
     * The idea is to create a variable ge which is all ones (rather, 56 ones)
     * if and only if the low $i$ words of $x$ are >= those of p.
     *
     * Remember p = little_endian(1111,1111,1111,1111,1110,1111,1111,1111)
     */
    word_t ge = -1, mask = (1ull<<56)-1;
    for (i=0; i<4; i++) {
        ge &= x->limb[i];
    }
    
    /* At this point, ge = 1111 iff bottom are all 1111.  Now propagate if 1110, or set if 1111 */
    ge = (ge & (x->limb[4] + 1)) | is_zero(x->limb[4] ^ mask);
    
    /* Propagate the rest */
    for (i=5; i<8; i++) {
        ge &= x->limb[i];
    }
    
    return ~is_zero(ge ^ mask);
}

