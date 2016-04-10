/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

#include "p448.h"

static __inline__ __uint128_t widemul(
    const uint64_t a,
    const uint64_t b
) {
    return ((__uint128_t)a) * ((__uint128_t)b);
}

static __inline__ uint64_t is_zero(uint64_t a) {
    /* let's hope the compiler isn't clever enough to optimize this. */
    return (((__uint128_t)a)-1)>>64;
}

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

    uint64_t aa[4], bb[4], bbb[4];

    unsigned int i;
    for (i=0; i<4; i++) {
        aa[i]  = a[i] + a[i+4];
        bb[i]  = b[i] + b[i+4];
        bbb[i] = bb[i] + b[i+4];
    }

    int I_HATE_UNROLLED_LOOPS = 0;

    if (I_HATE_UNROLLED_LOOPS) {
        /* The compiler probably won't unroll this,
         * so it's like 80% slower.
         */
        for (i=0; i<4; i++) {
            accum2 = 0;

            unsigned int j;
            for (j=0; j<=i; j++) {
                accum2 += widemul(a[j],   b[i-j]);
                accum1 += widemul(aa[j], bb[i-j]);
                accum0 += widemul(a[j+4], b[i-j+4]);
            }
            for (; j<4; j++) {
                accum2 += widemul(a[j],   b[i-j+8]);
                accum1 += widemul(aa[j], bbb[i-j+4]);
                accum0 += widemul(a[j+4], bb[i-j+4]);
            }

            accum1 -= accum2;
            accum0 += accum2;

            c[i]   = ((uint64_t)(accum0)) & mask;
            c[i+4] = ((uint64_t)(accum1)) & mask;

            accum0 >>= 56;
            accum1 >>= 56;
        }
    } else {
        accum2  = widemul(a[0],  b[0]);
        accum1 += widemul(aa[0], bb[0]);
        accum0 += widemul(a[4],  b[4]);

        accum2 += widemul(a[1],  b[7]);
        accum1 += widemul(aa[1], bbb[3]);
        accum0 += widemul(a[5],  bb[3]);

        accum2 += widemul(a[2],  b[6]);
        accum1 += widemul(aa[2], bbb[2]);
        accum0 += widemul(a[6],  bb[2]);

        accum2 += widemul(a[3],  b[5]);
        accum1 += widemul(aa[3], bbb[1]);
        accum0 += widemul(a[7],  bb[1]);

        accum1 -= accum2;
        accum0 += accum2;

        c[0] = ((uint64_t)(accum0)) & mask;
        c[4] = ((uint64_t)(accum1)) & mask;

        accum0 >>= 56;
        accum1 >>= 56;

        accum2  = widemul(a[0],  b[1]);
        accum1 += widemul(aa[0], bb[1]);
        accum0 += widemul(a[4],  b[5]);

        accum2 += widemul(a[1],  b[0]);
        accum1 += widemul(aa[1], bb[0]);
        accum0 += widemul(a[5],  b[4]);

        accum2 += widemul(a[2],  b[7]);
        accum1 += widemul(aa[2], bbb[3]);
        accum0 += widemul(a[6],  bb[3]);

        accum2 += widemul(a[3],  b[6]);
        accum1 += widemul(aa[3], bbb[2]);
        accum0 += widemul(a[7],  bb[2]);

        accum1 -= accum2;
        accum0 += accum2;

        c[1] = ((uint64_t)(accum0)) & mask;
        c[5] = ((uint64_t)(accum1)) & mask;

        accum0 >>= 56;
        accum1 >>= 56;

        accum2  = widemul(a[0],  b[2]);
        accum1 += widemul(aa[0], bb[2]);
        accum0 += widemul(a[4],  b[6]);

        accum2 += widemul(a[1],  b[1]);
        accum1 += widemul(aa[1], bb[1]);
        accum0 += widemul(a[5],  b[5]);

        accum2 += widemul(a[2],  b[0]);
        accum1 += widemul(aa[2], bb[0]);
        accum0 += widemul(a[6],  b[4]);

        accum2 += widemul(a[3],  b[7]);
        accum1 += widemul(aa[3], bbb[3]);
        accum0 += widemul(a[7],  bb[3]);

        accum1 -= accum2;
        accum0 += accum2;

        c[2] = ((uint64_t)(accum0)) & mask;
        c[6] = ((uint64_t)(accum1)) & mask;

        accum0 >>= 56;
        accum1 >>= 56;

        accum2  = widemul(a[0],  b[3]);
        accum1 += widemul(aa[0], bb[3]);
        accum0 += widemul(a[4],  b[7]);

        accum2 += widemul(a[1],  b[2]);
        accum1 += widemul(aa[1], bb[2]);
        accum0 += widemul(a[5],  b[6]);

        accum2 += widemul(a[2],  b[1]);
        accum1 += widemul(aa[2], bb[1]);
        accum0 += widemul(a[6],  b[5]);

        accum2 += widemul(a[3],  b[0]);
        accum1 += widemul(aa[3], bb[0]);
        accum0 += widemul(a[7],  b[4]);

        accum1 -= accum2;
        accum0 += accum2;

        c[3] = ((uint64_t)(accum0)) & mask;
        c[7] = ((uint64_t)(accum1)) & mask;

        accum0 >>= 56;
        accum1 >>= 56;
    } /* !I_HATE_UNROLLED_LOOPS */

    accum0 += accum1;
    accum0 += c[4];
    accum1 += c[0];
    c[4] = ((uint64_t)(accum0)) & mask;
    c[0] = ((uint64_t)(accum1)) & mask;

    accum0 >>= 56;
    accum1 >>= 56;

    c[5] += ((uint64_t)(accum0));
    c[1] += ((uint64_t)(accum1));
}

void
p448_mulw (
    p448_t *__restrict__ cs,
    const p448_t *as,
    uint64_t b
) {
    const uint64_t *a = as->limb;
    uint64_t *c = cs->limb;

    __uint128_t accum0 = 0, accum4 = 0;
    uint64_t mask = (1ull<<56) - 1;  

    int i;
    for (i=0; i<4; i++) {
        accum0 += widemul(b, a[i]);
        accum4 += widemul(b, a[i+4]);
        c[i]   = accum0 & mask; accum0 >>= 56;
        c[i+4] = accum4 & mask; accum4 >>= 56;
    }
    
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

    uint64_t aa[4];

    /* For some reason clang doesn't vectorize this without prompting? */
    unsigned int i;
    for (i=0; i<4; i++) {
        aa[i] = a[i] + a[i+4];
    }

    accum2  = widemul(a[0],a[3]);
    accum0  = widemul(aa[0],aa[3]);
    accum1  = widemul(a[4],a[7]);

    accum2 += widemul(a[1], a[2]);
    accum0 += widemul(aa[1], aa[2]);
    accum1 += widemul(a[5], a[6]);

    accum0 -= accum2;
    accum1 += accum2;

    c[3] = ((uint64_t)(accum1))<<1 & mask;
    c[7] = ((uint64_t)(accum0))<<1 & mask;

    accum0 >>= 55;
    accum1 >>= 55;

    accum0 += widemul(2*aa[1],aa[3]);
    accum1 += widemul(2*a[5], a[7]);
    accum0 += widemul(aa[2], aa[2]);
    accum1 += accum0;

    accum0 -= widemul(2*a[1], a[3]);
    accum1 += widemul(a[6], a[6]);
    
    accum2 = widemul(a[0],a[0]);
    accum1 -= accum2;
    accum0 += accum2;

    accum0 -= widemul(a[2], a[2]);
    accum1 += widemul(aa[0], aa[0]);
    accum0 += widemul(a[4], a[4]);

    c[0] = ((uint64_t)(accum0)) & mask;
    c[4] = ((uint64_t)(accum1)) & mask;

    accum0 >>= 56;
    accum1 >>= 56;

    accum2  = widemul(2*aa[2],aa[3]);
    accum0 -= widemul(2*a[2], a[3]);
    accum1 += widemul(2*a[6], a[7]);

    accum1 += accum2;
    accum0 += accum2;

    accum2  = widemul(2*a[0],a[1]);
    accum1 += widemul(2*aa[0], aa[1]);
    accum0 += widemul(2*a[4], a[5]);

    accum1 -= accum2;
    accum0 += accum2;

    c[1] = ((uint64_t)(accum0)) & mask;
    c[5] = ((uint64_t)(accum1)) & mask;

    accum0 >>= 56;
    accum1 >>= 56;

    accum2  = widemul(aa[3],aa[3]);
    accum0 -= widemul(a[3], a[3]);
    accum1 += widemul(a[7], a[7]);

    accum1 += accum2;
    accum0 += accum2;

    accum2  = widemul(2*a[0],a[2]);
    accum1 += widemul(2*aa[0], aa[2]);
    accum0 += widemul(2*a[4], a[6]);

    accum2 += widemul(a[1], a[1]);
    accum1 += widemul(aa[1], aa[1]);
    accum0 += widemul(a[5], a[5]);

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
        uint64_t out = 0;
        for (j=0; j<7; j++) {
            out |= ((uint64_t)serial[7*i+j])<<(8*j);
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
    uint64_t ge = -1, mask = (1ull<<56)-1;
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
