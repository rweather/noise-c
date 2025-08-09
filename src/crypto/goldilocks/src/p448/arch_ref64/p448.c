/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

#include "p448.h"

#ifdef _MSC_VER
#include <intrin.h>
typedef struct {
    uint64_t low;
    uint64_t high;
} uint128_t;

static __inline__ uint128_t widemul(
    const uint64_t a,
    const uint64_t b
) {
    uint128_t result;
    result.low = _umul128(a, b, &result.high);
    return result;
}

#define UINT128_LOW(x) ((x).low)
#define UINT128_HIGH(x) ((x).high)
#define UINT128_RSHIFT(x, n) ((n) >= 64 ? (x).high >> ((n) - 64) : ((x).low >> (n)) | ((x).high << (64 - (n))))
#define UINT128_ADD(a, b) { (a).low += (b).low; (a).high += (b).high + ((a).low < (b).low ? 1 : 0); }
#define UINT128_ADD_U64(a, b) { uint64_t old_low = (a).low; (a).low += (b); (a).high += ((a).low < old_low ? 1 : 0); }

#else
typedef __uint128_t uint128_t;

static __inline__ __uint128_t widemul(
    const uint64_t a,
    const uint64_t b
) {
    return ((__uint128_t)a) * ((__uint128_t)b);
}

#define UINT128_LOW(x) ((uint64_t)(x))
#define UINT128_HIGH(x) ((uint64_t)((x) >> 64))
#define UINT128_RSHIFT(x, n) ((x) >> (n))
#define UINT128_ADD(a, b) ((a) += (b))
#define UINT128_ADD_U64(a, b) ((a) += (b))

#endif

static __inline__ uint64_t is_zero(uint64_t a) {
#ifdef _MSC_VER
    uint128_t temp = {a, 0};
    temp.low = temp.low - 1;
    if (temp.low == UINT64_MAX) temp.high = UINT64_MAX;
    return temp.high;
#else
  /* let's hope the compiler isn't clever enough to optimize this. */
    return (((__uint128_t)a)-1)>>64;
#endif
}

void
p448_mul (
    p448_t *__restrict__ cs,
    const p448_t *as,
    const p448_t *bs
) {
    const uint64_t *a = as->limb, *b = bs->limb;
    uint64_t *c = cs->limb;

    uint128_t accum0 = {0, 0}, accum1 = {0, 0}, accum2;
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
            accum2 = (uint128_t){0, 0};

            unsigned int j;
            for (j=0; j<=i; j++) {
                UINT128_ADD(accum2, widemul(a[j], b[i-j]));
                UINT128_ADD(accum1, widemul(aa[j], bb[i-j]));
                UINT128_ADD(accum0, widemul(a[j+4], b[i-j+4]));
            }
            for (; j<4; j++) {
                UINT128_ADD(accum2, widemul(a[j], b[i-j+8]));
                UINT128_ADD(accum1, widemul(aa[j], bbb[i-j+4]));
                UINT128_ADD(accum0, widemul(a[j+4], bb[i-j+4]));
            }

#ifdef _MSC_VER
            // accum1 -= accum2
            if (accum1.low < accum2.low) accum1.high--;
            accum1.low -= accum2.low;
            accum1.high -= accum2.high;
            
            // accum0 += accum2
            UINT128_ADD(accum0, accum2);
#else
            accum1 -= accum2;
            accum0 += accum2;
#endif

            c[i]   = UINT128_LOW(accum0) & mask;
            c[i+4] = UINT128_LOW(accum1) & mask;

            accum0 = (uint128_t){UINT128_RSHIFT(accum0, 56), 0};
            accum1 = (uint128_t){UINT128_RSHIFT(accum1, 56), 0};
        }
    } else {
        accum2  = widemul(a[0],  b[0]);
        UINT128_ADD(accum1, widemul(aa[0], bb[0]));
        UINT128_ADD(accum0, widemul(a[4],  b[4]));

        UINT128_ADD(accum2, widemul(a[1],  b[7]));
        UINT128_ADD(accum1, widemul(aa[1], bbb[3]));
        UINT128_ADD(accum0, widemul(a[5],  bb[3]));

        UINT128_ADD(accum2, widemul(a[2],  b[6]));
        UINT128_ADD(accum1, widemul(aa[2], bbb[2]));
        UINT128_ADD(accum0, widemul(a[6],  bb[2]));

        UINT128_ADD(accum2, widemul(a[3],  b[5]));
        UINT128_ADD(accum1, widemul(aa[3], bbb[1]));
        UINT128_ADD(accum0, widemul(a[7],  bb[1]));

#ifdef _MSC_VER
        // accum1 -= accum2
        if (accum1.low < accum2.low) accum1.high--;
        accum1.low -= accum2.low;
        accum1.high -= accum2.high;
        
        // accum0 += accum2
        UINT128_ADD(accum0, accum2);
#else
        accum1 -= accum2;
        accum0 += accum2;
#endif

        c[0] = UINT128_LOW(accum0) & mask;
        c[4] = UINT128_LOW(accum1) & mask;

        accum0 = (uint128_t){UINT128_RSHIFT(accum0, 56), 0};
        accum1 = (uint128_t){UINT128_RSHIFT(accum1, 56), 0};

        accum2  = widemul(a[0],  b[1]);
        UINT128_ADD(accum1, widemul(aa[0], bb[1]));
        UINT128_ADD(accum0, widemul(a[4],  b[5]));

        UINT128_ADD(accum2, widemul(a[1], b[0]));
        UINT128_ADD(accum1, widemul(aa[1], bb[0]));
        UINT128_ADD(accum0, widemul(a[5],  b[4]));

        UINT128_ADD(accum2, widemul(a[2],  b[7]));
        UINT128_ADD(accum1, widemul(aa[2], bbb[3]));
        UINT128_ADD(accum0, widemul(a[6],  bb[3]));

        UINT128_ADD(accum2, widemul(a[3],  b[6]));
        UINT128_ADD(accum1, widemul(aa[3], bbb[2]));
        UINT128_ADD(accum0, widemul(a[7],  bb[2]));

#ifdef _MSC_VER
        // accum1 -= accum2
        if (accum1.low < accum2.low) accum1.high--;
        accum1.low -= accum2.low;
        accum1.high -= accum2.high;
        
        // accum0 += accum2
        UINT128_ADD(accum0, accum2);
#else
        accum1 -= accum2;
        accum0 += accum2;
#endif

        c[1] = UINT128_LOW(accum0) & mask;
        c[5] = UINT128_LOW(accum1) & mask;

        accum0 = (uint128_t){UINT128_RSHIFT(accum0, 56), 0};
        accum1 = (uint128_t){UINT128_RSHIFT(accum1, 56), 0};

        accum2  = widemul(a[0],  b[2]);
        UINT128_ADD(accum1, widemul(aa[0], bb[2]));
        UINT128_ADD(accum0, widemul(a[4],  b[6]));

        UINT128_ADD(accum2, widemul(a[1],  b[1]));
        UINT128_ADD(accum1, widemul(aa[1], bb[1]));
        UINT128_ADD(accum0, widemul(a[5],  b[5]));

        UINT128_ADD(accum2, widemul(a[2],  b[0]));
        UINT128_ADD(accum1, widemul(aa[2], bb[0]));
        UINT128_ADD(accum0, widemul(a[6],  b[4]));

        UINT128_ADD(accum2, widemul(a[3],  b[7]));
        UINT128_ADD(accum1, widemul(aa[3], bbb[3]));
        UINT128_ADD(accum0, widemul(a[7],  bb[3]));

#ifdef _MSC_VER
        // accum1 -= accum2
        if (accum1.low < accum2.low) accum1.high--;
        accum1.low -= accum2.low;
        accum1.high -= accum2.high;
        
        // accum0 += accum2
        UINT128_ADD(accum0, accum2);
#else
        accum1 -= accum2;
        accum0 += accum2;
#endif

        c[2] = UINT128_LOW(accum0) & mask;
        c[6] = UINT128_LOW(accum1) & mask;

        accum0 = (uint128_t){UINT128_RSHIFT(accum0, 56), 0};
        accum1 = (uint128_t){UINT128_RSHIFT(accum1, 56), 0};

        accum2  = widemul(a[0],  b[3]);
        UINT128_ADD(accum1, widemul(aa[0], bb[3]));
        UINT128_ADD(accum0, widemul(a[4],  b[7]));

        UINT128_ADD(accum2, widemul(a[1],  b[2]));
        UINT128_ADD(accum1, widemul(aa[1], bb[2]));
        UINT128_ADD(accum0, widemul(a[5],  b[6]));

        UINT128_ADD(accum2, widemul(a[2],  b[1]));
        UINT128_ADD(accum1, widemul(aa[2], bb[1]));
        UINT128_ADD(accum0, widemul(a[6],  b[5]));

        UINT128_ADD(accum2, widemul(a[3],  b[0]));
        UINT128_ADD(accum1, widemul(aa[3], bb[0]));
        UINT128_ADD(accum0, widemul(a[7],  b[4]));

#ifdef _MSC_VER
        // accum1 -= accum2
        if (accum1.low < accum2.low) accum1.high--;
        accum1.low -= accum2.low;
        accum1.high -= accum2.high;
        
        // accum0 += accum2
        UINT128_ADD(accum0, accum2);
#else
        accum1 -= accum2;
        accum0 += accum2;
#endif

        c[3] = UINT128_LOW(accum0) & mask;
        c[7] = UINT128_LOW(accum1) & mask;

        accum0 = (uint128_t){UINT128_RSHIFT(accum0, 56), 0};
        accum1 = (uint128_t){UINT128_RSHIFT(accum1, 56), 0};
    } /* !I_HATE_UNROLLED_LOOPS */

    UINT128_ADD(accum0, accum1);
    UINT128_ADD_U64(accum0, c[4]);
    UINT128_ADD_U64(accum1, c[0]);
    c[4] = UINT128_LOW(accum0) & mask;
    c[0] = UINT128_LOW(accum1) & mask;

    accum0 = (uint128_t){UINT128_RSHIFT(accum0, 56), 0};
    accum1 = (uint128_t){UINT128_RSHIFT(accum1, 56), 0};

    c[5] += UINT128_LOW(accum0);
    c[1] += UINT128_LOW(accum1);
}

void
p448_mulw (
    p448_t *__restrict__ cs,
    const p448_t *as,
    uint64_t b
) {
    const uint64_t *a = as->limb;
    uint64_t *c = cs->limb;

    uint128_t accum0 = {0, 0}, accum4 = {0, 0};
    uint64_t mask = (1ull<<56) - 1;  

    int i;
    for (i=0; i<4; i++) {
        UINT128_ADD(accum0, widemul(b, a[i]));
        UINT128_ADD(accum4, widemul(b, a[i+4]));
        c[i]   = UINT128_LOW(accum0) & mask; 
        accum0 = (uint128_t){UINT128_RSHIFT(accum0, 56), 0};
        c[i+4] = UINT128_LOW(accum4) & mask; 
        accum4 = (uint128_t){UINT128_RSHIFT(accum4, 56), 0};
    }
    
    UINT128_ADD(accum0, accum4);
    UINT128_ADD_U64(accum0, c[4]);
    c[4] = UINT128_LOW(accum0) & mask;
    UINT128_ADD_U64(accum4, UINT128_RSHIFT(accum0, 56));
    c[5] += UINT128_LOW(accum4);

    UINT128_ADD_U64(accum4, c[0]);
    c[0] = UINT128_LOW(accum4) & mask;
    UINT128_ADD_U64(accum0, UINT128_RSHIFT(accum4, 56));
    c[1] += UINT128_LOW(accum0);
}

void
p448_sqr (
    p448_t *__restrict__ cs,
    const p448_t *as
) {
    const uint64_t *a = as->limb;
    uint64_t *c = cs->limb;

    uint128_t accum0 = {0, 0}, accum1 = {0, 0}, accum2;
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

    UINT128_ADD(accum2, widemul(a[1], a[2]));
    UINT128_ADD(accum0, widemul(aa[1], aa[2]));
    UINT128_ADD(accum1, widemul(a[5], a[6]));

#ifdef _MSC_VER
    // accum0 -= accum2
    if (accum0.low < accum2.low) accum0.high--;
    accum0.low -= accum2.low;
    accum0.high -= accum2.high;
    
    // accum1 += accum2
    UINT128_ADD(accum1, accum2);
#else
    accum0 -= accum2;
    accum1 += accum2;
#endif

    c[3] = (UINT128_LOW(accum1))<<1 & mask;
    c[7] = (UINT128_LOW(accum0))<<1 & mask;

    accum0 = (uint128_t){UINT128_RSHIFT(accum0, 55), 0};
    accum1 = (uint128_t){UINT128_RSHIFT(accum1, 55), 0};

    UINT128_ADD(accum0, widemul(2*aa[1],aa[3]));
    UINT128_ADD(accum1, widemul(2*a[5], a[7]));
    UINT128_ADD(accum0, widemul(aa[2], aa[2]));
    UINT128_ADD(accum1, accum0);

    {
        uint128_t temp = widemul(2*a[1], a[3]);
#ifdef _MSC_VER
        if (accum0.low < temp.low) accum0.high--;
        accum0.low -= temp.low;
        accum0.high -= temp.high;
#else
        accum0 -= temp;
#endif
    }
    UINT128_ADD(accum1, widemul(a[6], a[6]));
    
    accum2 = widemul(a[0],a[0]);
#ifdef _MSC_VER
    // accum1 -= accum2
    if (accum1.low < accum2.low) accum1.high--;
    accum1.low -= accum2.low;
    accum1.high -= accum2.high;
    
    // accum0 += accum2
    UINT128_ADD(accum0, accum2);
#else
    accum1 -= accum2;
    accum0 += accum2;
#endif

    {
        uint128_t temp = widemul(a[2], a[2]);
#ifdef _MSC_VER
        if (accum0.low < temp.low) accum0.high--;
        accum0.low -= temp.low;
        accum0.high -= temp.high;
#else
        accum0 -= temp;
#endif
    }
    UINT128_ADD(accum1, widemul(aa[0], aa[0]));
    UINT128_ADD(accum0, widemul(a[4], a[4]));

    c[0] = UINT128_LOW(accum0) & mask;
    c[4] = UINT128_LOW(accum1) & mask;

    accum0 = (uint128_t){UINT128_RSHIFT(accum0, 56), 0};
    accum1 = (uint128_t){UINT128_RSHIFT(accum1, 56), 0};

    accum2  = widemul(2*aa[2],aa[3]);
    {
        uint128_t temp = widemul(2*a[2], a[3]);
#ifdef _MSC_VER
        if (accum0.low < temp.low) accum0.high--;
        accum0.low -= temp.low;
        accum0.high -= temp.high;
#else
        accum0 -= temp;
#endif
    }
    UINT128_ADD(accum1, widemul(2*a[6], a[7]));

    UINT128_ADD(accum1, accum2);
    UINT128_ADD(accum0, accum2);

    accum2  = widemul(2*a[0],a[1]);
    UINT128_ADD(accum1, widemul(2*aa[0], aa[1]));
    UINT128_ADD(accum0, widemul(2*a[4], a[5]));

#ifdef _MSC_VER
    // accum1 -= accum2
    if (accum1.low < accum2.low) accum1.high--;
    accum1.low -= accum2.low;
    accum1.high -= accum2.high;
    
    // accum0 += accum2
    UINT128_ADD(accum0, accum2);
#else
    accum1 -= accum2;
    accum0 += accum2;
#endif

    c[1] = UINT128_LOW(accum0) & mask;
    c[5] = UINT128_LOW(accum1) & mask;

    accum0 = (uint128_t){UINT128_RSHIFT(accum0, 56), 0};
    accum1 = (uint128_t){UINT128_RSHIFT(accum1, 56), 0};

    accum2  = widemul(aa[3],aa[3]);
    {
        uint128_t temp = widemul(a[3], a[3]);
#ifdef _MSC_VER
        if (accum0.low < temp.low) accum0.high--;
        accum0.low -= temp.low;
        accum0.high -= temp.high;
#else
        accum0 -= temp;
#endif
    }
    UINT128_ADD(accum1, widemul(a[7], a[7]));

    UINT128_ADD(accum1, accum2);
    UINT128_ADD(accum0, accum2);

    accum2  = widemul(2*a[0],a[2]);
    UINT128_ADD(accum1, widemul(2*aa[0], aa[2]));
    UINT128_ADD(accum0, widemul(2*a[4], a[6]));

    UINT128_ADD(accum2, widemul(a[1], a[1]));
    UINT128_ADD(accum1, widemul(aa[1], aa[1]));
    UINT128_ADD(accum0, widemul(a[5], a[5]));

#ifdef _MSC_VER
    // accum1 -= accum2
    if (accum1.low < accum2.low) accum1.high--;
    accum1.low -= accum2.low;
    accum1.high -= accum2.high;
    
    // accum0 += accum2
    UINT128_ADD(accum0, accum2);
#else
    accum1 -= accum2;
    accum0 += accum2;
#endif

    c[2] = UINT128_LOW(accum0) & mask;
    c[6] = UINT128_LOW(accum1) & mask;

    accum0 = (uint128_t){UINT128_RSHIFT(accum0, 56), 0};
    accum1 = (uint128_t){UINT128_RSHIFT(accum1, 56), 0};

    UINT128_ADD_U64(accum0, c[3]);
    UINT128_ADD_U64(accum1, c[7]);
    c[3] = UINT128_LOW(accum0) & mask;
    c[7] = UINT128_LOW(accum1) & mask;

    /* we could almost stop here, but it wouldn't be stable, so... */

    accum0 = (uint128_t){UINT128_RSHIFT(accum0, 56), 0};
    accum1 = (uint128_t){UINT128_RSHIFT(accum1, 56), 0};
    c[4] += UINT128_LOW(accum0) + UINT128_LOW(accum1);
    c[0] += UINT128_LOW(accum1);
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

#ifdef _MSC_VER
    int64_t scarry = 0;
#else
    __int128_t scarry = 0;
#endif
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
    uint128_t carry = { 0, 0 };

    /* add it back */
    for (i=0; i<8; i++) {
        UINT128_ADD_U64(carry, a->limb[i]);
        UINT128_ADD_U64(carry, ((i==4)?(scarry_mask&~1):scarry_mask));
        a->limb[i] = UINT128_LOW(carry) & mask;
        carry = (uint128_t){UINT128_RSHIFT(carry, 56), 0};
    }

    assert(is_zero(UINT128_LOW(carry)) | is_zero(scarry));
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
