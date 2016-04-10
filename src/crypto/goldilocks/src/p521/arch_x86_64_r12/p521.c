/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

#include "p521.h"

typedef struct {
  uint64x3_t lo, hi, hier;
} nonad_t;

static __inline__ uint64_t is_zero(uint64_t a) {
    /* let's hope the compiler isn't clever enough to optimize this. */
    return (((__uint128_t)a)-1)>>64;
}

static inline __uint128_t widemulu(uint64_t a, uint64_t b) {
    return ((__uint128_t)(a)) * b;
}

static inline __int128_t widemuls(int64_t a, int64_t b) {
    return ((__int128_t)(a)) * b;
}
 
/* This is a trick to prevent terrible register allocation by hiding things from clang's optimizer */
static inline uint64_t opacify(uint64_t x) {
    __asm__ volatile("" : "+r"(x));
    return x;
}

/* These used to be hexads, leading to 10% better performance, but there were overflow issues */
static inline void nonad_mul (
  nonad_t *hex,
  const uint64_t *a,
  const uint64_t *b
) {
    __uint128_t xu, xv, xw;

    uint64_t tmp = opacify(a[2]);
    xw = widemulu(tmp, b[0]);
    tmp <<= 1;
    xu = widemulu(tmp, b[1]);
    xv = widemulu(tmp, b[2]);

    tmp = opacify(a[1]);
    xw += widemulu(tmp, b[1]);
    xv += widemulu(tmp, b[0]);
    tmp <<= 1;
    xu += widemulu(tmp, b[2]);

    tmp = opacify(a[0]);
    xu += widemulu(tmp, b[0]);
    xv += widemulu(tmp, b[1]);
    xw += widemulu(tmp, b[2]);

    uint64x3_t
    lo = { (uint64_t)(xu), (uint64_t)(xv), (uint64_t)(xw), 0 },
    hi = { (uint64_t)(xu>>64), (uint64_t)(xv>>64), (uint64_t)(xw>>64), 0 };

    hex->hier = hi>>52;
    hex->hi = (hi<<12)>>6 | lo>>58;
    hex->lo = lo & mask58;
}

static inline void hexad_mul_signed (
  nonad_t *hex,
  const int64_t *a,
  const int64_t *b
) {
    __int128_t xu, xv, xw;

    int64_t tmp = opacify(a[2]);
    xw = widemuls(tmp, b[0]);
    tmp <<= 1;
    xu = widemuls(tmp, b[1]);
    xv = widemuls(tmp, b[2]);

    tmp = opacify(a[1]);
    xw += widemuls(tmp, b[1]);
    xv += widemuls(tmp, b[0]);
    tmp <<= 1;
    xu += widemuls(tmp, b[2]);

    tmp = opacify(a[0]);
    xu += widemuls(tmp, b[0]);
    xv += widemuls(tmp, b[1]);
    xw += widemuls(tmp, b[2]);

    uint64x3_t
    lo = { (uint64_t)(xu), (uint64_t)(xv), (uint64_t)(xw), 0 },
    hi = { (uint64_t)(xu>>64), (uint64_t)(xv>>64), (uint64_t)(xw>>64), 0 };

    /*
    hex->hier = (uint64x4_t)((int64x4_t)hi>>52);
    hex->hi = (hi<<12)>>6 | lo>>58;
    hex->lo = lo & mask58;
    */
    
    hex->hi = hi<<6 | lo>>58;
    hex->lo = lo & mask58;
}

static inline void nonad_sqr (
  nonad_t *hex,
  const uint64_t *a
) {
    __uint128_t xu, xv, xw;

    int64_t tmp = a[2];
    tmp <<= 1;
    xw = widemulu(tmp, a[0]);
    xv = widemulu(tmp, a[2]);
    tmp <<= 1;
    xu = widemulu(tmp, a[1]);

    tmp = a[1];
    xw += widemulu(tmp, a[1]);
    tmp <<= 1;
    xv += widemulu(tmp, a[0]);

    tmp = a[0];
    xu += widemulu(tmp, a[0]);

    uint64x3_t
    lo = { (uint64_t)(xu), (uint64_t)(xv), (uint64_t)(xw), 0 },
    hi = { (uint64_t)(xu>>64), (uint64_t)(xv>>64), (uint64_t)(xw>>64), 0 };

    hex->hier = hi>>52;
    hex->hi = (hi<<12)>>6 | lo>>58;
    hex->lo = lo & mask58;
}

static inline void hexad_sqr_signed (
  nonad_t *hex,
  const int64_t *a
) {
    __uint128_t xu, xv, xw;

    int64_t tmp = a[2];
    tmp <<= 1;
    xw = widemuls(tmp, a[0]);
    xv = widemuls(tmp, a[2]);
    tmp <<= 1;
    xu = widemuls(tmp, a[1]);

    tmp = a[1];
    xw += widemuls(tmp, a[1]);
    tmp <<= 1;
    xv += widemuls(tmp, a[0]);

    tmp = a[0];
    xu += widemuls(tmp, a[0]);

    uint64x3_t
    lo = { (uint64_t)(xu), (uint64_t)(xv), (uint64_t)(xw), 0 },
    hi = { (uint64_t)(xu>>64), (uint64_t)(xv>>64), (uint64_t)(xw>>64), 0 };


    /*
    hex->hier = (uint64x4_t)((int64x4_t)hi>>52);
    hex->hi = (hi<<12)>>6 | lo>>58;
    hex->lo = lo & mask58;
    */
    
    hex->hi = hi<<6 | lo>>58;
    hex->lo = lo & mask58;
}



void
p521_mul (
    p521_t *__restrict__ cs,
    const p521_t *as,
    const p521_t *bs
) {
    int i;
    
#if 0
    assert(as->limb[3] == 0 && as->limb[7] == 0 && as->limb[11] == 0);
    assert(bs->limb[3] == 0 && bs->limb[7] == 0 && bs->limb[11] == 0);
    for (i=0; i<12; i++) {
        assert(as->limb[i] < 5ull<<57);
        assert(bs->limb[i] < 5ull<<57);
    }
#endif
    
    /* Bounds on the hexads and nonads.
     *
     * Limbs < 2<<58 + ep.
     * Nonad mul < 1<<58, 1<<58, tiny
     * -> t0 < (3,2,2)<<58 + tiny
     * t1,t2 < 2<<58 + tiny
     *   * w < (4,2,2)
     * Hexad mul < +- (5,4,3) * 4<<116 -> 2^58 lo, +- (5,4,3) * 4<<58+ep
     * TimesW < (2,1,1)<<58, (6,5,4)*4<<58 + ep
    
     * ot2 = t0 + timesW(t2 + t1 - acdf.hi - bcef.lo);
         == (3,2,2) + (4,2,2) + (4,2,2) +- (6,5,4)*4 - (1) << 58
         in (-25, +35) << 58

    uint64x3_t ot0 = t0 + timesW(t2 + t1 - acdf.hi - bcef.lo);
    uint64x3_t ot1 = t0 + t1 - abde.lo + timesW(t2 - bcef.hi);
    uint64x3_t ot2 = t0 + t1 + t2 - abde.hi - acdf.lo + vhi2;
     
     */
    
    
    uint64_t *c = cs->limb;
    const uint64_t *a = as->limb, *b = bs->limb;

    nonad_t ad, be, cf, abde, bcef, acdf;
    nonad_mul(&ad, &a[0], &b[0]);
    nonad_mul(&be, &a[4], &b[4]);
    nonad_mul(&cf, &a[8], &b[8]);

    uint64_t amt = 26;
    uint64x3_t vhi = { amt*((1ull<<58)-1), amt*((1ull<<58)-1), amt*((1ull<<58)-1), 0 },
    vhi2 = { 0, 0, -amt<<57, 0 };

    uint64x3_t t2 = cf.lo + be.hi + ad.hier, t0 = ad.lo + timesW(cf.hi + be.hier) + vhi, t1 = ad.hi + be.lo + timesW(cf.hier);

    int64_t ta[4] VECTOR_ALIGNED, tb[4] VECTOR_ALIGNED;
    // it seems to be faster not to vectorize these loops
    for (i=0; i<3; i++) {
        ta[i] = a[i]-a[i+4];
        tb[i] = b[i]-b[i+4];
    }
    hexad_mul_signed(&abde,ta,tb);

    for (i=0; i<3; i++) {
        ta[i] = a[i+4]-a[i+8];
        tb[i] = b[i+4]-b[i+8];
    }
    hexad_mul_signed(&bcef,ta,tb);

    for (i=0; i<3; i++) {
        ta[i] = a[i]-a[i+8];
        tb[i] = b[i]-b[i+8];
    }
    hexad_mul_signed(&acdf,ta,tb);

    uint64x3_t ot0 = t0 + timesW(t2 + t1 - acdf.hi - bcef.lo);
    uint64x3_t ot1 = t0 + t1 - abde.lo + timesW(t2 - bcef.hi);
    uint64x3_t ot2 = t0 + t1 + t2 - abde.hi - acdf.lo + vhi2;

    uint64x3_t out0 = (ot0 & mask58) + timesW(ot2>>58);
    uint64x3_t out1 = (ot1 & mask58) + (ot0>>58);
    uint64x3_t out2 = (ot2 & mask58) + (ot1>>58);

    *(uint64x4_t *)&c[0] = out0;
    *(uint64x4_t *)&c[4] = out1;
    *(uint64x4_t *)&c[8] = out2;
}


void
p521_sqr (
    p521_t *__restrict__ cs,
    const p521_t *as
) {
    

    int i;
#if 0
    assert(as->limb[3] == 0 && as->limb[7] == 0 && as->limb[11] == 0);
    for (i=0; i<12; i++) {
        assert(as->limb[i] < 5ull<<57);
    }
#endif

    uint64_t *c = cs->limb;
    const uint64_t *a = as->limb;

    nonad_t ad, be, cf, abde, bcef, acdf;
    nonad_sqr(&ad, &a[0]);
    nonad_sqr(&be, &a[4]);
    nonad_sqr(&cf, &a[8]);

    uint64_t amt = 26;
    uint64x3_t vhi = { amt*((1ull<<58)-1), amt*((1ull<<58)-1), amt*((1ull<<58)-1), 0 },
    vhi2 = { 0, 0, -amt<<57, 0 };
    
    uint64x3_t t2 = cf.lo + be.hi + ad.hier, t0 = ad.lo + timesW(cf.hi + be.hier) + vhi, t1 = ad.hi + be.lo + timesW(cf.hier);

    int64_t ta[4] VECTOR_ALIGNED;
    // it seems to be faster not to vectorize these loops
    for (i=0; i<3; i++) {
        ta[i] = a[i]-a[i+4];
    }
    hexad_sqr_signed(&abde,ta);

    for (i=0; i<3; i++) {
        ta[i] = a[i+4]-a[i+8];
    }
    hexad_sqr_signed(&bcef,ta);

    for (i=0; i<3; i++) {
        ta[i] = a[i]-a[i+8];
    }
    hexad_sqr_signed(&acdf,ta);

    uint64x3_t ot0 = t0 + timesW(t2 + t1 - acdf.hi - bcef.lo);
    uint64x3_t ot1 = t0 + t1 - abde.lo + timesW(t2 - bcef.hi);
    uint64x3_t ot2 = t0 + t1 + t2 - abde.hi - acdf.lo + vhi2;

    uint64x3_t out0 = (ot0 & mask58) + timesW(ot2>>58);
    uint64x3_t out1 = (ot1 & mask58) + (ot0>>58);
    uint64x3_t out2 = (ot2 & mask58) + (ot1>>58);

    *(uint64x4_t *)&c[0] = out0;
    *(uint64x4_t *)&c[4] = out1;
    *(uint64x4_t *)&c[8] = out2;
}

void
p521_mulw (
    p521_t *__restrict__ cs,
    const p521_t *as,
    uint64_t b
) {
    
    

#if 0
    int i;
    assert(as->limb[3] == 0 && as->limb[7] == 0 && as->limb[11] == 0);
    for (i=0; i<12; i++) {
        assert(as->limb[i] < 1ull<<61);
    }
    assert(b < 1ull<<61);
#endif
    
    
    const uint64_t *a = as->limb;
    uint64_t *c = cs->limb;

    __uint128_t accum0 = 0, accum3 = 0, accum6 = 0;
    uint64_t mask = (1ull<<58) - 1;

    accum0 += widemulu(b, a[0]);
    accum3 += widemulu(b, a[1]);
    accum6 += widemulu(b, a[2]);
    c[0] = accum0 & mask; accum0 >>= 58;
    c[1] = accum3 & mask; accum3 >>= 58;
    c[2] = accum6 & mask; accum6 >>= 58;

    accum0 += widemulu(b, a[4]);
    accum3 += widemulu(b, a[5]);
    accum6 += widemulu(b, a[6]);
    c[4] = accum0 & mask; accum0 >>= 58;
    c[5] = accum3 & mask; accum3 >>= 58;
    c[6] = accum6 & mask; accum6 >>= 58;

    accum0 += widemulu(b, a[8]);
    accum3 += widemulu(b, a[9]);
    accum6 += widemulu(b, a[10]);
    c[8] = accum0 & mask; accum0 >>= 58;
    c[9] = accum3 & mask; accum3 >>= 58;
    c[10] = accum6 & (mask>>1); accum6 >>= 57;
    
    accum0 += c[1];
    c[1] = accum0 & mask;
    c[5] += accum0 >> 58;

    accum3 += c[2];
    c[2] = accum3 & mask;
    c[6] += accum3 >> 58;

    accum6 += c[0];
    c[0] = accum6 & mask;
    c[4] += accum6 >> 58;
    
    c[3] = c[7] = c[11] = 0;
}


void
p521_strong_reduce (
    p521_t *a
) {
    uint64_t mask = (1ull<<58)-1, mask2 = (1ull<<57)-1;

    /* first, clear high */
    __int128_t scarry = a->limb[LIMBPERM(8)]>>57;
    a->limb[LIMBPERM(8)] &= mask2;

    /* now the total is less than 2p */

    /* compute total_value - p.  No need to reduce mod p. */

    int i;
    for (i=0; i<9; i++) {
        scarry = scarry + a->limb[LIMBPERM(i)] - ((i==8) ? mask2 : mask);
        a->limb[LIMBPERM(i)] = scarry & ((i==8) ? mask2 : mask);
        scarry >>= (i==8) ? 57 : 58;
    }

    /* uncommon case: it was >= p, so now scarry = 0 and this = x
    * common case: it was < p, so now scarry = -1 and this = x - p + 2^521
    * so let's add back in p.  will carry back off the top for 2^521.
    */

    assert(is_zero(scarry) | is_zero(scarry+1));

    uint64_t scarry_mask = scarry & mask;
    __uint128_t carry = 0;

    /* add it back */
    for (i=0; i<9; i++) {
        carry = carry + a->limb[LIMBPERM(i)] + ((i==8)?(scarry_mask>>1):scarry_mask);
        a->limb[LIMBPERM(i)] = carry & ((i==8) ? mask>>1 : mask);
        carry >>= (i==8) ? 57 : 58;
    }

    assert(is_zero(carry + scarry));

    a->limb[3] = a->limb[7] = a->limb[11] = 0;
}

mask_t
p521_is_zero (
    const struct p521_t *a
) {
    struct p521_t b;
    p521_copy(&b,a);
    p521_strong_reduce(&b);

    uint64_t any = 0;
    unsigned int i;
    for (i=0; i<sizeof(b)/sizeof(b.limb[0]); i++) {
        any |= b.limb[i];
    }
    return is_zero(any);
}

void
p521_serialize (
    uint8_t *serial,
    const struct p521_t *x
) {
    unsigned int i,k=0;
    p521_t red;
    p521_copy(&red, x);
    p521_strong_reduce(&red);
    
    uint64_t r=0;
    int bits = 0;
    for (i=0; i<9; i++) {
        r |= red.limb[LIMBPERM(i)] << bits;
        for (bits += 58; bits >= 8; bits -= 8) {
            serial[k++] = r;
            r >>= 8;
        }
        assert(bits <= 6);
    }
    assert(bits);
    serial[k++] = r;
}

mask_t
p521_deserialize (
    p521_t *x,
    const uint8_t serial[LIMBPERM(66)]
) {
    int i,k=0,bits=0;
    __uint128_t out = 0;
    uint64_t mask = (1ull<<58)-1;
    for (i=0; i<9; i++) {
        out >>= 58;
        for (; bits<58; bits+=8) {
            out |= ((__uint128_t)serial[k++])<<bits;
        }
        x->limb[LIMBPERM(i)] = out & mask;
        bits -= 58;
    }
    
    /* Check for reduction.  First, high has to be < 2^57 */
    mask_t good = is_zero(out>>57);
    
    uint64_t and = -1ull;
    for (i=0; i<8; i++) {
        and &= x->limb[LIMBPERM(i)];
    }
    and &= (2*out+1);
    good &= is_zero((and+1)>>58);

    x->limb[3] = x->limb[7] = x->limb[11] = 0;
    
    return good;
}
