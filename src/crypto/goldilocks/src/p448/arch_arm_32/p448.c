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

static inline void __attribute__((gnu_inline,always_inline))
smlal (
    uint64_t *acc,
    const uint32_t a,
    const uint32_t b
) {

#ifdef  __ARMEL__
    uint32_t lo = *acc, hi = (*acc)>>32;
    
    __asm__ __volatile__ ("smlal %[lo], %[hi], %[a], %[b]"
        : [lo]"+&r"(lo), [hi]"+&r"(hi)
        : [a]"r"(a), [b]"r"(b));
    
    *acc = lo + (((uint64_t)hi)<<32);
#else
    *acc += (int64_t)(int32_t)a * (int64_t)(int32_t)b;
#endif
}

static inline void __attribute__((gnu_inline,always_inline))
smlal2 (
    uint64_t *acc,
    const uint32_t a,
    const uint32_t b
) {
#ifdef __ARMEL__
    uint32_t lo = *acc, hi = (*acc)>>32;
    
    __asm__ __volatile__ ("smlal %[lo], %[hi], %[a], %[b]"
        : [lo]"+&r"(lo), [hi]"+&r"(hi)
        : [a]"r"(a), [b]"r"(2*b));
    
    *acc = lo + (((uint64_t)hi)<<32);
#else
    *acc += (int64_t)(int32_t)a * (int64_t)(int32_t)(b * 2);
#endif
}

static inline void __attribute__((gnu_inline,always_inline))
smull (
    uint64_t *acc,
    const uint32_t a,
    const uint32_t b
) {
#ifdef __ARMEL__
    uint32_t lo, hi;
    
    __asm__ __volatile__ ("smull %[lo], %[hi], %[a], %[b]"
        : [lo]"=&r"(lo), [hi]"=&r"(hi)
        : [a]"r"(a), [b]"r"(b));
    
    *acc = lo + (((uint64_t)hi)<<32);
#else
    *acc = (int64_t)(int32_t)a * (int64_t)(int32_t)b;
#endif
}

static inline void __attribute__((gnu_inline,always_inline))
smull2 (
    uint64_t *acc,
    const uint32_t a,
    const uint32_t b
) {
#ifdef __ARMEL__
    uint32_t lo, hi;
    
    __asm__ /*__volatile__*/ ("smull %[lo], %[hi], %[a], %[b]"
        : [lo]"=&r"(lo), [hi]"=&r"(hi)
        : [a]"r"(a), [b]"r"(2*b));
    
    *acc = lo + (((uint64_t)hi)<<32);
#else
    *acc = (int64_t)(int32_t)a * (int64_t)(int32_t)(b * 2);
#endif
}

void
p448_mul (
    p448_t *__restrict__ cs,
    const p448_t *as,
    const p448_t *bs
) {
    
    const uint32_t *a = as->limb, *b = bs->limb;
    uint32_t *c = cs->limb;

    uint64_t accum0 = 0, accum1 = 0, accum2, accum3, accumC0, accumC1;
    uint32_t mask = (1<<28) - 1;  

    uint32_t aa[8], bm[8];

    int i;
    for (i=0; i<8; i++) {
        aa[i] = a[i] + a[i+8];
        bm[i] = b[i] - b[i+8];
    }

    uint32_t ax,bx;
    {
        /* t^3 terms */
        smull(&accum1, ax = aa[1], bx = b[15]);
        smull(&accum3, ax = aa[2], bx);
        smlal(&accum1, ax, bx = b[14]);
        smlal(&accum3, ax = aa[3], bx);
        smlal(&accum1, ax, bx = b[13]);
        smlal(&accum3, ax = aa[4], bx);
        smlal(&accum1, ax, bx = b[12]);
        smlal(&accum3, ax = aa[5], bx);
        smlal(&accum1, ax, bx = b[11]);
        smlal(&accum3, ax = aa[6], bx);
        smlal(&accum1, ax, bx = b[10]);
        smlal(&accum3, ax = aa[7], bx);
        smlal(&accum1, ax, bx = b[9]);
        
        accum0 = accum1;
        accum2 = accum3;
        
        /* t^2 terms */
        smlal(&accum2, ax = aa[0], bx);
        smlal(&accum0, ax, bx = b[8]);
        smlal(&accum2, ax = aa[1], bx);
        
        smlal(&accum0, ax = a[9], bx = b[7]);
        smlal(&accum2, ax = a[10], bx);
        smlal(&accum0, ax, bx = b[6]);
        smlal(&accum2, ax = a[11], bx);
        smlal(&accum0, ax, bx = b[5]);
        smlal(&accum2, ax = a[12], bx);
        smlal(&accum0, ax, bx = b[4]);
        smlal(&accum2, ax = a[13], bx);
        smlal(&accum0, ax, bx = b[3]);
        smlal(&accum2, ax = a[14], bx);
        smlal(&accum0, ax, bx = b[2]);
        smlal(&accum2, ax = a[15], bx);
        smlal(&accum0, ax, bx = b[1]);
        
        /* t terms */
        accum1 += accum0;
        accum3 += accum2;
        smlal(&accum3, ax = a[8], bx);
        smlal(&accum1, ax, bx = b[0]);
        smlal(&accum3, ax = a[9], bx);
        
        smlal(&accum1, ax = a[1], bx = bm[7]);
        smlal(&accum3, ax = a[2], bx);
        smlal(&accum1, ax, bx = bm[6]);
        smlal(&accum3, ax = a[3], bx);
        smlal(&accum1, ax, bx = bm[5]);
        smlal(&accum3, ax = a[4], bx);
        smlal(&accum1, ax, bx = bm[4]);
        smlal(&accum3, ax = a[5], bx);
        smlal(&accum1, ax, bx = bm[3]);
        smlal(&accum3, ax = a[6], bx);
        smlal(&accum1, ax, bx = bm[2]);
        smlal(&accum3, ax = a[7], bx);
        smlal(&accum1, ax, bx = bm[1]);
        
        /* 1 terms */
        smlal(&accum2, ax = a[0], bx);
        smlal(&accum0, ax, bx = bm[0]);
        smlal(&accum2, ax = a[1], bx);
        
        accum2 += accum0 >> 28;
        accum3 += accum1 >> 28;
        
        c[0] = ((uint32_t)(accum0)) & mask;
        c[1] = ((uint32_t)(accum2)) & mask;
        c[8] = ((uint32_t)(accum1)) & mask;
        c[9] = ((uint32_t)(accum3)) & mask;
        
        accumC0 = accum2 >> 28;
        accumC1 = accum3 >> 28;
    }
    {
        /* t^3 terms */
        smull(&accum1, ax = aa[3], bx = b[15]);
        smull(&accum3, ax = aa[4], bx);
        smlal(&accum1, ax, bx = b[14]);
        smlal(&accum3, ax = aa[5], bx);
        smlal(&accum1, ax, bx = b[13]);
        smlal(&accum3, ax = aa[6], bx);
        smlal(&accum1, ax, bx = b[12]);
        smlal(&accum3, ax = aa[7], bx);
        smlal(&accum1, ax, bx = b[11]);
        
        accum0 = accum1;
        accum2 = accum3;
        
        /* t^2 terms */
        smlal(&accum2, ax = aa[0], bx);
        smlal(&accum0, ax, bx = b[10]);
        smlal(&accum2, ax = aa[1], bx);
        smlal(&accum0, ax, bx = b[9]);
        smlal(&accum2, ax = aa[2], bx);
        smlal(&accum0, ax, bx = b[8]);
        smlal(&accum2, ax = aa[3], bx);
        
        smlal(&accum0, ax = a[11], bx = b[7]);
        smlal(&accum2, ax = a[12], bx);
        smlal(&accum0, ax, bx = b[6]);
        smlal(&accum2, ax = a[13], bx);
        smlal(&accum0, ax, bx = b[5]);
        smlal(&accum2, ax = a[14], bx);
        smlal(&accum0, ax, bx = b[4]);
        smlal(&accum2, ax = a[15], bx);
        smlal(&accum0, ax, bx = b[3]);
        
        /* t terms */
        accum1 += accum0;
        accum3 += accum2;
        smlal(&accum3, ax = a[8], bx);
        smlal(&accum1, ax, bx = b[2]);
        smlal(&accum3, ax = a[9], bx);
        smlal(&accum1, ax, bx = b[1]);
        smlal(&accum3, ax = a[10], bx);
        smlal(&accum1, ax, bx = b[0]);
        smlal(&accum3, ax = a[11], bx);
        
        smlal(&accum1, ax = a[3], bx = bm[7]);
        smlal(&accum3, ax = a[4], bx);
        smlal(&accum1, ax, bx = bm[6]);
        smlal(&accum3, ax = a[5], bx);
        smlal(&accum1, ax, bx = bm[5]);
        smlal(&accum3, ax = a[6], bx);
        smlal(&accum1, ax, bx = bm[4]);
        smlal(&accum3, ax = a[7], bx);
        smlal(&accum1, ax, bx = bm[3]);
        
        /* 1 terms */
        smlal(&accum2, ax = a[0], bx);
        smlal(&accum0, ax, bx = bm[2]);
        smlal(&accum2, ax = a[1], bx);
        smlal(&accum0, ax, bx = bm[1]);
        smlal(&accum2, ax = a[2], bx);
        smlal(&accum0, ax, bx = bm[0]);
        smlal(&accum2, ax = a[3], bx);
        
        accum0 += accumC0;
        accum1 += accumC1;
        accum2 += accum0 >> 28;
        accum3 += accum1 >> 28;
        
        c[2] = ((uint32_t)(accum0)) & mask;
        c[3] = ((uint32_t)(accum2)) & mask;
        c[10] = ((uint32_t)(accum1)) & mask;
        c[11] = ((uint32_t)(accum3)) & mask;
        
        accumC0 = accum2 >> 28;
        accumC1 = accum3 >> 28;
    }
    {
        
        /* t^3 terms */
        smull(&accum1, ax = aa[5], bx = b[15]);
        smull(&accum3, ax = aa[6], bx);
        smlal(&accum1, ax, bx = b[14]);
        smlal(&accum3, ax = aa[7], bx);
        smlal(&accum1, ax, bx = b[13]);
        
        accum0 = accum1;
        accum2 = accum3;
        
        /* t^2 terms */
        
        smlal(&accum2, ax = aa[0], bx);
        smlal(&accum0, ax, bx = b[12]);
        smlal(&accum2, ax = aa[1], bx);
        smlal(&accum0, ax, bx = b[11]);
        smlal(&accum2, ax = aa[2], bx);
        smlal(&accum0, ax, bx = b[10]);
        smlal(&accum2, ax = aa[3], bx);
        smlal(&accum0, ax, bx = b[9]);
        smlal(&accum2, ax = aa[4], bx);
        smlal(&accum0, ax, bx = b[8]);
        smlal(&accum2, ax = aa[5], bx);
        
        
        smlal(&accum0, ax = a[13], bx = b[7]);
        smlal(&accum2, ax = a[14], bx);
        smlal(&accum0, ax, bx = b[6]);
        smlal(&accum2, ax = a[15], bx);
        smlal(&accum0, ax, bx = b[5]);
        
        /* t terms */
        accum1 += accum0;
        accum3 += accum2;
        
        smlal(&accum3, ax = a[8], bx);
        smlal(&accum1, ax, bx = b[4]);
        smlal(&accum3, ax = a[9], bx);
        smlal(&accum1, ax, bx = b[3]);
        smlal(&accum3, ax = a[10], bx);
        smlal(&accum1, ax, bx = b[2]);
        smlal(&accum3, ax = a[11], bx);
        smlal(&accum1, ax, bx = b[1]);
        smlal(&accum3, ax = a[12], bx);
        smlal(&accum1, ax, bx = b[0]);
        smlal(&accum3, ax = a[13], bx);
        
        
        smlal(&accum1, ax = a[5], bx = bm[7]);
        smlal(&accum3, ax = a[6], bx);
        smlal(&accum1, ax, bx = bm[6]);
        smlal(&accum3, ax = a[7], bx);
        smlal(&accum1, ax, bx = bm[5]);
        
        /* 1 terms */
        
        smlal(&accum2, ax = a[0], bx);
        smlal(&accum0, ax, bx = bm[4]);
        smlal(&accum2, ax = a[1], bx);
        smlal(&accum0, ax, bx = bm[3]);
        smlal(&accum2, ax = a[2], bx);
        smlal(&accum0, ax, bx = bm[2]);
        smlal(&accum2, ax = a[3], bx);
        smlal(&accum0, ax, bx = bm[1]);
        smlal(&accum2, ax = a[4], bx);
        smlal(&accum0, ax, bx = bm[0]);
        smlal(&accum2, ax = a[5], bx);
        
        accum0 += accumC0;
        accum1 += accumC1;
        accum2 += accum0 >> 28;
        accum3 += accum1 >> 28;
        
        c[4] = ((uint32_t)(accum0)) & mask;
        c[5] = ((uint32_t)(accum2)) & mask;
        c[12] = ((uint32_t)(accum1)) & mask;
        c[13] = ((uint32_t)(accum3)) & mask;
        
        accumC0 = accum2 >> 28;
        accumC1 = accum3 >> 28;
    }
    {
        
        /* t^3 terms */
        smull(&accum1, ax = aa[7], bx = b[15]);
        accum0 = accum1;
        
        /* t^2 terms */
        
        smull(&accum2, ax = aa[0], bx);
        smlal(&accum0, ax, bx = b[14]);
        smlal(&accum2, ax = aa[1], bx);
        smlal(&accum0, ax, bx = b[13]);
        smlal(&accum2, ax = aa[2], bx);
        smlal(&accum0, ax, bx = b[12]);
        smlal(&accum2, ax = aa[3], bx);
        smlal(&accum0, ax, bx = b[11]);
        smlal(&accum2, ax = aa[4], bx);
        smlal(&accum0, ax, bx = b[10]);
        smlal(&accum2, ax = aa[5], bx);
        smlal(&accum0, ax, bx = b[9]);
        smlal(&accum2, ax = aa[6], bx);
        smlal(&accum0, ax, bx = b[8]);
        smlal(&accum2, ax = aa[7], bx);
        
        
        smlal(&accum0, ax = a[15], bx = b[7]);
        
        /* t terms */
        accum1 += accum0;
        accum3 = accum2;
        
        smlal(&accum3, ax = a[8], bx);
        smlal(&accum1, ax, bx = b[6]);
        smlal(&accum3, ax = a[9], bx);
        smlal(&accum1, ax, bx = b[5]);
        smlal(&accum3, ax = a[10], bx);
        smlal(&accum1, ax, bx = b[4]);
        smlal(&accum3, ax = a[11], bx);
        smlal(&accum1, ax, bx = b[3]);
        smlal(&accum3, ax = a[12], bx);
        smlal(&accum1, ax, bx = b[2]);
        smlal(&accum3, ax = a[13], bx);
        smlal(&accum1, ax, bx = b[1]);
        smlal(&accum3, ax = a[14], bx);
        smlal(&accum1, ax, bx = b[0]);
        smlal(&accum3, ax = a[15], bx);
        
        
        smlal(&accum1, ax = a[7], bx = bm[7]);
        
        /* 1 terms */
        
        smlal(&accum2, ax = a[0], bx);
        smlal(&accum0, ax, bx = bm[6]);
        smlal(&accum2, ax = a[1], bx);
        smlal(&accum0, ax, bx = bm[5]);
        smlal(&accum2, ax = a[2], bx);
        smlal(&accum0, ax, bx = bm[4]);
        smlal(&accum2, ax = a[3], bx);
        smlal(&accum0, ax, bx = bm[3]);
        smlal(&accum2, ax = a[4], bx);
        smlal(&accum0, ax, bx = bm[2]);
        smlal(&accum2, ax = a[5], bx);
        smlal(&accum0, ax, bx = bm[1]);
        smlal(&accum2, ax = a[6], bx);
        smlal(&accum0, ax, bx = bm[0]);
        smlal(&accum2, ax = a[7], bx);
        
        accum0 += accumC0;
        accum1 += accumC1;
        accum2 += accum0 >> 28;
        accum3 += accum1 >> 28;
        
        c[6] = ((uint32_t)(accum0)) & mask;
        c[7] = ((uint32_t)(accum2)) & mask;
        c[14] = ((uint32_t)(accum1)) & mask;
        c[15] = ((uint32_t)(accum3)) & mask;
        
        accum0 = accum2 >> 28;
        accum1 = accum3 >> 28;
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
p448_sqr (
    p448_t *__restrict__ cs,
    const p448_t *as
) {
    const uint32_t *a = as->limb;
    uint32_t *c = cs->limb;

    uint64_t accum0 = 0, accum1 = 0, accum2, accum3, accumC0, accumC1, tmp;
    uint32_t mask = (1<<28) - 1;  

    uint32_t bm[8];
    
    int i;
    for (i=0; i<8; i++) {
        bm[i] = a[i] - a[i+8];
    }

    uint32_t ax,bx;
    {
        /* t^3 terms */
        smull2(&accum1, ax = a[9], bx = a[15]);
        smull2(&accum3, ax = a[10], bx);
        smlal2(&accum1, ax, bx = a[14]);
        smlal2(&accum3, ax = a[11], bx);
        smlal2(&accum1, ax, bx = a[13]);
        smlal2(&accum3, ax = a[12], bx);
        smlal(&accum1, ax, ax);
        
        accum0 = accum1;
        accum2 = accum3;
        
        /* t^2 terms */
        smlal2(&accum2, ax = a[8], a[9]);
        smlal(&accum0, ax, ax);
        
        smlal2(&accum0, ax = a[1], bx = a[7]);
        smlal2(&accum2, ax = a[2], bx);
        smlal2(&accum0, ax, bx = a[6]);
        smlal2(&accum2, ax = a[3], bx);
        smlal2(&accum0, ax, bx = a[5]);
        smlal2(&accum2, ax = a[4], bx);
        smlal(&accum0, ax, ax);
        
        /* t terms */
        accum1 += accum0;
        accum3 += accum2;
        smlal2(&accum3, ax = a[0], bx = a[1]);
        smlal(&accum1, ax, ax);
        
        accum1 = -accum1;
        accum3 = -accum3;
        accum2 = -accum2;
        accum0 = -accum0;
        
        smlal2(&accum1, ax = bm[1], bx = bm[7]);
        smlal2(&accum3, ax = bm[2], bx);
        smlal2(&accum1, ax, bx = bm[6]);
        smlal2(&accum3, ax = bm[3], bx);
        smlal2(&accum1, ax, bx = bm[5]);
        smlal2(&accum3, ax = bm[4], bx);
        smlal(&accum1, ax, ax);
        
        /* 1 terms */
        smlal2(&accum2, ax = bm[0], bx = bm[1]);
        smlal(&accum0, ax, ax);
        
        tmp = -accum3; accum3 = tmp-accum2; accum2 = tmp;
        tmp = -accum1; accum1 = tmp-accum0; accum0 = tmp;
        
        accum2 += accum0 >> 28;
        accum3 += accum1 >> 28;
        
        c[0] = ((uint32_t)(accum0)) & mask;
        c[1] = ((uint32_t)(accum2)) & mask;
        c[8] = ((uint32_t)(accum1)) & mask;
        c[9] = ((uint32_t)(accum3)) & mask;
        
        accumC0 = accum2 >> 28;
        accumC1 = accum3 >> 28;
    }
    {
        /* t^3 terms */
        smull2(&accum1, ax = a[11], bx = a[15]);
        smull2(&accum3, ax = a[12], bx);
        smlal2(&accum1, ax, bx = a[14]);
        smlal2(&accum3, ax = a[13], bx);
        smlal(&accum1, ax, ax);
        
        accum0 = accum1;
        accum2 = accum3;
        
        /* t^2 terms */
        smlal2(&accum2, ax = a[8], bx = a[11]);
        smlal2(&accum0, ax, bx = a[10]);
        smlal2(&accum2, ax = a[9], bx);
        smlal(&accum0, ax, ax);
        
        smlal2(&accum0, ax = a[3], bx = a[7]);
        smlal2(&accum2, ax = a[4], bx);
        smlal2(&accum0, ax, bx = a[6]);
        smlal2(&accum2, ax = a[5], bx);
        smlal(&accum0, ax, ax);
        
        /* t terms */
        accum1 += accum0;
        accum3 += accum2;
        smlal2(&accum3, ax = a[0], bx = a[3]);
        smlal2(&accum1, ax, bx = a[2]);
        smlal2(&accum3, ax = a[1], bx);
        smlal(&accum1, ax, ax);
        
        accum1 = -accum1;
        accum3 = -accum3;
        accum2 = -accum2;
        accum0 = -accum0;
        
        smlal2(&accum1, ax = bm[3], bx = bm[7]);
        smlal2(&accum3, ax = bm[4], bx);
        smlal2(&accum1, ax, bx = bm[6]);
        smlal2(&accum3, ax = bm[5], bx);
        smlal(&accum1, ax, ax);
        
        /* 1 terms */
        smlal2(&accum2, ax = bm[0], bx = bm[3]);
        smlal2(&accum0, ax, bx = bm[2]);
        smlal2(&accum2, ax = bm[1], bx);
        smlal(&accum0, ax, ax);
        
        
        tmp = -accum3; accum3 = tmp-accum2; accum2 = tmp;
        tmp = -accum1; accum1 = tmp-accum0; accum0 = tmp;
        
        accum0 += accumC0;
        accum1 += accumC1;
        accum2 += accum0 >> 28;
        accum3 += accum1 >> 28;
        
        c[2] = ((uint32_t)(accum0)) & mask;
        c[3] = ((uint32_t)(accum2)) & mask;
        c[10] = ((uint32_t)(accum1)) & mask;
        c[11] = ((uint32_t)(accum3)) & mask;
        
        accumC0 = accum2 >> 28;
        accumC1 = accum3 >> 28;
    }
    {
        
        /* t^3 terms */
        smull2(&accum1, ax = a[13], bx = a[15]);
        smull2(&accum3, ax = a[14], bx);
        smlal(&accum1, ax, ax);
        
        accum0 = accum1;
        accum2 = accum3;
        
        /* t^2 terms */
        
        smlal2(&accum2, ax = a[8], bx = a[13]);
        smlal2(&accum0, ax, bx = a[12]);
        smlal2(&accum2, ax = a[9], bx);
        smlal2(&accum0, ax, bx = a[11]);
        smlal2(&accum2, ax = a[10], bx);
        smlal(&accum0, ax, ax);
        
        
        smlal2(&accum0, ax = a[5], bx = a[7]);
        smlal2(&accum2, ax = a[6], bx);
        smlal(&accum0, ax, ax);
        
        /* t terms */
        accum1 += accum0;
        accum3 += accum2;
        
        smlal2(&accum3, ax = a[0], bx = a[5]);
        smlal2(&accum1, ax, bx = a[4]);
        smlal2(&accum3, ax = a[1], bx);
        smlal2(&accum1, ax, bx = a[3]);
        smlal2(&accum3, ax = a[2], bx);
        smlal(&accum1, ax, ax);
        
        accum1 = -accum1;
        accum3 = -accum3;
        accum2 = -accum2;
        accum0 = -accum0;
        
        smlal2(&accum1, ax = bm[5], bx = bm[7]);
        smlal2(&accum3, ax = bm[6], bx);
        smlal(&accum1, ax, ax);
        
        /* 1 terms */
        
        smlal2(&accum2, ax = bm[0], bx = bm[5]);
        smlal2(&accum0, ax, bx = bm[4]);
        smlal2(&accum2, ax = bm[1], bx);
        smlal2(&accum0, ax, bx = bm[3]);
        smlal2(&accum2, ax = bm[2], bx);
        smlal(&accum0, ax, ax);
        
        
        tmp = -accum3; accum3 = tmp-accum2; accum2 = tmp;
        tmp = -accum1; accum1 = tmp-accum0; accum0 = tmp;
        
        accum0 += accumC0;
        accum1 += accumC1;
        accum2 += accum0 >> 28;
        accum3 += accum1 >> 28;
        
        c[4] = ((uint32_t)(accum0)) & mask;
        c[5] = ((uint32_t)(accum2)) & mask;
        c[12] = ((uint32_t)(accum1)) & mask;
        c[13] = ((uint32_t)(accum3)) & mask;
        
        accumC0 = accum2 >> 28;
        accumC1 = accum3 >> 28;
    }
    {
        
        /* t^3 terms */
        smull(&accum1, ax = a[15], bx = a[15]);
        accum0 = accum1;
        
        /* t^2 terms */
        
        smull2(&accum2, ax = a[8], bx);
        smlal2(&accum0, ax, bx = a[14]);
        smlal2(&accum2, ax = a[9], bx);
        smlal2(&accum0, ax, bx = a[13]);
        smlal2(&accum2, ax = a[10], bx);
        smlal2(&accum0, ax, bx = a[12]);
        smlal2(&accum2, ax = a[11], bx);
        smlal(&accum0, ax, ax);
        
        
        smlal(&accum0, ax = a[7], bx = a[7]);
        
        /* t terms */
        accum1 += accum0;
        accum3 = accum2;
        
        smlal2(&accum3, ax = a[0], bx);
        smlal2(&accum1, ax, bx = a[6]);
        smlal2(&accum3, ax = a[1], bx);
        smlal2(&accum1, ax, bx = a[5]);
        smlal2(&accum3, ax = a[2], bx);
        smlal2(&accum1, ax, bx = a[4]);
        smlal2(&accum3, ax = a[3], bx);
        smlal(&accum1, ax, ax);
        
        accum1 = -accum1;
        accum3 = -accum3;
        accum2 = -accum2;
        accum0 = -accum0;
        
        bx = bm[7];
        smlal(&accum1, bx, bx);
        
        /* 1 terms */
        
        smlal2(&accum2, ax = bm[0], bx);
        smlal2(&accum0, ax, bx = bm[6]);
        smlal2(&accum2, ax = bm[1], bx);
        smlal2(&accum0, ax, bx = bm[5]);
        smlal2(&accum2, ax = bm[2], bx);
        smlal2(&accum0, ax, bx = bm[4]);
        smlal2(&accum2, ax = bm[3], bx);
        smlal(&accum0, ax, ax);
        
        tmp = -accum3; accum3 = tmp-accum2; accum2 = tmp;
        tmp = -accum1; accum1 = tmp-accum0; accum0 = tmp;
        
        
        accum0 += accumC0;
        accum1 += accumC1;
        accum2 += accum0 >> 28;
        accum3 += accum1 >> 28;
        
        c[6] = ((uint32_t)(accum0)) & mask;
        c[7] = ((uint32_t)(accum2)) & mask;
        c[14] = ((uint32_t)(accum1)) & mask;
        c[15] = ((uint32_t)(accum3)) & mask;
        
        accum0 = accum2 >> 28;
        accum1 = accum3 >> 28;
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
    uint32_t mask = (1ull<<28)-1;  
    const uint32_t bhi = b>>28, blo = b & mask;
    
    const uint32_t *a = as->limb;
    uint32_t *c = cs->limb;

    uint64_t accum0, accum8;

    int i;

    uint32_t c0, c8, n0, n8;
    accum0 = widemul_32(bhi, a[15]);
    accum8 = widemul_32(bhi, a[15] + a[7]);
    c0 = a[0]; c8 = a[8];
    smlal(&accum0, blo, c0);
    smlal(&accum8, blo, c8);

    c[0] = accum0 & mask; accum0 >>= 28;
    c[8] = accum8 & mask; accum8 >>= 28;
    
    i=1;
    {
        n0 = a[i]; n8 = a[i+8];
        smlal(&accum0, bhi, c0);
        smlal(&accum8, bhi, c8);
        smlal(&accum0, blo, n0);
        smlal(&accum8, blo, n8);
        
        c[i] = accum0 & mask; accum0 >>= 28;
        c[i+8] = accum8 & mask; accum8 >>= 28;
        i++;
    }
    {
        c0 = a[i]; c8 = a[i+8];
        smlal(&accum0, bhi, n0);
        smlal(&accum8, bhi, n8);
        smlal(&accum0, blo, c0);
        smlal(&accum8, blo, c8);

        c[i] = accum0 & mask; accum0 >>= 28;
        c[i+8] = accum8 & mask; accum8 >>= 28;
        i++;
    }
    {
        n0 = a[i]; n8 = a[i+8];
        smlal(&accum0, bhi, c0);
        smlal(&accum8, bhi, c8);
        smlal(&accum0, blo, n0);
        smlal(&accum8, blo, n8);

        c[i] = accum0 & mask; accum0 >>= 28;
        c[i+8] = accum8 & mask; accum8 >>= 28;
        i++;
    }
    {
        c0 = a[i]; c8 = a[i+8];
        smlal(&accum0, bhi, n0);
        smlal(&accum8, bhi, n8);
        smlal(&accum0, blo, c0);
        smlal(&accum8, blo, c8);

        c[i] = accum0 & mask; accum0 >>= 28;
        c[i+8] = accum8 & mask; accum8 >>= 28;
        i++;
    }
    {
        n0 = a[i]; n8 = a[i+8];
        smlal(&accum0, bhi, c0);
        smlal(&accum8, bhi, c8);
        smlal(&accum0, blo, n0);
        smlal(&accum8, blo, n8);

        c[i] = accum0 & mask; accum0 >>= 28;
        c[i+8] = accum8 & mask; accum8 >>= 28;
        i++;
    }
    {
        c0 = a[i]; c8 = a[i+8];
        smlal(&accum0, bhi, n0);
        smlal(&accum8, bhi, n8);
        smlal(&accum0, blo, c0);
        smlal(&accum8, blo, c8);
        
        c[i] = accum0 & mask; accum0 >>= 28;
        c[i+8] = accum8 & mask; accum8 >>= 28;
        i++;
    }
    {
        n0 = a[i]; n8 = a[i+8];
        smlal(&accum0, bhi, c0);
        smlal(&accum8, bhi, c8);
        smlal(&accum0, blo, n0);
        smlal(&accum8, blo, n8);

        c[i] = accum0 & mask; accum0 >>= 28;
        c[i+8] = accum8 & mask; accum8 >>= 28;
        i++;
    }

    accum0 += accum8 + c[8];
    c[8] = accum0 & mask;
    c[9] += accum0 >> 28;

    accum8 += c[0];
    c[0] = accum8 & mask;
    c[1] += accum8 >> 28;
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
