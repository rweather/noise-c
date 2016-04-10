/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */
#ifndef __P448_H__
#define __P448_H__ 1

#include "word.h"

#include <stdint.h>
#include <assert.h>

typedef struct p448_t {
  uint32_t limb[16];
} __attribute__((aligned(32))) p448_t;

#define LIMBPERM(x) (((x)<<1 | (x)>>3) & 15)
#define USE_NEON_PERM 1

#ifdef __cplusplus
extern "C" {
#endif

static __inline__ void
p448_set_ui (
    p448_t *out,
    uint64_t x
) __attribute__((unused,always_inline));

static __inline__ void
p448_add_RAW (
    p448_t *out,
    const p448_t *a,
    const p448_t *b
) __attribute__((unused,always_inline));
             
static __inline__ void
p448_sub_RAW (
    p448_t *out,
    const p448_t *a,
    const p448_t *b
) __attribute__((unused,always_inline));
             
static __inline__ void
p448_neg_RAW (
    p448_t *out,
    const p448_t *a
) __attribute__((unused,always_inline));

static __inline__ void
p448_addw (
    p448_t *a,
    uint32_t x
) __attribute__((unused,always_inline));
             
static __inline__ void
p448_subw (
    p448_t *a,
    uint32_t x
) __attribute__((unused,always_inline));
             
static __inline__ void
p448_copy (
    p448_t *out,
    const p448_t *a
) __attribute__((unused,always_inline));
             
static __inline__ void
p448_weak_reduce (
    p448_t *inout
) __attribute__((unused,always_inline));
             
void
p448_strong_reduce (
    p448_t *inout
);

mask_t
p448_is_zero (
    const p448_t *in
);
             
static __inline__ void
p448_bias (
    p448_t *inout,
    int amount
) __attribute__((unused,always_inline));

void
p448_mul (
    p448_t *__restrict__ out,
    const p448_t *a,
    const p448_t *b
);

void
p448_mulw (
    p448_t *__restrict__ out,
    const p448_t *a,
    uint64_t b
);

void
p448_sqr (
    p448_t *__restrict__ out,
    const p448_t *a
);

void
p448_serialize (
    uint8_t *serial,
    const struct p448_t *x
);

mask_t
p448_deserialize (
    p448_t *x,
    const uint8_t serial[56]
);

/* -------------- Inline functions begin here -------------- */

void
p448_set_ui (
    p448_t *out,
    uint64_t x
) {
    int i;
    for (i=0; i<16; i++) {
      out->limb[i] = 0;
    }
    out->limb[0] = x & ((1<<28)-1);
    out->limb[2] = x>>28;
}

void
p448_add_RAW (
    p448_t *out,
    const p448_t *a,
    const p448_t *b
) {
    unsigned int i;
    for (i=0; i<sizeof(*out)/sizeof(uint32xn_t); i++) {
        ((uint32xn_t*)out)[i] = ((const uint32xn_t*)a)[i] + ((const uint32xn_t*)b)[i];
    }
}

void
p448_sub_RAW (
    p448_t *out,
    const p448_t *a,
    const p448_t *b
) {
    unsigned int i;
    for (i=0; i<sizeof(*out)/sizeof(uint32xn_t); i++) {
        ((uint32xn_t*)out)[i] = ((const uint32xn_t*)a)[i] - ((const uint32xn_t*)b)[i];
    }
    /*
    unsigned int i;
    for (i=0; i<sizeof(*out)/sizeof(out->limb[0]); i++) {
        out->limb[i] = a->limb[i] - b->limb[i];
    }
    */
}

void
p448_neg_RAW (
    p448_t *out,
    const p448_t *a
) {
    unsigned int i;
    for (i=0; i<sizeof(*out)/sizeof(uint32xn_t); i++) {
        ((uint32xn_t*)out)[i] = -((const uint32xn_t*)a)[i];
    }
    /*
    unsigned int i;
    for (i=0; i<sizeof(*out)/sizeof(out->limb[0]); i++) {
        out->limb[i] = -a->limb[i];
    }
    */
}

void
p448_addw (
    p448_t *a,
    uint32_t x
) {
  a->limb[0] += x;
}
             
void
p448_subw (
    p448_t *a,
    uint32_t x
) {
  a->limb[0] -= x;
}

void
p448_copy (
    p448_t *out,
    const p448_t *a
) {
  *out = *a;
}

void
p448_bias (
    p448_t *a,
    int amt
) {
    uint32_t co1 = ((1ull<<28)-1)*amt, co2 = co1-amt;
    uint32x4_t lo = {co1,co2,co1,co1}, hi = {co1,co1,co1,co1};
    uint32x4_t *aa = (uint32x4_t*) a;
    aa[0] += lo;
    aa[1] += hi;
    aa[2] += hi;
    aa[3] += hi;
}

void
p448_weak_reduce (
    p448_t *a
) {

    uint32x2_t *aa = (uint32x2_t*) a, vmask = {(1ull<<28)-1, (1ull<<28)-1}, vm2 = {0,-1},
       tmp = vshr_n_u32(aa[7],28);
       
    int i;
    for (i=7; i>=1; i--) {
        aa[i] = vsra_n_u32(aa[i] & vmask, aa[i-1], 28);
    }
    aa[0] = (aa[0] & vmask) + vrev64_u32(tmp) + (tmp&vm2);
}

#ifdef __cplusplus
}; /* extern "C" */
#endif

#endif /* __P448_H__ */
