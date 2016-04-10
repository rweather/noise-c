/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */
#ifndef __p480_H__
#define __p480_H__ 1

#include <stdint.h>
#include <assert.h>

#include "word.h"

typedef struct p480_t {
  uint64_t limb[8];
} __attribute__((aligned(32))) p480_t;

#ifdef __cplusplus
extern "C" {
#endif

static __inline__ void
p480_set_ui (
    p480_t *out,
    uint64_t x
) __attribute__((unused,always_inline));

static __inline__ void
p480_add_RAW (
    p480_t *out,
    const p480_t *a,
    const p480_t *b
) __attribute__((unused,always_inline));
             
static __inline__ void
p480_sub_RAW (
    p480_t *out,
    const p480_t *a,
    const p480_t *b
) __attribute__((unused,always_inline));
             
static __inline__ void
p480_neg_RAW (
    p480_t *out,
    const p480_t *a
) __attribute__((unused,always_inline));

static __inline__ void
p480_addw (
    p480_t *a,
    uint64_t x
) __attribute__((unused,always_inline));
             
static __inline__ void
p480_subw (
    p480_t *a,
    uint64_t x
) __attribute__((unused,always_inline));
             
static __inline__ void
p480_copy (
    p480_t *out,
    const p480_t *a
) __attribute__((unused,always_inline));
             
static __inline__ void
p480_weak_reduce (
    p480_t *inout
) __attribute__((unused,always_inline));
             
void
p480_strong_reduce (
    p480_t *inout
);

mask_t
p480_is_zero (
    const p480_t *in
);
  
static __inline__ void
p480_bias (
    p480_t *inout,
    int amount
) __attribute__((unused,always_inline));
         
void
p480_mul (
    p480_t *__restrict__ out,
    const p480_t *a,
    const p480_t *b
);

void
p480_mulw (
    p480_t *__restrict__ out,
    const p480_t *a,
    uint64_t b
);

void
p480_sqr (
    p480_t *__restrict__ out,
    const p480_t *a
);

void
p480_serialize (
    uint8_t *serial,
    const struct p480_t *x
);

mask_t
p480_deserialize (
    p480_t *x,
    const uint8_t serial[60]
);

/* -------------- Inline functions begin here -------------- */

void
p480_set_ui (
    p480_t *out,
    uint64_t x
) {
    int i;
    out->limb[0] = x;
    for (i=1; i<8; i++) {
      out->limb[i] = 0;
    }
}

void
p480_add_RAW (
    p480_t *out,
    const p480_t *a,
    const p480_t *b
) {
    unsigned int i;
    for (i=0; i<sizeof(*out)/sizeof(uint64xn_t); i++) {
        ((uint64xn_t*)out)[i] = ((const uint64xn_t*)a)[i] + ((const uint64xn_t*)b)[i];
    }
    /*
    unsigned int i;
    for (i=0; i<sizeof(*out)/sizeof(out->limb[0]); i++) {
        out->limb[i] = a->limb[i] + b->limb[i];
    }
    */
}

void
p480_sub_RAW (
    p480_t *out,
    const p480_t *a,
    const p480_t *b
) {
    unsigned int i;
    for (i=0; i<sizeof(*out)/sizeof(uint64xn_t); i++) {
        ((uint64xn_t*)out)[i] = ((const uint64xn_t*)a)[i] - ((const uint64xn_t*)b)[i];
    }
    /*
    unsigned int i;
    for (i=0; i<sizeof(*out)/sizeof(out->limb[0]); i++) {
        out->limb[i] = a->limb[i] - b->limb[i];
    }
    */
}

void
p480_neg_RAW (
    struct p480_t *out,
    const p480_t *a
) {
    unsigned int i;
    for (i=0; i<sizeof(*out)/sizeof(uint64xn_t); i++) {
        ((uint64xn_t*)out)[i] = -((const uint64xn_t*)a)[i];
    }
    /*
    unsigned int i;
    for (i=0; i<sizeof(*out)/sizeof(out->limb[0]); i++) {
        out->limb[i] = -a->limb[i];
    }
    */
}

void
p480_addw (
    p480_t *a,
    uint64_t x
) {
  a->limb[0] += x;
}
             
void
p480_subw (
    p480_t *a,
    uint64_t x
) {
  a->limb[0] -= x;
}

void
p480_copy (
    p480_t *out,
    const p480_t *a
) {
    unsigned int i;
    for (i=0; i<sizeof(*out)/sizeof(big_register_t); i++) {
        ((big_register_t *)out)[i] = ((const big_register_t *)a)[i];
    }
}

void
p480_bias (
    p480_t *a,
    int amt
) {
    uint64_t co1 = ((1ull<<60)-1)*amt, co2 = co1-amt;
    
#if __AVX2__
    uint64x4_t lo = {co1,co1,co1,co1}, hi = {co2,co1,co1,co1};
    uint64x4_t *aa = (uint64x4_t*) a;
    aa[0] += lo;
    aa[1] += hi;
#elif __SSE2__
    uint64x2_t lo = {co1,co1}, hi = {co2,co1};
    uint64x2_t *aa = (uint64x2_t*) a;
    aa[0] += lo;
    aa[1] += lo;
    aa[2] += hi;
    aa[3] += lo;
#else
    unsigned int i;
    for (i=0; i<sizeof(*a)/sizeof(uint64_t); i++) {
        a->limb[i] += (i==4) ? co2 : co1;
    }
#endif
}

void
p480_weak_reduce (
    p480_t *a
) {
    /* PERF: use pshufb/palignr if anyone cares about speed of this */
    uint64_t mask = (1ull<<60) - 1;
    uint64_t tmp = a->limb[7] >> 60;
    int i;
    a->limb[4] += tmp;
    for (i=7; i>0; i--) {
        a->limb[i] = (a->limb[i] & mask) + (a->limb[i-1]>>60);
    }
    a->limb[0] = (a->limb[0] & mask) + tmp;
}

#ifdef __cplusplus
}; /* extern "C" */
#endif

#endif /* __p480_H__ */
