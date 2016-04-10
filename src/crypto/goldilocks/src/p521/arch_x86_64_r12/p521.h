/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */
#ifndef __P521_H__
#define __P521_H__ 1

#include <stdint.h>
#include <assert.h>
#include <string.h>

#include "word.h"
#include "constant_time.h"

#define LIMBPERM(x) (((x)%3)*4 + (x)/3)
#define USE_P521_3x3_TRANSPOSE

typedef struct p521_t {
  uint64_t limb[12];
} __attribute__((aligned(32))) p521_t;

#ifdef __cplusplus
extern "C" {
#endif

static __inline__ void
p521_set_ui (
    p521_t *out,
    uint64_t x
) __attribute__((unused));

static __inline__ void
p521_add_RAW (
    p521_t *out,
    const p521_t *a,
    const p521_t *b
) __attribute__((unused));
             
static __inline__ void
p521_sub_RAW (
    p521_t *out,
    const p521_t *a,
    const p521_t *b
) __attribute__((unused));
             
static __inline__ void
p521_neg_RAW (
    p521_t *out,
    const p521_t *a
) __attribute__((unused));

static __inline__ void
p521_addw (
    p521_t *a,
    uint64_t x
) __attribute__((unused));
             
static __inline__ void
p521_subw (
    p521_t *a,
    uint64_t x
) __attribute__((unused));
             
static __inline__ void
p521_copy (
    p521_t *out,
    const p521_t *a
) __attribute__((unused));
             
static __inline__ void
p521_weak_reduce (
    p521_t *inout
) __attribute__((unused));
             
void
p521_strong_reduce (
    p521_t *inout
);

mask_t
p521_is_zero (
    const p521_t *in
);

static __inline__ void
p521_bias (
    p521_t *inout,
    int amount
) __attribute__((unused));
         
void
p521_mul (
    p521_t *__restrict__ out,
    const p521_t *a,
    const p521_t *b
);

void
p521_mulw (
    p521_t *__restrict__ out,
    const p521_t *a,
    uint64_t b
);

void
p521_sqr (
    p521_t *__restrict__ out,
    const p521_t *a
);

void
p521_serialize (
    uint8_t *serial,
    const struct p521_t *x
);

mask_t
p521_deserialize (
    p521_t *x,
    const uint8_t serial[66]
);

/* -------------- Inline functions begin here -------------- */

typedef uint64x4_t uint64x3_t; /* fit it in a vector register */

static const uint64x3_t mask58 = { (1ull<<58) - 1, (1ull<<58) - 1, (1ull<<58) - 1, 0 };

/* Currently requires CLANG.  Sorry. */
static inline uint64x3_t
__attribute__((unused))
timesW (
  uint64x3_t u
) {
  return u.zxyw + u.zwww;
}

void
p521_set_ui (
    p521_t *out,
    uint64_t x
) {
    int i;
    out->limb[0] = x;
    for (i=1; i<12; i++) {
      out->limb[i] = 0;
    }
}

void
p521_add_RAW (
    p521_t *out,
    const p521_t *a,
    const p521_t *b
) {
    unsigned int i;
    for (i=0; i<sizeof(*out)/sizeof(uint64xn_t); i++) {
        ((uint64xn_t*)out)[i] = ((const uint64xn_t*)a)[i] + ((const uint64xn_t*)b)[i];
    }
}

void
p521_sub_RAW (
    p521_t *out,
    const p521_t *a,
    const p521_t *b
) {
    unsigned int i;
    for (i=0; i<sizeof(*out)/sizeof(uint64xn_t); i++) {
        ((uint64xn_t*)out)[i] = ((const uint64xn_t*)a)[i] - ((const uint64xn_t*)b)[i];
    }
}

void
p521_neg_RAW (
    struct p521_t *out,
    const p521_t *a
) {
    unsigned int i;
    for (i=0; i<sizeof(*out)/sizeof(uint64xn_t); i++) {
        ((uint64xn_t*)out)[i] = -((const uint64xn_t*)a)[i];
    }
}

void
p521_addw (
    p521_t *a,
    uint64_t x
) {
    a->limb[0] += x;
}
             
void
p521_subw (
    p521_t *a,
    uint64_t x
) {
    a->limb[0] -= x;
}

void
p521_copy (
    p521_t *out,
    const p521_t *a
) {
    memcpy(out,a,sizeof(*a));
}

void
p521_bias (
    p521_t *a,
    int amt
) {
    uint64_t co0 = ((1ull<<58)-2)*amt, co1 = ((1ull<<58)-1)*amt;
    uint64x4_t vlo = { co0, co1, co1, 0 }, vhi = { co1, co1, co1, 0 };
    ((uint64x4_t*)a)[0] += vlo;
    ((uint64x4_t*)a)[1] += vhi;
    ((uint64x4_t*)a)[2] += vhi;
}

void
p521_weak_reduce (
    p521_t *a
) {
#if 0
    int i;
    assert(a->limb[3] == 0 && a->limb[7] == 0 && a->limb[11] == 0);
    for (i=0; i<12; i++) {
        assert(a->limb[i] < 3ull<<61);
    }
#endif
    
    uint64x3_t
        ot0 = ((uint64x4_t*)a)[0],
        ot1 = ((uint64x4_t*)a)[1],
        ot2 = ((uint64x4_t*)a)[2];
    
    uint64x3_t out0 = (ot0 & mask58) + timesW(ot2>>58);
    uint64x3_t out1 = (ot1 & mask58) + (ot0>>58);
    uint64x3_t out2 = (ot2 & mask58) + (ot1>>58);

    ((uint64x4_t*)a)[0] = out0;
    ((uint64x4_t*)a)[1] = out1;
    ((uint64x4_t*)a)[2] = out2;
}

#ifdef __cplusplus
}; /* extern "C" */
#endif

#endif /* __P521_H__ */
