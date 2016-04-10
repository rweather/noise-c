/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */
#ifndef __P448_H__
#define __P448_H__ 1

#include <stdint.h>
#include <assert.h>
#include <string.h>

#include "word.h"

typedef struct p448_t {
  uint64_t limb[8];
} __attribute__((aligned(32))) p448_t;

#ifdef __cplusplus
extern "C" {
#endif

static __inline__ void
p448_set_ui (
    p448_t *out,
    uint64_t x
) __attribute__((unused));

static __inline__ void
p448_add_RAW (
    p448_t *out,
    const p448_t *a,
    const p448_t *b
) __attribute__((unused));
             
static __inline__ void
p448_sub_RAW (
    p448_t *out,
    const p448_t *a,
    const p448_t *b
) __attribute__((unused));
             
static __inline__ void
p448_neg_RAW (
    p448_t *out,
    const p448_t *a
) __attribute__((unused));

static __inline__ void
p448_addw (
    p448_t *a,
    uint64_t x
) __attribute__((unused));
             
static __inline__ void
p448_subw (
    p448_t *a,
    uint64_t x
) __attribute__((unused));
             
static __inline__ void
p448_copy (
    p448_t *out,
    const p448_t *a
) __attribute__((unused));
             
static __inline__ void
p448_weak_reduce (
    p448_t *inout
) __attribute__((unused));
             
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
) __attribute__((unused));

static __inline__ void
p448_really_bias (
    p448_t *inout,
    int amount
) __attribute__((unused));
         
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
    out->limb[0] = x;
    for (i=1; i<8; i++) {
      out->limb[i] = 0;
    }
}

void
p448_add_RAW (
    p448_t *out,
    const p448_t *a,
    const p448_t *b
) {
    unsigned int i;
    for (i=0; i<8; i++) {
        out->limb[i] = a->limb[i] + b->limb[i];
    }
    p448_weak_reduce(out);
}

void
p448_sub_RAW (
    p448_t *out,
    const p448_t *a,
    const p448_t *b
) {
    unsigned int i;
    uint64_t co1 = ((1ull<<56)-1)*2, co2 = co1-2;
    for (i=0; i<8; i++) {
        out->limb[i] = a->limb[i] - b->limb[i] + ((i==4) ? co2 : co1);
    }
    p448_weak_reduce(out);
}

void
p448_neg_RAW (
    struct p448_t *out,
    const p448_t *a
) {
    unsigned int i;
    uint64_t co1 = ((1ull<<56)-1)*2, co2 = co1-2;
    for (i=0; i<8; i++) {
        out->limb[i] = ((i==4) ? co2 : co1) - a->limb[i];
    }
    p448_weak_reduce(out);
}

void
p448_addw (
    p448_t *a,
    uint64_t x
) {
  a->limb[0] += x;
  a->limb[1] += a->limb[0]>>56;
  a->limb[0] &= (1ull<<56)-1;
}
             
void
p448_subw (
    p448_t *a,
    uint64_t x
) {
  a->limb[0] -= x;
  p448_really_bias(a, 1);
  p448_weak_reduce(a);
}

void
p448_copy (
    p448_t *out,
    const p448_t *a
) {
    memcpy(out,a,sizeof(*a));
}

void
p448_really_bias (
    p448_t *a,
    int amt
) {
    uint64_t co1 = ((1ull<<56)-1)*amt, co2 = co1-amt;
    int i;
    for (i=0; i<8; i++) {
        a->limb[i] += (i==4) ? co2 : co1;
    }
}

void
p448_bias (
    p448_t *a,
    int amt
) {
    (void) a;
    (void) amt;
}

void
p448_weak_reduce (
    p448_t *a
) {
    uint64_t mask = (1ull<<56) - 1;
    uint64_t tmp = a->limb[7] >> 56;
    int i;
    a->limb[4] += tmp;
    for (i=7; i>0; i--) {
        a->limb[i] = (a->limb[i] & mask) + (a->limb[i-1]>>56);
    }
    a->limb[0] = (a->limb[0] & mask) + tmp;
}

#ifdef __cplusplus
}; /* extern "C" */
#endif

#endif /* __P448_H__ */
