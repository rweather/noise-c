/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */
#ifndef __P521_H__
#define __P521_H__ 1

#include <stdint.h>
#include <assert.h>
#include <string.h>

#include "word.h"

typedef struct p521_t {
  uint64_t limb[9];
} p521_t;

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

static __inline__ void
p521_really_bias (
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

void
p521_set_ui (
    p521_t *out,
    uint64_t x
) {
    int i;
    out->limb[0] = x;
    for (i=1; i<9; i++) {
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
    for (i=0; i<9; i++) {
        out->limb[i] = a->limb[i] + b->limb[i];
    }
    p521_weak_reduce(out);
}

void
p521_sub_RAW (
    p521_t *out,
    const p521_t *a,
    const p521_t *b
) {
    unsigned int i;
    uint64_t co1 = ((1ull<<58)-1)*4, co2 = ((1ull<<57)-1)*4;
    for (i=0; i<9; i++) {
        out->limb[i] = a->limb[i] - b->limb[i] + ((i==8) ? co2 : co1);
    }
    p521_weak_reduce(out);
}

void
p521_neg_RAW (
    struct p521_t *out,
    const p521_t *a
) {
    unsigned int i;
    uint64_t co1 = ((1ull<<58)-1)*4, co2 = ((1ull<<57)-1)*4;
    for (i=0; i<9; i++) {
        out->limb[i] = ((i==8) ? co2 : co1) - a->limb[i];
    }
    p521_weak_reduce(out);
}

void
p521_addw (
    p521_t *a,
    uint64_t x
) {
  a->limb[0] += x;
  a->limb[1] += a->limb[0]>>58;
  a->limb[0] &= (1ull<<58)-1;
}
             
void
p521_subw (
    p521_t *a,
    uint64_t x
) {
  a->limb[0] -= x;
  p521_really_bias(a, 1);
  p521_weak_reduce(a);
}

void
p521_copy (
    p521_t *out,
    const p521_t *a
) {
    memcpy(out,a,sizeof(*a));
}

void
p521_really_bias (
    p521_t *a,
    int amt
) {
    uint64_t co1 = ((1ull<<58)-1)*2*amt, co2 = ((1ull<<57)-1)*2*amt;
    int i;
    for (i=0; i<9; i++) {
        a->limb[i] += (i==8) ? co2 : co1;
    }
}

void
p521_bias (
    p521_t *a,
    int amt
) {
    (void) a;
    (void) amt;
}

void
p521_weak_reduce (
    p521_t *a
) {
    uint64_t mask = (1ull<<58) - 1;
    uint64_t tmp = a->limb[8] >> 57;
    int i;
    for (i=8; i>0; i--) {
        a->limb[i] = (a->limb[i] & ((i==8) ? mask>>1 : mask)) + (a->limb[i-1]>>58);
    }
    a->limb[0] = (a->limb[0] & mask) + tmp;
}

#ifdef __cplusplus
}; /* extern "C" */
#endif

#endif /* __P521_H__ */
