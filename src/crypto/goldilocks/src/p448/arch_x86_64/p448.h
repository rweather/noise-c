/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */
#ifndef __P448_H__
#define __P448_H__ 1

#include <stdint.h>
#include <assert.h>

#ifdef _MSC_VER
#include <intrin.h>
#include <immintrin.h>
#define __forceinline__ __forceinline
#define __restrict__ __restrict
#else
#define __forceinline__ __attribute__((always_inline)) inline
#define __restrict__ __restrict__
#endif

#include "word.h"

#ifdef _MSC_VER
__declspec(align(32))
typedef struct p448_t {
    uint64_t limb[8];
} p448_t;
#else
typedef struct p448_t {
    uint64_t limb[8];
} __attribute__((aligned(32))) p448_t;
#endif

#ifdef __cplusplus
extern "C" {
#endif

static __forceinline__ void
p448_set_ui(
    p448_t *out,
    uint64_t x
);

static __forceinline__ void
p448_add_RAW(
    p448_t *out,
    const p448_t *a,
    const p448_t *b
);

static __forceinline__ void
p448_sub_RAW(
    p448_t *out,
    const p448_t *a,
    const p448_t *b
);

static __forceinline__ void
p448_neg_RAW(
    p448_t *out,
    const p448_t *a
);

static __forceinline__ void
p448_addw(
    p448_t *a,
    uint64_t x
);

static __forceinline__ void
p448_subw(
    p448_t *a,
    uint64_t x
);

static __forceinline__ void
p448_copy(
    p448_t *out,
    const p448_t *a
);

static __forceinline__ void
p448_weak_reduce(
    p448_t *inout
);

void
p448_strong_reduce(
    p448_t *inout
);

mask_t
p448_is_zero(
    const p448_t *in
);

static __forceinline__ void
p448_bias(
    p448_t *inout,
    int amount
);

void
p448_mul(
    p448_t *__restrict__ out,
    const p448_t *a,
    const p448_t *b
);

void
p448_mulw(
    p448_t *__restrict__ out,
    const p448_t *a,
    uint64_t b
);

void
p448_sqr(
    p448_t *__restrict__ out,
    const p448_t *a
);

void
p448_serialize(
    uint8_t *serial,
    const struct p448_t *x
);

mask_t
p448_deserialize(
    p448_t *x,
    const uint8_t serial[56]
);

/* -------------- Inline functions begin here -------------- */

static __forceinline__ void
p448_set_ui(
    p448_t *out,
    uint64_t x
) {
    int i;
    out->limb[0] = x;
    for (i = 1; i < 8; i++) {
        out->limb[i] = 0;
    }
}

static __forceinline__ void
p448_add_RAW(
    p448_t *out,
    const p448_t *a,
    const p448_t *b
) {
    unsigned int i;
    for (i = 0; i < sizeof(*out) / sizeof(uint64xn_t); i++) {
        ((uint64xn_t*)out)[i] = ((const uint64xn_t*)a)[i] + ((const uint64xn_t*)b)[i];
    }
}

static __forceinline__ void
p448_sub_RAW(
    p448_t *out,
    const p448_t *a,
    const p448_t *b
) {
    unsigned int i;
    for (i = 0; i < sizeof(*out) / sizeof(uint64xn_t); i++) {
        ((uint64xn_t*)out)[i] = ((const uint64xn_t*)a)[i] - ((const uint64xn_t*)b)[i];
    }
}

static __forceinline__ void
p448_neg_RAW(
    struct p448_t *out,
    const p448_t *a
) {
    unsigned int i;
    for (i = 0; i < sizeof(*out) / sizeof(uint64xn_t); i++) {
        ((uint64xn_t*)out)[i] = -((const uint64xn_t*)a)[i];
    }
}

static __forceinline__ void
p448_addw(
    p448_t *a,
    uint64_t x
) {
    a->limb[0] += x;
}

static __forceinline__ void
p448_subw(
    p448_t *a,
    uint64_t x
) {
    a->limb[0] -= x;
}

static __forceinline__ void
p448_copy(
    p448_t *out,
    const p448_t *a
) {
    unsigned int i;
    for (i = 0; i < sizeof(*out) / sizeof(big_register_t); i++) {
        ((big_register_t *)out)[i] = ((const big_register_t *)a)[i];
    }
}

static __forceinline__ void
p448_bias(
    p448_t *a,
    int amt
) {
    uint64_t co1 = ((1ull << 56) - 1) * amt, co2 = co1 - amt;

#ifdef _MSC_VER
#ifdef __AVX2__
    __m256i lo = _mm256_set_epi64x(co1, co1, co1, co1);
    __m256i hi = _mm256_set_epi64x(co1, co1, co1, co2);
    __m256i *aa = (__m256i*) a;
    aa[0] = _mm256_add_epi64(aa[0], lo);
    aa[1] = _mm256_add_epi64(aa[1], hi);
#elif defined(__SSE2__)
    __m128i lo = _mm_set_epi64x(co1, co1);
    __m128i hi = _mm_set_epi64x(co1, co2);
    __m128i *aa = (__m128i*) a;
    aa[0] = _mm_add_epi64(aa[0], lo);
    aa[1] = _mm_add_epi64(aa[1], lo);
    aa[2] = _mm_add_epi64(aa[2], hi);
    aa[3] = _mm_add_epi64(aa[3], lo);
#else
    unsigned int i;
    for (i = 0; i < sizeof(*a) / sizeof(uint64_t); i++) {
        a->limb[i] += (i == 4) ? co2 : co1;
    }
#endif
#else
#if __AVX2__
    uint64x4_t lo = { co1, co1, co1, co1 }, hi = { co2, co1, co1, co1 };
    uint64x4_t *aa = (uint64x4_t*) a;
    aa[0] += lo;
    aa[1] += hi;
#elif __SSE2__
    uint64x2_t lo = { co1, co1 }, hi = { co2, co1 };
    uint64x2_t *aa = (uint64x2_t*) a;
    aa[0] += lo;
    aa[1] += lo;
    aa[2] += hi;
    aa[3] += lo;
#else
    unsigned int i;
    for (i = 0; i < sizeof(*a) / sizeof(uint64_t); i++) {
        a->limb[i] += (i == 4) ? co2 : co1;
    }
#endif
#endif
}

static __forceinline__ void
p448_weak_reduce(
    p448_t *a
) {
    /* PERF: use pshufb/palignr if anyone cares about speed of this */
    uint64_t mask = (1ull << 56) - 1;
    uint64_t tmp = a->limb[7] >> 56;
    int i;
    a->limb[4] += tmp;
    for (i = 7; i > 0; i--) {
        a->limb[i] = (a->limb[i] & mask) + (a->limb[i - 1] >> 56);
    }
    a->limb[0] = (a->limb[0] & mask) + tmp;
}

#ifdef __cplusplus
}; /* extern "C" */
#endif

#endif /* __P448_H__ */
