#ifndef POLY_H
#define POLY_H

#include <stdint.h>
#include "params.h"

//alignment to 32-byte boundaries in memory.
#ifdef __GNUC__
typedef struct __attribute__ ((aligned (32))) {
  uint16_t coeffs[PARAM_N];
} poly;
#elif defined(_MSC_VER)
typedef __declspec(align(32)) struct {
  uint16_t coeffs[PARAM_N];
} poly;
#else
typedef struct {
  uint16_t coeffs[PARAM_N];
} poly;
#endif

void poly_uniform(poly *a, const unsigned char *seed);
void poly_getnoise(poly *r, unsigned char *seed, unsigned char nonce);
void poly_add(poly *r, const poly *a, const poly *b);

void poly_ntt(poly *r);
void poly_invntt(poly *r);
void poly_pointwise(poly *r, const poly *a, const poly *b);

void poly_frombytes(poly *r, const unsigned char *a);
void poly_tobytes(unsigned char *r, const poly *p);

#endif
