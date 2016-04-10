/**
 * @cond internal
 * @file field.c
 * @copyright
 *   Copyright (c) 2014 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief High-level arithmetic routines, independent of field (except 3 mod 4).
 */

#include "field.h"
#include "ec_point.h" 

mask_t
field_eq (
    const field_a_t a,
    const field_a_t b
) {
    field_a_t ra, rb;
    field_copy(ra, a);
    field_copy(rb, b);
    field_weak_reduce(ra);
    field_weak_reduce(rb);
    field_sub_RAW(ra, ra, rb);
    field_bias(ra, 2);
    return field_is_zero(ra);
}

void
field_inverse (
    field_a_t a,
    const field_a_t x
) {
    field_a_t L0, L1;
    field_isr ( L0, x );
    field_sqr ( L1, L0 );
    field_sqr ( L0, L1 );
    field_mul ( a, x, L0 );
}

mask_t
field_is_square (
    const field_a_t x
) {
    field_a_t L0, L1;
    field_isr ( L0, x );
    field_sqr ( L1, L0 );
    field_mul ( L0, x, L1 );
    field_subw( L0, 1 );
    return field_is_zero( L0 ) | field_is_zero( x );
}

void
field_simultaneous_invert (
    field_a_t *__restrict__ out,
    const field_a_t *in,
    unsigned int n
) {
  if (n==0) {
      return;
  } else if (n==1) {
      field_inverse(out[0],in[0]);
      return;
  }
  
  field_copy(out[1], in[0]);
  int i;
  for (i=1; i<(int) (n-1); i++) {
      field_mul(out[i+1], out[i], in[i]);
  }
  field_mul(out[0], out[n-1], in[n-1]);
  
  field_a_t tmp;
  field_inverse(tmp, out[0]);
  field_copy(out[0], tmp);
  
  /* at this point, out[0] = product(in[i]) ^ -1
   * out[i] = product(in[0]..in[i-1]) if i != 0
   */
  for (i=n-1; i>0; i--) {
      field_mul(tmp, out[i], out[0]);
      field_copy(out[i], tmp);
      
      field_mul(tmp, out[0], in[i]);
      field_copy(out[0], tmp);
  }
}
