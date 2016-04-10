/**
 * @cond internal
 * @file f_arithmetic.c
 * @copyright
 *   Copyright (c) 2014 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief Field-specific arithmetic.
 */

#include "ec_point.h"

void 
field_isr (
    field_a_t a,
    const field_a_t x
) {
    field_a_t L0, L1, L2, L3;
    field_sqr  (   L2,     x );
    field_mul  (   L1,     x,   L2 );
    field_sqrn (   L0,   L1,     2 );
    field_mul  (   L2,   L1,   L0 );
    field_sqrn (   L0,   L2,     4 );
    field_mul  (   L1,   L2,   L0 );
    field_sqr  (   L0,   L1 );
    field_mul  (   L2,     x,   L0 );
    field_sqrn (   L0,   L2,     8 );
    field_mul  (   L2,   L1,   L0 );
    field_sqrn (   L0,   L2,    17 );
    field_mul  (   L1,   L2,   L0 );
    field_sqrn (   L0,   L1,    17 );
    field_mul  (   L1,   L2,   L0 );
    field_sqrn (   L3,   L1,    17 );
    field_mul  (   L0,   L2,   L3 );
    field_sqrn (   L2,   L0,    51 );
    field_mul  (   L0,   L1,   L2 );
    field_sqrn (   L1,   L0,   119 );
    field_mul  (   L2,   L0,   L1 );
    field_sqr  (   L0,   L2 );
    field_mul  (   L1,     x,   L0 );
    field_sqrn (   L0,   L1,   239 );
    field_mul  (     a,   L2,   L0 );
}
