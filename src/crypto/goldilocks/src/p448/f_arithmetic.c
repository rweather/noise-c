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
    field_a_t L0, L1, L2;
    field_sqr  (   L1,     x );
    field_mul  (   L2,     x,   L1 );
    field_sqr  (   L1,   L2 );
    field_mul  (   L2,     x,   L1 );
    field_sqrn (   L1,   L2,     3 );
    field_mul  (   L0,   L2,   L1 );
    field_sqrn (   L1,   L0,     3 );
    field_mul  (   L0,   L2,   L1 );
    field_sqrn (   L2,   L0,     9 );
    field_mul  (   L1,   L0,   L2 );
    field_sqr  (   L0,   L1 );
    field_mul  (   L2,     x,   L0 );
    field_sqrn (   L0,   L2,    18 );
    field_mul  (   L2,   L1,   L0 );
    field_sqrn (   L0,   L2,    37 );
    field_mul  (   L1,   L2,   L0 );
    field_sqrn (   L0,   L1,    37 );
    field_mul  (   L1,   L2,   L0 );
    field_sqrn (   L0,   L1,   111 );
    field_mul  (   L2,   L1,   L0 );
    field_sqr  (   L0,   L2 );
    field_mul  (   L1,     x,   L0 );
    field_sqrn (   L0,   L1,   223 );
    field_mul  (     a,   L2,   L0 );
}
