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
    field_mul  (   L0,     x,   L1 );
    field_sqrn (   L2,   L0,     2 );
    field_mul  (   L1,   L0,   L2 );
    field_sqrn (   L2,   L1,     4 );
    field_mul  (   L0,   L1,   L2 );
    field_sqrn (   L2,   L0,     8 );
    field_mul  (   L1,   L0,   L2 );
    field_sqrn (   L2,   L1,    16 );
    field_mul  (   L0,   L1,   L2 );
    field_sqrn (   L2,   L0,    32 );
    field_mul  (   L1,   L0,   L2 );
    field_sqr  (   L2,   L1 );
    field_mul  (   L0,     x,   L2 );
    field_sqrn (   L2,   L0,    64 );
    field_mul  (   L0,   L1,   L2 );
    field_sqrn (   L2,   L0,   129 );
    field_mul  (   L1,   L0,   L2 );
    field_sqr  (   L2,   L1 );
    field_mul  (   L0,     x,   L2 );
    field_sqrn (   L2,   L0,   259 );
    field_mul  (   L1,   L0,   L2 );
    field_sqr  (   L0,   L1 );
    field_mul  (     a,     x,   L0 );
}
