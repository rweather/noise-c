/**
 * @file f_magic.h
 * @copyright
 *   Copyright (c) 2014 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief Goldilocks magic numbers (group orders, coefficients, algo params etc).
 */

#ifndef __GOLDI_F_MAGIC_H__
#define __GOLDI_F_MAGIC_H__ 1

#include "field.h"
#include "ec_point.h"

/**
 * @brief The Edwards "d" term for this curve.
 */
static const int64_t EDWARDS_D = -376014;

/** @brief The number of combs to use for signed comb algo */
#define COMB_N (USE_BIG_COMBS ? 4  : 5)

/** @brief The number of teeth of the combs for signed comb algo */
#define COMB_T (USE_BIG_COMBS ? 5  : 4)

/** @brief The spacing the of combs for signed comb algo */
#define COMB_S (USE_BIG_COMBS ? 26 : 26)

#endif /* __GOLDI_F_MAGIC_H__ */
