/**
 * @file f_field.h
 * @brief Field-specific code.
 * @copyright
 *   Copyright (c) 2014 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 */
#ifndef __F_FIELD_H__
#define __F_FIELD_H__ 1

#include "constant_time.h"
#include <string.h>

#include "p480.h"
#define FIELD_BITS           480
#define field_t              p480_t
#define field_mul            p480_mul
#define field_sqr            p480_sqr
#define field_add_RAW        p480_add_RAW
#define field_sub_RAW        p480_sub_RAW
#define field_mulw           p480_mulw
#define field_addw           p480_addw
#define field_subw_RAW       p480_subw
#define field_neg_RAW        p480_neg_RAW
#define field_set_ui         p480_set_ui
#define field_bias           p480_bias
#define field_inverse        p480_inverse
#define field_eq             p480_eq
#define field_isr            p480_isr
#define field_simultaneous_invert p480_simultaneous_invert
#define field_weak_reduce    p480_weak_reduce
#define field_strong_reduce  p480_strong_reduce
#define field_serialize      p480_serialize
#define field_deserialize    p480_deserialize
#define field_is_zero        p480_is_zero

#endif /* __F_FIELD_H__ */
