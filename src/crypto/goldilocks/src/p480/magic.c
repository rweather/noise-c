/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

#include "field.h"
#include "magic.h"
#include "barrett_field.h"

/* FUTURE: automatically generate this file? */

const uint8_t FIELD_MODULUS[FIELD_BYTES] = {
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
/*!*/ 0xfe, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

const word_t SCALARMUL_FIXED_WINDOW_ADJUSTMENT[2*SCALAR_WORDS] = {
    U64LE(0x58b51bc56ea8f0c4),
    U64LE(0xd361f6a2348b50c9),
    U64LE(0x08089c139c0002ae),
    U64LE(0x0001d2ac3d9503a0),
    U64LE(0x0000000000000000),
    U64LE(0x0000000000000000),
    U64LE(0x0000000000000000),
    0x40000000,
    
    U64LE(0xcb9c25073e36965b),
    U64LE(0x6f2d48d8460f1661),
    U64LE(0x0ab6256f7aaaae3e),
    U64LE(0x00026e3afcc6af80),
    U64LE(0x0000000000000000),
    U64LE(0x0000000000000000),
    U64LE(0x0000000000000000),
    0x00000000
};

const affine_a_t goldilocks_base_point = {{
    {{{
        U60LE(0x849ff7f845c30d3),
        U60LE(0x7dda488553a4c5b),
        U60LE(0x1d3a2d9844831ea),
        U60LE(0xb33ecf6ade470a2),
        U60LE(0x8b3cb95210bd3c3),
        U60LE(0xfc955e59aeefa65),
        U60LE(0x3ab247cd530013c),
        U60LE(0x7ca42af3d564280)
    }}},
    {{{ 5 }}}
}};

static const word_t curve_prime_order_lo[(240+WORD_BITS-1)/WORD_BITS] = {
    U64LE(0x72e70941cf8da597),
    U64LE(0x9bcb52361183c598),
    U64LE(0x02ad895bdeaaab8f),
    U64LE(0x9b8ebf31abe0)
};
const struct barrett_prime_t curve_prime_order = {
    GOLDI_FIELD_WORDS,
    30 % WORD_BITS,
    sizeof(curve_prime_order_lo)/sizeof(curve_prime_order_lo[0]),
    curve_prime_order_lo
};

const field_a_t
sqrt_d_minus_1 = {{{
    232 /* Whoa, it comes out even. */
}}};
