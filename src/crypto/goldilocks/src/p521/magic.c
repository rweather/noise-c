/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

#include "field.h"
#include "magic.h"
#include "barrett_field.h"

/* FUTURE: automatically generate this file? */

const uint8_t FIELD_MODULUS[FIELD_BYTES] = {
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0x01
};

const word_t SCALARMUL_FIXED_WINDOW_ADJUSTMENT[2*SCALAR_WORDS] = {
    U64LE(0xbf15dbca0ae7f294),
    U64LE(0x04273ba96570e0ba),
    U64LE(0xc94750a1813ac0fb),
    U64LE(0xea4939b8b9037a08),
    U64LE(0x0000000000000002),
    U64LE(0x0000000000000000),
    U64LE(0x0000000000000000),
    U64LE(0x0000000000000000),
    0x80,
        
    U64LE(0x7e2bb79415cfe529),
    U64LE(0x084e7752cae1c175),
    U64LE(0x928ea143027581f6),
    U64LE(0xd49273717206f411),
    U64LE(0x0000000000000005),
    U64LE(0x0000000000000000),
    U64LE(0x0000000000000000),
    U64LE(0x0000000000000000),
    0x0
};

const affine_a_t goldilocks_base_point = {{
    {{{
#ifdef USE_P521_3x3_TRANSPOSE
        U58LE(0x02a940a2f19ba6c),
        U58LE(0x3331c90d2c6ba52),
        U58LE(0x2878a3bfd9f42fc),
	0,
        U58LE(0x03ec4cd920e2a8c),
        U58LE(0x0c6203913f6ecc5),
        U58LE(0x06277e432c8a5ac),
	0,
        U58LE(0x1d568fc99c6059d),
        U58LE(0x1b2063b22fcf270),
        U58LE(0x0752cb45c48648b),
	0
#else
        U58LE(0x02a940a2f19ba6c),
        U58LE(0x03ec4cd920e2a8c),
        U58LE(0x1d568fc99c6059d),
        U58LE(0x3331c90d2c6ba52),
        U58LE(0x0c6203913f6ecc5),
        U58LE(0x1b2063b22fcf270),
        U58LE(0x2878a3bfd9f42fc),
        U58LE(0x06277e432c8a5ac),
        U58LE(0x0752cb45c48648b)
#endif
    }}},
    {{{ 12 }}}
}};

static const word_t curve_prime_order_lo[(261+WORD_BITS-1)/WORD_BITS] = {
    U64LE(0xbf15dbca0ae7f295),
    U64LE(0x4273ba96570e0ba),
    U64LE(0xc94750a1813ac0fb),
    U64LE(0xea4939b8b9037a08),
    2
};
const struct barrett_prime_t curve_prime_order = {
    GOLDI_FIELD_WORDS,
    7 % WORD_BITS,
    sizeof(curve_prime_order_lo)/sizeof(curve_prime_order_lo[0]),
    curve_prime_order_lo
};

const field_a_t
sqrt_d_minus_1 = {{{
#ifdef USE_P521_3x3_TRANSPOSE
    U58LE(0x1e2be72c1c81990),
    U58LE(0x207dfc238a33e46),
    U58LE(0x2264cfb418c4c30),
    0,
    U58LE(0x1135002ad596c69),
    U58LE(0x0e30107cd79d1f6),
    U58LE(0x0524b9e715937f5),
    0,
    U58LE(0x2ab3a257a22666d),
    U58LE(0x2d80cc2936a1824),
    U58LE(0x0a9ea3ac10d6aed),
    0
#else
    U58LE(0x1e2be72c1c81990),
    U58LE(0x1135002ad596c69),
    U58LE(0x2ab3a257a22666d),
    U58LE(0x207dfc238a33e46),
    U58LE(0x0e30107cd79d1f6),
    U58LE(0x2d80cc2936a1824),
    U58LE(0x2264cfb418c4c30),
    U58LE(0x0524b9e715937f5),
    U58LE(0x0a9ea3ac10d6aed)
#endif
}}};
