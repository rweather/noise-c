/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

#include "field.h"
#include "magic.h"
#include "barrett_field.h"

/* FUTURE: automatically generate this file? */

const uint8_t FIELD_MODULUS[FIELD_BYTES] = {
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
/*!*/ 0xfe, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

const word_t SCALARMUL_FIXED_WINDOW_ADJUSTMENT[2*SCALAR_WORDS] = {
    U64LE(0xebec9967f5d3f5c2),
    U64LE(0x0aa09b49b16c9a02),
    U64LE(0x7f6126aec172cd8e),
    U64LE(0x00000007b027e54d),
    U64LE(0x0000000000000000),
    U64LE(0x0000000000000000),
    U64LE(0x4000000000000000),
    
    U64LE(0xc873d6d54a7bb0cf),
    U64LE(0xe933d8d723a70aad),
    U64LE(0xbb124b65129c96fd),
    U64LE(0x00000008335dc163),
    U64LE(0x0000000000000000),
    U64LE(0x0000000000000000),
    U64LE(0x0000000000000000)
};

const affine_a_t goldilocks_base_point = {{
#ifdef USE_NEON_PERM
    {{{ 0xaed939f,0xc59d070,0xf0de840,0x5f065c3, 0xf4ba0c7,0xdf73324,0xc170033,0x3a6a26a,
       0x4c63d96,0x4609845,0xf3932d9,0x1b4faff, 0x6147eaa,0xa2692ff,0x9cecfa9,0x297ea0e
    }}},
#else
    {{{ U56LE(0xf0de840aed939f), U56LE(0xc170033f4ba0c7),
       U56LE(0xf3932d94c63d96), U56LE(0x9cecfa96147eaa),
       U56LE(0x5f065c3c59d070), U56LE(0x3a6a26adf73324),
       U56LE(0x1b4faff4609845), U56LE(0x297ea0ea2692ff)
    }}},
#endif
    {{{ 19 }}}
}};

static const word_t curve_prime_order_lo[(224+WORD_BITS-1)/WORD_BITS] = {
    U64LE(0xdc873d6d54a7bb0d),
    U64LE(0xde933d8d723a70aa),
    U64LE(0x3bb124b65129c96f),
    0x8335dc16
};
const struct barrett_prime_t curve_prime_order = {
    GOLDI_FIELD_WORDS,
    62 % WORD_BITS,
    sizeof(curve_prime_order_lo)/sizeof(curve_prime_order_lo[0]),
    curve_prime_order_lo
};

const field_a_t
sqrt_d_minus_1 = {{{
#ifdef USE_NEON_PERM
    0x6749f46,0x24d9770,0xd2e2183,0xa49f7b4,
    0xb4f0179,0x8c5f656,0x888db42,0xdcac462,
    0xbdeea38,0x748734a,0x5a189aa,0x49443b8,
    0x6f14c06,0x0b25b7a,0x51e65ca,0x12fec0c
#else
    U56LE(0xd2e21836749f46),
    U56LE(0x888db42b4f0179),
    U56LE(0x5a189aabdeea38),
    U56LE(0x51e65ca6f14c06),
    U56LE(0xa49f7b424d9770),
    U56LE(0xdcac4628c5f656),
    U56LE(0x49443b8748734a),
    U56LE(0x12fec0c0b25b7a)
#endif
}}};
