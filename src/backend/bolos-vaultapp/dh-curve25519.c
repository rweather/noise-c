/*
 * Copyright (C) 2016 Southern Storm Software, Pty Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include <string.h>
#include "internal.h"

#include "os.h"
#include "cx.h"

static int noise_curve25519_set_keypair_private(NoiseDHState *state, const uint8_t *private_key);

// Big endian compressed curve25519 generator point
static uint8_t const C_Curve25519_G[] = {
  //compressed
  0x02,
  //x big endian
  0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

typedef struct
{
  struct NoiseDHState_s parent;
  uint8_t private_key[32];
  uint8_t public_key[sizeof(C_Curve25519_G)];
} NoiseCurve25519State;

static void be2le(uint8_t *v, size_t len)
{
  uint8_t t;
  int i, j;

  j = len - 1;
  len /= 2;

  for (i = 0; len > 0; i++, j--, len--) {
    t = v[i];
    v[i] = v[j];
    v[j] = t;
    i++;
    j--;
  }
}

static int noise_curve25519_generate_keypair
    (NoiseDHState *state, const NoiseDHState *other)
{
  NoiseCurve25519State *st = (NoiseCurve25519State *)state;

  noise_rand_bytes(st->private_key, sizeof(st->private_key));
  noise_curve25519_set_keypair_private(state, st->private_key);

  return NOISE_ERROR_NONE;
}

static int noise_curve25519_set_keypair
        (NoiseDHState *state, const uint8_t *private_key,
         const uint8_t *public_key)
{
  /* Check that the public key actually corresponds to the private key */
  NoiseCurve25519State *st = (NoiseCurve25519State *)state;
  NoiseCurve25519State temp;
  int equal;

  memcpy(&temp, st, sizeof(temp));
  noise_curve25519_set_keypair_private((NoiseDHState *)(&temp), private_key);
  equal = noise_is_equal(temp.public_key, public_key, sizeof(public_key));

  memcpy(st->private_key, private_key, sizeof(st->private_key));
  memcpy(st->public_key, public_key, sizeof(st->public_key));
  return NOISE_ERROR_INVALID_PUBLIC_KEY & (equal - 1);
}

static int noise_curve25519_set_keypair_private
        (NoiseDHState *state, const uint8_t *private_key)
{
  NoiseCurve25519State *st = (NoiseCurve25519State *)state;
  uint8_t tmp_public[sizeof(C_Curve25519_G)];
  uint8_t tmp_private[32];

  memcpy(st->private_key, private_key, 32);
  memcpy(tmp_public, C_Curve25519_G, sizeof(C_Curve25519_G)); // little endian
  //tmp_public[31 + 1] &= 0x7fu;
  be2le(tmp_public + 1, sizeof(tmp_public) - 1);

  memcpy(tmp_private, private_key, sizeof(tmp_private));
  tmp_private[0] &= 0xf8u;
  tmp_private[31] &= 0x7fu;
  tmp_private[31] |= 0x40u;
  be2le(tmp_private, 32);

  cx_ecfp_scalar_mult(CX_CURVE_Curve25519, tmp_public, sizeof(tmp_public), tmp_private, sizeof(tmp_private));

  be2le(tmp_public + 1, sizeof(tmp_public) - 1);

  memcpy(st->public_key, tmp_public + 1, sizeof(st->public_key));
  return NOISE_ERROR_NONE;
}

static int noise_curve25519_validate_public_key
        (const NoiseDHState *state, const uint8_t *public_key)
{
    /* Nothing to do here yet */
    return NOISE_ERROR_NONE;
}

static int noise_curve25519_copy
    (NoiseDHState *state, const NoiseDHState *from, const NoiseDHState *other)
{
    NoiseCurve25519State *st = (NoiseCurve25519State *)state;
    const NoiseCurve25519State *from_st = (const NoiseCurve25519State *)from;
    memcpy(st->private_key, from_st->private_key, sizeof(st->private_key));
    memcpy(st->public_key, from_st->public_key, sizeof(st->public_key));
    return NOISE_ERROR_NONE;
}

static int noise_curve25519_calculate
    (const NoiseDHState *private_key_state,
     const NoiseDHState *public_key_state,
     uint8_t *shared_key)
{
  uint8_t tmp[1 + 32];
  memcpy(tmp + 1, public_key_state->public_key, 32);
  tmp[31 + 1] &= 0x7fu;
  be2le(tmp + 1, 32);
  tmp[0] = 0x02;

  uint8_t tmp_private[32];
  memcpy(tmp_private, private_key_state->private_key, 32);
  tmp_private[0] &= 0xf8u;
  tmp_private[31] &= 0x7fu;
  tmp_private[31] |= 0x40u;
  be2le(tmp_private, 32);

  cx_ecfp_scalar_mult(CX_CURVE_Curve25519, tmp, 33, tmp_private, 32); // Receive little endian
  be2le(tmp + 1, 32);

  memcpy(shared_key, tmp + 1, 32);

  return NOISE_ERROR_NONE;
}

NoiseDHState *noise_curve25519_new(void)
{
    NoiseCurve25519State *state = noise_new(NoiseCurve25519State);
    if (!state)
        return 0;
    state->parent.dh_id = NOISE_DH_CURVE25519;
    state->parent.nulls_allowed = 1;
    state->parent.private_key_len = 32;
    state->parent.public_key_len = 32;
    state->parent.shared_key_len = 32;
    state->parent.private_key = state->private_key;
    state->parent.public_key = state->public_key;
    state->parent.generate_keypair = noise_curve25519_generate_keypair;
    state->parent.set_keypair = noise_curve25519_set_keypair;
    state->parent.set_keypair_private = noise_curve25519_set_keypair_private;
    state->parent.validate_public_key = noise_curve25519_validate_public_key;
    state->parent.copy = noise_curve25519_copy;
    state->parent.calculate = noise_curve25519_calculate;
    return &(state->parent);
}
