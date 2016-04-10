/**
 * @file sizes.h
 * @copyright
 *   Copyright (c) 2014 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief BATMAN / SUPERCOP glue for benchmarking.
 */

#include <string.h>
#include <stdlib.h>
#include "api.h"
#include "crypto_dh.h"

int crypto_dh_keypair (
    unsigned char pk[SECRETKEY_BYTES],
    unsigned char sk[PUBLICKEY_BYTES]
) {
  int ret;
  ret = goldilocks_init();
  if (ret && ret != GOLDI_EALREADYINIT)
    return ret;
  if ((ret = goldilocks_keygen(
      (struct goldilocks_private_key_t *)sk,
      (struct goldilocks_public_key_t *)pk
  ))) abort();
  return ret;
}

int crypto_dh (
    unsigned char s[SHAREDSECRET_BYTES],
    const unsigned char pk[PUBLICKEY_BYTES],
    const unsigned char sk[SECRETKEY_BYTES]
) {
  return goldilocks_shared_secret (
        s,
        (const struct goldilocks_private_key_t *)sk,
        (const struct goldilocks_public_key_t *)pk
  );
}
