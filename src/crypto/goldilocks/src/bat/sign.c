/**
 * @file sizes.h
 * @copyright
 *   Copyright (c) 2014 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief BATMAN / SUPERCOP glue for benchmarking.
 */

#include <stdlib.h>
#include <string.h>
#include "api.h"
#include "crypto_sign.h"

int crypto_sign_keypair (
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

int crypto_sign (
    unsigned char *sm,
    unsigned long long *smlen,
    const unsigned char *m,
    unsigned long long mlen,
    const unsigned char sk[SECRETKEY_BYTES]
) {
    unsigned char sig[SIGNATURE_BYTES];
    int ret = goldilocks_sign(
        sig, m, mlen,
        (const struct goldilocks_private_key_t *)sk
    );
    if (!ret) {
        memmove(sm + SIGNATURE_BYTES, m, mlen);
        memcpy(sm, sig, SIGNATURE_BYTES);
        *smlen = mlen + SIGNATURE_BYTES;
    }
    return ret ? -1 : 0;
}

int crypto_sign_open (
    unsigned char *m,
    unsigned long long *mlen,
    const unsigned char *sm,
    unsigned long long smlen,
    const unsigned char pk[PUBLICKEY_BYTES]
) {
    int ret = goldilocks_verify(
        sm, sm + SIGNATURE_BYTES, smlen - SIGNATURE_BYTES,
        (const struct goldilocks_public_key_t *)pk
    );
    if (!ret) {
        *mlen = smlen - SIGNATURE_BYTES;
        memmove(m, sm + SIGNATURE_BYTES, *mlen);
    }
    return ret ? -1 : 0;
}
