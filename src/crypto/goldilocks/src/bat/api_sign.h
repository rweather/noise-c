/**
 * @file sizes.h
 * @copyright
 *   Copyright (c) 2014 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief BATMAN / SUPERCOP glue for benchmarking.
 */

#include <string.h>
#include "goldilocks.h"

#define PUBLICKEY_BYTES GOLDI_PUBLIC_KEY_BYTES
#define SECRETKEY_BYTES GOLDI_PRIVATE_KEY_BYTES
#define SIGNATURE_BYTES GOLDI_SIGNATURE_BYTES

#define CRYPTO_PUBLICKEYBYTES PUBLICKEY_BYTES
#define CRYPTO_SECRETKEYBYTES SECRETKEY_BYTES
#define CRYPTO_BYTES SIGNATURE_BYTES
#define PRIVATEKEY_BYTES SECRETKEY_BYTES
#define CRYPTO_VERSION "__TODAY__"

#define CRYPTO_DETERMINISTIC 1

