/*
 * Galois/Counter Mode (GCM) and GMAC with AES
 *
 * Copyright (c) 2012, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */


#include <string.h>
#include <stdint.h>
#include "aes-gcm.h"

#ifdef USE_BOLOS_VAULTAPP_BACKEND
#include "cx.h"
#define AES_CONTEXT_T  cx_aes_key_t
#define AES_BLOCK_SIZE CX_AES_BLOCK_SIZE
#define AES(key, mode, in, in_len, out, out_len) cx_aes(key, mode, in, in_len, out, out_len)
#define AES_INIT_KEY(raw_key, key_len, key_context) (cx_aes_init_key(raw_key, key_len, key_context) == key_len)

#define AES_LAST CX_LAST
#define AES_ENCRYPT CX_ENCRYPT
#define AES_PAD_NONE CX_PAD_NONE
#define AES_CHAIN_ECB CX_CHAIN_ECB

#define memcpy os_memcpy
#define memset os_memset

#elif USE_BOLOS_VAULTHSM_BACKEND
#include <bolos.h>
#define AES_CONTEXT_T bls_aes_key_t
#define AES_BLOCK_SIZE BLS_AES_BLOCK_SIZE
#define AES(key, mode, in, in_len, out, out_len) \
  do { \
    bls_aes(key, mode, \
	    &((const bls_area_t){.buffer=in, .length=in_len}), \
	    &((bls_area_t){.buffer=out, .length=out_len})); \
  } while (0);
#define AES_INIT_KEY(raw_key, key_len, key_context) (bls_aes_init_key(raw_key, key_len, key_context) == 1)

#define AES_LAST BLS_LAST
#define AES_ENCRYPT BLS_ENCRYPT
#define AES_PAD_NONE BLS_PAD_NONE
#define AES_CHAIN_ECB BLS_CHAIN_ECB

// Found in enclave but not exposed in sdk
#define MAX_SYMMETRIC_KEY_LEN 32

typedef bls_area_t area_t;

#else
#error USE_BOLOS_VAULTAPP_BACKEND or USE_BOLOS_VAULTHSM_BACKEND should be defined
#endif

/* bolos handles a limited number of crypto handles and does not allow release them once allocated.*/
/* So we reuse the same handle for all operations in this file. */
AES_CONTEXT_T aes = {0};

static int os_memcmp_const(const void *a, const void *b, size_t len)
{
	const uint8_t *aa = a;
	const uint8_t *bb = b;
	size_t i;
	uint8_t res;

	for (res = 0, i = 0; i < len; i++)
		res |= aa[i] ^ bb[i];

	return res;
}

/* fill the aes key with 0 */
static int aes_wipe_key(AES_CONTEXT_T *aes) {
#ifdef USE_BOLOS_VAULTHSM_BACKEND
  const uint8_t zero_key[MAX_SYMMETRIC_KEY_LEN] = {0};

  if (!AES_INIT_KEY(zero_key, MAX_SYMMETRIC_KEY_LEN, aes))
    return -1;
  return 0;
#else /* USE_BOLOS_VAULTHSM_BACKEND */
  memset(&aes, 0, sizeof(*aes));
  return 0;
#endif
}


static void inc32(uint8_t *block)
{
	uint32_t val;
	val = WPA_GET_BE32(block + AES_BLOCK_SIZE - 4);
	val++;
	WPA_PUT_BE32(block + AES_BLOCK_SIZE - 4, val);
}


static void xor_block(uint8_t *dst, const uint8_t *src)
{
  uint8_t *d = (uint8_t *) dst;
  const uint8_t *s = (const uint8_t *) src;

  *d++ ^= *s++;
  *d++ ^= *s++;
  *d++ ^= *s++;
  *d++ ^= *s++;

  *d++ ^= *s++;
  *d++ ^= *s++;
  *d++ ^= *s++;
  *d++ ^= *s++;

  *d++ ^= *s++;
  *d++ ^= *s++;
  *d++ ^= *s++;
  *d++ ^= *s++;

  *d++ ^= *s++;
  *d++ ^= *s++;
  *d++ ^= *s++;
  *d++ ^= *s++;
}

static void shift_right_block(uint8_t *v)
{
	uint32_t val;

	val = WPA_GET_BE32(v + 12);
	val >>= 1;
	if (v[11] & 0x01)
		val |= 0x80000000;
	WPA_PUT_BE32(v + 12, val);

	val = WPA_GET_BE32(v + 8);
	val >>= 1;
	if (v[7] & 0x01)
		val |= 0x80000000;
	WPA_PUT_BE32(v + 8, val);

	val = WPA_GET_BE32(v + 4);
	val >>= 1;
	if (v[3] & 0x01)
		val |= 0x80000000;
	WPA_PUT_BE32(v + 4, val);

	val = WPA_GET_BE32(v);
	val >>= 1;
	WPA_PUT_BE32(v, val);
}


/* Multiplication in GF(2^128) */
static void gf_mult(const uint8_t *x, const uint8_t *y, uint8_t *z)
{
	uint8_t v[16];
	int i, j;

	memset(z, 0, 16); /* Z_0 = 0^128 */
	memcpy(v, y, 16); /* V_0 = Y */

	for (i = 0; i < 16; i++) {
		for (j = 0; j < 8; j++) {
			if (x[i] & BIT(7 - j)) {
				/* Z_(i + 1) = Z_i XOR V_i */
				xor_block(z, v);
			} else {
				/* Z_(i + 1) = Z_i */
			}

			if (v[15] & 0x01) {
				/* V_(i + 1) = (V_i >> 1) XOR R */
				shift_right_block(v);
				/* R = 11100001 || 0^120 */
				v[0] ^= 0xe1;
			} else {
				/* V_(i + 1) = V_i >> 1 */
				shift_right_block(v);
			}
		}
	}
}


static void ghash_start(uint8_t *y)
{
	/* Y_0 = 0^128 */
	memset(y, 0, 16);
}


static void ghash(const uint8_t *h, const uint8_t *x, size_t xlen, uint8_t *y)
{
	size_t m, i;
	const uint8_t *xpos = x;
	uint8_t tmp[16];

	m = xlen / 16;

	for (i = 0; i < m; i++) {
		/* Y_i = (Y^(i-1) XOR X_i) dot H */
		xor_block(y, xpos);
		xpos += 16;

		/* dot operation:
		 * multiplication operation for binary Galois (finite) field of
		 * 2^128 elements */
		gf_mult(y, h, tmp);
		memcpy(y, tmp, 16);
	}

	if (x + xlen > xpos) {
		/* Add zero padded last block */
		size_t last = x + xlen - xpos;
		memcpy(tmp, xpos, last);
		memset(tmp + last, 0, sizeof(tmp) - last);

		/* Y_i = (Y^(i-1) XOR X_i) dot H */
		xor_block(y, tmp);

		/* dot operation:
		 * multiplication operation for binary Galois (finite) field of
		 * 2^128 elements */
		gf_mult(y, h, tmp);
		memcpy(y, tmp, 16);
	}
	/* Return Y_m */
}


static void aes_gctr(AES_CONTEXT_T *aes, const uint8_t *icb, const uint8_t *x, size_t xlen, uint8_t *y)
{
	size_t i, n, last;
	uint8_t cb[AES_BLOCK_SIZE], tmp[AES_BLOCK_SIZE];
	const uint8_t *xpos = x;
	uint8_t *ypos = y;

	if (xlen == 0)
		return;

	n = xlen / 16;

	memcpy(cb, icb, AES_BLOCK_SIZE);
	/* Full blocks */
	for (i = 0; i < n; i++) {
	  /* aes_encrypt(aes, cb, ypos); */
	  AES(aes, AES_LAST | AES_ENCRYPT | AES_PAD_NONE | AES_CHAIN_ECB, cb, sizeof(cb), ypos, AES_BLOCK_SIZE);
	  xor_block(ypos, xpos);
	  xpos += AES_BLOCK_SIZE;
	  ypos += AES_BLOCK_SIZE;
	  inc32(cb);
	}

	last = x + xlen - xpos;
	if (last) {
	  /* Last, partial block */
	  AES(aes, AES_LAST | AES_ENCRYPT | AES_PAD_NONE | AES_CHAIN_ECB, cb, sizeof(cb), tmp, sizeof(tmp));
	  /* aes_encrypt(aes, cb, tmp); */
	  for (i = 0; i < last; i++)
	    *ypos++ = *xpos++ ^ tmp[i];
	}
}


static int aes_gcm_init_hash_subkey(const uint8_t *key, size_t key_len, AES_CONTEXT_T *aes, uint8_t *H)
{
  /* void *aes; */

  /* aes = aes_encrypt_init(key, key_len); */
  /* if (aes == NULL) */
  /* 	return NULL; */
  if (!AES_INIT_KEY(key, key_len, aes)) {
    return -1;
  }

  /* Generate hash subkey H = AES_K(0^128) */
  /* memset(H, 0, AES_BLOCK_SIZE); */
  /* aes_encrypt(aes, H, H); */
  /* wpa_hexdump_key(MSG_EXCESSIVE, "Hash subkey H for GHASH", */
  /* 		H, AES_BLOCK_SIZE); */
  memset(H, 0, AES_BLOCK_SIZE);
  AES(aes, AES_LAST | AES_ENCRYPT | AES_PAD_NONE | AES_CHAIN_ECB, H, AES_BLOCK_SIZE, H, AES_BLOCK_SIZE);
  return 0;
}


static void aes_gcm_prepare_j0(const uint8_t *iv, size_t iv_len, const uint8_t *H, uint8_t *J0)
{
	uint8_t len_buf[16];

	if (iv_len == 12) {
		/* Prepare block J_0 = IV || 0^31 || 1 [len(IV) = 96] */
		memcpy(J0, iv, iv_len);
		memset(J0 + iv_len, 0, AES_BLOCK_SIZE - iv_len);
		J0[AES_BLOCK_SIZE - 1] = 0x01;
	} else {
		/*
		 * s = 128 * ceil(len(IV)/128) - len(IV)
		 * J_0 = GHASH_H(IV || 0^(s+64) || [len(IV)]_64)
		 */
		ghash_start(J0);
		ghash(H, iv, iv_len, J0);
		WPA_PUT_BE64(len_buf, 0);
		WPA_PUT_BE64(len_buf + 8, iv_len * 8);
		ghash(H, len_buf, sizeof(len_buf), J0);
	}
}


static void aes_gcm_gctr(AES_CONTEXT_T *aes, const uint8_t *J0, const uint8_t *in, size_t len,
			 uint8_t *out)
{
	uint8_t J0inc[AES_BLOCK_SIZE];

	if (len == 0)
		return;

	memcpy(J0inc, J0, AES_BLOCK_SIZE);
	inc32(J0inc);
	aes_gctr(aes, J0inc, in, len, out);
}


static void aes_gcm_ghash(const uint8_t *H, const uint8_t *aad, size_t aad_len,
			  const uint8_t *crypt, size_t crypt_len, uint8_t *S)
{
	uint8_t len_buf[16];

	/*
	 * u = 128 * ceil[len(C)/128] - len(C)
	 * v = 128 * ceil[len(A)/128] - len(A)
	 * S = GHASH_H(A || 0^v || C || 0^u || [len(A)]64 || [len(C)]64)
	 * (i.e., zero padded to block size A || C and lengths of each in bits)
	 */
	ghash_start(S);
	ghash(H, aad, aad_len, S);
	ghash(H, crypt, crypt_len, S);
	WPA_PUT_BE64(len_buf, aad_len * 8);
	WPA_PUT_BE64(len_buf + 8, crypt_len * 8);
	ghash(H, len_buf, sizeof(len_buf), S);

	/* wpa_hexdump_key(MSG_EXCESSIVE, "S = GHASH_H(...)", S, 16); */
}


/**
 * aes_gcm_ae - GCM-AE_K(IV, P, A)
 */
int aes_gcm_ae(const uint8_t *key, size_t key_len, const uint8_t *iv, size_t iv_len,
	       const uint8_t *plain, size_t plain_len,
	       const uint8_t *aad, size_t aad_len, uint8_t *crypt, uint8_t *tag)
{
	uint8_t H[AES_BLOCK_SIZE];
	uint8_t J0[AES_BLOCK_SIZE];
	uint8_t S[16];

	if (iv == NULL || iv_len < 1) {
	  return -1;
	}

	if (aes_gcm_init_hash_subkey(key, key_len, &aes, H) < 0) {
	  return -1;
	}
	/* if (aes == NULL) */
	/* 	return -1; */

	aes_gcm_prepare_j0(iv, iv_len, H, J0);

	/* C = GCTR_K(inc_32(J_0), P) */
	aes_gcm_gctr(&aes, J0, plain, plain_len, crypt);

	aes_gcm_ghash(H, aad, aad_len, crypt, plain_len, S);

	/* T = MSB_t(GCTR_K(J_0, S)) */
	aes_gctr(&aes, J0, S, sizeof(S), tag);

	/* Return (C, T) */
	/* aes_encrypt_deinit(aes); */
	return aes_wipe_key(&aes);
}


/**
 * aes_gcm_ad - GCM-AD_K(IV, C, A, T)
 */
int aes_gcm_ad(const uint8_t *key, size_t key_len, const uint8_t *iv, size_t iv_len,
	       const uint8_t *crypt, size_t crypt_len,
	       const uint8_t *aad, size_t aad_len, const uint8_t *tag, uint8_t *plain)
{
	uint8_t H[AES_BLOCK_SIZE];
	uint8_t J0[AES_BLOCK_SIZE];
	uint8_t S[16], T[16];

	if (iv == NULL || iv_len < 1) {
	  return -1;
	}

	if (aes_gcm_init_hash_subkey(key, key_len, &aes, H) < 0) {
	  return -1;
	}

	aes_gcm_prepare_j0(iv, iv_len, H, J0);

	/* P = GCTR_K(inc_32(J_0), C) */
	aes_gcm_gctr(&aes, J0, crypt, crypt_len, plain);

	aes_gcm_ghash(H, aad, aad_len, crypt, crypt_len, S);

	/* T' = MSB_t(GCTR_K(J_0, S)) */
	aes_gctr(&aes, J0, S, sizeof(S), T);

	/* aes_encrypt_deinit(aes); */
	if (aes_wipe_key(&aes) != 0) {
	  return -1;
	}

	if (os_memcmp_const(tag, T, 16) != 0) {
	  return -1;
	}

	return 0;
}


int aes_gmac(const uint8_t *key, size_t key_len, const uint8_t *iv, size_t iv_len,
	     const uint8_t *aad, size_t aad_len, uint8_t *tag)
{
	return aes_gcm_ae(key, key_len, iv, iv_len, NULL, 0, aad, aad_len, NULL,
			  tag);
}
