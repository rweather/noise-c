/*
	a custom hash must have a 512bit digest and implement:

	struct ed25519_hash_context;

	void ed25519_hash_init(ed25519_hash_context *ctx);
	void ed25519_hash_update(ed25519_hash_context *ctx, const uint8_t *in, size_t inlen);
	void ed25519_hash_final(ed25519_hash_context *ctx, uint8_t *hash);
	void ed25519_hash(uint8_t *hash, const uint8_t *in, size_t inlen);
*/

/* Definitions for using the SHA512 code from Noise-C */

#include "../sha2/sha512.h"

#define ed25519_hash_context sha512_context_t
#define ed25519_hash_init sha512_reset
#define ed25519_hash_update sha512_update
#define ed25519_hash_final sha512_finish
#define ed25519_hash sha512_hash
