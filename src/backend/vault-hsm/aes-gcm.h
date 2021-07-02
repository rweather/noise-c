
#ifndef _AES_GCM_H_
# define _AES_GCM_H_

#include <stdint.h>
#include <stddef.h>


#if defined(__linux__) || defined(__GLIBC__)
#include <endian.h>
#include <byteswap.h>
#endif /* __linux__ */

#ifndef WPA_BYTE_SWAP_DEFINED

#ifndef __BYTE_ORDER
#ifndef __LITTLE_ENDIAN
#ifndef __BIG_ENDIAN
#define __LITTLE_ENDIAN 1234
#define __BIG_ENDIAN 4321
#if defined(sparc)
#define __BYTE_ORDER __BIG_ENDIAN
#endif
#endif /* __BIG_ENDIAN */
#endif /* __LITTLE_ENDIAN */
#endif /* __BYTE_ORDER */

#define WPA_BYTE_SWAP_DEFINED
#endif /* !WPA_BYTE_SWAP_DEFINED */


/* Macros for handling unaligned memory accesses */

#define WPA_GET_BE16(a) ((uint16_t) (((a)[0] << 8) | (a)[1]))
#define WPA_PUT_BE16(a, val)			\
	do {					\
		(a)[0] = ((uint16_t) (val)) >> 8;	\
		(a)[1] = ((uint16_t) (val)) & 0xff;	\
	} while (0)

#define WPA_GET_LE16(a) ((uint16_t) (((a)[1] << 8) | (a)[0]))
#define WPA_PUT_LE16(a, val)			\
	do {					\
		(a)[1] = ((uint16_t) (val)) >> 8;	\
		(a)[0] = ((uint16_t) (val)) & 0xff;	\
	} while (0)

#define WPA_GET_BE24(a) ((((uint32_t) (a)[0]) << 16) | (((uint32_t) (a)[1]) << 8) | \
			 ((uint32_t) (a)[2]))
#define WPA_PUT_BE24(a, val)					\
	do {							\
		(a)[0] = (uint8_t) ((((uint32_t) (val)) >> 16) & 0xff);	\
		(a)[1] = (uint8_t) ((((uint32_t) (val)) >> 8) & 0xff);	\
		(a)[2] = (uint8_t) (((uint32_t) (val)) & 0xff);		\
	} while (0)

#define WPA_GET_BE32(a) ((((uint32_t) (a)[0]) << 24) | (((uint32_t) (a)[1]) << 16) | \
			 (((uint32_t) (a)[2]) << 8) | ((uint32_t) (a)[3]))
#define WPA_PUT_BE32(a, val)					\
	do {							\
		(a)[0] = (uint8_t) ((((uint32_t) (val)) >> 24) & 0xff);	\
		(a)[1] = (uint8_t) ((((uint32_t) (val)) >> 16) & 0xff);	\
		(a)[2] = (uint8_t) ((((uint32_t) (val)) >> 8) & 0xff);	\
		(a)[3] = (uint8_t) (((uint32_t) (val)) & 0xff);		\
	} while (0)

#define WPA_GET_LE32(a) ((((uint32_t) (a)[3]) << 24) | (((uint32_t) (a)[2]) << 16) | \
			 (((uint32_t) (a)[1]) << 8) | ((uint32_t) (a)[0]))
#define WPA_PUT_LE32(a, val)					\
	do {							\
		(a)[3] = (uint8_t) ((((uint32_t) (val)) >> 24) & 0xff);	\
		(a)[2] = (uint8_t) ((((uint32_t) (val)) >> 16) & 0xff);	\
		(a)[1] = (uint8_t) ((((uint32_t) (val)) >> 8) & 0xff);	\
		(a)[0] = (uint8_t) (((uint32_t) (val)) & 0xff);		\
	} while (0)

#define WPA_GET_BE64(a) ((((uint64_t) (a)[0]) << 56) | (((uint64_t) (a)[1]) << 48) | \
			 (((uint64_t) (a)[2]) << 40) | (((uint64_t) (a)[3]) << 32) | \
			 (((uint64_t) (a)[4]) << 24) | (((uint64_t) (a)[5]) << 16) | \
			 (((uint64_t) (a)[6]) << 8) | ((uint64_t) (a)[7]))
#define WPA_PUT_BE64(a, val)				\
	do {						\
		(a)[0] = (uint8_t) (((uint64_t) (val)) >> 56);	\
		(a)[1] = (uint8_t) (((uint64_t) (val)) >> 48);	\
		(a)[2] = (uint8_t) (((uint64_t) (val)) >> 40);	\
		(a)[3] = (uint8_t) (((uint64_t) (val)) >> 32);	\
		(a)[4] = (uint8_t) (((uint64_t) (val)) >> 24);	\
		(a)[5] = (uint8_t) (((uint64_t) (val)) >> 16);	\
		(a)[6] = (uint8_t) (((uint64_t) (val)) >> 8);	\
		(a)[7] = (uint8_t) (((uint64_t) (val)) & 0xff);	\
	} while (0)

#define WPA_GET_LE64(a) ((((uint64_t) (a)[7]) << 56) | (((uint64_t) (a)[6]) << 48) | \
			 (((uint64_t) (a)[5]) << 40) | (((uint64_t) (a)[4]) << 32) | \
			 (((uint64_t) (a)[3]) << 24) | (((uint64_t) (a)[2]) << 16) | \
			 (((uint64_t) (a)[1]) << 8) | ((uint64_t) (a)[0]))

#ifndef BIT
#define BIT(x) (1 << (x))
#endif


int aes_gcm_ae(const uint8_t *key, size_t key_len, const uint8_t *iv, size_t iv_len,
	       const uint8_t *plain, size_t plain_len,
	       const uint8_t *aad, size_t aad_len, uint8_t *crypt, uint8_t *tag);

int aes_gcm_ad(const uint8_t *key, size_t key_len, const uint8_t *iv, size_t iv_len,
	       const uint8_t *crypt, size_t crypt_len,
	       const uint8_t *aad, size_t aad_len, const uint8_t *tag, uint8_t *plain);

int aes_gmac(const uint8_t *key, size_t key_len, const uint8_t *iv, size_t iv_len,
	     const uint8_t *aad, size_t aad_len, uint8_t *tag);




#endif /* _AES_GCM_H_ */
