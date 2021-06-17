
AUTOMAKE_OPTIONS = subdir-objects

lib_LIBRARIES = libnoiseprotocol.a

# Definitions for Ed448-Goldilocks (Curve448 reference implementation)
GOLDILOCKS_SRCDIR = $(top_srcdir)/src/crypto/goldilocks/src
GOLDILOCKS_CPPFLAGS = \
	-I$(GOLDILOCKS_SRCDIR)/include \
	-I$(GOLDILOCKS_SRCDIR)/p448 \
	-I$(GOLDILOCKS_SRCDIR)/p448/@GOLDILOCKS_ARCH@

AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src $(GOLDILOCKS_CPPFLAGS)
AM_CFLAGS = @WARNING_FLAGS@

if USE_OPENSSL
AM_CPPFLAGS += -DUSE_OPENSSL=1
AM_CFLAGS += $(openssl_CFLAGS)
endif

if USE_LIBSODIUM
AM_CPPFLAGS += -DUSE_LIBSODIUM=1
AM_CFLAGS += $(libsodium_CFLAGS)
else !USE_LIBSODIUM
# Definitions for ed25519-donna (Ed25519 reference implementation)
ED25519_CPPFLAGS = -DED25519_CUSTOMHASH -DED25519_CUSTOMRANDOM
AM_CPPFLAGS += $(ED25519_CPPFLAGS)
endif

libnoiseprotocol_a_SOURCES = \
	cipherstate.c \
	dhstate.c \
	errors.c \
	handshakestate.c \
	hashstate.c \
	internal.c \
	names.c \
	patterns.c \
	randstate.c \
	signstate.c \
	symmetricstate.c \
	util.c \
	../backend/ref/dh-curve448.c \
	../backend/ref/dh-newhope.c \
	../backend/ref/hash-blake2s.c \
	../crypto/blake2/blake2s.c \
	../crypto/curve448/curve448.c \
	../crypto/goldilocks/src/p448/@GOLDILOCKS_ARCH@/p448.c \
	../crypto/newhope/batcher.c \
	../crypto/newhope/error_correction.c \
	../crypto/newhope/error_correction.h \
	../crypto/newhope/fips202.c \
	../crypto/newhope/fips202.h \
	../crypto/newhope/newhope.c \
	../crypto/newhope/newhope.h \
	../crypto/newhope/ntt.c \
	../crypto/newhope/ntt.h \
	../crypto/newhope/params.h \
	../crypto/newhope/poly.c \
	../crypto/newhope/poly.h \
	../crypto/newhope/precomp.c \
	../crypto/newhope/randombytes.h \
	../crypto/newhope/reduce.c \
	../crypto/newhope/reduce.h

if USE_OPENSSL
libnoiseprotocol_a_SOURCES += \
	../backend/openssl/cipher-aesgcm.c
else !USE_OPENSSL
if USE_LIBSODIUM
libnoiseprotocol_a_SOURCES += \
	../backend/sodium/cipher-aesgcm.c
else
libnoiseprotocol_a_SOURCES += \
	../backend/ref/cipher-aesgcm.c
endif
endif

if USE_LIBSODIUM
libnoiseprotocol_a_SOURCES += \
	rand_sodium.c \
	../backend/sodium/cipher-aesgcm.c \
	../backend/sodium/cipher-chachapoly.c \
	../backend/sodium/dh-curve25519.c \
	../backend/sodium/hash-blake2b.c \
	../backend/sodium/hash-sha256.c \
	../backend/sodium/hash-sha512.c \
	../backend/sodium/sign-ed25519.c
else !USE_LIBSODIUM
libnoiseprotocol_a_SOURCES += \
	rand_os.c \
	../backend/ref/cipher-aesgcm.c \
	../backend/ref/cipher-chachapoly.c \
	../backend/ref/dh-curve25519.c \
	../backend/ref/hash-blake2b.c \
	../backend/ref/hash-sha256.c \
	../backend/ref/hash-sha512.c \
	../backend/ref/sign-ed25519.c \
	../crypto/aes/rijndael-alg-fst.c \
	../crypto/blake2/blake2b.c \
	../crypto/chacha/chacha.c \
	../crypto/donna/poly1305-donna.c \
	../crypto/ghash/ghash.c \
	../crypto/newhope/crypto_stream_chacha20.c \
	../crypto/newhope/crypto_stream_chacha20.h \
	../crypto/sha2/sha256.c \
	../crypto/sha2/sha512.c \
	../crypto/ed25519/ed25519.c
endif
