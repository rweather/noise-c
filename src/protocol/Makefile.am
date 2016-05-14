
AUTOMAKE_OPTIONS = subdir-objects

lib_LIBRARIES = libnoiseprotocol.a

# Definitions for Ed448-Goldilocks (Curve448 reference implementation)
GOLDILOCKS_SRCDIR = $(top_srcdir)/src/crypto/goldilocks/src
GOLDILOCKS_CPPFLAGS = \
	-I$(GOLDILOCKS_SRCDIR)/include \
	-I$(GOLDILOCKS_SRCDIR)/p448 \
	-I$(GOLDILOCKS_SRCDIR)/p448/@GOLDILOCKS_ARCH@

# Definitions for ed25519-donna (Ed25519 reference implementation)
ED25519_CPPFLAGS = -DED25519_CUSTOMHASH -DED25519_CUSTOMRANDOM

AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src $(GOLDILOCKS_CPPFLAGS) $(ED25519_CPPFLAGS)
AM_CFLAGS = @WARNING_FLAGS@

libnoiseprotocol_a_SOURCES = \
	cipherstate.c \
	dhstate.c \
	errors.c \
	handshakestate.c \
	hashstate.c \
        internal.h \
	names.c \
	patterns.c \
	randstate.c \
	rand_os.c \
	signstate.c \
	symmetricstate.c \
	util.c \
	../backend/ref/cipher-aesgcm.c \
	../backend/ref/cipher-chachapoly.c \
	../backend/ref/dh-curve25519.c \
	../backend/ref/dh-curve448.c \
	../backend/ref/hash-blake2s.c \
	../backend/ref/hash-blake2b.c \
	../backend/ref/hash-sha256.c \
	../backend/ref/hash-sha512.c \
	../backend/ref/sign-ed25519.c \
	../crypto/aes/rijndael-alg-fst.c \
	../crypto/blake2/blake2s.c \
	../crypto/blake2/blake2b.c \
	../crypto/chacha/chacha.c \
	../crypto/curve448/curve448.c \
	../crypto/donna/poly1305-donna.c \
	../crypto/ghash/ghash.c \
	../crypto/sha2/sha256.c \
	../crypto/sha2/sha512.c \
	../crypto/goldilocks/src/p448/@GOLDILOCKS_ARCH@/p448.c \
	../crypto/ed25519/ed25519.c
