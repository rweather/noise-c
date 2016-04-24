
.PHONY: all clean check

TOPDIR = ../..
SRCDIR = $(TOPDIR)/src

LIBRARY = libnoiseprotocol.a

# Definitions for Ed448-Goldilocks (Curve448 reference implementation)
GOLDILOCKS_ARCH = arch_ref64
GOLDILOCKS_SRCDIR = $(SRCDIR)/crypto/goldilocks/src
GOLDILOCKS_CPPFLAGS = \
	-I$(GOLDILOCKS_SRCDIR)/include \
	-I$(GOLDILOCKS_SRCDIR)/p448 \
	-I$(GOLDILOCKS_SRCDIR)/p448/$(GOLDILOCKS_ARCH)

# Definitions for ed25519-donna (Ed25519 reference implementation)
ED25519_CPPFLAGS = -DED25519_CUSTOMHASH -DED25519_CUSTOMRANDOM

CPPFLAGS = -I$(TOPDIR)/include -I$(SRCDIR) -I$(SRCDIR)/protocol \
	$(GOLDILOCKS_CPPFLAGS) $(ED25519_CPPFLAGS)
CFLAGS = -std=c99 -g -O2 -Wall $(CPPFLAGS)

MAIN_SOURCES = \
	$(SRCDIR)/protocol/cipherstate.c \
	$(SRCDIR)/protocol/dhstate.c \
	$(SRCDIR)/protocol/errors.c \
	$(SRCDIR)/protocol/handshakestate.c \
	$(SRCDIR)/protocol/hashstate.c \
	$(SRCDIR)/protocol/names.c \
	$(SRCDIR)/protocol/patterns.c \
	$(SRCDIR)/protocol/randstate.c \
	$(SRCDIR)/protocol/rand_os.c \
	$(SRCDIR)/protocol/signstate.c \
	$(SRCDIR)/protocol/symmetricstate.c \
	$(SRCDIR)/protocol/util.c

BACKEND_REF_SOURCES = \
	$(SRCDIR)/backend/ref/cipher-aesgcm.c \
	$(SRCDIR)/backend/ref/cipher-chachapoly.c \
	$(SRCDIR)/backend/ref/dh-curve25519.c \
	$(SRCDIR)/backend/ref/dh-curve448.c \
	$(SRCDIR)/backend/ref/hash-blake2s.c \
	$(SRCDIR)/backend/ref/hash-blake2b.c \
	$(SRCDIR)/backend/ref/hash-sha256.c \
	$(SRCDIR)/backend/ref/hash-sha512.c \
	$(SRCDIR)/backend/ref/sign-ed25519.c

CRYPTO_REF_SOURCES = \
	$(SRCDIR)/crypto/aes/rijndael-alg-fst.c \
	$(SRCDIR)/crypto/blake2/blake2s-ref.c \
	$(SRCDIR)/crypto/blake2/blake2b-ref.c \
	$(SRCDIR)/crypto/chacha/chacha.c \
	$(SRCDIR)/crypto/curve448/curve448.c \
	$(SRCDIR)/crypto/donna/poly1305-donna.c \
	$(SRCDIR)/crypto/donna/curve25519-donna.c \
	$(SRCDIR)/crypto/ghash/ghash.c \
	$(SRCDIR)/crypto/sha2/sha256.c \
	$(SRCDIR)/crypto/sha2/sha512.c \
	$(SRCDIR)/crypto/goldilocks/src/p448/$(GOLDILOCKS_ARCH)/p448.c \
	$(SRCDIR)/crypto/ed25519/ed25519.c

SOURCES = $(MAIN_SOURCES) $(BACKEND_REF_SOURCES) $(CRYPTO_REF_SOURCES)

OBJECTS = $(patsubst %.c,%.o,$(SOURCES))
DEPS    = $(patsubst $(SRCDIR)/%.c,.depend/%.d,$(SOURCES))

all: $(LIBRARY)

$(LIBRARY): $(OBJECTS)
	$(RM) $(LIBRARY)
	$(AR) cr $(LIBRARY) $(OBJECTS)

clean:
	$(RM) $(OBJECTS) $(LIBRARY)
	$(RM) -r .depend

check:  all

.depend/%.d: $(SRCDIR)/%.c
	@set -e; rm -f $@; mkdir -p `dirname $@`; \
	$(CC) -MM $(CPPFLAGS) $< > $@.$$$$; \
	sed 's,\(.*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

-include $(DEPS)
