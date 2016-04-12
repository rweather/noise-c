
.PHONY: all clean check

TOPDIR = ..
SRCDIR = .

LIBRARY = libnoiseprotocol.a

# Definitions for Ed448-Goldilocks (Curve448 reference implementation)
GOLDILOCKS_ARCH = arch_32
GOLDILOCKS_SRCDIR = $(SRCDIR)/crypto/goldilocks/src
GOLDILOCKS_CPPFLAGS = \
	-I$(GOLDILOCKS_SRCDIR)/include \
	-I$(GOLDILOCKS_SRCDIR)/p448 \
	-I$(GOLDILOCKS_SRCDIR)/p448/$(GOLDILOCKS_ARCH)

CPPFLAGS = -I$(TOPDIR)/include -I$(SRCDIR) $(GOLDILOCKS_CPPFLAGS)
CFLAGS = -std=c99 -g -Wall $(CPPFLAGS)

MAIN_SOURCES = \
	cipherstate.c \
        dhstate.c \
        errors.c \
	handshakestate.c \
        hashstate.c \
        names.c \
	patterns.c \
        rand.c \
	symmetricstate.c \
	util.c

BACKEND_REF_SOURCES = \
	backend/ref/cipher-aesgcm.c \
	backend/ref/cipher-chachapoly.c \
	backend/ref/dh-curve25519.c \
	backend/ref/dh-curve448.c \
	backend/ref/hash-blake2s.c \
	backend/ref/hash-blake2b.c \
	backend/ref/hash-sha256.c \
	backend/ref/hash-sha512.c

CRYPTO_REF_SOURCES = \
	crypto/aes/rijndael-alg-fst.c \
	crypto/blake2/blake2s-ref.c \
	crypto/blake2/blake2b-ref.c \
	crypto/chacha/chacha.c \
	crypto/curve448/curve448.c \
	crypto/donna/poly1305-donna.c \
	crypto/donna/curve25519-donna.c \
	crypto/ghash/ghash.c \
	crypto/sha2/sha224-256.c \
	crypto/sha2/sha384-512.c \
	crypto/goldilocks/src/p448/$(GOLDILOCKS_ARCH)/p448.c

SOURCES = $(MAIN_SOURCES) $(BACKEND_REF_SOURCES) $(CRYPTO_REF_SOURCES)

OBJECTS = $(patsubst %.c,%.o,$(SOURCES))
DEPS    = $(patsubst %.c,.depend/%.d,$(SOURCES))

all: $(LIBRARY)

$(LIBRARY): $(OBJECTS)
	$(RM) $(LIBRARY)
	$(AR) cr $(LIBRARY) $(OBJECTS)

clean:
	$(RM) $(OBJECTS) $(LIBRARY)
	$(RM) -r .depend

check:  all

.depend/%.d: %.c
	@set -e; rm -f $@; mkdir -p `dirname $@`; \
	$(CC) -MM $(CPPFLAGS) $< > $@.$$$$; \
	sed 's,\(.*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

-include $(DEPS)
