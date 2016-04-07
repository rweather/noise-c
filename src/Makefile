
.PHONY: all clean check

TOPDIR = ..
SRCDIR = .

LIBRARY = libnoiseprotocol.a

CPPFLAGS = -I$(TOPDIR)/include -I$(SRCDIR)
CFLAGS = -std=c99 -g -Wall $(CPPFLAGS)

MAIN_SOURCES = \
	cipherstate.c \
	symmetricstate.c \
	util.c

BACKEND_REF_SOURCES = \
	backend/ref/cipher-aesgcm.c \
	backend/ref/cipher-chachapoly.c

CRYPTO_REF_SOURCES = \
	crypto/donna/poly1305-donna.c \
	crypto/donna/curve25519-donna.c \
	crypto/chacha/chacha.c \
	crypto/aes/rijndael-alg-fst.c \
	crypto/blake2/blake2s-ref.c \
	crypto/blake2/blake2b-ref.c

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

check:

.depend/%.d: %.c
	@set -e; rm -f $@; mkdir -p `dirname $@`; \
	$(CC) -MM $(CPPFLAGS) $< > $@.$$$$; \
	sed 's,\(.*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

-include $(DEPS)
