
noinst_PROGRAMS = test-noise

test_noise_SOURCES = \
	test-cipherstate.c \
	test-dhstate.c \
	test-errors.c \
	test-handshakestate.c \
	test-hashstate.c \
	test-main.c \
	test-names.c \
	test-patterns.c \
	test-protobufs.c \
	test-randstate.c \
	test-signstate.c \
	test-symmetricstate.c

AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src
AM_CFLAGS = @WARNING_FLAGS@

LDADD = ../../src/keys/libnoisekeys.a \
        ../../src/protobufs/libnoiseprotobufs.a \
        ../../src/protocol/libnoiseprotocol.a

check-local:
	./test-noise

if USE_LIBSODIUM
AM_CPPFLAGS += -DUSE_LIBSODIUM=1
AM_CFLAGS += $(libsodium_CFLAGS)
LDADD += $(libsodium_LIBS)
endif

if USE_OPENSSL
AM_CPPFLAGS += -DUSE_OPENSSL=1
AM_CFLAGS += $(openssl_CFLAGS)
LDADD += $(openssl_LIBS)
endif
