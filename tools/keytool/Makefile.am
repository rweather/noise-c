
bin_PROGRAMS = noise-keytool

noise_keytool_SOURCES = \
	generate.c \
	keytool.c \
	show.c \
	sign.c

AM_CPPFLAGS = -I$(top_srcdir)/include
AM_CFLAGS = @WARNING_FLAGS@

LDADD = ../../src/keys/libnoisekeys.a \
        ../../src/protobufs/libnoiseprotobufs.a \
        ../../src/protocol/libnoiseprotocol.a

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
