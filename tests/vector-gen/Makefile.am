
noinst_PROGRAMS = vector-gen

vector_gen_SOURCES = \
    vector-gen.c \
    simple-cipherstate.h \
    simple-cipherstate.c \
    simple-handshakestate.h \
    simple-handshakestate.c \
    simple-symmetricstate.h \
    simple-symmetricstate.c

AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src/protocol
AM_CFLAGS = @WARNING_FLAGS@

LDADD = ../../src/protocol/libnoiseprotocol.a

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
