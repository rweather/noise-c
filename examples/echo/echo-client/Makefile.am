
AUTOMAKE_OPTIONS = subdir-objects

noinst_PROGRAMS = echo-client

echo_client_SOURCES = echo-client.c

AM_CPPFLAGS = -I$(top_srcdir)/include -I$(srcdir)/../echo-server
AM_CFLAGS = @WARNING_FLAGS@

LDADD = ../../../src/protocol/libnoiseprotocol.a

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
