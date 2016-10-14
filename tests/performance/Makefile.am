
noinst_PROGRAMS = test-performance

test_performance_SOURCES = test-performance.c md5.c

AM_CPPFLAGS = -I$(top_srcdir)/include
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
