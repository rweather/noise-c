
noinst_PROGRAMS = test-vector

test_vector_SOURCES = test-vector.c json-reader.c

AM_CPPFLAGS = -I$(top_srcdir)/include
AM_CFLAGS = @WARNING_FLAGS@

LDADD = ../../src/protocol/libnoiseprotocol.a

VECTORS = \
    $(srcdir)/cacophony.txt \
    $(srcdir)/noise-c-basic.txt \
    $(srcdir)/noise-c-fallback.txt \
    $(srcdir)/noise-c-hybrid.txt

check-local:
	./test-vector $(VECTORS)

EXTRA_DIST = $(VECTORS)

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
