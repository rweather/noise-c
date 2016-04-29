
AUTOMAKE_OPTIONS = serial-tests

noinst_PROGRAMS = test-vector

test_vector_SOURCES = test-vector.c json-reader.c

AM_CPPFLAGS = -I$(top_srcdir)/include
AM_CFLAGS = @WARNING_FLAGS@

LDADD = ../../src/protocol/libnoiseprotocol.a

TESTS = $(noinst_PROGRAMS)
