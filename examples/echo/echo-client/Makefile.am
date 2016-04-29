
AUTOMAKE_OPTIONS = subdir-objects

noinst_PROGRAMS = echo-client

echo_client_SOURCES = echo-client.c

AM_CPPFLAGS = -I$(top_srcdir)/include -I$(srcdir)/../echo-server
AM_CFLAGS = @WARNING_FLAGS@

LDADD = ../../../src/protocol/libnoiseprotocol.a
