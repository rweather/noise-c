
noinst_PROGRAMS = echo-server

echo_server_SOURCES = \
	echo-server.c \
	echo-common.c

AM_CPPFLAGS = -I$(top_srcdir)/include
AM_CFLAGS = @WARNING_FLAGS@

LDADD = ../../../src/protocol/libnoiseprotocol.a
