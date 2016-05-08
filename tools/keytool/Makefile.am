
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
