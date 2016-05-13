
lib_LIBRARIES = libnoisekeys.a

AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/include/noise/keys
AM_CFLAGS = @WARNING_FLAGS@

libnoisekeys_a_SOURCES = \
	certificate.c \
	loader.c

protos:
	$(top_builddir)/tools/protoc/noise-protoc \
		-c $(top_srcdir)/src/keys/certificate.c \
		-h $(top_srcdir)/include/noise/keys/certificate.h \
		-l $(top_srcdir)/COPYING \
		$(top_srcdir)/doc/noise-certificate.proto
