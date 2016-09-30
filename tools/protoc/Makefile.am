
bin_PROGRAMS = noise-protoc

BUILT_SOURCES = proto3-grammar.h

noise_protoc_SOURCES = \
	main.c \
        proto3-ast.c \
        proto3-generate-c.c \
        proto3-grammar.y \
        proto3-lexer.l

AM_CFLAGS = @WARNING_FLAGS@
AM_YFLAGS = -d

CLEANFILES = proto3-grammar.c proto3-grammar.h proto3-lexer.c

EXTRA_DIST = test.proto
