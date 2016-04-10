# Copyright (c) 2014 Cryptography Research, Inc.
# Released under the MIT License.  See LICENSE.txt for license information.


UNAME := $(shell uname)
MACHINE := $(shell uname -m)

ifeq ($(UNAME),Darwin)
CC = clang
else
CC = gcc
endif
LD = $(CC)
ASM ?= $(CC)

ifneq (,$(findstring x86_64,$(MACHINE)))
ARCH ?= arch_x86_64
else
# no i386 port yet
ARCH ?= arch_arm_32
endif

FIELD ?= p448

WARNFLAGS = -pedantic -Wall -Wextra -Werror -Wunreachable-code \
	 -Wmissing-declarations -Wunused-function -Wno-overlength-strings $(EXWARN)
	 
	 
INCFLAGS = -Isrc/include -Iinclude -Isrc/$(FIELD) -Isrc/$(FIELD)/$(ARCH)
LANGFLAGS = -std=c99 -fno-strict-aliasing
GENFLAGS = -ffunction-sections -fdata-sections -fvisibility=hidden -fomit-frame-pointer -fPIC
OFLAGS = -O3

TODAY = $(shell date "+%Y-%m-%d")

ifneq (,$(findstring arm,$(MACHINE)))
ifneq (,$(findstring neon,$(ARCH)))
ARCHFLAGS += -mfpu=neon
else
ARCHFLAGS += -mfpu=vfpv3-d16
endif
ARCHFLAGS += -mcpu=cortex-a8 # FIXME
GENFLAGS += -DN_TESTS_BASE=1000 # sooooo sloooooow
else
ARCHFLAGS += -maes -mavx2 -mbmi2 #TODO
endif

ifeq ($(CC),clang)
WARNFLAGS += -Wgcc-compat
endif

ifeq (,$(findstring 64,$(ARCH))$(findstring gcc,$(CC)))
# ARCHFLAGS += -m32
XCFLAGS += -DGOLDI_FORCE_32_BIT=1
endif

CFLAGS  = $(LANGFLAGS) $(WARNFLAGS) $(INCFLAGS) $(OFLAGS) $(ARCHFLAGS) $(GENFLAGS) $(XCFLAGS)
LDFLAGS = $(ARCHFLAGS) $(XLDFLAGS)
ASFLAGS = $(ARCHFLAGS)

.PHONY: clean all test bench todo doc lib bat
.PRECIOUS: build/%.s

HEADERS= Makefile $(shell find . -name "*.h") build/timestamp

LIBCOMPONENTS= build/goldilocks.o build/barrett_field.o build/crandom.o \
  build/$(FIELD).o build/ec_point.o build/scalarmul.o build/sha512.o build/magic.o \
	build/f_arithmetic.o build/arithmetic.o

TESTCOMPONENTS=build/test.o build/test_scalarmul.o build/test_sha512.o \
	build/test_pointops.o build/test_arithmetic.o build/test_goldilocks.o build/magic.o

BENCHCOMPONENTS=build/bench.o

BATBASE=ed448goldilocks-bats-$(TODAY)
BATNAME=build/$(BATBASE)

all: lib build/test build/bench

scan: clean
	scan-build --use-analyzer=`which clang` \
		 -enable-checker deadcode -enable-checker llvm \
		 -enable-checker osx -enable-checker security -enable-checker unix \
		make build/bench build/test build/goldilocks.so

build/bench: $(LIBCOMPONENTS) $(BENCHCOMPONENTS)
	$(LD) $(LDFLAGS) -o $@ $^

build/test: $(LIBCOMPONENTS) $(TESTCOMPONENTS)
	$(LD) $(LDFLAGS) -o $@ $^ -lgmp

lib: build/goldilocks.so

build/goldilocks.so: $(LIBCOMPONENTS)
	rm -f $@
ifeq ($(UNAME),Darwin)
	libtool -macosx_version_min 10.6 -dynamic -dead_strip -lc -x -o $@ \
		  $(LIBCOMPONENTS)
else
	$(LD) -shared -Wl,-soname,goldilocks.so.1 -Wl,--gc-sections -o $@ $(LIBCOMPONENTS)
	strip --discard-all $@
	ln -sf $@ build/goldilocks.so.1
endif

build/timestamp:
	mkdir -p build
	touch $@

build/%.o: build/%.s
	$(ASM) $(ASFLAGS) -c -o $@ $<

build/%.s: src/%.c $(HEADERS)
	$(CC) $(CFLAGS) -S -c -o $@ $<

build/%.s: test/%.c $(HEADERS)
	$(CC) $(CFLAGS) -S -c -o $@ $<

build/%.s: src/$(FIELD)/$(ARCH)/%.c $(HEADERS)
	$(CC) $(CFLAGS) -S -c -o $@ $<

build/%.s: src/$(FIELD)/%.c $(HEADERS)
	$(CC) $(CFLAGS) -S -c -o $@ $<

doc/timestamp:
	mkdir -p doc
	touch $@

doc: Doxyfile doc/timestamp src/*.c src/include/*.h src/$(ARCH)/*.c src/$(ARCH)/*.h
	doxygen

bat: $(BATNAME)

$(BATNAME): include/* src/* src/*/* test/batarch.map
	rm -fr $@
	for prim in dh sign; do \
          targ="$@/crypto_$$prim/ed448goldilocks"; \
	  (while read arch where; do \
	    mkdir -p $$targ/`basename $$arch`; \
	    cp include/*.h src/*.c src/include/*.h src/bat/$$prim.c src/p448/$$where/*.c src/p448/$$where/*.h src/p448/*.c src/p448/*.h $$targ/`basename $$arch`; \
	    cp src/bat/api_$$prim.h $$targ/`basename $$arch`/api.h; \
	    perl -p -i -e 's/.*endif.*GOLDILOCKS_CONFIG_H/#define SUPERCOP_WONT_LET_ME_OPEN_FILES 1\n\n$$&/' $$targ/`basename $$arch`/config.h; \
	    perl -p -i -e 's/SYSNAME/'`basename $(BATNAME)`_`basename $$arch`'/g' $$targ/`basename $$arch`/api.h;  \
	    perl -p -i -e 's/__TODAY__/'$(TODAY)'/g' $$targ/`basename $$arch`/api.h;  \
	    done \
	  ) < test/batarch.map; \
	  echo 'Mike Hamburg' > $$targ/designers; \
	  echo 'Ed448-Goldilocks sign and dh' > $$targ/description; \
        done
	(cd build && tar czf $(BATBASE).tgz $(BATBASE) )
	

todo::
	@(find * -name '*.h'; find * -name '*.c') | xargs egrep --color=auto -w \
		'HACK|TODO|FIXME|BUG|XXX|PERF|FUTURE|REMOVE|MAGIC'
	@echo '============================='
	@(for i in FIXME BUG XXX TODO HACK PERF FUTURE REMOVE MAGIC; do \
	  (find * -name '*.h'; find * -name '*.c') | xargs egrep -w $$i > /dev/null || continue; \
	  /bin/echo -n $$i'       ' | head -c 10; \
	  (find * -name '*.h'; find * -name '*.c') | xargs egrep -w $$i| wc -l; \
	done)
	@echo '============================='
	@echo -n 'Total     '
	@(find * -name '*.h'; find * -name '*.c') | xargs egrep -w \
		'HACK|TODO|FIXME|BUG|XXX|PERF|FUTURE|REMOVE|MAGIC' | wc -l

bench: build/bench
	./$<

test: build/test
	./$<

clean:
	rm -fr build doc $(BATNAME)
