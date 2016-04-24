
.PHONY: all clean check

TOPDIR = ../..
SRCDIR = .

TEST_APP = test-performance

CPPFLAGS = -I$(TOPDIR)/include
CFLAGS = -g -O2 -Wall $(CPPFLAGS)
LDFLAGS = -L$(TOPDIR)/src/protocol -lnoiseprotocol

SOURCES = \
	test-performance.c \
	md5.c

OBJECTS = $(patsubst %.c,%.o,$(SOURCES))
DEPS    = $(patsubst %.c,.depend/%.d,$(SOURCES))

all: $(TEST_APP)

$(TEST_APP): $(OBJECTS)
	$(CC) $(CFLAGS) -o $(TEST_APP) $(OBJECTS) $(LDFLAGS)

clean:
	$(RM) $(OBJECTS) $(TEST_APP)
	$(RM) -r .depend

check:

.depend/%.d: %.c
	@set -e; rm -f $@; mkdir -p `dirname $@`; \
	$(CC) -MM $(CPPFLAGS) $< > $@.$$$$; \
	sed 's,\(.*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

-include $(DEPS)
