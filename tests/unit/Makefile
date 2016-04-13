
.PHONY: all clean check

TOPDIR = ../..
SRCDIR = .

TEST_APP = test-noise

CPPFLAGS = -I$(TOPDIR)/include -I$(TOPDIR)/src
CFLAGS = -std=c99 -g -Wall $(CPPFLAGS)
LDFLAGS = -L$(TOPDIR)/src/protocol -lnoiseprotocol

SOURCES = \
	test-cipherstate.c \
	test-dhstate.c \
	test-errors.c \
	test-hashstate.c \
	test-main.c \
	test-names.c \
	test-patterns.c

OBJECTS = $(patsubst %.c,%.o,$(SOURCES))
DEPS    = $(patsubst %.c,.depend/%.d,$(SOURCES))

all: $(TEST_APP)

$(TEST_APP): $(OBJECTS)
	$(CC) $(CFLAGS) -o $(TEST_APP) $(OBJECTS) $(LDFLAGS)

clean:
	$(RM) $(OBJECTS) $(TEST_APP)
	$(RM) -r .depend

check:  all
	./$(TEST_APP)

.depend/%.d: %.c
	@set -e; rm -f $@; mkdir -p `dirname $@`; \
	$(CC) -MM $(CPPFLAGS) $< > $@.$$$$; \
	sed 's,\(.*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

-include $(DEPS)
