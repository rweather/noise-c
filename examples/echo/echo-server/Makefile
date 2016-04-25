
.PHONY: all clean check

TOPDIR = ../../..
SRCDIR = .

TEST_APP = echo-server

CPPFLAGS = -I$(TOPDIR)/include
CFLAGS = -std=c99 -g -O2 -Wall $(CPPFLAGS)
LDFLAGS = -L$(TOPDIR)/src/protocol -lnoiseprotocol

ifneq (,$(findstring mingw32,$(CC)))
    LDFLAGS += -lws2_32
endif

SOURCES = \
	echo-server.c \
	echo-common.c

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
