
.PHONY: all clean check

TOPDIR = ../../..
SRCDIR = ..

TEST_APP = echo-client

CPPFLAGS = -I$(TOPDIR)/include -I$(SRCDIR)/echo-server
CFLAGS = -std=c99 -g -O2 -Wall $(CPPFLAGS)
LDFLAGS = -L$(TOPDIR)/src/protocol -lnoiseprotocol

ifneq (,$(findstring mingw32,$(CC)))
    LDFLAGS += -lws2_32
endif

SOURCES = \
	$(SRCDIR)/echo-client/echo-client.c \
	$(SRCDIR)/echo-server/echo-common.c

OBJECTS = $(patsubst %.c,%.o,$(SOURCES))
DEPS    = $(patsubst $(SRCDIR)/%.c,.depend/%.d,$(SOURCES))

all: $(TEST_APP)

$(TEST_APP): $(OBJECTS)
	$(CC) $(CFLAGS) -o $(TEST_APP) $(OBJECTS) $(LDFLAGS)

clean:
	$(RM) $(OBJECTS) $(TEST_APP)
	$(RM) -r .depend

check:

.depend/%.d: $(SRCDIR)/%.c
	@set -e; rm -f $@; mkdir -p `dirname $@`; \
	$(CC) -MM $(CPPFLAGS) $< > $@.$$$$; \
	sed 's,\(.*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

-include $(DEPS)
