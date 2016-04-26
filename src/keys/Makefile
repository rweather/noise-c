
.PHONY: all clean check

TOPDIR = ../..
SRCDIR = .

LIBRARY = libnoisekeys.a

CPPFLAGS = -I$(TOPDIR)/include
CFLAGS = -std=c99 -g -O2 -Wall $(CPPFLAGS)

SOURCES = \
	$(SRCDIR)/keystate.c \
	$(SRCDIR)/keyinternal.c

OBJECTS = $(patsubst %.c,%.o,$(SOURCES))
DEPS    = $(patsubst $(SRCDIR)/%.c,.depend/%.d,$(SOURCES))

all: $(LIBRARY)

$(LIBRARY): $(OBJECTS)
	$(RM) $(LIBRARY)
	$(AR) cr $(LIBRARY) $(OBJECTS)

clean:
	$(RM) $(OBJECTS) $(LIBRARY)
	$(RM) -r .depend

check:  all

.depend/%.d: $(SRCDIR)/%.c
	@set -e; rm -f $@; mkdir -p `dirname $@`; \
	$(CC) -MM $(CPPFLAGS) $< > $@.$$$$; \
	sed 's,\(.*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

-include $(DEPS)
