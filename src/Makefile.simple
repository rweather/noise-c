
.PHONY: all clean check

SUBDIRS       = protocol

all:
	@for dir in $(SUBDIRS) ; do \
	    $(MAKE) -C $$dir all; \
        done

clean:
	@for dir in $(SUBDIRS) ; do \
	    $(MAKE) -C $$dir clean; \
        done

check:	all
