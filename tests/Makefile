
.PHONY: all clean check

SUBDIRS = unit

all:
	@for dir in $(SUBDIRS) ; do \
	    $(MAKE) -C $$dir all; \
        done

clean:
	@for dir in $(SUBDIRS) ; do \
	    $(MAKE) -C $$dir clean; \
        done

check:
	@for dir in $(SUBDIRS) ; do \
	    $(MAKE) -C $$dir check; \
        done
