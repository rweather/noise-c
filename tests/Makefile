
.PHONY: all clean check

SUBDIRS = unit vector performance

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
