
.PHONY: all clean check

SUBDIRS = echo-client echo-keygen echo-server

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
