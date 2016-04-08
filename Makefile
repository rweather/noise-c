
.PHONY: all clean check docs

SUBDIRS       = src tests
TESTS_SUBDIRS = tests

all:
	@for dir in $(SUBDIRS) ; do \
	    $(MAKE) -C $$dir all; \
        done

clean:
	@for dir in $(SUBDIRS) ; do \
	    $(MAKE) -C $$dir clean; \
        done

check:	all
	@for dir in $(TESTS_SUBDIRS) ; do \
	    $(MAKE) -C $$dir check; \
        done

docs:
	(cd doc; doxygen)
