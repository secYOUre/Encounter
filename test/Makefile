# encounter-tests Makefile

BINS=encounter-primer encounter-stressful
LIBNAME=libencounter

# Fallback to gcc when $CC is not in $PATH
CC:=$(shell sh -c 'type $(CC) >/dev/null 2>/dev/null && echo $(CC) || echo gcc')
OPTIMIZATION?=-O0
WARNINGS=-Wall -W -Wstrict-prototypes -Wwrite-strings
DEBUG?= -g -ggdb
INCLUDEPATH=-I../include/encounter 
CFLAGS=-DUSE_OPENSSL $(INCLUDEPATH)
LDFLAGS+=-L../src  -lencounter -lcrypto -lbsd
REAL_CFLAGS=$(OPTIMIZATION) -fPIC $(CFLAGS) $(WARNINGS) $(DEBUG)
REAL_LDFLAGS=$(LDFLAGS)

all: $(BINS)

# Deps (use make dep to generate this)
primer.o: ../test/primer.c ../include/encounter/encounter.h
stressful.o: ../test/stressful.c ../include/encounter/encounter.h

# Binaries:
encounter-%: %.o $(STLIBNAME)
	$(CC) -o $@ $(REAL_LDFLAGS) $< $(STLIBNAME)

test: encounter-primer encounter-stressful
	./encounter-primer

.c.o:
	$(CC) -std=c99 -pedantic -c $(REAL_CFLAGS) $(REAL_LDFLAGS) $<

clean:
	rm -rf $(DYLIBNAME) $(STLIBNAME) $(BINS) encounter-primer* encounter-stressful* *.o *.gcda *.gcno *.gcov

dep:
	$(CC) $(CFLAGS) -MM *.c ../test/*.c

# Installation related variables and target
PREFIX?=/usr/local
INCLUDE_PATH?=include/encounter
LIBRARY_PATH?=lib
INSTALL_INCLUDE_PATH= $(PREFIX)/$(INCLUDE_PATH)
INSTALL_LIBRARY_PATH= $(PREFIX)/$(LIBRARY_PATH)

ifeq ($(uname_S),SunOS)
  INSTALL?= cp -r
endif

INSTALL?= cp -a

install: $(DYLIBNAME) $(STLIBNAME)
	mkdir -p $(INSTALL_INCLUDE_PATH) $(INSTALL_LIBRARY_PATH)
	$(INSTALL) encounter.h $(INSTALL_INCLUDE_PATH)
	$(INSTALL) $(DYLIBNAME) $(INSTALL_LIBRARY_PATH)/$(DYLIB_MINOR_NAME)
	cd $(INSTALL_LIBRARY_PATH) && ln -sf $(DYLIB_MINOR_NAME) $(DYLIB_MAJOR_NAME)
	cd $(INSTALL_LIBRARY_PATH) && ln -sf $(DYLIB_MAJOR_NAME) $(DYLIBNAME)
	$(INSTALL) $(STLIBNAME) $(INSTALL_LIBRARY_PATH)

32bit:
	@echo ""
	@echo "WARNING: if this fails under Linux you probably need to install libc6-dev-i386"
	@echo ""
	$(MAKE) CFLAGS="-m32" LDFLAGS="-m32"

gprof:
	$(MAKE) CFLAGS="-pg" LDFLAGS="-pg"

gcov:
	$(MAKE) CFLAGS="-fprofile-arcs -ftest-coverage" LDFLAGS="-fprofile-arcs"

coverage: gcov
	make check
	mkdir -p tmp/lcov
	lcov -d . -c -o tmp/lcov/encounter.info
	genhtml --legend -o tmp/lcov/report tmp/lcov/encounter.info

noopt:
	$(MAKE) OPTIMIZATION=""

.PHONY: all test check clean dep install 32bit gprof gcov noopt
