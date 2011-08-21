# encounter Makefile

OBJ=openssl_drv.o plainstore_drv.o encounter.o keyset.o utils.o
LIBNAME=libencounter

ENCOUNTER_MAJOR=0
ENCOUNTER_MINOR=1

# Fallback to gcc when $CC is not in $PATH
CC:=$(shell sh -c 'type $(CC) >/dev/null 2>/dev/null && echo $(CC) || echo gcc')
OPTIMIZATION?=-O0
WARNINGS=-Wall -W -Wstrict-prototypes -Wwrite-strings
DEBUG?= -g -ggdb -D__ENCOUNTER_DEBUG_
INCLUDEPATH=-I../include/encounter
CFLAGS=-DUSE_OPENSSL -DUSE_PLAINSTORE $(INCLUDEPATH)
REAL_CFLAGS=$(OPTIMIZATION) -fPIC $(CFLAGS) $(WARNINGS) $(DEBUG)
REAL_LDFLAGS=$(LDFLAGS)

DYLIBSUFFIX=so
STLIBSUFFIX=a
DYLIB_MINOR_NAME=$(LIBNAME).$(DYLIBSUFFIX).$(ENCOUNTER_MAJOR).$(ENCOUNTER_MINOR)
DYLIB_MAJOR_NAME=$(LIBNAME).$(DYLIBSUFFIX).$(ENCOUNTER_MAJOR)
DYLIBNAME=$(LIBNAME).$(DYLIBSUFFIX)
DYLIB_MAKE_CMD=$(CC) -shared -Wl,-soname,$(DYLIB_MINOR_NAME) -o $(DYLIBNAME) $(LDFLAGS)
STLIBNAME=$(LIBNAME).$(STLIBSUFFIX)
STLIB_MAKE_CMD=ar rcs $(STLIBNAME)

# Platform-specific override
uname_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')
ifeq ($(uname_S),SunOS)
	REAL_LDFLAGS+= -ldl -lnsl -lsocket
	DYLIB_MAKE_CMD=$(CC) -G -o $(DYLIBNAME) -h $(DYLIB_MINOR_NAME) $(LDFLAGS)
	INSTALL= cp -r
endif
ifeq ($(uname_S),Darwin)
	DYLIBSUFFIX=dylib
	DYLIB_MINOR_NAME=$(LIBNAME).$(ENCOUNTER_MAJOR).$(ENCOUNTER_MINOR).$(DYLIBSUFFIX)
	DYLIB_MAJOR_NAME=$(LIBNAME).$(ENCOUNTER_MAJOR).$(DYLIBSUFFIX)
	DYLIB_MAKE_CMD=$(CC) -shared -Wl,-install_name,$(DYLIB_MINOR_NAME) -o $(DULIBNAME) $(LDFLAGS)
endif
ifeq ($(uname_S),Linux)
	REAL_LDFLAGS+= -lbsd
endif

all: $(DYLIBNAME) 

# Deps (use make dep to generate this)
encounter.o: encounter.c ../include/encounter/encounter.h encounter_priv.h openssl_drv.h 
openssl_drv.o: openssl_drv.c openssl_drv.h ../include/encounter/encounter.h
plainstore_drv.o: plainstore_drv.c ../include/encounter/encounter.h \
 encounter_priv.h openssl_drv.h plainstore_drv.h utils.h
utils.o: utils.c utils.h ../include/encounter/encounter.h encounter_priv.h openssl_drv.h plainstore_drv.h
keyset.o: keyset.c ../include/encounter/encounter.h encounter_priv.h \
 openssl_drv.h plainstore_drv.h keyset.h
example.o: ../test/example.c ../include/encounter/encounter.h

$(DYLIBNAME): $(OBJ)
	$(DYLIB_MAKE_CMD) $(OBJ)

$(STLIBNAME): $(OBJ)
	$(STLIB_MAKE_CMD) $(OBJ)

dynamic: $(DYLIBNAME)
static: $(STLIBNAME)

# Binaries:
encounter-%: %.o $(STLIBNAME)
	$(CC) -o $@ $(REAL_LDFLAGS) $< $(STLIBNAME)

test: encounter-example
	./encounter-example

.c.o:
	$(CC) -std=c99 -pedantic -c $(REAL_CFLAGS) $<

clean:
	rm -rf $(DYLIBNAME) $(STLIBNAME) *.o *.gcda *.gcno *.gcov

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
