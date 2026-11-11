CC ?= gcc
UNAME := $(shell uname -s)
PROTO_C := ../EasySuiteWin/proto.c
PROTO_H := ../EasySuiteWin/proto.h

ifeq ($(UNAME),Linux)
GTK_CFLAGS := $(shell pkg-config --cflags gtk+-3.0 2>/dev/null)
GTK_LIBS := $(shell pkg-config --libs gtk+-3.0 2>/dev/null)
FUSE_CFLAGS := $(shell pkg-config --cflags fuse3 2>/dev/null)
FUSE_LIBS := $(shell pkg-config --libs fuse3 2>/dev/null)
ifeq ($(strip $(GTK_LIBS)),)
$(error GTK 3 headers not found. Install libgtk-3-dev, or the equivalent package, then re-run make.)
endif
ifeq ($(strip $(FUSE_LIBS)),)
$(error FUSE 3 headers not found. Install libfuse3-dev and fuse3, then re-run make.)
endif
CFLAGS := -O2 -Wall -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 $(GTK_CFLAGS) $(FUSE_CFLAGS) -I../EasySuiteWin
LIBS := $(GTK_LIBS) $(FUSE_LIBS) -lpthread

all: easysuite

easysuite: easysuite.c $(PROTO_C) $(PROTO_H)
	$(CC) $(CFLAGS) -o $@ easysuite.c $(PROTO_C) $(LIBS)
else
all: selftest
endif

selftest: $(PROTO_C) $(PROTO_H)
	clang -DSELFTEST -Wall -Wextra -O2 -I../EasySuiteWin -o easysuite-test $(PROTO_C) && ./easysuite-test

clean:
	rm -f easysuite easysuite-test
