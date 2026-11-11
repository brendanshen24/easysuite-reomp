CC := x86_64-w64-mingw32-gcc
WINDRES := x86_64-w64-mingw32-windres
CFLAGS := -O2 -Wall -mwindows -static -DUNICODE -D_UNICODE -D_WIN32_WINNT=0x0601

all: easysuite.exe

easysuite.res: easysuite.rc easysuite.manifest
	$(WINDRES) -O coff -o $@ easysuite.rc

easysuite.exe: easysuite.c proto.c proto.h easysuite.res
	$(CC) $(CFLAGS) -o $@ easysuite.c proto.c easysuite.res -lcomctl32 -lcomdlg32 -lshell32 -lole32 -luuid

selftest: proto.c proto.h
	clang -DSELFTEST -Wall -Wextra -O2 -o proto-test proto.c && ./proto-test

clean:
	rm -f easysuite.exe easysuite.res proto-test
