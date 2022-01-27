CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc
STRIP_x64 := x86_64-w64-mingw32-strip
STRIP_x86 := i686-w64-mingw32-strip
OPTIONS := -shared -masm=intel -Wall -Wno-pointer-arith

bokuloader: clean
	$(CC_x64) -c BokuLoader64.c -o BokuLoader.x64.o $(OPTIONS)
	$(STRIP_x64) --strip-unneeded BokuLoader.x64.o
	$(CC_x86) -c BokuLoader32.c -o BokuLoader.x86.o $(OPTIONS)
	$(STRIP_x86) --strip-unneeded BokuLoader.x86.o

clean:
	rm -f *.o
