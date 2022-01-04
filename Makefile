CC_x64 := x86_64-w64-mingw32-gcc
STRIP_x64 := x86_64-w64-mingw32-strip

bokuloader: clean
	$(CC_x64) -c BokuLoader.c -o BokuLoader.x64.o -shared -masm=intel
	$(STRIP_x64) --strip-unneeded BokuLoader.x64.o

clean:
	rm -f *.o
