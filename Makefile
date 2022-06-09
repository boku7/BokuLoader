CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc
OPTIONS := -masm=intel -Wall -Wno-pointer-arith

bokuloader: clean
	$(CC_x64) -c BokuLoader64.c -o dist/BokuLoader.x64.o $(OPTIONS)
clean:
	rm -f dist/*.o
