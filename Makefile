CC_x64 := x86_64-w64-mingw32-gcc
CFLAGS	:= $(CFLAGS) -O0 
CFLAGS  := $(CFLAGS) -masm=intel -Wall -Wno-pointer-arith -w

bokuloader: clean
	$(CC_x64) $(CFLAGS) -c src/BokuLoader.c -o dist/BokuLoader.x64.o 
clean:
	rm -f dist/*.o
	rm -f ./*.c
