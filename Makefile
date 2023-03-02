CC_x64 := x86_64-w64-mingw32-gcc
CFLAGS	:= $(CFLAGS) -Wl,-e,BokuLoader
CFLAGS	:= $(CFLAGS) -O0 -fno-asynchronous-unwind-tables -nostdlib 
CFLAGS 	:= $(CFLAGS) -fno-ident -fpack-struct=8 -falign-functions=1
CFLAGS  := $(CFLAGS) -s -falign-jumps=1 -w
CFLAGS	:= $(CFLAGS) -falign-labels=1 -fPIC -masm=intel
LFLAGS	:= $(LFLAGS) -Wl,-s,--no-seh,--enable-stdcall-fixup

bokuloader: clean
	$(CC_x64) $(CFLAGS) $(LFLAGS) -c src/BokuLoader.c -o dist/BokuLoader.x64.o 
clean:
	rm -f dist/*.o
	rm -f ./*.c
