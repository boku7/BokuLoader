CC_x64 := x86_64-w64-mingw32-gcc
OPTIONS := -masm=intel -Wall -Wno-pointer-arith -w

bokuloader: clean
	$(CC_x64) -c src/BokuLoader.c -o dist/BokuLoader.x64.o $(OPTIONS)
clean:
	rm -f dist/*.o
	rm -f ./*.c
