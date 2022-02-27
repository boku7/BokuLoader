CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc
OPTIONS := -masm=intel -Wall -Wno-pointer-arith

bokuloader: clean
	$(CC_x64) -c BokuLoader64.c -o dist/BokuLoader_rx_leave.x64.o $(OPTIONS)
	$(CC_x64) -c BokuLoader64.c -o dist/BokuLoader_rwx_leave.x64.o $(OPTIONS) -DUSE_RWX
	$(CC_x64) -c BokuLoader64.c -o dist/BokuLoader_rx_free.x64.o $(OPTIONS) -DFREE_HEADERS
	$(CC_x64) -c BokuLoader64.c -o dist/BokuLoader_rwx_free.x64.o $(OPTIONS) -DUSE_RWX -DFREE_HEADERS
	$(CC_x64) -c BokuLoader64.c -o dist/BokuLoader_rx_stomp.x64.o $(OPTIONS) -DSTOMP_HEADERS
	$(CC_x64) -c BokuLoader64.c -o dist/BokuLoader_rwx_stomp.x64.o $(OPTIONS) -DUSE_RWX -DSTOMP_HEADERS

	$(CC_x86) -c BokuLoader32.c -o dist/BokuLoader_rx_leave.x86.o $(OPTIONS)
	$(CC_x86) -c BokuLoader32.c -o dist/BokuLoader_rwx_leave.x86.o $(OPTIONS) -DUSE_RWX
	$(CC_x86) -c BokuLoader32.c -o dist/BokuLoader_rx_free.x86.o $(OPTIONS) -DFREE_HEADERS
	$(CC_x86) -c BokuLoader32.c -o dist/BokuLoader_rwx_free.x86.o $(OPTIONS) -DUSE_RWX -DFREE_HEADERS
	$(CC_x86) -c BokuLoader32.c -o dist/BokuLoader_rx_stomp.x86.o $(OPTIONS) -DSTOMP_HEADERS
	$(CC_x86) -c BokuLoader32.c -o dist/BokuLoader_rwx_stomp.x86.o $(OPTIONS) -DUSE_RWX -DSTOMP_HEADERS
clean:
	rm -f dist/*.o
