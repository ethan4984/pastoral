CC = build/tools/host-gcc/bin/x86_64-pastoral-gcc

main:
	$(CC) init.c -o init
	mv init build/system-root

build_toolchain:
	mkdir -p build
	cd build && xbstrap init .. && xbstrap install --all
