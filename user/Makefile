CC = build/tools/host-gcc/bin/x86_64-pastoral-gcc

.PHONY: default
default: etcfiles init su


etcfiles:
	cp passwd build/system-root/etc
	cp group build/system-root/etc

init: init.c
	$(CC) $^ -o $@
	mv $@ build/system-root/usr/sbin/

su: su.c
	$(CC) $^ -o $@
	mv $@ build/system-root/usr/sbin/
	chmod +s build/system-root/usr/sbin/$@

build_toolchain:
	mkdir -p build
	cd build && xbstrap init .. && xbstrap install --all
