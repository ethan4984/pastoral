CC = build/tools/host-gcc/bin/x86_64-pastoral-gcc

.PHONY: default
default: etcfiles init su program runfolder


etcfiles:
	cp .bashrc build/system-root/
	cp .nanorc build/system-root/etc
	cp passwd build/system-root/etc
	cp group build/system-root/etc
	cp inittab build/system-root/etc

init: init.c
	$(CC) $^ -o $@
	mv $@ build/system-root/usr/sbin/

su: su.c
	$(CC) $^ -o $@
	mv $@ build/system-root/usr/sbin/
	chmod +s build/system-root/usr/sbin/$@

program: program.c
	$(CC) $^ -o $@
	mv $@ build/system-root/usr/sbin/

runfolder:
	mkdir -p build/system-root/run

build_toolchain:
	mkdir -p build
	cd build && xbstrap init .. && xbstrap install --all
