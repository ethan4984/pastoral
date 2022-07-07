DISK_IMAGE = pastoral.img
INITRAMFS = initramfs.tar

.PHONY: all
all: $(DISK_IMAGE)

QEMUFLAGS = -m 4G \
			-smp 1 \
			-drive id=disk,file=pastoral.img,if=none \
			-device ahci,id=ahci \
			-device ide-hd,drive=disk,bus=ahci.0 \
			-device intel-iommu,aw-bits=48 \
			-machine type=q35

.PHONY: run
run: $(DISK_IMAGE)
	qemu-system-x86_64 $(QEMUFLAGS) -enable-kvm -serial stdio 

.PHONY: console
console: $(DISK_IMAGE)
	qemu-system-x86_64 $(QEMUFLAGS) -no-reboot -monitor stdio -d int -D qemu.log -no-shutdown 

.PHONY: int
int: $(DISK_IMAGE)
	qemu-system-x86_64 $(QEMUFLAGS) -d int -M smm=off -no-reboot -no-shutdown

limine:
	git clone https://github.com/limine-bootloader/limine.git --branch=v3.0-branch-binary --depth=1
	make -C limine

.PHONY: kernel
kernel:
	$(MAKE) -C kernel

$(INITRAMFS):
	cd user/build/system-root/ && tar -c --format=posix -f ../../../initramfs.tar .

$(DISK_IMAGE): $(INITRAMFS) limine kernel 
	cd user && make
	rm -rf pastoral.img
	dd if=/dev/zero bs=1M count=0 seek=1024 of=pastoral.img
	parted -s pastoral.img mklabel msdos
	parted -s pastoral.img mkpart primary 1 100%
	rm -rf disk_image
	mkdir disk_image
	sudo losetup -Pf --show pastoral.img > loopback_dev
	sudo mkfs.ext2 `cat loopback_dev`p1
	sudo mount `cat loopback_dev`p1 disk_image
	sudo mkdir disk_image/boot
	sudo cp kernel/pastoral.elf disk_image/boot/
	sudo cp kernel/limine.cfg disk_image/
	sudo cp limine/limine.sys disk_image/boot/
	sudo cp user/.bashrc disk_image/
	sudo cp initramfs.tar disk_image/boot/
	sync
	sudo umount disk_image/
	sudo losetup -d `cat loopback_dev`
	rm -rf disk_image loopback_dev
	limine/limine-deploy pastoral.img 

rebuild_mlibc:
	cd user/build && xbstrap install mlibc --rebuild

.PHONY: clean
clean:
	rm -f $(DISK_IMAGE) $(INITRAMFS) serial.log qemu.log
	$(MAKE) -C kernel clean 

.PHONY: distclean
distclean: clean
	rm -rf limine
