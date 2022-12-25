DISK_IMAGE = pastoral.img
ISO_IMAGE = pastoral.iso
INITRAMFS = initramfs.tar

.PHONY: all
all: $(DISK_IMAGE)

QEMUFLAGS = -m 4G \
			-smp 1 \
			-drive id=disk,file=$(DISK_IMAGE),if=none \
			-device ahci,id=ahci \
			-device ide-hd,drive=disk,bus=ahci.0 \
			-device intel-iommu,aw-bits=48 \
			-machine type=q35

QEMUFLAGS_ISO = -m 4G \
				-smp 1 \
				-drive id=disk,file=$(ISO_IMAGE),if=none \
				-device ahci,id=ahci \
				-device ide-hd,drive=disk,bus=ahci.0 \
				-device intel-iommu,aw-bits=48 \
				-machine type=q35

.PHONY: run
run: $(DISK_IMAGE)
	qemu-system-x86_64 $(QEMUFLAGS) -enable-kvm -serial stdio

.PHONY: run_initrd
run_initrd: $(ISO_IMAGE)
	qemu-system-x86_64 $(QEMUFLAGS_ISO) -enable-kvm -serial stdio

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

$(ISO_IMAGE): $(INITRAMFS) limine kernel
	cd user && make
	rm -rf pastoral.iso
	rm -rf disk_image
	mkdir disk_image
	mkdir disk_image/boot
	cp kernel/pastoral.elf initramfs.tar limine/limine-cd.bin limine/limine-cd-efi.bin limine/limine.sys kernel/limine_initrd.cfg disk_image/boot
	mv disk_image/boot/limine_initrd.cfg disk_image/boot/limine.cfg
	xorriso -as mkisofs -b boot/limine-cd.bin -no-emul-boot -boot-load-size 4 -boot-info-table --efi-boot boot/limine-cd-efi.bin -efi-boot-part --efi-boot-image --protective-msdos-label disk_image -o pastoral.iso
	./limine/limine-deploy pastoral.iso
	rm -rf disk_image

$(DISK_IMAGE): limine kernel
	cd user && make
	rm -f pastoral.img 
	dd if=/dev/zero bs=1M count=0 seek=1024 of=pastoral.img
	parted -s pastoral.img mklabel msdos
	parted -s pastoral.img mkpart primary 1 100%
	rm -rf disk_image
	mkdir disk_image
	sudo losetup -Pf --show pastoral.img > loopback_dev
	sudo mkfs.ext2 `cat loopback_dev`p1
	sudo mount `cat loopback_dev`p1 disk_image
	sudo mkdir disk_image/boot
	sudo cp kernel/pastoral.elf kernel/limine.cfg limine/limine.sys disk_image/boot
	sync
	sudo umount disk_image/
	sudo losetup -d `cat loopback_dev`
	rm -rf disk_image loopback_dev
	./limine/limine-deploy pastoral.img

rebuild_mlibc:
	cd user/build && xbstrap install mlibc --rebuild

.PHONY: clean
clean:
	rm -f $(DISK_IMAGE) $(INITRAMFS) serial.log qemu.log
	$(MAKE) -C kernel clean

.PHONY: distclean
distclean: clean
	rm -rf limine
